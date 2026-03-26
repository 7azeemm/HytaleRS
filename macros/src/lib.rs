extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::parse::Parser;
use syn::{Data, DeriveInput, Error, Fields, Result, parse_macro_input};

#[derive(Default)]
struct PacketAttrs {
    id: Option<u32>,
    max_size: Option<u32>,
    compressed: bool,
}

impl PacketAttrs {
    fn parse(&mut self, meta: syn::meta::ParseNestedMeta) -> Result<()> {
        if meta.path.is_ident("id") {
            self.id = Some(meta.value()?.parse::<syn::LitInt>()?.base10_parse()?);
            Ok(())
        } else if meta.path.is_ident("max_size") {
            self.max_size = Some(meta.value()?.parse::<syn::LitInt>()?.base10_parse()?);
            Ok(())
        } else if meta.path.is_ident("compressed") {
            self.compressed = true;
            Ok(())
        } else {
            Err(meta.error("unsupported attribute"))
        }
    }
}

fn generate_layout(field_types: &[&syn::Type]) -> proc_macro2::TokenStream {
    quote! {
        {
            const _: () = {
                let mut seen_var = false;
                #(
                    if <#field_types as crate::io::codecs::PacketCodec>::SIZE.is_none() {
                        seen_var = true;
                    } else if seen_var {
                        panic!("fixed field after variable field");
                    }
                )*
            };

            let fixed_block_size = 0 #(+ match <#field_types as crate::io::codecs::PacketCodec>::SIZE {
                Some(size) => size,
                None => 0,
            })*;

            let var_field_count = 0usize #(+ if <#field_types as crate::io::codecs::PacketCodec>::SIZE.is_none() { 1 } else { 0 })*;
            let opt_field_count = 0usize #(+ if <#field_types as crate::io::codecs::PacketCodec>::OPTIONAL { 1 } else { 0 })*;

            crate::io::packet::PacketLayout {
                fixed_block_size,
                var_field_count,
                opt_field_count
            }
        }
    }
}

#[proc_macro_attribute]
pub fn packet(args: TokenStream, input: TokenStream) -> TokenStream {
    let mut attrs = PacketAttrs::default();
    let parser = syn::meta::parser(|meta| attrs.parse(meta));
    parse_macro_input!(args with parser);

    let input = parse_macro_input!(input as DeriveInput);
    let struct_name = &input.ident;

    let Some(id) = attrs.id else {
        return Error::new(proc_macro2::Span::call_site(), "missing `id`")
            .to_compile_error()
            .into();
    };

    let Some(max_size) = attrs.max_size else {
        return Error::new(proc_macro2::Span::call_site(), "missing `max_size`")
            .to_compile_error()
            .into();
    };

    let compressed = attrs.compressed;

    // Extract fields
    let fields = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(fields) => fields.named.iter().collect::<Vec<_>>(),
            _ => {
                return Error::new_spanned(struct_name, "packet must have named fields")
                    .to_compile_error()
                    .into();
            }
        },
        _ => {
            return Error::new_spanned(struct_name, "packet must be a struct")
                .to_compile_error()
                .into();
        }
    };

    let field_names: Vec<_> = fields.iter().map(|f| f.ident.as_ref().unwrap()).collect();
    let field_types: Vec<_> = fields.iter().map(|f| &f.ty).collect();
    let layout = generate_layout(&field_types);

    let expanded = quote! {
        #[derive(Debug, Clone)]
        #input

        impl crate::io::packet::Packet for #struct_name {
            const LAYOUT: crate::io::packet::PacketLayout = #layout;
            const ID: u32 = #id;
            const NAME: &'static str = stringify!(#struct_name);
            const IS_COMPRESSED: bool = #compressed;
            const MAX_SIZE: u32 = #max_size;
        }

        impl crate::io::codecs::PacketCodec for #struct_name {
            const SIZE: Option<usize> = None;

            fn encode(&self, enc: &mut crate::io::encoder::Encoder) -> crate::io::errors::PacketResult<()> {
                #(
                    enc.write(&self.#field_names)?;
                )*

                Ok(())
            }

            fn decode(dec: &mut crate::io::decoder::Decoder) -> crate::io::errors::PacketResult<Self> {
                #(
                    let #field_names: #field_types = dec.read(stringify!(#field_names))?;
                )*

                Ok(Self {
                    #(#field_names,)*
                })
            }
        }

        inventory::submit! {
            crate::io::packet::PacketInfo {
                id: <#struct_name as crate::io::packet::Packet>::ID,
                name: stringify!(#struct_name),
                is_compressed: <#struct_name as crate::io::packet::Packet>::IS_COMPRESSED,
                max_size: <#struct_name as crate::io::packet::Packet>::MAX_SIZE,
            }
        }
    };

    TokenStream::from(expanded)
}

#[proc_macro_attribute]
pub fn packet_field(_args: TokenStream, input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    let fields = match &input.data {
        Data::Struct(data) => &data.fields,
        _ => {
            return Error::new_spanned(input, "packet_field can only be applied to structs")
                .to_compile_error()
                .into();
        }
    };

    let field_names: Vec<_> = fields.iter().filter_map(|f| f.ident.as_ref()).collect();
    let field_types: Vec<_> = fields.iter().map(|f| &f.ty).collect();
    let layout = generate_layout(&field_types);

    let expanded = quote! {
        #[derive(Debug, Clone)]
        #input

        impl #name {
            pub const LAYOUT: crate::io::packet::PacketLayout = #layout;
        }

        impl crate::io::codecs::PacketCodec for #name {
            const SIZE: Option<usize> = {
                let all_sized = true #(&& <#field_types as crate::io::codecs::PacketCodec>::SIZE.is_some())*;

                if all_sized {
                    let null_bytes = Self::LAYOUT.opt_field_count.div_ceil(8);
                    Some(null_bytes #(+ <#field_types as crate::io::codecs::PacketCodec>::SIZE.unwrap())*)
                } else {
                    None
                }
            };

            fn encode(&self, enc: &mut crate::io::encoder::Encoder) -> crate::io::errors::PacketResult<()> {
                let needs_scope = Self::LAYOUT.opt_field_count > 0 || Self::LAYOUT.var_field_count > 0;

                if needs_scope {
                    enc.enter_field(&Self::LAYOUT);
                }

                #(
                    enc.write(&self.#field_names)?;
                )*

                if needs_scope {
                    enc.leave_field();
                }

                Ok(())
            }

            fn decode(dec: &mut crate::io::decoder::Decoder) -> crate::io::errors::PacketResult<Self> {
                let needs_scope = Self::LAYOUT.opt_field_count > 0 || Self::LAYOUT.var_field_count > 0;

                if needs_scope {
                    dec.enter_field(&Self::LAYOUT);
                }

                #(
                    let #field_names: #field_types = dec.read(stringify!(#field_names))?;
                )*

                if needs_scope {
                    dec.leave_field();
                }

                Ok(Self {
                    #(#field_names,)*
                })
            }
        }
    };

    TokenStream::from(expanded)
}

#[proc_macro_attribute]
pub fn packet_enum(_args: TokenStream, input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    // Verify it's an enum with only unit variants
    match &input.data {
        Data::Enum(data) => {
            for variant in &data.variants {
                if !variant.fields.is_empty() {
                    return Error::new_spanned(
                        variant,
                        "packet_enum only supports unit variants (no fields)",
                    )
                    .to_compile_error()
                    .into();
                }
            }
        }
        _ => {
            return Error::new_spanned(input, "packet_enum can only be applied to enums")
                .to_compile_error()
                .into();
        }
    };

    let expanded = quote! {
        #[derive(Debug, Clone, Copy, num_enum::IntoPrimitive, num_enum::TryFromPrimitive,
            strum_macros::Display, serde::Serialize, serde::Deserialize)]
        #[repr(u8)]
        #input

        impl crate::io::codecs::PacketCodec for #name {
            const SIZE: Option<usize> = Some(1);

            fn encode(&self, enc: &mut crate::io::encoder::Encoder) -> crate::io::errors::PacketResult<()> {
                enc.write_byte(*self as u8);
                Ok(())
            }

            fn decode(dec: &mut crate::io::decoder::Decoder) -> crate::io::errors::PacketResult<Self> {
                let byte = dec.read_byte()?;
                <Self as std::convert::TryFrom<u8>>::try_from(byte)
                    .map_err(|_| crate::io::errors::PacketError::DecodeError(
                        format!("Failed to decode enum {}: invalid value {}", stringify!(#name), byte),
                    ))
            }
        }
    };

    TokenStream::from(expanded)
}

#[derive(Default)]
struct InteractionAttrs {
    id: Option<usize>,
}

impl InteractionAttrs {
    fn parse(&mut self, meta: syn::meta::ParseNestedMeta) -> Result<()> {
        if meta.path.is_ident("id") {
            self.id = Some(meta.value()?.parse::<syn::LitInt>()?.base10_parse()?);
            Ok(())
        } else {
            Err(meta.error("unsupported attribute"))
        }
    }
}

#[proc_macro_attribute]
pub fn interaction(args: TokenStream, input: TokenStream) -> TokenStream {
    let mut attrs = InteractionAttrs::default();
    let parser = syn::meta::parser(|meta| attrs.parse(meta));
    parse_macro_input!(args with parser);

    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    let Some(id) = attrs.id else {
        return Error::new(proc_macro2::Span::call_site(), "missing `id`")
            .to_compile_error()
            .into();
    };

    quote! {
        #input

        impl crate::packets::assets::interactions::interaction::InteractionKind for #name {
            fn id(&self) -> usize { #id }

            fn encode(&self, enc: &mut crate::io::encoder::Encoder) -> crate::io::errors::PacketResult<()> {
                crate::io::codecs::PacketCodec::encode(self, enc)
            }

            fn clone_box(&self) -> Box<dyn crate::packets::assets::interactions::interaction::InteractionKind> {
                Box::new(self.clone())
            }
        }
    }.into()
}