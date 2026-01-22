use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput, Data, Fields, LitInt, Attribute};

#[proc_macro_derive(Packet, attributes(packet_id))]
pub fn derive_packet(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    let packet_id = match extract_packet_id(&input.attrs) {
        Ok(id) => id,
        Err(e) => return e.to_compile_error().into(),
    };

    let Data::Struct(data) = &input.data else {
        return syn::Error::new_spanned(&input, "Packet derive only supports structs")
            .to_compile_error()
            .into();
    };

    let Fields::Named(fields) = &data.fields else {
        return syn::Error::new_spanned(&input, "Packet derive only supports named fields")
            .to_compile_error()
            .into();
    };

    let field_names: Vec<_> = fields.named.iter().map(|f| f.ident.as_ref().unwrap()).collect();
    let field_types: Vec<_> = fields.named.iter().map(|f| &f.ty).collect();

    // Encode: all fields that implement PacketField::encode
    let encode_fields = field_names.iter().map(|name| {
        quote! { self.#name.encode(writer)?; }
    });

    // Decode: all fields that implement PacketField::decode
    let decode_fields = field_names.iter().zip(field_types.iter()).map(|(name, ty)| {
        quote! { let #name = <#ty>::decode(reader)?; }
    });

    let expanded = quote! {
        impl crate::server::core::network::packet::packet::Packet for #name {
            fn packet_id(&self) -> u32 {
                #packet_id
            }

            fn default_id() -> u32 {
                #packet_id
            }

            fn encode(&self, writer: &mut dyn std::io::Write) -> std::io::Result<()> {
                #(#encode_fields)*
                Ok(())
            }

            fn decode(reader: &mut dyn std::io::Read) -> Result<Self, crate::server::core::network::packet::packet_codec::CodecError>
            where
                Self: Sized,
            {
                use std::io::Read;
                use crate::server::core::network::packet::packet_codec::CodecError;
                
                #(#decode_fields)*
                Ok(#name {
                    #(#field_names),*
                })
            }
        }
    };

    TokenStream::from(expanded)
}

fn extract_packet_id(attrs: &[Attribute]) -> syn::Result<u32> {
    for attr in attrs {
        if attr.path().is_ident("packet_id") {
            let lit: LitInt = attr.parse_args()?;
            return Ok(lit.base10_parse()?);
        }
    }
    Err(syn::Error::new_spanned(attrs.first(), "Missing #[packet_id(N)] attribute"))
}

#[proc_macro_derive(PacketField)]
pub fn derive_packet_field(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    let implementation = match &input.data {
        Data::Enum(data_enum) => generate_enum_packet_field(name, data_enum),
        Data::Struct(data_struct) => generate_struct_packet_field(name, data_struct),
        _ => {
            return syn::Error::new_spanned(&input, "PacketField only supports structs and enums")
                .to_compile_error()
                .into();
        }
    };

    implementation.into()
}

fn generate_enum_packet_field(name: &syn::Ident, data_enum: &syn::DataEnum) -> proc_macro2::TokenStream {
    let mut variants_vec = Vec::new();

    for variant in &data_enum.variants {
        let ident = &variant.ident;
        let discriminant = match &variant.discriminant {
            Some((_, expr)) => expr,
            None => {
                let error = syn::Error::new_spanned(
                    variant,
                    "All enum variants must have explicit discriminants",
                );
                return error.to_compile_error();
            }
        };
        variants_vec.push((ident, discriminant));
    }

    let encode_arms = variants_vec.iter().map(|(ident, disc)| {
        quote! { #name::#ident => {
            let value: u8 = #disc as u8;
            value.encode(writer)
        } }
    });

    let decode_arms = variants_vec.iter().map(|(ident, disc)| {
        quote! { #disc => Ok(#name::#ident) }
    });

    quote! {
        impl crate::server::core::network::packet::packet_codec::PacketField for #name {
            fn encode(&self, writer: &mut dyn std::io::Write) -> std::io::Result<()> {
                match self {
                    #(#encode_arms),*
                }
            }

            fn decode(reader: &mut dyn std::io::Read) -> Result<Self, crate::server::core::network::packet::packet_codec::CodecError> {
                let value = u8::decode(reader)?;
                match value {
                    #(#decode_arms,)*
                    v => Err(crate::server::core::network::packet::packet_codec::CodecError::Decode(
                        format!("Invalid {} discriminant: {}", stringify!(#name), v)
                    )),
                }
            }
        }
    }
}

fn generate_struct_packet_field(name: &syn::Ident, data_struct: &syn::DataStruct) -> proc_macro2::TokenStream {
    let fields = match &data_struct.fields {
        Fields::Named(f) => f,
        _ => {
            let error = syn::Error::new_spanned(
                &data_struct.fields,
                "PacketField only supports named fields",
            );
            return error.to_compile_error();
        }
    };

    let field_names: Vec<_> = fields.named.iter().map(|f| f.ident.as_ref().unwrap()).collect();
    let field_types: Vec<_> = fields.named.iter().map(|f| &f.ty).collect();

    let encode_fields = field_names.iter().map(|field_name| {
        quote! { self.#field_name.encode(writer)?; }
    });

    let decode_fields = field_names.iter().zip(field_types.iter()).map(|(field_name, ty)| {
        quote! { let #field_name = <#ty>::decode(reader)?; }
    });

    quote! {
        impl crate::server::core::network::packet::packet_codec::PacketField for #name {
            fn encode(&self, writer: &mut dyn std::io::Write) -> std::io::Result<()> {
                #(#encode_fields)*
                Ok(())
            }

            fn decode(reader: &mut dyn std::io::Read) -> Result<Self, crate::server::core::network::packet::packet_codec::CodecError> {
                use std::io::Read;
                
                #(#decode_fields)*
                Ok(#name {
                    #(#field_names),*
                })
            }
        }
    }
}
