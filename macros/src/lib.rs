extern crate proc_macro;

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput, Data, Error, Result};

#[proc_macro_attribute]
pub fn packet_enum(_args: TokenStream, input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    match packet_enum_impl(&input) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.to_compile_error().into(),
    }
}

fn packet_enum_impl(input: &DeriveInput) -> Result<proc_macro2::TokenStream> {
    let name = &input.ident;

    // Verify it's an enum with only unit variants
    match &input.data {
        Data::Enum(data) => {
            for variant in &data.variants {
                if !variant.fields.is_empty() {
                    return Err(Error::new_spanned(
                        variant,
                        "packet_enum only supports unit variants (no fields)",
                    ));
                }
            }
        },
        _ => return Err(Error::new_spanned(input, "packet_enum can only be applied to enums")),
    }

    let expanded = quote! {
        #[derive(Debug, Clone, Copy, num_enum::IntoPrimitive, num_enum::TryFromPrimitive, strum_macros::Display)]
        #[repr(u8)]
        #input

        impl crate::io::codecs::PacketCodec for #name {
            const SIZE: Option<usize> = Some(1);

            fn encode(&self, enc: &mut crate::io::encoder::Encoder) -> crate::io::errors::PacketResult<()> {
                enc.write_bytes(&[*self as u8]);
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

    Ok(expanded)
}

#[proc_macro_attribute]
pub fn packet_field(_args: TokenStream, input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    match packet_field_impl(&input) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.to_compile_error().into(),
    }
}

fn packet_field_impl(input: &DeriveInput) -> Result<proc_macro2::TokenStream> {
    let name = &input.ident;
    let fields = match &input.data {
        Data::Struct(data) => &data.fields,
        _ => return Err(Error::new_spanned(input, "packet_field can only be applied to structs")),
    };

    let field_names: Vec<_> = fields.iter().filter_map(|f| f.ident.as_ref()).collect();
    let field_types: Vec<_> = fields.iter().map(|f| &f.ty).collect();
    let field_names_str: Vec<_> = field_names.iter().map(|n| n.to_string()).collect();

    let expanded = quote! {
        #[derive(Debug, Clone)]
        #input

        impl crate::io::codecs::PacketCodec for #name {
            const SIZE: Option<usize> = None;

            fn encode(&self, enc: &mut crate::io::encoder::Encoder) -> crate::io::errors::PacketResult<()> {
                #(
                    enc.write_var(&self.#field_names)?;
                )*
                Ok(())
            }

            fn decode(dec: &mut crate::io::decoder::Decoder) -> crate::io::errors::PacketResult<Self> {
                #(
                    let #field_names = dec.read_var::<#field_types>(#field_names_str)?;
                )*
                Ok(Self {
                    #(#field_names,)*
                })
            }
        }
    };

    Ok(expanded)
}