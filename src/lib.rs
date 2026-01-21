use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput, Data, Fields, Meta, LitInt};

/// Automatically implement the Packet trait for a struct
///
/// # Example
/// ```rust
/// #[derive(Packet)]
/// #[packet_id = 0x01]
/// pub struct LoginPacket {
///     pub username: String,
///     pub uuid: String,
/// }
///
/// // Automatically generates:
/// // - packet_id() method
/// // - encode() and decode() methods
/// // - default_id() static method for auto-registration
/// ```
#[proc_macro_derive(Packet, attributes(packet_id))]
pub fn derive_packet(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    let packet_id = match extract_packet_id(&input.attrs) {
        Ok(id) => id,
        Err(e) => return e.to_compile_error().into(),
    };

    let encode_impl = generate_encode(&input.data);
    let decode_impl = generate_decode(&input.data, name);

    let expanded = quote! {
        impl crate::server::core::network::packet::packet::Packet for #name {
            fn packet_id(&self) -> u32 {
                #packet_id
            }

            fn default_id() -> u32 {
                #packet_id
            }

            fn encode(&self, writer: &mut dyn std::io::Write) -> std::io::Result<()> {
                use crate::server::core::network::packet::packet_codec::CodecField;
                #encode_impl
                Ok(())
            }

            fn decode(reader: &mut dyn std::io::Read) -> Result<Self, crate::server::core::network::packet::packet_codec::CodecError> {
                #decode_impl
            }
        }
    };

    TokenStream::from(expanded)
}

fn extract_packet_id(attrs: &[syn::Attribute]) -> syn::Result<LitInt> {
    for attr in attrs {
        if attr.path().is_ident("packet_id") {
            let lit: LitInt = attr.parse_args()?;
            return Ok(lit);
        }
    }
    Err(syn::Error::new(
        proc_macro2::Span::call_site(),
        "Missing #[packet_id(0xNN)] attribute",
    ))
}

fn generate_encode(data: &Data) -> proc_macro2::TokenStream {
    let Data::Struct(data) = data else {
        return quote! {};
    };
    let Fields::Named(fields) = &data.fields else {
        return quote! {};
    };

    let encode_fields = fields.named.iter().map(|f| {
        let name = &f.ident;
        quote! { self.#name.encode(writer)?; }
    });

    quote! { #(#encode_fields)* }
}

fn generate_decode(data: &Data, struct_name: &syn::Ident) -> proc_macro2::TokenStream {
    let Data::Struct(data) = data else {
        return quote! { Ok(#struct_name) };
    };
    let Fields::Named(fields) = &data.fields else {
        return quote! { Ok(#struct_name) };
    };

    let field_data: Vec<_> = fields.named.iter().map(|f| {
        (&f.ident, &f.ty)
    }).collect();

    let decode_fields = field_data.iter().map(|(name, ty)| {
        quote! { let #name = <#ty>::decode(reader)?; }
    });

    let field_names = field_data.iter().map(|(name, _)| name);

    quote! {
        #(#decode_fields)*
        Ok(#struct_name { #(#field_names),* })
    }
}

#[proc_macro_derive(PacketField)]
pub fn derive_packet_field(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = &input.ident;

    let implementation = match &input.data {
        Data::Enum(data_enum) => generate_enum_codec(name, data_enum),
        Data::Struct(data_struct) => generate_struct_codec(name, data_struct),
        _ => panic!("PacketField only supports structs and enums"),
    };

    implementation.into()
}

fn generate_enum_codec(name: &syn::Ident, data_enum: &syn::DataEnum) -> proc_macro2::TokenStream {
    let variants: Vec<_> = data_enum.variants.iter().map(|v| {
        let ident = &v.ident;
        let discriminant = match &v.discriminant {
            Some((_, expr)) => quote! { #expr },
            None => panic!("All enum variants must have explicit discriminants"),
        };
        (ident, discriminant)
    }).collect();

    let encode_arms = variants.iter().map(|(ident, disc)| {
        quote! { #name::#ident => writer.write_all(&[#disc as u8]) }
    });

    let decode_arms = variants.iter().map(|(ident, disc)| {
        quote! { #disc => Ok(#name::#ident) }
    });

    quote! {
        impl crate::server::core::network::packet::packet_codec::CodecField for #name {
            fn encode(&self, writer: &mut dyn std::io::Write) -> std::io::Result<()> {
                match self {
                    #(#encode_arms),*
                }
            }

            fn decode(reader: &mut dyn std::io::Read) -> Result<Self, crate::server::core::network::packet::packet_codec::CodecError> {
                let mut byte = [0u8; 1];
                reader.read_exact(&mut byte)
                    .map_err(|e| crate::server::core::network::packet::packet_codec::CodecError::Decode(format!("Failed to read {}: {}", stringify!(#name), e)))?;

                match byte[0] {
                    #(#decode_arms,)*
                    v => Err(crate::server::core::network::packet::packet_codec::CodecError::Decode(format!("Invalid {}: {}", stringify!(#name), v))),
                }
            }
        }
    }
}

fn generate_struct_codec(name: &syn::Ident, data_struct: &syn::DataStruct) -> proc_macro2::TokenStream {
    let Fields::Named(fields) = &data_struct.fields else {
        panic!("PacketField only supports structs with named fields");
    };

    let encode_fields = fields.named.iter().map(|f| {
        let field_name = &f.ident;
        quote! { self.#field_name.encode(writer)?; }
    });

    let field_data: Vec<_> = fields.named.iter().map(|f| {
        (&f.ident, &f.ty)
    }).collect();

    let decode_fields = field_data.iter().map(|(field_name, ty)| {
        quote! { let #field_name = <#ty>::decode(reader)?; }
    });

    let field_names = field_data.iter().map(|(field_name, _)| field_name);

    quote! {
        impl crate::server::core::network::packet::packet_codec::CodecField for #name {
            fn encode(&self, writer: &mut dyn std::io::Write) -> std::io::Result<()> {
                #(#encode_fields)*
                Ok(())
            }

            fn decode(reader: &mut dyn std::io::Read) -> Result<Self, crate::server::core::network::packet::packet_codec::CodecError> {
                #(#decode_fields)*
                Ok(#name { #(#field_names),* })
            }
        }
    }
}
