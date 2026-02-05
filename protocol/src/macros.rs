#[macro_export]
macro_rules! packet {
    (
        id: $packet_id:expr,
        name: $packet_name:ident,
        $(compressed: $compressed:tt,)?
        max_size: $max_size:expr
        $(, fixed { $($fixed_name:ident: $fixed_type:ty),* $(,)? })?
        $(, var { $($var_name:ident: $var_type:ty),* $(,)? })?
    ) => {
        #[derive(Debug)]
        pub struct $packet_name {
            $(
                $(pub $fixed_name: $fixed_type,)*
            )?
            $(
                $(pub $var_name: $var_type,)*
            )?
        }

        impl $crate::io::packet::Packet for $packet_name {
            const METADATA: $crate::io::packet::PacketLayout = {
                let fixed_size = 0
                    $(
                        $(+ match <$fixed_type as $crate::io::codecs::PacketCodec>::SIZE {
                            Some(size) => size,
                            None => 0,
                        })*
                    )?;

                let var_count = 0
                    $(
                        $(+ { let _: $var_type; 1 })*
                    )?;

                let optional_count = 0
                    $(
                        $(+ <$fixed_type as $crate::io::codecs::PacketCodec>::IS_OPTIONAL as usize)*
                    )?
                    $(
                        $(+ <$var_type as $crate::io::codecs::PacketCodec>::IS_OPTIONAL as usize)*
                    )?;

                $crate::io::packet::PacketLayout {
                    fixed_block_size: fixed_size,
                    var_field_count: var_count,
                    optional_field_count: optional_count,
                }
            };

            const ID: u32 = $packet_id;
            const NAME: &'static str = stringify!($packet_name);
            $(const IS_COMPRESSED: bool = $compressed;)?
            const MAX_SIZE: u32 = $max_size;
        }

        impl $crate::io::codecs::PacketCodec for $packet_name {
            const SIZE: Option<usize> = None;

            fn encode(&self, enc: &mut $crate::io::encoder::Encoder) -> $crate::io::errors::PacketResult<()> {
                // Fixed block
                $(
                    $(
                        enc.write_fixed(&self.$fixed_name, stringify!($fixed_name))?;
                    )*
                )?

                // Variable block (only enter if we have var fields)
                $(
                    enc.enter_var_block();
                    $(
                        enc.write_var(&self.$var_name)?;
                    )*
                )?

                Ok(())
            }

            fn decode(dec: &mut $crate::io::decoder::Decoder) -> $crate::io::errors::PacketResult<Self> {
                // Fixed block
                $(
                    $(
                        let $fixed_name = dec.read_fixed::<$fixed_type>(stringify!($fixed_name))?;
                    )*
                )?

                // Variable block (only enter if we have var fields)
                $(
                    dec.enter_var_block();
                    $(
                        let $var_name = dec.read_var::<$var_type>(stringify!($var_name))?;
                    )*
                )?

                Ok(Self {
                    $(
                        $($fixed_name,)*
                    )?
                    $(
                        $($var_name,)*
                    )?
                })
            }
        }

        inventory::submit! {
            $crate::io::packet::PacketInfo {
                id: <$packet_name as $crate::io::packet::Packet>::ID,
                name: stringify!($packet_name),
                is_compressed: <$packet_name as $crate::io::packet::Packet>::IS_COMPRESSED,
                max_size: <$packet_name as $crate::io::packet::Packet>::MAX_SIZE,
            }
        }
    };
}