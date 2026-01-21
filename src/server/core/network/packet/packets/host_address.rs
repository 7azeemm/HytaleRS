use HytaleRS::PacketField;

#[derive(PacketField, Debug)]
pub struct HostAddress {
    host: String,
    port: i16
}
