use macros::packet_enum;

#[packet_enum]
pub enum UpdateType {
    Init,
    AddOrUpdate,
    Remove,
}
