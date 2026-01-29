use crate::server::core::network::connection_manager::ConnectionContext;

#[async_trait::async_trait]
pub trait PacketHandler: Send + Sync {
    async fn handle(&mut self, packet_id: u32, data: &[u8], cx: &mut ConnectionContext) -> HandlerAction;
    async fn register(&mut self, cx: &mut ConnectionContext);
}

pub enum HandlerAction {
    Continue,
    Transition(Box<dyn PacketHandler>),
    Disconnect(String),
    Error(String)
}

#[macro_export]
macro_rules! handle_packet {
    ($self:expr, $packet_type:ty, $data:expr, $method:ident, $cx:expr) => {{
        match $crate::server::core::network::packet::packet_decoder::PacketDecoder::decode::<$packet_type>($data) {
            Some(packet) => $self.$method(packet, $cx).await,
            None => $crate::server::core::network::packet::packet_handler::HandlerAction::Disconnect(
                "Failed to decode packet".to_owned()
            ),
        }
    }};
}