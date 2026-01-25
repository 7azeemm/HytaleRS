use crate::server::core::network::connection_manager::ConnectionContext;

#[async_trait::async_trait]
pub trait PacketHandler: Send + Sync {
    async fn handle(&mut self, packet_id: u32, data: &[u8], cx: &mut ConnectionContext) -> Result<HandlerAction, String>;
    async fn register(&mut self, cx: &mut ConnectionContext);
}

pub enum HandlerAction {
    Continue,
    Transition(Box<dyn PacketHandler>),
    Disconnect(String),
}
