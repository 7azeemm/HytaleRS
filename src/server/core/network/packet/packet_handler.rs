use crate::server::core::network::connection_manager::{Connection, ConnectionContext};

#[async_trait::async_trait]
pub trait PacketHandler: Send + Sync {
    async fn handle(&mut self, packet_id: u32, data: &[u8], cx: &mut ConnectionContext) -> Result<HandlerAction, String>;
}

pub enum HandlerAction {
    Continue,
    Transition(Box<dyn PacketHandler>),
    Disconnect(String),
}
