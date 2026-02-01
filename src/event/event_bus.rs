use ahash::{HashMap, HashMapExt};
use parking_lot::RwLock;
use std::any::{Any, TypeId};
use std::pin::Pin;
use std::sync::LazyLock;
use std::sync::Arc;
use futures::Future;

pub static EVENT_BUS: LazyLock<EventBus> = LazyLock::new(|| EventBus::new());

pub trait Event: Send + Sync + 'static {}
pub type Priority = u32;

enum Handler {
    Sync(Arc<dyn Fn(&dyn Any) + Send + Sync>),
    Async(Arc<dyn Fn(&dyn Any) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>),
}

pub struct HandlerEntry {
    handler: Handler,
    priority: Priority,
}

pub struct EventBus {
    handlers: RwLock<HashMap<TypeId, Vec<Arc<HandlerEntry>>>>,
}

impl EventBus {
    pub fn new() -> Self {
        Self {
            handlers: RwLock::new(HashMap::new()),
        }
    }

    pub fn on<E: Event, F>(&self, priority: Option<Priority>, handler: F)
    where
        F: Fn(&E) + Send + Sync + 'static,
    {
        let type_id = TypeId::of::<E>();
        let priority = priority.unwrap_or(0);

        let wrapped = Arc::new(move |event: &dyn Any| {
            if let Some(event) = event.downcast_ref::<E>() {
                handler(event);
            }
        });

        let entry = Arc::new(HandlerEntry {
            handler: Handler::Sync(wrapped),
            priority,
        });

        let mut handlers = self.handlers.write();
        let entry_list = handlers.entry(type_id).or_insert_with(Vec::new);

        let insert_pos = entry_list.partition_point(|e| e.priority > priority);
        entry_list.insert(insert_pos, entry);
    }

    pub fn on_async<E: Event, F, Fut>(&self, priority: Option<Priority>, handler: F)
    where
        F: Fn(&E) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let type_id = TypeId::of::<E>();
        let priority = priority.unwrap_or(0);

        let wrapped = Arc::new(move |event: &dyn Any| -> Pin<Box<dyn Future<Output = ()> + Send>> {
            Box::pin(handler(event.downcast_ref::<E>().unwrap()))
        });

        let entry = Arc::new(HandlerEntry {
            handler: Handler::Async(wrapped),
            priority,
        });

        let mut handlers = self.handlers.write();
        let entry_list = handlers.entry(type_id).or_insert_with(Vec::new);

        let insert_pos = entry_list.partition_point(|e| e.priority > priority);
        entry_list.insert(insert_pos, entry);
    }

    pub async fn dispatch<E: Event>(&self, event: &E) {
        let type_id = TypeId::of::<E>();

        let handlers = {
            self.handlers.read()
                .get(&type_id)
                .map(|h| h.clone())
                .unwrap_or_default()
        };

        for entry in handlers {
            match &entry.handler {
                Handler::Sync(sync_handler) => sync_handler(event as &dyn Any),
                Handler::Async(async_handler) => async_handler(event as &dyn Any).await
            }
        }
    }
}