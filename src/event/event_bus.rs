use ahash::{HashMap, HashMapExt};
use parking_lot::RwLock;
use std::any::{Any, TypeId};
use std::sync::LazyLock;

pub static EVENT_BUS: LazyLock<EventBus> = LazyLock::new(|| EventBus::new());

pub trait Event: Send + Sync + 'static {}
pub type Priority = u32;

trait Handler: Send + Sync {
    fn call(&self, event: &dyn Any);
}

pub struct EventBus {
    handlers: RwLock<HashMap<TypeId, Vec<HandlerEntry>>>,
}

struct HandlerEntry {
    handler: Box<dyn Handler>,
    priority: Priority,
}

struct ConcreteHandler<E: Event, F: Fn(&E) + Send + Sync> {
    closure: F,
    _phantom: std::marker::PhantomData<E>,
}

impl<E: Event, F: Fn(&E) + Send + Sync> Handler for ConcreteHandler<E, F> {
    fn call(&self, event: &dyn Any) {
        if let Some(event) = event.downcast_ref::<E>() {
            (self.closure)(event);
        }
    }
}

impl EventBus {
    pub fn new() -> Self {
        Self { handlers: RwLock::new(HashMap::new()) }
    }

    pub fn on<E: Event, F>(&self, priority: Option<Priority>, handler: F)
    where
        F: Fn(&E) + Send + Sync + 'static,
    {
        let type_id = TypeId::of::<E>();
        let priority = priority.unwrap_or(0);

        let mut handlers = self.handlers.write();
        let entry = handlers.entry(type_id).or_insert_with(Vec::new);

        let insert_pos = entry.partition_point(|e| e.priority > priority);
        entry.insert(insert_pos, HandlerEntry {
            handler: Box::new(ConcreteHandler {
                closure: handler,
                _phantom: std::marker::PhantomData,
            }),
            priority,
        });
    }

    pub fn dispatch<E: Event>(&self, event: &E) {
        let type_id = TypeId::of::<E>();
        let handlers = self.handlers.read();

        if let Some(entries) = handlers.get(&type_id) {
            for entry in entries {
                entry.handler.call(event as &dyn Any);
            }
        }
    }
}