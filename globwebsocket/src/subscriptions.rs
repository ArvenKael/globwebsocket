//! Bounded, process-local invalidation notifications. The database is authoritative.
//!
//! The bus is generic over the application's event type. It deliberately carries
//! no entity data: a subscriber re-reads through authorized operations.
use super::App;
use loco_rs::app::AppContext;
use serde::{de::DeserializeOwned, Serialize};
use std::{
    collections::HashMap,
    hash::Hash,
    sync::{Arc, Mutex},
};
use tokio::sync::broadcast;

/// The application's invalidation vocabulary.
pub trait Topic: Copy + Eq + Hash + Serialize + DeserializeOwned + Send + Sync + 'static {
    /// Every topic a connection subscribes to by default.
    const ALL: &'static [Self];

    /// Stable wire name, matching the topic's Serde representation.
    fn as_str(&self) -> &'static str;
}

/// The application's broadcast event type.
pub trait BusEvent<A: App + ?Sized>: Clone + Send + 'static {
    /// Build the data-free invalidation event for one topic.
    fn topic_event(topic: A::Topic) -> Self;

    /// Whether this event is addressed to one account. The transport drops
    /// events for other accounts before any session or authorization work.
    fn targeted_to(&self, _user_id: i32) -> bool {
        true
    }

    /// `Some` for a data-free topic invalidation; `None` for a data event that
    /// connection hooks encode.
    fn topic(&self) -> Option<A::Topic> {
        None
    }
}

/// Process-wide fan-out plus per-user presence counts.
pub struct SubscriptionBus<A: App> {
    sender: broadcast::Sender<A::Event>,
    presence: Arc<Mutex<PresenceConnections>>,
}

impl<A: App> Clone for SubscriptionBus<A> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
            presence: self.presence.clone(),
        }
    }
}

impl<A: App> Default for SubscriptionBus<A> {
    fn default() -> Self {
        Self {
            sender: broadcast::channel(256).0,
            presence: Arc::default(),
        }
    }
}

impl<A: App> SubscriptionBus<A> {
    /// Send one event to every live socket.
    pub fn publish(&self, event: A::Event) {
        let _ = self.sender.send(event);
    }

    /// Subscribe one connection to the broadcast stream.
    pub fn subscribe(&self) -> broadcast::Receiver<A::Event> {
        self.sender.subscribe()
    }

    /// Add one authenticated socket. Returns true only for the offline -> online transition.
    pub fn connect(&self, user_id: i32) -> bool {
        let Ok(mut counts) = self.presence.lock() else {
            return false;
        };
        counts.connect(user_id)
    }

    /// Remove one socket. Returns true only for the online -> offline transition.
    pub fn disconnect(&self, user_id: i32) -> bool {
        let Ok(mut counts) = self.presence.lock() else {
            return false;
        };
        counts.disconnect(user_id)
    }

    pub fn is_online(&self, user_id: i32) -> bool {
        self.presence
            .lock()
            .map(|counts| counts.is_online(user_id))
            .unwrap_or(false)
    }

    /// Live socket count for one account.
    pub fn connection_count(&self, user_id: i32) -> usize {
        self.presence
            .lock()
            .map(|counts| counts.0.get(&user_id).copied().unwrap_or(0))
            .unwrap_or(0)
    }
}

#[derive(Debug, Default)]
struct PresenceConnections(HashMap<i32, usize>);

impl PresenceConnections {
    fn connect(&mut self, user_id: i32) -> bool {
        let count = self.0.entry(user_id).or_default();
        let was_offline = *count == 0;
        *count += 1;
        was_offline
    }

    fn disconnect(&mut self, user_id: i32) -> bool {
        let Some(count) = self.0.get_mut(&user_id) else {
            return false;
        };
        *count = count.saturating_sub(1);
        if *count == 0 {
            self.0.remove(&user_id);
            true
        } else {
            false
        }
    }

    fn is_online(&self, user_id: i32) -> bool {
        self.0.get(&user_id).copied().unwrap_or(0) > 0
    }
}

/// Notify connected clients after committed data changes. Payloads contain no
/// data; clients must reload through authorized operations.
pub fn publish<A: App>(ctx: &AppContext, event: A::Event) {
    if let Some(bus) = ctx.shared_store.get::<SubscriptionBus<A>>() {
        bus.publish(event);
    }
}

/// Add one authenticated socket to presence.
pub fn connect<A: App>(ctx: &AppContext, user_id: i32) -> bool {
    ctx.shared_store
        .get::<SubscriptionBus<A>>()
        .map(|bus| bus.connect(user_id))
        .unwrap_or(false)
}

/// Remove one socket from presence.
pub fn disconnect<A: App>(ctx: &AppContext, user_id: i32) -> bool {
    ctx.shared_store
        .get::<SubscriptionBus<A>>()
        .map(|bus| bus.disconnect(user_id))
        .unwrap_or(false)
}

/// Whether an account has at least one authenticated socket.
pub fn is_online<A: App>(ctx: &AppContext, user_id: i32) -> bool {
    ctx.shared_store
        .get::<SubscriptionBus<A>>()
        .is_some_and(|bus| bus.is_online(user_id))
}

#[cfg(test)]
mod tests {
    use super::{BusEvent, PresenceConnections, SubscriptionBus, Topic};
    use crate::{App, Audit, Identity};
    use axum::http::HeaderMap;
    use loco_rs::app::AppContext;
    use serde::{Deserialize, Serialize};
    use serde_json::Value;

    #[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    enum TestTopic {
        One,
        Two,
    }

    impl Topic for TestTopic {
        const ALL: &'static [Self] = &[Self::One, Self::Two];
        fn as_str(&self) -> &'static str {
            match self {
                Self::One => "one",
                Self::Two => "two",
            }
        }
    }

    #[derive(Clone, Debug)]
    enum TestEvent {
        Topic(TestTopic),
        Owned { owner: i32 },
    }

    impl BusEvent<TestApp> for TestEvent {
        fn topic_event(topic: TestTopic) -> Self {
            Self::Topic(topic)
        }
        fn targeted_to(&self, user_id: i32) -> bool {
            match self {
                Self::Topic(_) => true,
                Self::Owned { owner } => *owner == user_id,
            }
        }
        fn topic(&self) -> Option<TestTopic> {
            match self {
                Self::Topic(topic) => Some(*topic),
                Self::Owned { .. } => None,
            }
        }
    }

    struct TestApp;

    impl App for TestApp {
        type Topic = TestTopic;
        type Event = TestEvent;
        type Policy = ();
        type Auditor = TestAudit;

        async fn authenticate(
            _ctx: &AppContext,
            _credentials: &HeaderMap,
        ) -> loco_rs::Result<Identity> {
            Err(loco_rs::Error::Unauthorized("test".into()))
        }

        async fn authorize(
            _ctx: &AppContext,
            _identity: Identity,
            _operation: &'static str,
            _policy: Option<&Self::Policy>,
        ) -> loco_rs::Result<bool> {
            Ok(true)
        }

        fn auditor() -> Self::Auditor {
            TestAudit
        }
    }

    struct TestAudit;

    impl Audit for TestAudit {
        fn targets(&self, _payload: &Value) -> Value {
            Value::Null
        }

        fn capture<'a, F>(
            &'a self,
            _ctx: &'a AppContext,
            _credentials: &'a HeaderMap,
            _source: &'a str,
            _operation: &'a str,
            _targets: Value,
            action: F,
        ) -> impl std::future::Future<Output = axum::response::Response> + Send + 'a
        where
            F: std::future::Future<Output = axum::response::Response> + Send + 'a,
        {
            action
        }
    }

    impl crate::Policy for () {
        async fn permits(&self, _ctx: &AppContext, _user_id: i32) -> loco_rs::Result<bool> {
            Ok(true)
        }
    }

    #[test]
    fn user_stays_online_until_last_socket_disconnects() {
        let mut presence = PresenceConnections::default();
        assert!(presence.connect(7));
        assert!(!presence.connect(7));
        assert!(presence.is_online(7));
        assert!(!presence.disconnect(7));
        assert!(presence.is_online(7));
        assert!(presence.disconnect(7));
        assert!(!presence.is_online(7));
        assert!(!presence.disconnect(7));
    }

    #[test]
    fn bus_routes_and_invalidates_with_app_types() {
        let bus = SubscriptionBus::<TestApp>::default();
        assert!(bus.connect(3));
        assert_eq!(bus.connection_count(3), 1);
        let mut receiver = bus.subscribe();
        bus.publish(TestEvent::topic_event(TestTopic::Two));
        let event = receiver.try_recv().expect("event");
        assert_eq!(event.topic(), Some(TestTopic::Two));
        assert!(event.targeted_to(99));
        assert!(!TestEvent::Owned { owner: 7 }.targeted_to(99));
    }
}
