//! Optional module-owned state for one websocket connection.
use super::{App, Registry};
use async_trait::async_trait;
use axum::http::HeaderMap;
use loco_rs::{app::AppContext, prelude::Response, Result};
use serde_json::Value;

#[derive(Clone, Copy, Debug)]
pub struct SessionIdentity {
    pub user_id: i32,
    pub session_id: i32,
}

/// Connection hooks supplement ordinary typed operations. Implementations own
/// their connection state and enforce current access for intercepted operations
/// and notifications. A factory is registered once by the owning module.
#[async_trait]
pub trait Session<A: App>: Send + 'static {
    fn open(ctx: &AppContext, identity: Option<SessionIdentity>) -> Self
    where
        Self: Sized;

    async fn operation(
        &mut self,
        _ctx: &AppContext,
        _credentials: &HeaderMap,
        _operation: &str,
        _payload: &Value,
    ) -> Option<Response> {
        None
    }

    /// True when the module publishes a more specific event for this mutation.
    fn handles_invalidation(&self, _operation: &str, _topic: A::Topic) -> bool {
        false
    }

    /// Called only for successful replies, before sending them to the client.
    async fn after_response(
        &mut self,
        _ctx: &AppContext,
        _operation: &str,
        _payload: &Value,
        _body: &[u8],
    ) {
    }

    async fn event(
        &mut self,
        _ctx: &AppContext,
        _credentials: &HeaderMap,
        _event: &A::Event,
    ) -> Result<Option<Value>> {
        Ok(None)
    }

    async fn revalidate(&mut self, _ctx: &AppContext) {}
    async fn close(&mut self, _ctx: &AppContext) {}
}

impl<A: App, X> Registry<A, X> {
    /// Register one connection hook. Duplicate contributions from a module
    /// reject startup instead of silently replacing an existing hook.
    pub fn try_register_session<S: Session<A>>(
        &mut self,
        module: &'static str,
    ) -> Result<&mut Self> {
        if self.sessions.contains_key(module) {
            return Err(loco_rs::Error::string(&format!(
                "duplicate websocket session for module {module}"
            )));
        }
        self.sessions
            .insert(module, |ctx, identity| Box::new(S::open(ctx, identity)));
        Ok(self)
    }
}

#[cfg(test)]
mod tests {}
