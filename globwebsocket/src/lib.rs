//! Typed WebSocket operations and transport, independent of any application
//! controller.
//!
//! # The model
//!
//! A client sends one JSON text frame:
//!
//! ```json
//! {"id":1,"operation":"projects.joined","payload":{"query":{"limit":100}}}
//! ```
//!
//! The answer carries the matching `id`, a numeric `status`, the response
//! `content_type`, and a base64-encoded `body`. Each operation is a plain
//! `serde` type with a stable wire name:
//!
//! ```ignore
//! #[derive(Deserialize, GlobWebsocket)]
//! #[serde(deny_unknown_fields)]
//! #[websocket("projects.create")]
//! struct CreateProject {
//!     name: String,
//! }
//!
//! #[async_trait::async_trait]
//! impl Operation for CreateProject {
//!     async fn execute(self, ctx: AppContext, credentials: HeaderMap) -> Result<Response> {
//!         // ...
//!     }
//! }
//! ```
//!
//! and a [`Registry`] maps wire names to erased handlers. The transport owns
//! framing, concurrency limits, origin checks, revalidation, and invalidation
//! fan-out; an application owns identity, authorization, auditing, and the
//! concrete topic/event vocabulary through [`App`].

extern crate self as globwebsocket;

use axum::{
    body::to_bytes,
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    http::{header, uri::Authority, HeaderMap, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use loco_rs::app::AppContext;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    any::TypeId,
    collections::{BTreeMap, HashMap, HashSet},
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

pub use globwebsocket_derive::GlobWebsocket;
use subscriptions::{BusEvent, Topic};

pub mod session;
pub mod subscriptions;

// ---------------------------------------------------------------------------
// Application seams
// ---------------------------------------------------------------------------

/// The authenticated principal attached to one connection or operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Identity {
    pub user_id: i32,
    pub session_id: i32,
}

/// A registered operation access policy.
///
/// Applications decide what a policy means. The transport only asks whether an
/// authenticated principal currently satisfies it; every call is re-evaluated,
/// so revocation applies to an already-open socket.
pub trait Policy: Clone + Send + Sync + 'static {
    /// Return `Ok(true)` when `user_id` may execute the operation right now.
    fn permits(
        &self,
        ctx: &AppContext,
        user_id: i32,
    ) -> impl Future<Output = loco_rs::Result<bool>> + Send;

    /// Capability keys the policy references, for startup validation.
    fn keys(&self) -> &[&'static str] {
        &[]
    }
}

/// Mandatory request auditing around every dispatch.
pub trait Audit: Send + Sync + 'static {
    /// Extract safe record identifiers from one operation payload.
    fn targets(&self, payload: &Value) -> Value;

    /// Capture one operation attempt. Implementations must finish the audit
    /// record before the response is delivered.
    fn capture<'a, F>(
        &'a self,
        ctx: &'a AppContext,
        credentials: &'a HeaderMap,
        source: &'a str,
        operation: &'a str,
        targets: Value,
        action: F,
    ) -> impl Future<Output = Response> + Send + 'a
    where
        F: Future<Output = Response> + Send + 'a;
}

/// Everything the transport cannot know about a concrete application.
///
/// Associated types keep the registry statically typed: invalidations carry the
/// app's `Topic`, session hooks see the app's `Event`, and policies stay the
/// app's own type. Nothing here is specific to this project.
pub trait App: Send + Sync + 'static {
    type Topic: subscriptions::Topic;
    type Event: subscriptions::BusEvent<Self>;
    type Policy: Policy;
    type Auditor: Audit;

    /// Resolve credentials into a principal. `Err` is treated as anonymous on
    /// the upgrade and as a 401 reply inside an operation.
    fn authenticate(
        ctx: &AppContext,
        credentials: &HeaderMap,
    ) -> impl Future<Output = loco_rs::Result<Identity>> + Send;

    /// Apply the operation's registered policy, or the application's fallback
    /// rule when the operation was registered without one.
    fn authorize(
        ctx: &AppContext,
        identity: Identity,
        operation: &'static str,
        policy: Option<&Self::Policy>,
    ) -> impl Future<Output = loco_rs::Result<bool>> + Send;

    /// The audit sink used for every dispatched operation.
    fn auditor() -> Self::Auditor;

    /// Topic invalidated when a user's first socket connects and last socket
    /// disconnects. `None` disables presence fan-out.
    fn presence_topic() -> Option<Self::Topic> {
        None
    }
}

// ---------------------------------------------------------------------------
// Typed operations
// ---------------------------------------------------------------------------

/// Derive this on a deserializable operation and supply `#[websocket("name")]`.
pub trait GlobWebsocket: DeserializeOwned + Send + 'static {
    const NAME: &'static str;

    /// Server-declared top-level payload field/type hints. These are useful to
    /// build assistant call guidance without weakening the operation's normal
    /// Serde validation or pretending arbitrary Rust types are JSON Schemas.
    fn payload_fields() -> &'static [(&'static str, &'static str)] {
        &[]
    }

    /// Best-effort nested payload schema traced from the operation's actual
    /// Serde deserializer. Unsupported custom or tagged types return `None`.
    fn payload_schema() -> Option<Value> {
        None
    }
}

/// A typed operation that can be registered on its own.
#[async_trait::async_trait]
pub trait Operation: GlobWebsocket {
    async fn execute(self, ctx: AppContext, credentials: HeaderMap) -> loco_rs::Result<Response>;
}

/// Trace one typed operation payload during registry construction. The result
/// is cached in AI metadata and never recomputed for assistant requests.
pub fn trace_payload_schema<T: DeserializeOwned + 'static>() -> Option<Value> {
    let mut tracer = serde_reflection::Tracer::new(
        serde_reflection::TracerConfig::default().is_human_readable(true),
    );
    let samples = serde_reflection::Samples::new();
    let (root, _value) = tracer.trace_type_once::<T>(&samples).ok()?;
    let registry = tracer.registry().ok()?;
    let mut visiting = HashSet::new();
    let mut budget = 256usize;
    let schema = serde_format_schema(&root, &registry, &mut visiting, 0, &mut budget)?;
    (serde_json::to_vec(&schema).ok()?.len() <= 16 * 1024).then_some(schema)
}

fn serde_format_schema(
    format: &serde_reflection::Format,
    registry: &serde_reflection::Registry,
    visiting: &mut HashSet<String>,
    depth: usize,
    budget: &mut usize,
) -> Option<Value> {
    if depth > 12 || *budget == 0 {
        return None;
    }
    *budget -= 1;
    use serde_reflection::Format as F;
    Some(match format {
        F::TypeName(name) => {
            if !visiting.insert(name.clone()) {
                return None;
            }
            let container = registry.get(name)?;
            let result = container_schema(container, registry, visiting, depth + 1, budget)?;
            visiting.remove(name);
            result
        }
        F::Unit => json!({"type":"null"}),
        F::Bool => json!({"type":"boolean"}),
        F::I8 | F::I16 | F::I32 | F::I64 | F::I128 | F::U8 | F::U16 | F::U32 | F::U64 | F::U128 => {
            json!({"type":"integer"})
        }
        F::F32 | F::F64 => json!({"type":"number"}),
        F::Char | F::Str => json!({"type":"string"}),
        F::Option(inner) => json!({"anyOf":[
            serde_format_schema(inner, registry, visiting, depth + 1, budget)?,
            {"type":"null"}
        ]}),
        F::Seq(inner) => json!({
            "type":"array",
            "items":serde_format_schema(inner, registry, visiting, depth + 1, budget)?
        }),
        F::Map { key, value } if matches!(key.as_ref(), F::Str | F::Char) => json!({
            "type":"object",
            "additionalProperties":serde_format_schema(value, registry, visiting, depth + 1, budget)?
        }),
        F::Tuple(items) => tuple_schema(items, registry, visiting, depth, budget)?,
        F::TupleArray { content, size } => json!({
            "type":"array",
            "items":serde_format_schema(content, registry, visiting, depth + 1, budget)?,
            "minItems":size,
            "maxItems":size
        }),
        // Byte arrays and unresolved variables can represent opaque/binary
        // payloads. Do not invent a JSON shape for them.
        F::Bytes | F::Variable(_) | F::Map { .. } => return None,
    })
}

fn tuple_schema(
    items: &[serde_reflection::Format],
    registry: &serde_reflection::Registry,
    visiting: &mut HashSet<String>,
    depth: usize,
    budget: &mut usize,
) -> Option<Value> {
    let first = items.first()?;
    let schema = serde_format_schema(first, registry, visiting, depth + 1, budget)?;
    for item in items.iter().skip(1) {
        if serde_format_schema(item, registry, visiting, depth + 1, budget)? != schema {
            return None;
        }
    }
    Some(json!({"type":"array","items":schema,"minItems":items.len(),"maxItems":items.len()}))
}

fn container_schema(
    container: &serde_reflection::ContainerFormat,
    registry: &serde_reflection::Registry,
    visiting: &mut HashSet<String>,
    depth: usize,
    budget: &mut usize,
) -> Option<Value> {
    use serde_reflection::ContainerFormat as C;
    match container {
        C::UnitStruct => Some(json!({"type":"object","properties":{}})),
        C::NewTypeStruct(inner) => {
            serde_format_schema(inner, registry, visiting, depth + 1, budget)
        }
        C::TupleStruct(items) => tuple_schema(items, registry, visiting, depth, budget),
        C::Struct(fields) => {
            let mut properties = serde_json::Map::new();
            for field in fields {
                properties.insert(
                    field.name.clone(),
                    serde_format_schema(&field.value, registry, visiting, depth + 1, budget)?,
                );
            }
            Some(json!({"type":"object","properties":properties,"additionalProperties":true}))
        }
        // serde-reflection does not preserve Serde's internally/adjacently
        // tagged enum representation. Omitting it avoids a misleading schema.
        C::Enum(_) => None,
    }
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

pub type OperationFuture = Pin<Box<dyn Future<Output = Response> + Send>>;
pub type Handler = Arc<dyn Fn(Value, AppContext, HeaderMap) -> OperationFuture + Send + Sync>;

type SessionFactory<A> =
    fn(&AppContext, Option<session::SessionIdentity>) -> Box<dyn session::Session<A>>;

/// Maps wire names to typed handlers, policies, invalidations, and per-module
/// connection hooks.
pub struct Registry<A: App, X = ()> {
    handlers: HashMap<&'static str, Handler>,
    operation_types: HashMap<&'static str, TypeId>,
    mutations: HashMap<&'static str, A::Topic>,
    sessions: BTreeMap<&'static str, SessionFactory<A>>,
    policies: HashMap<&'static str, A::Policy>,
    /// Application-owned state attached to the registry (for example an AI tool
    /// catalog). The transport never inspects it.
    pub extra: X,
}

impl<A: App, X: Clone> Clone for Registry<A, X> {
    fn clone(&self) -> Self {
        Self {
            handlers: self.handlers.clone(),
            operation_types: self.operation_types.clone(),
            mutations: self.mutations.clone(),
            sessions: self.sessions.clone(),
            policies: self.policies.clone(),
            extra: self.extra.clone(),
        }
    }
}

impl<A: App, X: Default> Default for Registry<A, X> {
    fn default() -> Self {
        Self {
            handlers: HashMap::new(),
            operation_types: HashMap::new(),
            mutations: HashMap::new(),
            sessions: BTreeMap::new(),
            policies: HashMap::new(),
            extra: X::default(),
        }
    }
}

impl<A: App, X> Registry<A, X> {
    /// Register one typed operation. Duplicate names are a startup error.
    pub fn register<T, F, Fut>(&mut self, handler: F) -> &mut Self
    where
        T: GlobWebsocket,
        F: Fn(T, AppContext, HeaderMap) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = loco_rs::Result<Response>> + Send + 'static,
    {
        self.register_with_policy::<T, F, Fut>(handler, None)
    }

    /// Fallible registration for module operations with an explicit policy.
    pub fn try_register_operation<T: Operation>(
        &mut self,
        policy: A::Policy,
    ) -> loco_rs::Result<&mut Self> {
        if self.handlers.contains_key(T::NAME) {
            return Err(loco_rs::Error::string(&format!(
                "duplicate websocket operation: {}",
                T::NAME
            )));
        }
        self.policies.insert(T::NAME, policy.clone());
        self.register_with_policy::<T, _, _>(
            |operation, ctx, credentials| operation.execute(ctx, credentials),
            Some(policy),
        );
        Ok(self)
    }

    /// Register a typed operation without a module policy.
    pub fn register_operation<T: Operation>(&mut self) -> &mut Self {
        self.register::<T, _, _>(|operation, ctx, credentials| operation.execute(ctx, credentials))
    }

    /// Register a fallible mutation and its invalidation topic.
    pub fn try_register_mutation<T: Operation>(
        &mut self,
        policy: A::Policy,
        topic: A::Topic,
    ) -> loco_rs::Result<&mut Self> {
        self.try_register_operation::<T>(policy)?;
        self.mutations.insert(T::NAME, topic);
        Ok(self)
    }

    /// Register a mutation that invalidates a subscribed data topic on success.
    pub fn register_mutation<T: Operation>(&mut self, topic: A::Topic) -> &mut Self {
        self.register_operation::<T>();
        self.mutations.insert(T::NAME, topic);
        self
    }

    /// Bind an invalidating topic to an already registered operation.
    pub fn set_mutation<T: GlobWebsocket>(&mut self, topic: A::Topic) -> &mut Self {
        self.mutations.insert(T::NAME, topic);
        self
    }

    fn register_with_policy<T, F, Fut>(
        &mut self,
        handler: F,
        policy: Option<A::Policy>,
    ) -> &mut Self
    where
        T: GlobWebsocket,
        F: Fn(T, AppContext, HeaderMap) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = loco_rs::Result<Response>> + Send + 'static,
    {
        let handler = Arc::new(handler);
        let erased: Handler = Arc::new(move |payload, ctx, credentials| {
            let handler = handler.clone();
            let policy = policy.clone();
            Box::pin(async move {
                // Authenticate and authorize before decoding the typed payload.
                // An unauthenticated frame therefore stops here instead of
                // spending work on a shape it could never execute.
                let identity = match A::authenticate(&ctx, &credentials).await {
                    Ok(identity) => identity,
                    Err(error) => return error.into_response(),
                };
                match A::authorize(&ctx, identity, T::NAME, policy.as_ref()).await {
                    Ok(true) => {}
                    Ok(false) => return StatusCode::UNAUTHORIZED.into_response(),
                    Err(error) => return error.into_response(),
                }
                match serde_json::from_value::<T>(payload) {
                    Ok(payload) => match handler(payload, ctx, credentials).await {
                        Ok(response) => response,
                        Err(error) => error.into_response(),
                    },
                    Err(_) => StatusCode::BAD_REQUEST.into_response(),
                }
            })
        });
        assert!(
            self.handlers.insert(T::NAME, erased).is_none(),
            "duplicate websocket operation: {}",
            T::NAME
        );
        self.operation_types.insert(T::NAME, TypeId::of::<T>());
        self
    }

    /// The erased handler for one wire name.
    pub fn handler(&self, name: &str) -> Option<Handler> {
        self.handlers.get(name).cloned()
    }

    /// Whether an operation name is registered.
    pub fn contains(&self, name: &str) -> bool {
        self.handlers.contains_key(name)
    }

    /// Every registered wire name.
    pub fn operation_names(&self) -> impl Iterator<Item = &&'static str> {
        self.handlers.keys()
    }

    /// The concrete Rust type registered under one wire name.
    pub fn operation_type(&self, name: &str) -> Option<TypeId> {
        self.operation_types.get(name).copied()
    }

    /// The registered policy for one operation, if it declared one.
    pub fn policy(&self, name: &str) -> Option<&A::Policy> {
        self.policies.get(name)
    }

    /// Every explicitly registered policy.
    pub fn policies(&self) -> impl Iterator<Item = (&&'static str, &A::Policy)> {
        self.policies.iter()
    }

    /// The invalidation topic for one operation, if it is a mutation.
    pub fn mutation(&self, name: &str) -> Option<A::Topic> {
        self.mutations.get(name).copied()
    }

    /// Application-owned state attached at construction.
    pub fn extra(&self) -> &X {
        &self.extra
    }

    /// Mutable application-owned state attached at construction.
    pub fn extra_mut(&mut self) -> &mut X {
        &mut self.extra
    }

    /// Build one connection hook instance per registered module session.
    pub fn open_sessions(
        &self,
        ctx: &AppContext,
        identity: Option<session::SessionIdentity>,
    ) -> Vec<Box<dyn session::Session<A>>> {
        self.sessions
            .values()
            .map(|open| open(ctx, identity))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Wire protocol
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    id: u64,
    operation: String,
    #[serde(default)]
    payload: Value,
}

/// Anonymous sockets are pre-authentication, so their frames are bounded far
/// below the authenticated frame ceiling and parsed only into this envelope.
/// Parsing attacker-controlled JSON into `Value` would let a small array expand
/// into allocations many times its wire size before any credential check.
const ANONYMOUS_MESSAGE_LIMIT: usize = 4 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AnonymousRequest {
    id: u64,
    operation: String,
    // Parse and discard the payload without materializing a `Value` tree.
    #[serde(default)]
    payload: serde::de::IgnoredAny,
}

/// Parse an unauthenticated frame without building an arbitrary JSON `Value`
/// tree. The payload is bounded and discarded: no registered operation can
/// succeed before authentication, so an empty payload still yields the same
/// 401/404 reply while a large array cannot expand into megabytes of nodes.
fn anonymous_request(text: &str) -> Option<Request> {
    if text.len() > ANONYMOUS_MESSAGE_LIMIT {
        return None;
    }
    let AnonymousRequest {
        id,
        operation,
        payload,
    } = serde_json::from_str::<AnonymousRequest>(text).ok()?;
    let _ = payload;
    Some(Request {
        id,
        operation,
        payload: Value::Object(serde_json::Map::new()),
    })
}

#[derive(Serialize)]
struct Reply {
    id: u64,
    status: u16,
    body: String,
    content_type: Option<String>,
}

/// Authenticated sockets keep the historical 8 MiB frame ceiling. File and
/// voice uploads use their own HTTP endpoints, not websocket frames.
const SOCKET_LIMIT: usize = 8 * 1024 * 1024;

/// Process-wide cap on live `/ws` sessions.
///
/// The transport is the app-level backstop below typical file-descriptor and
/// task limits, so anonymous sockets cannot accumulate without bound.
const MAX_CONNECTIONS: usize = 512;

/// Live connection counter shared by every upgrade in this process.
struct ConnectionLimiter {
    live: AtomicUsize,
}

impl ConnectionLimiter {
    const fn new() -> Self {
        Self {
            live: AtomicUsize::new(0),
        }
    }

    /// Reserve one slot, or return `None` when `cap` sessions are already live.
    fn acquire(&self, cap: usize) -> Option<ConnectionPermit<'_>> {
        let mut live = self.live.load(Ordering::Acquire);
        loop {
            if live >= cap {
                return None;
            }
            match self.live.compare_exchange_weak(
                live,
                live + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(ConnectionPermit { limiter: self }),
                Err(current) => live = current,
            }
        }
    }

    #[cfg(test)]
    fn live(&self) -> usize {
        self.live.load(Ordering::Acquire)
    }
}

/// Holds one live-connection slot and releases it on every session exit path.
struct ConnectionPermit<'a> {
    limiter: &'a ConnectionLimiter,
}

impl Drop for ConnectionPermit<'_> {
    fn drop(&mut self) {
        self.limiter.live.fetch_sub(1, Ordering::AcqRel);
    }
}

static LIVE_CONNECTIONS: ConnectionLimiter = ConnectionLimiter::new();

/// Return a header only when exactly one value is present. Duplicate
/// `Origin`/`Host` headers make an origin comparison ambiguous, so they are
/// treated as invalid rather than picking whichever value was sent first.
pub fn single_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    values.next().is_none().then_some(value)
}

/// One origin reduced to the components that define browser origin equality.
#[derive(Debug, PartialEq, Eq)]
struct WebOrigin {
    scheme: &'static str,
    host: String,
    port: u16,
}

fn web_origin_scheme(value: &str) -> Option<&'static str> {
    if value.eq_ignore_ascii_case("http") {
        Some("http")
    } else if value.eq_ignore_ascii_case("https") {
        Some("https")
    } else {
        None
    }
}

fn default_port(scheme: &str) -> u16 {
    if scheme == "https" {
        443
    } else {
        80
    }
}

fn parse_web_origin(value: &str) -> Option<WebOrigin> {
    let uri = value.trim().parse::<Uri>().ok()?;
    let scheme = web_origin_scheme(uri.scheme_str()?)?;
    // A browser Origin is exactly scheme://host[:port]. Reject paths, queries
    // and user info instead of comparing only a subset of attacker input.
    if uri.path() != "/" || uri.query().is_some() {
        return None;
    }
    let authority = uri.authority()?;
    if authority.as_str().contains('@') {
        return None;
    }
    let host = authority.host().to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }
    Some(WebOrigin {
        scheme,
        host,
        port: authority.port_u16().unwrap_or(default_port(scheme)),
    })
}

/// Parse a request `Host` authority. An omitted port stays `None`: a proxy
/// configured with `proxy_set_header Host $host` strips the port even when the
/// public origin uses a nonstandard one, so the caller must decide what the
/// effective port is instead of assuming the scheme default.
fn parse_host_authority(value: &str) -> Option<(String, Option<u16>)> {
    let authority = value.trim().parse::<Authority>().ok()?;
    if authority.as_str().contains('@') {
        return None;
    }
    let host = authority.host().to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }
    Some((host, authority.port_u16()))
}

/// Compare a browser `Origin` with the public deployment origin.
///
/// Both sides are reduced to scheme, host and effective port, so an explicit
/// default port matches an omitted one while any other port must match
/// exactly. `configured_origin` is the externally visible origin; an exact
/// match there is authoritative and covers deployments whose proxy forwards
/// `Host` without the public port.
///
/// Otherwise the request `Host` is compared under the effective connection
/// scheme. The app terminates plain TCP itself, so `http` is the default.
/// `X-Forwarded-Proto` is trusted only when it agrees with the scheme the
/// operator declared. A direct client must not be able to claim TLS merely by
/// sending a forwarding header.
///
/// When `Host` omits a port, the operator-declared port is used if `Host`
/// names the declared public host; otherwise the scheme's default applies.
pub fn same_origin(
    origin: Option<&str>,
    host: Option<&str>,
    forwarded_proto: Option<&str>,
    configured_origin: Option<&str>,
) -> bool {
    let Some(origin) = origin.and_then(parse_web_origin) else {
        return false;
    };
    let configured = configured_origin.and_then(parse_web_origin);
    if configured.as_ref() == Some(&origin) {
        return true;
    }
    let forwarded = forwarded_proto
        .and_then(|value| {
            let value = value.trim();
            (!value.contains(',')).then_some(value)
        })
        .and_then(web_origin_scheme);
    let scheme = match (configured.as_ref().map(|value| value.scheme), forwarded) {
        (Some("https"), Some("https")) => "https",
        // A TLS-only deployment must never accept a plaintext origin, and
        // without an operator-declared HTTPS origin a direct client cannot
        // prove the connection is TLS.
        (Some("https"), _) | (_, Some("https")) => return false,
        _ => "http",
    };
    let Some((host, explicit_port)) = host.and_then(parse_host_authority) else {
        return false;
    };
    // A port-less `Host` only means "the scheme default" when the operator has
    // not declared a different port for that exact public host. Otherwise the
    // declared port is the one the public origin actually listens on, and
    // assuming 80/443 would accept a different service on the same host.
    let port = explicit_port.unwrap_or_else(|| {
        configured
            .as_ref()
            .filter(|configured| configured.scheme == scheme && configured.host == host)
            .map_or_else(|| default_port(scheme), |configured| configured.port)
    });
    origin.scheme == scheme && origin.host == host && origin.port == port
}

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

pub async fn upgrade<A: App, X: Clone + Send + Sync + 'static>(
    ctx: AppContext,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> loco_rs::Result<Response> {
    let same_origin = same_origin(
        single_header(&headers, "origin"),
        single_header(&headers, "host"),
        single_header(&headers, "x-forwarded-proto"),
        Some(ctx.config.server.host.as_str()),
    );
    let native_bearer =
        !headers.contains_key(header::ORIGIN) && headers.contains_key(header::AUTHORIZATION);
    if !same_origin && !native_bearer {
        return Err(loco_rs::Error::Unauthorized("Invalid origin".into()));
    }
    let registry = ctx
        .shared_store
        .get::<Registry<A, X>>()
        .ok_or(loco_rs::Error::InternalServerError)?
        .clone();
    let mut credentials = HeaderMap::new();
    for key in [header::COOKIE, header::AUTHORIZATION] {
        for value in headers.get_all(&key) {
            credentials.append(key.clone(), value.clone());
        }
    }
    // Same-origin browsers also use this socket to ask whether a session exists.
    // Keep that handshake available, but only authenticated upgrades count as online.
    let user_id = A::authenticate(&ctx, &credentials)
        .await
        .ok()
        .map(|identity| identity.user_id);
    // The permit is acquired only once the upgrade will be handed to axum, so
    // origin or authentication work above never holds a slot. A rejected
    // upgrade never acquires one, and a saturated cap never creates a session
    // task at all.
    let Some(permit) = LIVE_CONNECTIONS.acquire(MAX_CONNECTIONS) else {
        return Err(loco_rs::Error::CustomError(
            StatusCode::SERVICE_UNAVAILABLE,
            loco_rs::controller::ErrorDetail::new("unavailable", "Too many websocket connections"),
        ));
    };
    // The larger ceiling applies only to authenticated sockets. Anonymous
    // upgrades can only send a `session.me` probe, so bound their transport
    // frames before JSON parsing can run at all.
    let message_limit = if user_id.is_some() {
        SOCKET_LIMIT
    } else {
        ANONYMOUS_MESSAGE_LIMIT
    };
    Ok(ws
        .max_message_size(message_limit)
        .max_frame_size(message_limit)
        .on_upgrade(move |socket| session(socket, ctx, credentials, registry, user_id, permit)))
}

// Connection state is serialized only for module hooks. Ordinary handlers never
// hold this lock while awaiting database, storage, or network work.
struct ConnectionState<A: App> {
    extensions: Vec<Box<dyn session::Session<A>>>,
    subscriptions: HashSet<A::Topic>,
}

/// Notifications a lagged socket needs to recover. Every invalidation carries no
/// data, so replaying all subscribed topics is safe and makes the socket reload
/// through authorized operations; `resync` additionally asks the client to
/// reconcile state that is not topic-based (a dropped call ring or a missed
/// assistant frame). The database stays authoritative.
fn lag_notices<T: subscriptions::Topic>(subscribed: &HashSet<T>, skipped: u64) -> Vec<Value> {
    subscribed
        .iter()
        .copied()
        .map(|topic| json!({"event":"invalidate", "topic":topic}))
        .chain(std::iter::once(
            json!({"event":"resync", "skipped":skipped}),
        ))
        .collect()
}

/// Bound both concurrent execution and buffered replies per connection.
const MAX_IN_FLIGHT_OPERATIONS: usize = 8;
const MAX_PENDING_MESSAGES: usize = 8;
const RESPONSE_LIMIT: usize = 6 * 1024 * 1024;

type SharedConnectionState<A> = Arc<tokio::sync::Mutex<ConnectionState<A>>>;

enum OutboundMessage {
    Reply(u64, String),
    /// A data-free invalidation or resync marker. It names only a topic, so it
    /// never needs a fresh session lookup before delivery; the periodic
    /// revalidation still closes a signed-out socket.
    Signal(String),
    Notification(String),
}

async fn execute_request<A: App, X: Clone + Send + Sync + 'static>(
    request: Request,
    ctx: AppContext,
    credentials: HeaderMap,
    registry: Registry<A, X>,
    state: SharedConnectionState<A>,
    previous_preflight: Option<tokio::sync::oneshot::Receiver<()>>,
    preflight_done: tokio::sync::oneshot::Sender<()>,
) -> loco_rs::Result<String> {
    // Keep connection-state changes in receive order, while allowing ordinary
    // handlers to overlap after their audited preflight has finished. Dropping
    // the sender also releases the next preflight if auditing rejects this one.
    if let Some(previous) = previous_preflight {
        let _ = previous.await;
    }
    let auditor = A::auditor();
    let response = auditor
        .capture(
            &ctx,
            &credentials,
            "websocket",
            &request.operation,
            auditor.targets(&request.payload),
            async {
                {
                    let mut state = state.lock().await;
                    for extension in &mut state.extensions {
                        if let Some(response) = extension
                            .operation(&ctx, &credentials, &request.operation, &request.payload)
                            .await
                        {
                            return response;
                        }
                    }
                    if matches!(
                        request.operation.as_str(),
                        "subscriptions.subscribe" | "subscriptions.unsubscribe"
                    ) {
                        return match (
                            A::authenticate(&ctx, &credentials).await,
                            serde_json::from_value::<A::Topic>(
                                request.payload.get("topic").cloned().unwrap_or(Value::Null),
                            ),
                        ) {
                            (Err(error), _) => error.into_response(),
                            (Ok(_), Ok(topic)) => {
                                if request.operation == "subscriptions.subscribe" {
                                    state.subscriptions.insert(topic);
                                } else {
                                    state.subscriptions.remove(&topic);
                                }
                                StatusCode::NO_CONTENT.into_response()
                            }
                            (_, Err(_)) => StatusCode::BAD_REQUEST.into_response(),
                        };
                    }
                }
                drop(preflight_done);
                let Some(handler) = registry.handler(&request.operation) else {
                    return StatusCode::NOT_FOUND.into_response();
                };
                let response =
                    handler(request.payload.clone(), ctx.clone(), credentials.clone()).await;
                if response.status().is_success() {
                    if let Some(topic) = registry.mutation(&request.operation) {
                        let state = state.lock().await;
                        if !state.extensions.iter().any(|extension| {
                            extension.handles_invalidation(&request.operation, topic)
                        }) {
                            subscriptions::publish::<A>(&ctx, A::Event::topic_event(topic));
                        }
                    }
                }
                response
            },
        )
        .await;
    let status = response.status().as_u16();
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let body = to_bytes(response.into_body(), RESPONSE_LIMIT)
        .await
        .map_err(|_| loco_rs::Error::InternalServerError)?;
    if status < 300 {
        let mut state = state.lock().await;
        for extension in &mut state.extensions {
            extension
                .after_response(&ctx, &request.operation, &request.payload, &body)
                .await;
        }
    }
    Ok(serde_json::to_string(&Reply {
        id: request.id,
        status,
        body: STANDARD.encode(body),
        content_type,
    })?)
}

async fn session<A: App, X: Clone + Send + Sync + 'static>(
    socket: WebSocket,
    ctx: AppContext,
    credentials: HeaderMap,
    registry: Registry<A, X>,
    user_id: Option<i32>,
    _permit: ConnectionPermit<'_>,
) {
    use futures_util::{SinkExt, StreamExt};

    // Anonymous sockets get a fixed 10s window from session start. Nothing an
    // inbound client sends can extend it; credentials are fixed at upgrade.
    let unauthenticated_idle = tokio::time::sleep(std::time::Duration::from_secs(10));
    tokio::pin!(unauthenticated_idle);

    let Some(bus) = ctx.shared_store.get::<subscriptions::SubscriptionBus<A>>() else {
        return;
    };
    let bus = bus.clone();
    let identity =
        A::authenticate(&ctx, &credentials)
            .await
            .ok()
            .map(|auth| session::SessionIdentity {
                user_id: auth.user_id,
                session_id: auth.session_id,
            });
    let state = Arc::new(tokio::sync::Mutex::new(ConnectionState {
        extensions: registry.open_sessions(&ctx, identity),
        subscriptions: A::Topic::ALL.iter().copied().collect(),
    }));
    if user_id.is_some_and(|user_id| bus.connect(user_id)) {
        if let Some(topic) = A::presence_topic() {
            subscriptions::publish::<A>(&ctx, A::Event::topic_event(topic));
        }
    }
    let mut events = bus.subscribe();
    let mut revalidate = tokio::time::interval(std::time::Duration::from_secs(10));
    revalidate.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let (mut sink, mut incoming) = socket.split();
    let (outgoing, mut messages) =
        tokio::sync::mpsc::channel::<OutboundMessage>(MAX_PENDING_MESSAGES);
    // These are connection-owned transport tasks, not durable background jobs.
    // They are aborted and joined before module connection cleanup runs.
    let mut operations: tokio::task::JoinSet<(u64, loco_rs::Result<String>)> =
        tokio::task::JoinSet::new();
    let mut active_ids = HashSet::new();
    let mut preflight_tail = None;
    {
        let writer = async {
            let mut last_signal_check: Option<tokio::time::Instant> = None;
            while let Some(message) = messages.recv().await {
                let (id, mut json, requires_session) = match message {
                    OutboundMessage::Reply(id, json) => (Some(id), json, true),
                    OutboundMessage::Signal(json) => (None, json, false),
                    OutboundMessage::Notification(json) => (None, json, true),
                };
                // A reply may have waited behind another transfer. Never deliver
                // buffered data after logout, but preserve explicit 401 replies.
                // Data-free signals are checked at most once per second: an
                // invalidation burst must not cost one session query per
                // socket, but a revoked session still closes promptly.
                let signal_check_due = !requires_session
                    && last_signal_check.is_none_or(|at: tokio::time::Instant| {
                        at.elapsed() >= std::time::Duration::from_secs(1)
                    });
                if signal_check_due {
                    last_signal_check = Some(tokio::time::Instant::now());
                }
                if (requires_session || signal_check_due)
                    && user_id.is_some()
                    && A::authenticate(&ctx, &credentials).await.is_err()
                {
                    let Some(id) = id else {
                        break;
                    };
                    let Ok(denied) = serde_json::to_string(&Reply {
                        id,
                        status: 401,
                        content_type: Some("application/json".into()),
                        body: STANDARD.encode(br#"{"error":"Session is no longer active"}"#),
                    }) else {
                        break;
                    };
                    json = denied;
                }
                if !matches!(
                    tokio::time::timeout(
                        std::time::Duration::from_secs(10),
                        sink.send(Message::Text(json.into()))
                    )
                    .await,
                    Ok(Ok(()))
                ) {
                    break;
                }
            }
        };
        let reader = async {
            loop {
                tokio::select! {
                    _ = revalidate.tick(), if user_id.is_some() => {
                        let mut state = state.lock().await;
                        for extension in &mut state.extensions { extension.revalidate(&ctx).await; }
                        if A::authenticate(&ctx, &credentials).await.is_err() { break; }
                    }
                    _ = &mut unauthenticated_idle, if user_id.is_none() => break,
                    completed = operations.join_next(), if !operations.is_empty() => {
                        let Some(Ok((id, Ok(json)))) = completed else { break; };
                        active_ids.remove(&id);
                        if outgoing.send(OutboundMessage::Reply(id, json)).await.is_err() { break; }
                    }
                    message = incoming.next() => {
                        let Some(Ok(message)) = message else { break; };
                        let Message::Text(text) = message else {
                            if matches!(message, Message::Close(_)) { break; }
                            continue;
                        };
                        // Unauthenticated frames are bounded and parsed
                        // without materializing an arbitrary JSON `Value`;
                        // the payload is discarded before the usual 401/404
                        // authentication path.
                        let request = if user_id.is_some() {
                            serde_json::from_str::<Request>(&text).ok()
                        } else {
                            anonymous_request(&text)
                        };
                        let Some(request) = request else { break; };
                        // Reusing a live ID makes response correlation ambiguous.
                        if active_ids.contains(&request.id) { break; }
                        if operations.len() >= MAX_IN_FLIGHT_OPERATIONS {
                            let reply = Reply {
                                id: request.id, status: 429,
                                content_type: Some("application/json".into()),
                                body: STANDARD.encode(br#"{"error":"Too many in-flight operations; wait for a response before retrying"}"#),
                            };
                            let Ok(json) = serde_json::to_string(&reply) else { break; };
                            if outgoing.send(OutboundMessage::Reply(request.id, json)).await.is_err() { break; }
                            continue;
                        }
                        active_ids.insert(request.id);
                        let (preflight_done, next_preflight) = tokio::sync::oneshot::channel();
                        let previous_preflight = preflight_tail.replace(next_preflight);
                        let (ctx, credentials, registry, state) = (ctx.clone(), credentials.clone(), registry.clone(), state.clone());
                        operations.spawn(async move {
                            let id = request.id;
                            (id, execute_request(request, ctx, credentials, registry, state, previous_preflight, preflight_done).await)
                        });
                    }
                    event = events.recv(), if user_id.is_some() => {
                        // The bus is bounded and deliberately drops the oldest
                        // data-free notifications for a slow socket. Never let
                        // that leave the socket silently stale: reload every
                        // subscribed topic, including permissions, and ask the
                        // client to reconcile non-topic state (a dropped call
                        // ring, a missed assistant frame).
                        let event = match event {
                            Ok(event) => event,
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                                let notices = {
                                    let state = state.lock().await;
                                    lag_notices(&state.subscriptions, skipped)
                                };
                                let mut delivered = true;
                                for notice in notices {
                                    let Ok(json) = serde_json::to_string(&notice) else {
                                        delivered = false;
                                        break;
                                    };
                                    if outgoing
                                        .send(OutboundMessage::Signal(json))
                                        .await
                                        .is_err()
                                    {
                                        delivered = false;
                                        break;
                                    }
                                }
                                if !delivered { break; }
                                continue;
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                        };
                        // Owner/recipient routing comes before any session or
                        // authorization work: a call or assistant frame for
                        // another account must cost this socket nothing, so one
                        // cheap publish cannot turn into O(sockets) database
                        // lookups. Authentication of delivered events still
                        // happens in the writer, immediately before the send.
                        if !user_id.is_some_and(|user_id| event.targeted_to(user_id)) {
                            continue;
                        }
                        let mut state = state.lock().await;
                        let mut data_free = false;
                        let payload = if let Some(topic) = event.topic() {
                            if !state.subscriptions.contains(&topic) { continue; }
                            data_free = true;
                            serde_json::json!({"event":"invalidate", "topic":topic})
                        } else {
                            let mut payload = None;
                            let mut failed = false;
                            for extension in &mut state.extensions {
                                match extension.event(&ctx, &credentials, &event).await {
                                    Ok(Some(value)) => { payload = Some(value); break; }
                                    Ok(None) => {}
                                    Err(_) => { failed = true; break; }
                                }
                            }
                            if failed { break; }
                            let Some(payload) = payload else { continue; };
                            payload
                        };
                        let Ok(json) = serde_json::to_string(&payload) else { break; };
                        let message = if data_free {
                            OutboundMessage::Signal(json)
                        } else {
                            OutboundMessage::Notification(json)
                        };
                        if outgoing.send(message).await.is_err() { break; }
                    }
                }
            }
        };
        tokio::select! { _ = writer => {}, _ = reader => {} }
    }
    operations.abort_all();
    while operations.join_next().await.is_some() {}
    let mut state = state.lock().await;
    for extension in &mut state.extensions {
        extension.close(&ctx).await;
    }
    if user_id.is_some_and(|user_id| bus.disconnect(user_id)) {
        if let Some(topic) = A::presence_topic() {
            subscriptions::publish::<A>(&ctx, A::Event::topic_event(topic));
        }
    }
}

// ---------------------------------------------------------------------------
// Binary helpers
// ---------------------------------------------------------------------------

pub fn bytes(encoded: &str) -> loco_rs::Result<axum::body::Bytes> {
    STANDARD
        .decode(encoded)
        .map(axum::body::Bytes::from)
        .map_err(|_| loco_rs::Error::BadRequest("Invalid binary payload".into()))
}

/// Largest byte slice one binary operation should return. The transport
/// base64-encodes the body, so a chunk of this size stays comfortably below
/// the reply limit while keeping large downloads to a bounded number of
/// round trips.
pub const MAX_BINARY_CHUNK: usize = 1024 * 1024;

/// Build a binary operation reply. The transport encodes `body` as base64 and
/// carries `content-type`, so clients receive the original bytes after
/// decoding `reply.body`.
pub fn binary(body: impl Into<axum::body::Bytes>, content_type: &str) -> loco_rs::Result<Response> {
    Response::builder()
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CACHE_CONTROL, "no-store")
        .header("x-content-type-options", "nosniff")
        .body(axum::body::Body::from(body.into()))
        .map_err(|_| loco_rs::Error::InternalServerError)
}

/// Clamp a requested download window to the transport's binary chunk ceiling.
/// Returns `(offset, length)` for one reply.
pub fn chunk_window(
    size: usize,
    offset: Option<u64>,
    length: Option<u64>,
) -> loco_rs::Result<(usize, usize)> {
    let offset = usize::try_from(offset.unwrap_or(0))
        .map_err(|_| loco_rs::Error::BadRequest("Invalid chunk offset".into()))?;
    if offset > size {
        return Err(loco_rs::Error::BadRequest(
            "Chunk offset is outside the payload".into(),
        ));
    }
    let remaining = size - offset;
    let requested = usize::try_from(length.unwrap_or(MAX_BINARY_CHUNK as u64))
        .map_err(|_| loco_rs::Error::BadRequest("Invalid chunk length".into()))?;
    Ok((offset, requested.min(remaining).min(MAX_BINARY_CHUNK)))
}

/// Encode one operation reply body. Public so applications can build custom
/// transports or tests around the same wire envelope.
pub fn encode_body(body: impl AsRef<[u8]>) -> String {
    STANDARD.encode(body)
}

#[cfg(test)]
mod tests {
    #[test]
    fn chunk_windows_are_bounded_and_never_exceed_the_payload() {
        assert_eq!(super::chunk_window(10, None, None).unwrap(), (0, 10));
        assert_eq!(
            super::chunk_window(super::MAX_BINARY_CHUNK + 5, Some(0), None).unwrap(),
            (0, super::MAX_BINARY_CHUNK)
        );
        assert_eq!(super::chunk_window(10, Some(4), Some(100)).unwrap(), (4, 6));
        assert_eq!(super::chunk_window(10, Some(10), None).unwrap(), (10, 0));
        assert!(super::chunk_window(10, Some(11), None).is_err());
        assert_eq!(
            super::chunk_window(10, Some(0), Some(u64::MAX)).unwrap(),
            (0, 10)
        );
    }

    #[test]
    fn binary_helper_sets_a_safe_content_type_and_cache_policy() {
        let response = super::binary(vec![1, 2, 3], "application/octet-stream").unwrap();
        assert_eq!(
            response.headers()["content-type"],
            "application/octet-stream"
        );
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(response.headers()["x-content-type-options"], "nosniff");
        assert_eq!(super::MAX_BINARY_CHUNK, 1024 * 1024);
    }

    #[test]
    fn connection_limiter_caps_live_sessions_and_releases_slots() {
        let limiter = super::ConnectionLimiter::new();
        assert!(limiter.acquire(0).is_none());

        let first = limiter.acquire(2).expect("first permit");
        let second = limiter.acquire(2).expect("second permit");
        assert!(limiter.acquire(2).is_none());
        assert_eq!(limiter.live(), 2);

        drop(first);
        assert_eq!(limiter.live(), 1);
        let replacement = limiter.acquire(2).expect("released slot is reusable");
        drop(second);
        drop(replacement);
        assert_eq!(limiter.live(), 0);
    }

    #[test]
    fn origin_comparison_uses_exact_scheme_host_and_effective_port() {
        assert!(super::same_origin(
            Some("https://enterprise.example.com"),
            Some("enterprise.example.com"),
            Some("https"),
            Some("https://enterprise.example.com"),
        ));
        assert!(super::same_origin(
            Some("https://enterprise.example.com:443"),
            Some("enterprise.example.com"),
            Some("https"),
            Some("https://enterprise.example.com"),
        ));
        assert!(super::same_origin(
            Some("https://enterprise.example.com"),
            Some("enterprise.example.com"),
            Some("https"),
            Some("https://api.example.com"),
        ));
        assert!(super::same_origin(
            Some("https://enterprise.example.com:8443"),
            Some("enterprise.example.com"),
            Some("https"),
            Some("https://enterprise.example.com:8443"),
        ));
        assert!(!super::same_origin(
            Some("https://enterprise.example.com:8443"),
            Some("enterprise.example.com"),
            Some("https"),
            Some("https://enterprise.example.com"),
        ));
        assert!(super::same_origin(
            Some("https://enterprise.example.com:8443"),
            Some("enterprise.example.com:8443"),
            Some("https"),
            Some("https://enterprise.example.com"),
        ));
        assert!(!super::same_origin(
            Some("https://enterprise.example.com"),
            Some("enterprise.example.com"),
            Some("https"),
            Some("https://enterprise.example.com:8443"),
        ));
        assert!(!super::same_origin(
            Some("http://localhost"),
            Some("localhost"),
            None,
            Some("http://localhost:5150"),
        ));
        assert!(super::same_origin(
            Some("http://localhost:5150"),
            Some("localhost:5150"),
            None,
            None,
        ));
        assert!(!super::same_origin(
            Some("http://localhost:5150"),
            Some("localhost"),
            None,
            None,
        ));
        assert!(!super::same_origin(
            Some("https://localhost"),
            Some("localhost"),
            None,
            Some("http://localhost"),
        ));
        assert!(!super::same_origin(
            Some("https://localhost"),
            Some("localhost"),
            Some("https"),
            Some("http://localhost"),
        ));
        assert!(!super::same_origin(
            Some("http://enterprise.example.com"),
            Some("enterprise.example.com"),
            Some("https"),
            Some("https://enterprise.example.com"),
        ));
        assert!(!super::same_origin(
            Some("https://other.example.com"),
            Some("other.example.com"),
            None,
            Some("https://enterprise.example.com"),
        ));
        assert!(!super::same_origin(
            Some("https://enterprise.example.com"),
            Some("enterprise.example.com"),
            Some("https, http"),
            Some("https://api.example.com"),
        ));
        assert!(super::same_origin(
            Some("http://localhost:5150"),
            Some("localhost:5150"),
            None,
            Some("http://localhost"),
        ));
        assert!(!super::same_origin(
            Some("https://other.example.com"),
            Some("enterprise.example.com"),
            Some("https"),
            Some("https://enterprise.example.com"),
        ));
        assert!(!super::same_origin(None, Some("localhost"), None, None));
        assert!(!super::same_origin(
            Some("https://localhost/redirect"),
            Some("localhost"),
            Some("https"),
            Some("https://localhost"),
        ));
        assert!(!super::same_origin(
            Some("https://user@localhost"),
            Some("localhost"),
            Some("https"),
            Some("https://localhost"),
        ));
        assert!(super::same_origin(
            Some("http://[::1]:5150"),
            Some("[::1]:5150"),
            None,
            None,
        ));
    }

    #[test]
    fn origin_comparison_rejects_duplicate_host_headers() {
        let mut headers = axum::http::HeaderMap::new();
        headers.append("host", "example.test".parse().unwrap());
        headers.append("host", "evil.test".parse().unwrap());
        assert_eq!(super::single_header(&headers, "host"), None);
        headers.remove("host");
        headers.insert("host", "example.test".parse().unwrap());
        assert_eq!(super::single_header(&headers, "host"), Some("example.test"));
    }

    #[test]
    fn anonymous_sockets_parse_only_a_bounded_envelope() {
        let probe = super::anonymous_request(r#"{"id":1,"operation":"session.me","payload":{}}"#)
            .expect("session probe");
        assert_eq!(probe.id, 1);
        assert_eq!(probe.operation, "session.me");
        assert!(probe
            .payload
            .as_object()
            .is_some_and(|value| value.is_empty()));
        assert!(super::anonymous_request(
            r#"{"id":3,"operation":"users.list","payload":{"query":{"limit":10}}}"#
        )
        .is_some());
        assert!(super::anonymous_request("not json").is_none());
        let oversized = format!(
            r#"{{"id":5,"operation":"session.me","payload":{{"pad":"{}"}}}}"#,
            "x".repeat(super::ANONYMOUS_MESSAGE_LIMIT)
        );
        assert!(super::anonymous_request(&oversized).is_none());
    }
}
