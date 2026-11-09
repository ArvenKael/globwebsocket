# globwebsocket

Typed WebSocket operations over one Loco endpoint.

Every application operation is a plain `serde` type with a stable wire name.
A `Registry` maps wire names to erased handlers, and the shared transport owns
framing, concurrency limits, origin checks, session revalidation, and
invalidation fan-out. The application supplies identity, authorization,
auditing, and its own topic/event vocabulary.

## The wire protocol

A client sends one JSON text frame:

```json
{"id":1,"operation":"projects.joined","payload":{"query":{"limit":100}}}
```

The reply carries the matching `id`, a numeric `status`, the response
`content_type`, and a base64-encoded `body`:

```json
{"id":1,"status":200,"content_type":"application/json","body":"eyJyb3dzIjpbXX0="}
```

Replies may arrive out of order; correlate them by `id` and use a unique ID per
outstanding request. A connection accepts up to eight concurrent operations; a
request received while all eight slots are occupied returns `429` without
executing.

## Defining an operation

```rust
use axum::http::HeaderMap;
use globwebsocket::{GlobWebsocket, Operation};
use loco_rs::{app::AppContext, prelude::Response};
use serde::Deserialize;

#[derive(Deserialize, GlobWebsocket)]
#[serde(deny_unknown_fields)]
#[websocket("projects.create")]
struct CreateProject {
    name: String,
}

#[async_trait::async_trait]
impl Operation for CreateProject {
    async fn execute(self, ctx: AppContext, _credentials: HeaderMap) -> loco_rs::Result<Response> {
        // authenticate, authorize, and act through your own domain model
        loco_rs::controller::format::json(serde_json::json!({"name": self.name}))
    }
}
```

The derive macro only assigns the wire name and payload hints. Authentication
and policy checks happen inside the erased handler before the typed payload is
decoded, so an unauthorized frame never spends work on a payload shape.

## Wiring an application

Implement [`App`](src/lib.rs) once. Its associated types carry the app's own
types through the shared transport:

```rust
impl globwebsocket::App for Enterprise {
    type Topic = subscriptions::Topic;
    type Event = subscriptions::Event;
    type Policy = OperationPolicy;
    type Auditor = AuditService;

    fn authenticate(/* ... */) -> impl Future<Output = loco_rs::Result<Identity>> + Send { /* ... */ }
    fn authorize(/* ... */) -> impl Future<Output = loco_rs::Result<bool>> + Send { /* ... */ }
    fn auditor() -> Self::Auditor { AuditService }
    fn presence_topic() -> Option<Self::Topic> { Some(subscriptions::Topic::Presence) }
}
```

Then build the registry, store it in `AppContext::shared_store`, and route:

```rust
pub fn routes() -> Routes {
    Routes::new().add("/ws", get(upgrade))
}

pub async fn upgrade(
    State(ctx): State<AppContext>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> loco_rs::Result<Response> {
    globwebsocket::upgrade::<Enterprise, ToolRegistry>(ctx, headers, ws).await
}
```

Register operations, mutations, and per-connection hooks:

```rust
registry
    .try_register_operation::<ProjectsJoined>(policy)?
    .try_register_mutation::<ProjectsCreate>(policy, Topic::Projects)?
    .try_register_session::<ProjectsSession>("projects")?;
```

## What the transport guarantees

- Same-origin browser upgrades, with exact scheme/host/effective-port matching
  and explicit handling of proxy-forwarded origins.
- A process-wide cap on live sessions, with the slot released on every exit
  path.
- Bounded anonymous frames that are parsed without materializing a JSON tree.
- Per-connection concurrency and buffered-reply limits, plus a send timeout.
- Session revalidation before buffered data is delivered.
- Serialized connection hooks, so module state is not mutated concurrently.
- Bounded invalidation fan-out; a lagged socket resyncs every subscribed topic
  rather than silently going stale.

## Layout

- `globwebsocket` — transport, registry, wire protocol, subscriptions, session hooks.
- `globwebsocket-derive` — `#[derive(GlobWebsocket)]` with `#[websocket("name")]`.

## License

MIT
