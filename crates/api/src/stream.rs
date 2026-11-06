//! SSE (NB-03): `GET /api/v1/stream` -> alarm changes.
//! `?device_id=` -> also events of this device.
//! Poll DB 1/s per connection -> works for a change from any process.
//! Server shutdown (`ApiConfig::shutdown`) -> stream end, queued events dropped.

use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::{Query, State};
use axum::response::sse::{Event as SseEvent, KeepAlive, Sse};
use axum::routing::get;
use futures_util::stream::{self, Stream};
use serde::Deserialize;
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{ApiError, AppState, device_of, ts};

/// Re-read window. Commits are not in time order.
const OVERLAP: time::Duration = time::Duration::seconds(2);

pub(crate) fn routes() -> Router<Arc<AppState>> {
    Router::new().route("/stream", get(stream_handler))
}

#[derive(Debug, Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
struct StreamQuery {
    /// Also stream events of this device.
    #[serde(default)]
    device_id: Option<Uuid>,
}

struct Cursor {
    state: Arc<AppState>,
    device: Option<Uuid>,
    /// Caller's device scope, taken in the handler.
    /// Stream runs after handler return -> outside the request's task-local values.
    scope: Option<Arc<dhonomos_store::DeviceScope>>,
    since: OffsetDateTime,
    /// Recently sent -> skip repeats from the overlap.
    sent: HashMap<String, OffsetDateTime>,
    queue: std::collections::VecDeque<SseEvent>,
    first: bool,
}

impl Cursor {
    async fn poll(&mut self) {
        let now = OffsetDateTime::now_utc();
        let since = self.since - OVERLAP;
        let s = &self.state;
        if let Some(device) = self.device
            && let Ok(events) = s.store.events_since(device, since, 500).await
        {
            for e in events {
                let key = format!("e{}", e.id);
                if self.sent.insert(key, e.occurred_at).is_none() {
                    let data = json!({ "id": e.id, "device_id": e.device_id, "kind": e.kind,
                                       "detail": e.detail, "occurred_at": ts(e.occurred_at) });
                    self.queue.push_back(
                        SseEvent::default()
                            .event("device_event")
                            .data(data.to_string()),
                    );
                }
            }
        }
        if let Ok(alarms) = s
            .store
            .alarms_changed_since(
                s.config.tenant_id,
                self.device,
                self.scope.as_deref(),
                since,
            )
            .await
        {
            for a in alarms {
                let stamp = a.acked_at.or(a.cleared_at).unwrap_or(a.raised_at);
                let key = format!("a{}:{}:{}", a.id, a.state, a.acked_at.is_some());
                if self.sent.insert(key, stamp).is_none() {
                    let data = dhonomos_core::alarms::alarm_json(&a);
                    self.queue
                        .push_back(SseEvent::default().event("alarm").data(data.to_string()));
                }
            }
        }
        self.since = now;
        let horizon = now - OVERLAP - OVERLAP;
        self.sent.retain(|_, t| *t >= horizon);
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/stream",
    tag = "stream",
    operation_id = "stream_events",
    summary = "Server-sent events",
    description = "NB-03. Polls the database once a second.",
    params(
        StreamQuery,
    ),
    responses(
        (status = 200, description = "An event stream: `ready` first, then `alarm` and (with `device_id`) `device_event` events with JSON data", content_type = "text/event-stream", body = String),
        (status = 404, description = "Unknown device"),
    ),
)]
async fn stream_handler(
    State(s): State<Arc<AppState>>,
    Query(q): Query<StreamQuery>,
) -> Result<Sse<impl Stream<Item = Result<SseEvent, Infallible>>>, ApiError> {
    if let Some(d) = q.device_id {
        device_of(&s, d).await?;
    }
    let cursor = Cursor {
        state: s,
        device: q.device_id,
        scope: crate::auth::caller_scope()?,
        // Only changes from now on.
        since: OffsetDateTime::now_utc(),
        sent: HashMap::new(),
        queue: std::collections::VecDeque::new(),
        first: true,
    };
    let events = stream::unfold(cursor, |mut c| async move {
        loop {
            if let Some(e) = c.queue.pop_front() {
                return Some((Ok(e), c));
            }
            if c.first {
                c.first = false;
                return Some((Ok(SseEvent::default().event("ready").data("{}")), c));
            }
            let state = c.state.clone();
            tokio::select! {
                () = tokio::time::sleep(Duration::from_secs(1)) => {}
                () = crate::stopping(&state) => return None,
            }
            tokio::select! {
                () = c.poll() => {}
                () = crate::stopping(&state) => return None,
            }
        }
    });
    Ok(Sse::new(events).keep_alive(KeepAlive::default()))
}
