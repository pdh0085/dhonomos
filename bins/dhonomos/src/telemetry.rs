//! OpenTelemetry traces (OP-01): spans -> OTLP/HTTP (protobuf) -> collector.

use opentelemetry::trace::TracerProvider as _;
use opentelemetry_http::{Bytes, HttpClient, HttpError, Request, Response};
use opentelemetry_otlp::{WithExportConfig as _, WithHttpConfig as _};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::trace::{Sampler, SdkTracerProvider};

/// OTLP requests via the Dhonomos HTTP(S) client, spawned on the Tokio runtime.
/// SDK batch exporter runs on its own thread, outside the runtime.
#[derive(Debug)]
struct OtlpClient {
    runtime: tokio::runtime::Handle,
}

#[async_trait::async_trait]
impl HttpClient for OtlpClient {
    async fn send_bytes(&self, request: Request<Bytes>) -> Result<Response<Bytes>, HttpError> {
        let (parts, body) = request.into_parts();
        let headers: Vec<(String, String)> = parts
            .headers
            .iter()
            .filter_map(|(k, v)| Some((k.as_str().to_owned(), v.to_str().ok()?.to_owned())))
            .collect();
        let (method, url) = (parts.method.to_string(), parts.uri.to_string());
        let (status, _, body) =
            self.runtime
                .spawn(async move {
                    dhonomos_core::webhook::exchange(&method, &url, &headers, body).await
                })
                .await
                .map_err(|e| HttpError::from(e.to_string()))?
                .map_err(HttpError::from)?;
        Response::builder()
            .status(status)
            .body(body)
            .map_err(|e| HttpError::from(e.to_string()))
    }
}

/// Tracer provider -> `endpoint` (e.g. `http://collector:4318/v1/traces`).
/// Samples `ratio` of root spans; children follow their parent.
pub(crate) fn provider(
    endpoint: &str,
    service: &str,
    ratio: f64,
) -> anyhow::Result<SdkTracerProvider> {
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_endpoint(endpoint)
        .with_http_client(OtlpClient {
            runtime: tokio::runtime::Handle::current(),
        })
        .build()?;
    Ok(SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_sampler(Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(
            ratio,
        ))))
        .with_resource(
            Resource::builder()
                .with_service_name(service.to_owned())
                .build(),
        )
        .build())
}

/// `tracing` layer: spans -> OpenTelemetry spans.
pub(crate) fn layer<S>(
    provider: &SdkTracerProvider,
) -> tracing_opentelemetry::OpenTelemetryLayer<S, opentelemetry_sdk::trace::Tracer>
where
    S: tracing::Subscriber + for<'span> tracing_subscriber::registry::LookupSpan<'span>,
{
    tracing_opentelemetry::layer().with_tracer(provider.tracer("dhonomos"))
}
