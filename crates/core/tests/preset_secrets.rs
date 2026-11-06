//! Stored preset with secrets, fired by Inform -> plaintext to device, never in DB (audit NEW-1).
//! Over HTTP: real listener + CWMP backend + PostgreSQL container.
#![allow(clippy::unwrap_used)]

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use dhonomos_core::secrets::{preset_context, redact_preset, rewrap_secrets, task_context};
use dhonomos_core::{CpeCredentials, CwmpBackend, SecretBox};
use dhonomos_cwmp_codec::{
    Body, CwmpNamespace, DownloadResponse, Envelope, GetParameterValuesResponse, Rpc,
};
use dhonomos_cwmp_server::{AcsServer, AuthMode, Config, bind};
use dhonomos_store::{CwmpIdentity, DEFAULT_TENANT, Store, TaskState};
use http_body_util::{BodyExt as _, Full};
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::ImageExt;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use tokio::net::TcpStream;
use uuid::Uuid;

const INFORM: &[u8] = include_bytes!("../../cwmp-codec/tests/corpus/genieacs-sim/01-Inform.xml");
const KEY: &str = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";

struct Cpe {
    sender: hyper::client::conn::http1::SendRequest<Full<Bytes>>,
}

impl Cpe {
    async fn connect(addr: SocketAddr) -> Self {
        let io = TokioIo::new(TcpStream::connect(addr).await.unwrap());
        let (sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();
        tokio::spawn(conn);
        Self { sender }
    }

    async fn post(&mut self, body: Vec<u8>) -> (StatusCode, Option<Envelope>) {
        let resp = self
            .sender
            .send_request(
                Request::post("/")
                    .body(Full::new(Bytes::from(body)))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        (status, Envelope::decode(&bytes).unwrap())
    }

    async fn reply(
        &mut self,
        to: &Envelope,
        rpc: impl Into<Rpc>,
    ) -> (StatusCode, Option<Envelope>) {
        let env = Envelope::rpc(CwmpNamespace::V1_0, to.header.id.clone().unwrap(), rpc);
        self.post(env.encode().into_bytes()).await
    }
}

fn rpc(e: &Option<Envelope>) -> &Rpc {
    match &e.as_ref().unwrap().body {
        Body::Rpc(r) => r,
        Body::Fault(f) => panic!("fault {f:?}"),
    }
}

fn identity() -> CwmpIdentity {
    CwmpIdentity {
        oui: "202BC1".into(),
        product_class: "BM632w".into(),
        serial_number: "000000".into(),
    }
}

async fn database() -> (
    testcontainers_modules::testcontainers::ContainerAsync<Postgres>,
    Store,
) {
    let container = Postgres::default()
        .with_tag("17-alpine")
        .start()
        .await
        .unwrap();
    let port = container.get_host_port_ipv4(5432).await.unwrap();
    let store = Store::connect(
        &format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres"),
        4,
    )
    .await
    .unwrap();
    store.migrate().await.unwrap();
    (container, store)
}

/// Store a preset as the API does: secrets sealed for its row, history masked.
async fn save_preset(
    store: &Store,
    secrets: &SecretBox,
    name: &str,
    mut definition: Value,
) -> Uuid {
    let id = Uuid::now_v7();
    secrets.seal_preset(&mut definition, id, None).unwrap();
    store
        .put_preset(
            DEFAULT_TENANT,
            id,
            name,
            true,
            &definition,
            &redact_preset(&definition),
            Some(0),
            None,
        )
        .await
        .unwrap();
    id
}

#[tokio::test]
async fn a_stored_preset_delivers_its_secrets_to_the_device_only() {
    let (_container, store) = database().await;
    let secrets = Arc::new(SecretBox::from_base64(KEY, "k1").unwrap());
    let preset_id = save_preset(
        &store,
        &secrets,
        "provision",
        json!({
            "name": "provision",
            "when": { "oui": "202BC1" },
            "once": true,
            "run": [
                { "kind": "set_parameter_values", "payload": { "values": [
                    { "name": "InternetGatewayDevice.ManagementServer.ConnectionRequestPassword",
                      "value": "cr-s3cret", "secret": true, "type": "string" },
                    { "name": "InternetGatewayDevice.ManagementServer.PeriodicInformInterval",
                      "value": "3600", "type": "unsignedInt" },
                ] } },
                { "kind": "download", "payload": {
                    "url": "http://files.example/fw.bin", "username": "dl", "password": "file-pw",
                    "file_type": "1 Firmware Upgrade Image" } },
            ],
        }),
    )
    .await;

    // Row = ciphertext only.
    let stored = store.list_presets(DEFAULT_TENANT).await.unwrap().remove(0);
    let text = stored.definition.to_string();
    assert!(
        !text.contains("cr-s3cret") && !text.contains("file-pw"),
        "{text}"
    );

    // Server with key -> loads it + queues tasks for a booting device.
    let (presets, errors) =
        dhonomos_core::presets::load_stored(&store, DEFAULT_TENANT, Some(secrets.clone()))
            .await
            .unwrap();
    assert!(errors.is_empty(), "{errors:?}");
    assert_eq!(presets.len(), 1);
    let backend = CwmpBackend::new(store.clone(), DEFAULT_TENANT, CpeCredentials::None)
        .with_presets(presets)
        .with_secrets(secrets.clone());
    let config = Config {
        auth: AuthMode::None,
        ..Config::default()
    };
    let listener = bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(AcsServer::new(config, backend).serve(listener, std::future::pending()));

    let mut sent_values = Vec::new();
    let mut sent_downloads = Vec::new();
    for _ in 0..2 {
        let mut cpe = Cpe::connect(addr).await;
        cpe.post(INFORM.to_vec()).await;
        let (mut status, mut req) = cpe.post(Vec::new()).await;
        while status == StatusCode::OK {
            let answer: Rpc = match rpc(&req) {
                Rpc::SetParameterValues(spv) => {
                    sent_values.push(spv.parameter_list.clone());
                    dhonomos_cwmp_codec::SetParameterValuesResponse { status: 0 }.into()
                }
                Rpc::Download(dl) => {
                    sent_downloads.push((dl.username.clone(), dl.password.clone()));
                    DownloadResponse::default().into()
                }
                _ => GetParameterValuesResponse::default().into(),
            };
            (status, req) = cpe.reply(req.as_ref().unwrap(), answer).await;
        }
    }

    // Device got the plaintext x1 (preset is `once`).
    let secret_sent = sent_values
        .iter()
        .flatten()
        .find(|p| p.name.ends_with("ConnectionRequestPassword"))
        .expect("the secret value was set");
    assert_eq!(secret_sent.value, "cr-s3cret");
    assert_eq!(
        sent_values
            .iter()
            .flatten()
            .filter(|p| p.name.ends_with("ConnectionRequestPassword"))
            .count(),
        1
    );
    assert_eq!(sent_downloads, [("dl".to_owned(), "file-pw".to_owned())]);

    // DB: ciphertext bound to each queued task, never plaintext.
    let device = store
        .find_cwmp_device(DEFAULT_TENANT, &identity())
        .await
        .unwrap()
        .unwrap();
    let tasks = store.list_tasks(device, 50).await.unwrap();
    let from_preset: Vec<_> = tasks
        .iter()
        .filter(|t| t.kind == "set_parameter_values" || t.kind == "download")
        .filter(|t| t.created_by.as_deref() == Some("preset:provision"))
        .collect();
    assert_eq!(from_preset.len(), 2);
    for t in &from_preset {
        let payload = t.payload.to_string();
        assert!(payload.contains("enc:v2:"), "{payload}");
        assert!(
            !payload.contains("cr-s3cret") && !payload.contains("file-pw"),
            "{payload}"
        );
        if t.kind == "set_parameter_values" {
            assert_eq!(t.state, TaskState::Succeeded, "{t:?}");
        }
        // Bound to the task: opens with task context, not with preset context.
        let mut own = t.payload.clone();
        secrets
            .decrypt_fields(&mut own, &task_context(t.id))
            .unwrap();
        let mut as_preset = t.payload.clone();
        assert!(
            secrets
                .decrypt_fields(&mut as_preset, &preset_context(preset_id, 0))
                .is_err()
        );
    }

    // Server without key -> preset refused + error, no ciphertext sent to devices.
    let (without_key, errors) = dhonomos_core::presets::load_stored(&store, DEFAULT_TENANT, None)
        .await
        .unwrap();
    assert!(without_key.is_empty());
    assert!(
        errors[0].to_string().contains("--secrets-key"),
        "{errors:?}"
    );

    // Key rotation -> reseal preset secrets + plain ones from before sealing, mask old history.
    let new_key = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU=";
    let rotating = SecretBox::from_base64(new_key, "k2")
        .unwrap()
        .with_old_keys(&[KEY])
        .unwrap();
    store
        .put_preset(
            DEFAULT_TENANT,
            Uuid::now_v7(),
            "legacy",
            true,
            &json!({ "name": "legacy", "run": [
                { "kind": "download", "payload": { "url": "http://f/x", "password": "plain-pw" } }] }),
            &json!({ "name": "legacy", "run": [
                { "kind": "download", "payload": { "url": "http://f/x", "password": "plain-pw" } }] }),
            Some(0),
            None,
        )
        .await
        .unwrap();
    let done = rewrap_secrets(&store, &rotating).await.unwrap();
    assert_eq!(
        done.presets, 3,
        "two presets and one history entry: {done:?}"
    );
    assert_eq!(done.unreadable, 0, "{done:?}");
    assert_eq!(rewrap_secrets(&store, &rotating).await.unwrap().presets, 0);
    let all = store.list_presets(DEFAULT_TENANT).await.unwrap();
    assert!(
        !serde_json::to_string(&all.iter().map(|p| &p.definition).collect::<Vec<_>>())
            .unwrap()
            .contains("plain-pw")
    );
    let new_only = SecretBox::from_base64(new_key, "k2").unwrap();
    for p in &all {
        let mut dl = p.definition["run"]
            .as_array()
            .unwrap()
            .iter()
            .position(|t| t["kind"] == "download")
            .map(|i| (i, p.definition["run"][i]["payload"].clone()))
            .unwrap();
        new_only
            .decrypt_fields(&mut dl.1, &preset_context(p.id, dl.0))
            .unwrap();
        let expect = if p.name == "legacy" {
            "plain-pw"
        } else {
            "file-pw"
        };
        assert_eq!(dl.1["password"], expect, "{}", p.name);
    }
    let history = store
        .preset_history(DEFAULT_TENANT, "legacy", 10)
        .await
        .unwrap();
    assert!(
        !history[0]
            .definition
            .as_ref()
            .unwrap()
            .to_string()
            .contains("plain-pw")
    );
}
