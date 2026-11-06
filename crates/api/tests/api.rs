//! REST API tests, PostgreSQL container.
#![allow(clippy::unwrap_used)]

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use dhonomos_api::{ApiConfig, router};
use dhonomos_store::{CwmpIdentity, DEFAULT_TENANT, InformUpdate, ParamUpdate, Store};
use http_body_util::BodyExt as _;
use serde_json::{Value, json};
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::{ContainerAsync, ImageExt};
use tower::ServiceExt as _;
use uuid::Uuid;

async fn setup(token: Option<&str>) -> (ContainerAsync<Postgres>, Store, Router, Uuid) {
    setup_with_shutdown(token, None).await
}

/// [`setup`] + [`ApiConfig::shutdown`].
async fn setup_with_shutdown(
    token: Option<&str>,
    shutdown: Option<tokio::sync::watch::Receiver<bool>>,
) -> (ContainerAsync<Postgres>, Store, Router, Uuid) {
    let c = Postgres::default()
        .with_tag("17-alpine")
        .start()
        .await
        .unwrap();
    let port = c.get_host_port_ipv4(5432).await.unwrap();
    let store = Store::connect(
        &format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres"),
        4,
    )
    .await
    .unwrap();
    store.migrate().await.unwrap();
    let id = store
        .upsert_cwmp_device(
            DEFAULT_TENANT,
            &CwmpIdentity {
                oui: "001122".into(),
                product_class: "Box".into(),
                serial_number: "SN1".into(),
            },
            &InformUpdate {
                software_version: Some("1.0".into()),
                ..InformUpdate::default()
            },
        )
        .await
        .unwrap()
        .id;
    store
        .upsert_params(
            id,
            &[ParamUpdate {
                path: "Device.DeviceInfo.UpTime".into(),
                value: Some("42".into()),
                xsd_type: Some("unsignedInt".into()),
                writable: Some(false),
            }],
        )
        .await
        .unwrap();
    let app = router(
        store.clone(),
        ApiConfig {
            bearer_token: token.map(Into::into),
            tenant_id: DEFAULT_TENANT,
            waker: Some(
                dhonomos_core::Waker::new(store.clone(), None, std::time::Duration::from_secs(1))
                    .with_address_policy(dhonomos_core::AddressPolicy::permit_all()),
            ),
            usp: None,
            metrics: Some(
                metrics_exporter_prometheus::PrometheusBuilder::new()
                    .build_recorder()
                    .handle(),
            ),
            metrics_ingest: None,
            files: None,
            secrets: None,
            broker: None,
            ca: None,
            presets: Default::default(),
            presets_in_db: false,
            alarm_rules: Default::default(),
            alarm_rules_file: None,
            secure_cookies: false,
            session_hours: 0.into(),
            session_idle_minutes: 0.into(),
            trusted_proxies: Vec::new(),
            public_url: None,
            rate_limit: 0.into(),
            oidc: None,
            totp: Default::default(),
            xmpp: None,
            wireguard: Default::default(),
            shutdown,
            server_settings: Default::default(),
            settings_hooks: Default::default(),
        },
    );
    (c, store, app, id)
}

async fn call(
    app: &Router,
    method: &str,
    uri: &str,
    body: Option<Value>,
    token: Option<&str>,
) -> (StatusCode, Value) {
    let mut req = Request::builder().method(method).uri(uri);
    if let Some(t) = token {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    let req = match body {
        Some(b) => req
            .header("content-type", "application/json")
            .body(Body::from(b.to_string())),
        None => req.body(Body::empty()),
    }
    .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let v = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, v)
}

#[tokio::test]
async fn devices_parameters_and_tasks() {
    let (_c, _store, app, id) = setup(None).await;
    let (s, _) = call(&app, "GET", "/healthz", None, None).await;
    assert_eq!(s, StatusCode::OK);

    let (s, v) = call(&app, "GET", "/api/v1/devices", None, None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["items"][0]["serial_number"], "SN1");
    assert_eq!(v["items"][0]["software_version"], "1.0");

    let (s, v) = call(
        &app,
        "GET",
        &format!("/api/v1/devices/{id}/parameters?prefix=Device.DeviceInfo."),
        None,
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["items"][0]["value"], "42");
    assert_eq!(v["items"][0]["type"], "unsignedInt");

    let uri = format!("/api/v1/devices/{id}/tasks");
    let (s, v) = call(
        &app,
        "POST",
        &uri,
        Some(json!({"kind": "reboot", "idempotency_key": "k"})),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);
    assert_eq!(
        (v["kind"].as_str(), v["state"].as_str()),
        (Some("reboot"), Some("pending"))
    );
    let task = v["id"].as_str().unwrap().to_owned();
    let (s, v2) = call(
        &app,
        "POST",
        &uri,
        Some(json!({"kind": "reboot", "idempotency_key": "k"})),
        None,
    )
    .await;
    assert_eq!(
        (s, v2["id"].as_str()),
        (StatusCode::OK, Some(task.as_str()))
    );

    let (s, v) = call(
        &app,
        "POST",
        &uri,
        Some(json!({"kind": "set_parameter_values", "payload": {"values": [
            {"name": "Device.ManagementServer.PeriodicInformInterval", "value": "600", "type": "unsignedInt"}
        ]}, "priority": 5})),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    assert_eq!(v["payload"]["values"][0]["type"], "unsignedInt");

    let (s, v) = call(
        &app,
        "POST",
        &uri,
        Some(json!({"kind": "frobnicate"})),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(v["error"].as_str().unwrap().contains("unknown variant"));

    let (s, v) = call(&app, "GET", &uri, None, None).await;
    assert_eq!(
        (s, v["items"].as_array().unwrap().len()),
        (StatusCode::OK, 2)
    );

    let (s, _) = call(&app, "DELETE", &format!("/api/v1/tasks/{task}"), None, None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, v) = call(&app, "DELETE", &format!("/api/v1/tasks/{task}"), None, None).await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert!(v["error"].as_str().unwrap().contains("cancelled"));

    // Audit trail: 2 creations (idempotent repeat != change) + 1 cancel.
    let (s, v) = call(&app, "GET", "/api/v1/audit", None, None).await;
    assert_eq!(s, StatusCode::OK);
    let actions: Vec<_> = v["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["action"].as_str().unwrap())
        .collect();
    assert_eq!(actions, ["task.cancel", "task.create", "task.create"]);
    assert_eq!(
        v["items"][0]["actor"], "anonymous",
        "open API (no accounts, no token)"
    );
}

#[tokio::test]
async fn not_found_and_tenant_isolation() {
    let (_c, store, app, _) = setup(None).await;
    let (s, v) = call(
        &app,
        "GET",
        &format!("/api/v1/devices/{}", Uuid::now_v7()),
        None,
        None,
    )
    .await;
    assert_eq!(
        (s, v["error"].as_str()),
        (StatusCode::NOT_FOUND, Some("device not found"))
    );
    let (s, _) = call(&app, "GET", "/api/v1/devices/not-a-uuid", None, None).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    let other = Uuid::now_v7();
    sqlx_insert_tenant(&store, other).await;
    let foreign = store
        .upsert_cwmp_device(
            other,
            &CwmpIdentity {
                oui: "AA".into(),
                product_class: String::new(),
                serial_number: "X".into(),
            },
            &InformUpdate::default(),
        )
        .await
        .unwrap()
        .id;
    let (s, _) = call(
        &app,
        "GET",
        &format!("/api/v1/devices/{foreign}"),
        None,
        None,
    )
    .await;
    assert_eq!(
        s,
        StatusCode::NOT_FOUND,
        "devices of other tenants are invisible"
    );
}

async fn sqlx_insert_tenant(store: &Store, id: Uuid) {
    sqlx::query("INSERT INTO tenants (id, name) VALUES ($1, 'other')")
        .bind(id)
        .execute(store.pool())
        .await
        .unwrap();
}

#[tokio::test]
async fn bearer_token() {
    let (_c, _store, app, _) = setup(Some("s3cret")).await;
    let (s, v) = call(&app, "GET", "/api/v1/devices", None, None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(v["error"], "log in, or send a bearer token or API key");
    let (s, _) = call(&app, "GET", "/api/v1/devices", None, Some("wrong")).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _) = call(&app, "GET", "/api/v1/devices", None, Some("s3cret")).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = call(&app, "GET", "/healthz", None, None).await;
    assert_eq!(s, StatusCode::OK, "health check stays open");
    let (s, _) = call(&app, "GET", "/metrics", None, None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "metrics need the token");
    let (s, _) = call(&app, "GET", "/metrics", None, Some("s3cret")).await;
    assert_eq!(s, StatusCode::OK);
}

#[tokio::test]
async fn device_tags_and_attributes() {
    let (_c, _store, app, id) = setup(None).await;
    let patch = |body: Value| {
        let app = app.clone();
        async move {
            call(
                &app,
                "PATCH",
                &format!("/api/v1/devices/{id}"),
                Some(body),
                None,
            )
            .await
        }
    };
    let (s, d) = patch(json!({
        "tags": ["vip", "fiber", "vip"],
        "attributes": { "subscriber": "S-1001", "line": "OLT3/1/7" }
    }))
    .await;
    assert_eq!(s, StatusCode::OK, "{d}");
    assert_eq!(d["tags"], json!(["fiber", "vip"]));
    assert_eq!(
        d["attributes"],
        json!({ "subscriber": "S-1001", "line": "OLT3/1/7" })
    );
    assert_eq!(d["status"], "active", "status untouched");
    // Merge: 1 key changed, 1 removed, rest kept.
    let (_, d) =
        patch(json!({ "attributes": { "subscriber": "S-2002", "line": null, "plan": "gold" } }))
            .await;
    assert_eq!(
        d["attributes"],
        json!({ "subscriber": "S-2002", "plan": "gold" })
    );
    assert_eq!(d["tags"], json!(["fiber", "vip"]));
    for bad in [
        json!({ "attributes": { "bad key": "x" } }),
        json!({ "attributes": { "k": "x".repeat(300) } }),
        json!({ "tags": [""] }),
        json!({ "status": "gone" }),
        json!({ "colour": "red" }),
    ] {
        let (s, _) = patch(bad.clone()).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{bad}");
    }
    // Find device by attribute, by any attribute value, in CSV.
    let (_, v) = call(
        &app,
        "GET",
        "/api/v1/devices?attr=subscriber=S-2002",
        None,
        None,
    )
    .await;
    assert_eq!(v["total"], 1);
    let (_, v) = call(
        &app,
        "GET",
        "/api/v1/devices?attr=subscriber=S-9",
        None,
        None,
    )
    .await;
    assert_eq!(v["total"], 0);
    let (_, v) = call(&app, "GET", "/api/v1/devices?q=s-2002", None, None).await;
    assert_eq!(v["total"], 1);
    let (s, _) = call(&app, "GET", "/api/v1/devices?attr=nokey", None, None).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    // Jobs (+ alarms, silences) target devices by attribute too.
    let preview = |attributes: Value| {
        let app = app.clone();
        async move {
            call(
                &app,
                "POST",
                "/api/v1/jobs/preview",
                Some(json!({ "target": { "attributes": attributes } })),
                None,
            )
            .await
            .1["count"]
                .as_i64()
        }
    };
    assert_eq!(preview(json!({ "plan": "gold" })).await, Some(1));
    assert_eq!(preview(json!({ "plan": "silver" })).await, Some(0));
    assert_eq!(preview(json!({})).await, Some(1));
    let resp = app
        .clone()
        .oneshot(
            Request::get("/api/v1/devices/export.csv?attr=plan=gold")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let csv = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(csv.lines().next().unwrap().ends_with(",attributes"));
    assert!(
        csv.contains(r#""{""plan"":""gold"",""subscriber"":""S-2002""}""#),
        "{csv}"
    );
}

#[tokio::test]
async fn attributes_import_from_csv() {
    let (_c, store, app, id) = setup(None).await;
    // 2 devices, different vendors, same serial number.
    for oui in ["AAAAAA", "BBBBBB"] {
        store
            .upsert_cwmp_device(
                DEFAULT_TENANT,
                &CwmpIdentity {
                    oui: oui.into(),
                    product_class: "Box".into(),
                    serial_number: "DUP".into(),
                },
                &InformUpdate::default(),
            )
            .await
            .unwrap();
    }
    store
        .update_device(
            DEFAULT_TENANT,
            id,
            None,
            Some(&json!({ "line": "old-line" })),
        )
        .await
        .unwrap();
    let post = |uri: &str, csv: &str| {
        let (app, uri, csv) = (app.clone(), uri.to_owned(), csv.to_owned());
        async move {
            let resp = app
                .oneshot(
                    Request::post(uri)
                        .header("content-type", "text/csv")
                        .body(Body::from(csv))
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = resp.status();
            let body = resp.into_body().collect().await.unwrap().to_bytes();
            (status, serde_json::from_slice::<Value>(&body).unwrap())
        }
    };
    let csv = "serial_number,subscriber,plan,line\r\nSN1,S-1001,gold,\r\nDUP,S-9,silver,x\r\nNOPE,S-0,gold,y\r\n,orphan,,\r\n";
    let (s, dry) = post("/api/v1/devices/attributes/import?dry_run=true", csv).await;
    assert_eq!(s, StatusCode::OK, "{dry}");
    assert_eq!(
        (
            dry["rows"].as_i64(),
            dry["matched"].as_i64(),
            dry["updated"].as_i64()
        ),
        (Some(4), Some(1), Some(0))
    );
    assert_eq!(dry["ambiguous"], json!(["DUP"]));
    assert_eq!(dry["unknown"], json!(["NOPE"]));
    assert_eq!(dry["invalid"][0]["line"], 5);
    assert_eq!(
        store.get_device(id).await.unwrap().unwrap().attributes,
        json!({ "line": "old-line" }),
        "dry run changes nothing"
    );
    let (_, done) = post("/api/v1/devices/attributes/import", csv).await;
    assert_eq!(done["updated"], 1);
    // Empty `line` cell -> old value kept.
    assert_eq!(
        store.get_device(id).await.unwrap().unwrap().attributes,
        json!({ "line": "old-line", "plan": "gold", "subscriber": "S-1001" })
    );
    for bad in [
        "model,plan\nX,y",
        "serial_number\nSN1",
        "serial_number,bad key\nSN1,x",
        "",
    ] {
        let (s, _) = post("/api/v1/devices/attributes/import", bad).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{bad:?}");
    }
    let audit = store
        .list_audit(DEFAULT_TENANT, &Default::default(), 10)
        .await
        .unwrap();
    assert!(audit.iter().any(|a| a.action == "device.attributes.import"));
}

/// Mock OpenID provider: discovery, JWKS, token endpoint (checks PKCE).
/// -> ES256 ID token with the claims the test sets.
struct MockIdp {
    issuer: String,
    claims: std::sync::Arc<std::sync::Mutex<Value>>,
    challenge: std::sync::Arc<std::sync::Mutex<String>>,
}

async fn mock_idp() -> MockIdp {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _};
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
    let key = std::sync::Arc::new(
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap(),
    );
    let point = key.public_key().as_ref().to_vec();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer = format!("http://{}", listener.local_addr().unwrap());
    let claims = std::sync::Arc::new(std::sync::Mutex::new(json!({})));
    let challenge = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let (iss, c2, ch2) = (issuer.clone(), claims.clone(), challenge.clone());
    let app = axum::Router::new()
        .route(
            "/.well-known/openid-configuration",
            axum::routing::get({
                let iss = iss.clone();
                move || async move {
                    axum::Json(json!({
                        "issuer": iss,
                        "authorization_endpoint": format!("{iss}/authorize"),
                        "token_endpoint": format!("{iss}/token"),
                        "jwks_uri": format!("{iss}/jwks"),
                    }))
                }
            }),
        )
        .route(
            "/jwks",
            axum::routing::get(move || async move {
                axum::Json(json!({ "keys": [{
                    "kty": "EC", "crv": "P-256", "kid": "k1",
                    "x": B64.encode(&point[1..33]), "y": B64.encode(&point[33..65]),
                }]}))
            }),
        )
        .route(
            "/token",
            axum::routing::post(move |headers: axum::http::HeaderMap, body: String| {
                let (key, claims, challenge) = (key.clone(), c2.clone(), ch2.clone());
                async move {
                    let form: std::collections::HashMap<String, String> = body
                        .split('&')
                        .filter_map(|kv| kv.split_once('='))
                        .map(|(k, v)| (k.to_owned(), v.replace("%2F", "/").replace("%3A", ":")))
                        .collect();
                    let verifier = &form["code_verifier"];
                    let expect = B64.encode(ring::digest::digest(
                        &ring::digest::SHA256,
                        verifier.as_bytes(),
                    ));
                    let basic = headers["authorization"].to_str().unwrap().to_owned();
                    if form["grant_type"] != "authorization_code"
                        || form["code"] != "good-code"
                        || *challenge.lock().unwrap() != expect
                        || basic
                            != format!(
                                "Basic {}",
                                base64::engine::general_purpose::STANDARD.encode("dhonomos:s3")
                            )
                    {
                        return (
                            StatusCode::BAD_REQUEST,
                            axum::Json(json!({ "error": "invalid_grant" })),
                        );
                    }
                    let header = B64.encode(r#"{"alg":"ES256","kid":"k1"}"#);
                    let payload = B64.encode(claims.lock().unwrap().to_string());
                    let input = format!("{header}.{payload}");
                    let sig = key
                        .sign(&ring::rand::SystemRandom::new(), input.as_bytes())
                        .unwrap();
                    let token = format!("{input}.{}", B64.encode(sig.as_ref()));
                    (
                        StatusCode::OK,
                        axum::Json(json!({ "id_token": token, "token_type": "Bearer" })),
                    )
                }
            }),
        );
    tokio::spawn(async move { axum::serve(listener, app).await });
    MockIdp {
        issuer,
        claims,
        challenge,
    }
}

#[tokio::test]
async fn oidc_single_sign_on() {
    let (_c, store, _, _) = setup(None).await;
    let idp = mock_idp().await;
    let app = router(
        store.clone(),
        ApiConfig {
            tenant_id: DEFAULT_TENANT,
            oidc: Some(dhonomos_api::OidcConfig {
                issuer: idp.issuer.clone(),
                client_id: "dhonomos".into(),
                client_secret: Some("s3".into()),
                redirect_url: "http://dhonomos.test/api/v1/auth/oidc/callback".into(),
                scopes: "openid profile groups".into(),
                username_claim: "preferred_username".into(),
                role_claim: "groups".into(),
                admin: vec!["dhonomos-admins".into()],
                operator: vec!["noc".into()],
                viewer: Vec::new(),
            }),
            ..ApiConfig::default()
        },
    );
    // Browser: keeps the login cookie + sends it with the callback.
    let jar = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let get = |uri: String, cookie: Option<String>| {
        let (app, jar) = (app.clone(), jar.clone());
        async move {
            let mut req = Request::get(&uri);
            let login = uri.contains("/oidc/login");
            let cookie = cookie
                .or_else(|| (uri.contains("/oidc/callback")).then(|| jar.lock().unwrap().clone()));
            if let Some(c) = cookie {
                req = req.header("cookie", c);
            }
            let resp = app.oneshot(req.body(Body::empty()).unwrap()).await.unwrap();
            let h = |n: &str| {
                resp.headers()
                    .get(n)
                    .map(|v| v.to_str().unwrap().to_owned())
            };
            if login {
                let c = h("set-cookie").unwrap();
                *jar.lock().unwrap() = c.split(';').next().unwrap().to_owned();
            }
            (resp.status(), h("location"), h("set-cookie"))
        }
    };
    let (_, v) = call(&app, "GET", "/api/v1/auth/config", None, None).await;
    assert_eq!(v["sso"], true);
    // Start -> redirect to provider with state, nonce, PKCE challenge.
    let start = |idp_claims: Value| {
        let (claims, challenge) = (idp.claims.clone(), idp.challenge.clone());
        async move {
            let (s, loc, _) = get("/api/v1/auth/oidc/login?return_to=/jobs".into(), None).await;
            assert_eq!(s, StatusCode::FOUND);
            let loc = loc.unwrap();
            let param = |k: &str| {
                loc.split(['?', '&'])
                    .find_map(|kv| kv.strip_prefix(&format!("{k}=")))
                    .unwrap()
                    .to_owned()
            };
            assert!(loc.contains("/authorize?response_type=code&client_id=dhonomos"));
            assert_eq!(param("code_challenge_method"), "S256");
            *challenge.lock().unwrap() = param("code_challenge");
            let mut c = idp_claims;
            if c["nonce"].is_null() {
                c["nonce"] = json!(param("nonce"));
            }
            *claims.lock().unwrap() = c;
            param("state")
        }
    };
    let exp = time::OffsetDateTime::now_utc().unix_timestamp() + 300;
    let good = json!({ "iss": idp.issuer, "aud": "dhonomos", "exp": exp, "sub": "u-1",
                       "preferred_username": "kim", "groups": ["noc", "staff"] });
    // No accounts yet -> open (development).
    let (s, _) = call(&app, "GET", "/api/v1/devices", None, None).await;
    assert_eq!(s, StatusCode::OK);
    let state = start(good.clone()).await;
    let (s, loc, cookie) = get(
        format!("/api/v1/auth/oidc/callback?code=good-code&state={state}"),
        None,
    )
    .await;
    assert_eq!((s, loc.as_deref()), (StatusCode::FOUND, Some("/jobs")));
    // Account made by the callback -> open mode closed at once (audit M-1).
    let (s, _) = call(&app, "GET", "/api/v1/devices", None, None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "SSO made the first account");
    let cookie = cookie.unwrap().split(';').next().unwrap().to_owned();
    let resp = app
        .clone()
        .oneshot(
            Request::get("/api/v1/auth/me")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let me: Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(
        (me["name"].as_str(), me["role"].as_str()),
        (Some("sso:kim"), Some("operator"))
    );
    // SSO user -> no password login.
    let (s, _) = call(
        &app,
        "POST",
        "/api/v1/auth/login",
        Some(json!({ "username": "sso:kim", "password": "!sso" })),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);

    // State good once; failure -> back to login page with a reason.
    let (_, loc, _) = get(
        format!("/api/v1/auth/oidc/callback?code=good-code&state={state}"),
        None,
    )
    .await;
    assert!(
        loc.unwrap()
            .starts_with("/login?sso_error=the%20login%20expired")
    );
    let state = start(json!({ "iss": idp.issuer, "aud": "dhonomos", "exp": exp,
                              "preferred_username": "guest", "groups": ["sales"] }))
    .await;
    let (_, loc, cookie) = get(
        format!("/api/v1/auth/oidc/callback?code=good-code&state={state}"),
        None,
    )
    .await;
    assert!(loc.unwrap().contains("no%20Dhonomos%20role"));
    assert!(
        cookie.is_none_or(|c| !c.starts_with("dhonomos_session=")),
        "no session for a user without a role"
    );
    let mut wrong_nonce = good.clone();
    wrong_nonce["nonce"] = json!("replayed");
    let state = start(wrong_nonce).await;
    let (_, loc, _) = get(
        format!("/api/v1/auth/oidc/callback?code=good-code&state={state}"),
        None,
    )
    .await;
    assert!(loc.unwrap().contains("does%20not%20belong"));
    let mut expired = good.clone();
    expired["exp"] = json!(exp - 3600);
    let state = start(expired).await;
    let (_, loc, _) = get(
        format!("/api/v1/auth/oidc/callback?code=good-code&state={state}"),
        None,
    )
    .await;
    assert!(loc.unwrap().contains("expired"));
    let state = start(good).await;
    let (_, loc, _) = get(
        format!("/api/v1/auth/oidc/callback?code=bad-code&state={state}"),
        None,
    )
    .await;
    assert!(loc.unwrap().contains("refused"));
}

#[tokio::test]
async fn usp_websocket_server_urls() {
    let (_c, store, app, cwmp) = setup(None).await;
    let (s, d) = call(
        &app,
        "POST",
        "/api/v1/devices",
        Some(json!({ "endpoint_id": "proto::ws-server", "usp_ws_url": "ws://192.0.2.9:7650/usp" })),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{d}");
    assert_eq!(d["usp_ws_url"], "ws://192.0.2.9:7650/usp");
    assert_eq!(
        store.usp_ws_clients(DEFAULT_TENANT).await.unwrap(),
        [(
            "proto::ws-server".to_owned(),
            "ws://192.0.2.9:7650/usp".to_owned()
        )]
    );
    let id = d["id"].as_str().unwrap().to_owned();
    let patch = |body: Value, dev: String| {
        let app = app.clone();
        async move {
            call(
                &app,
                "PATCH",
                &format!("/api/v1/devices/{dev}"),
                Some(body),
                None,
            )
            .await
        }
    };
    let (_, d) = patch(
        json!({ "usp_ws_url": "wss://agent.example/usp" }),
        id.clone(),
    )
    .await;
    assert_eq!(d["usp_ws_url"], "wss://agent.example/usp");
    let (_, d) = patch(json!({ "usp_ws_url": "" }), id.clone()).await;
    assert_eq!(d["usp_ws_url"], Value::Null);
    assert!(
        store
            .usp_ws_clients(DEFAULT_TENANT)
            .await
            .unwrap()
            .is_empty()
    );
    let (s, _) = patch(json!({ "usp_ws_url": "http://agent/usp" }), id).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    let (s, _) = patch(json!({ "usp_ws_url": "ws://x/usp" }), cwmp.to_string()).await;
    assert_eq!(
        s,
        StatusCode::UNPROCESSABLE_ENTITY,
        "CWMP devices have no USP MTP"
    );
}

#[tokio::test]
async fn csv_exports() {
    let (_c, store, app, id) = setup(None).await;
    let get = |uri: &str| {
        let app = app.clone();
        let uri = uri.to_owned();
        async move {
            let resp = app
                .oneshot(Request::get(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            let status = resp.status();
            let ctype = resp
                .headers()
                .get("content-type")
                .map(|v| v.to_str().unwrap().to_owned());
            let body = resp.into_body().collect().await.unwrap().to_bytes();
            (status, ctype, String::from_utf8(body.to_vec()).unwrap())
        }
    };
    // Tag that a spreadsheet would run as a formula.
    store.add_tags(id, &["=cmd".to_owned()]).await.unwrap();
    let (s, ctype, body) = get("/api/v1/devices/export.csv").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(ctype.as_deref(), Some("text/csv; charset=utf-8"));
    let lines: Vec<&str> = body.split("\r\n").filter(|l| !l.is_empty()).collect();
    assert!(lines[0].starts_with("id,serial_number,endpoint_id,protocol"));
    assert_eq!(lines.len(), 2);
    assert!(lines[1].starts_with(&format!("{id},SN1,,cwmp,001122,Box")));
    assert!(lines[1].contains(",'=cmd,"), "{}", lines[1]);
    let (_, _, none) = get("/api/v1/devices/export.csv?q=no-such-device").await;
    assert_eq!(
        none.split("\r\n").filter(|l| !l.is_empty()).count(),
        1,
        "header only"
    );

    let (s, _, alarms) = get("/api/v1/alarms/export.csv").await;
    assert_eq!(s, StatusCode::OK);
    assert!(alarms.starts_with("id,raised_at,cleared_at,severity"));
    let (s, _, _) = get(&format!("/api/v1/jobs/{}/members.csv", Uuid::now_v7())).await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    let audit = store
        .list_audit(DEFAULT_TENANT, &Default::default(), 10)
        .await
        .unwrap();
    assert!(audit.iter().any(|a| a.action == "export.devices"));
}

/// `GET /devices/facets`: values for the device list filters (OUI, product class, model).
/// Each ignores its own filter; caller scope applies. Also: matching list filters.
#[tokio::test]
async fn device_list_facets_and_exact_filters() {
    let admin = "admin-token";
    let (_c, store, app, _) = setup(Some(admin)).await;
    for (serial, oui, class, model, manufacturer) in [
        ("SN2", "001122", "Box", "M1", "Acme"),
        ("SN3", "00AA01", "Gate", "M2", "Beta"),
    ] {
        let id = store
            .upsert_cwmp_device(
                DEFAULT_TENANT,
                &CwmpIdentity {
                    oui: oui.into(),
                    product_class: class.into(),
                    serial_number: serial.into(),
                },
                &InformUpdate {
                    model_name: Some(model.into()),
                    manufacturer: Some(manufacturer.into()),
                    ..InformUpdate::default()
                },
            )
            .await
            .unwrap()
            .id;
        if serial == "SN2" {
            store.add_tags(id, &["east".to_owned()]).await.unwrap();
        }
    }

    let (s, v) = call(&app, "GET", "/api/v1/devices/facets", None, Some(admin)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        v,
        json!({
            "oui": [
                { "value": "001122", "count": 2, "manufacturer": "Acme" },
                { "value": "00AA01", "count": 1, "manufacturer": "Beta" },
            ],
            "product_class": [
                { "value": "Box", "count": 2 },
                { "value": "Gate", "count": 1 },
            ],
            "model_name": [
                { "value": "M1", "count": 1 },
                { "value": "M2", "count": 1 },
            ],
        })
    );

    // Selected OUI -> narrows the other lists, not its own.
    let (s, narrowed) = call(
        &app,
        "GET",
        "/api/v1/devices/facets?oui=00AA01&limit=1&offset=5",
        None,
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{narrowed}");
    assert_eq!(narrowed["oui"], v["oui"]);
    assert_eq!(
        narrowed["product_class"],
        json!([{ "value": "Gate", "count": 1 }])
    );
    assert_eq!(
        narrowed["model_name"],
        json!([{ "value": "M2", "count": 1 }])
    );

    // List filters on the same columns.
    let (_, v) = call(
        &app,
        "GET",
        "/api/v1/devices?model_name=M1",
        None,
        Some(admin),
    )
    .await;
    assert_eq!(v["total"], 1, "{v}");
    assert_eq!(v["items"][0]["serial_number"], "SN2");
    let (_, v) = call(&app, "GET", "/api/v1/devices?oui=00AA01", None, Some(admin)).await;
    assert_eq!(v["total"], 1, "{v}");
    assert_eq!(v["items"][0]["serial_number"], "SN3");
    let (_, v) = call(&app, "GET", "/api/v1/devices?oui=%20", None, Some(admin)).await;
    assert_eq!(v["total"], 3, "a blank filter matches everything: {v}");

    let (s, v) = call(
        &app,
        "GET",
        "/api/v1/devices/facets?filter=%28",
        None,
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");

    // Scoped caller -> values of devices in its scope only.
    let east = api_key(&app, admin, "viewer", Some(json!({ "tags": ["east"] }))).await;
    let (s, v) = call(&app, "GET", "/api/v1/devices/facets", None, Some(&east)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        v,
        json!({
            "oui": [{ "value": "001122", "count": 1, "manufacturer": "Acme" }],
            "product_class": [{ "value": "Box", "count": 1 }],
            "model_name": [{ "value": "M1", "count": 1 }],
        })
    );
}

#[tokio::test]
async fn requests_are_rate_limited_per_caller() {
    let (_c, store, _, _) = setup(None).await;
    let app = router(
        store.clone(),
        ApiConfig {
            bearer_token: Some("t0k".into()),
            tenant_id: DEFAULT_TENANT,
            rate_limit: 2.into(),
            ..ApiConfig::default()
        },
    );
    // Burst of 4x the rate -> then 429 + Retry-After.
    for _ in 0..8 {
        let (s, _) = call(&app, "GET", "/api/v1/devices", None, Some("t0k")).await;
        assert_eq!(s, StatusCode::OK);
    }
    let resp = app
        .clone()
        .oneshot(
            Request::get("/api/v1/devices")
                .header("authorization", "Bearer t0k")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(resp.headers().contains_key("retry-after"));
    // Failed auth limited per client address too.
    let mut last = StatusCode::OK;
    for _ in 0..9 {
        (last, _) = call(&app, "GET", "/api/v1/devices", None, Some("wrong")).await;
    }
    assert_eq!(last, StatusCode::TOO_MANY_REQUESTS);
}

/// Rate limit changes at runtime (runtime settings), off included.
#[tokio::test]
async fn the_rate_limit_changes_while_running() {
    let (_c, store, _, _) = setup(None).await;
    let rate = dhonomos_core::Shared::new(0u32);
    let app = router(
        store.clone(),
        ApiConfig {
            bearer_token: Some("t0k".into()),
            tenant_id: DEFAULT_TENANT,
            rate_limit: rate.clone(),
            ..ApiConfig::default()
        },
    );
    let get = || call(&app, "GET", "/api/v1/devices", None, Some("t0k"));
    for _ in 0..20 {
        assert_eq!(get().await.0, StatusCode::OK, "off");
    }
    rate.replace(1);
    for _ in 0..4 {
        assert_eq!(get().await.0, StatusCode::OK, "a burst of four");
    }
    assert_eq!(get().await.0, StatusCode::TOO_MANY_REQUESTS);
    rate.replace(0);
    assert_eq!(get().await.0, StatusCode::OK, "off again");
}

#[tokio::test]
async fn openapi_document_is_public() {
    let (_c, _store, app, _) = setup(Some("s3cret")).await;
    let (s, v) = call(&app, "GET", "/api/v1/openapi.json", None, None).await;
    assert_eq!(s, StatusCode::OK, "readable without credentials");
    assert!(v["openapi"].as_str().unwrap().starts_with("3.1"));
    assert_eq!(v["info"]["title"], "Dhonomos API");
    assert!(v["paths"]["/api/v1/devices"]["get"].is_object());
    assert!(v["paths"]["/api/v1/openapi.json"]["get"].is_object());
    // Only the document is public.
    let (s, _) = call(&app, "GET", "/api/v1/devices", None, None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn ui_routes_fall_back_to_the_app() {
    let (_c, _store, app, _) = setup(None).await;
    let get = |uri: &'static str| {
        let app = app.clone();
        async move {
            let resp = app
                .oneshot(Request::get(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            let ct = resp
                .headers()
                .get("content-type")
                .map(|v| v.to_str().unwrap().to_owned());
            (resp.status(), ct)
        }
    };
    // No UI build -> fallback says how to build it; with build -> HTML.
    let (s, _) = get("/devices/123").await;
    assert!(s == StatusCode::OK || s == StatusCode::NOT_FOUND);
    let (s, _) = get("/_app/immutable/missing.js").await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, ct) = get("/api/v1/devices").await;
    assert_eq!(
        (s, ct.as_deref()),
        (StatusCode::OK, Some("application/json")),
        "API is not shadowed"
    );
}

#[tokio::test]
async fn files_upload_and_signed_download() {
    use dhonomos_api::{FilesConfig, file_server};
    use dhonomos_core::FileSigner;

    let (_c, store, _, device) = setup(None).await;
    let dir = std::env::temp_dir().join(format!("dhonomos-files-{}", Uuid::now_v7()));
    std::fs::create_dir_all(&dir).unwrap();
    let signer = FileSigner::new(
        b"k".to_vec(),
        "http://files.test",
        std::time::Duration::from_secs(3600),
    );
    let files = FilesConfig::new(dir.clone(), signer.clone(), 1024, Default::default());
    let app = router(
        store.clone(),
        ApiConfig {
            bearer_token: None,
            tenant_id: DEFAULT_TENANT,
            waker: None,
            usp: None,
            metrics: None,
            metrics_ingest: None,
            files: Some(files.clone()),
            secrets: None,
            broker: None,
            ca: None,
            presets: Default::default(),
            presets_in_db: false,
            alarm_rules: Default::default(),
            alarm_rules_file: None,
            secure_cookies: false,
            session_hours: 0.into(),
            session_idle_minutes: 0.into(),
            trusted_proxies: Vec::new(),
            public_url: None,
            rate_limit: 0.into(),
            oidc: None,
            totp: Default::default(),
            xmpp: None,
            wireguard: Default::default(),
            shutdown: None,
            server_settings: Default::default(),
            settings_hooks: Default::default(),
        },
    );
    let put = |uri: &str, body: Vec<u8>| {
        let app = app.clone();
        let req = Request::put(uri).body(Body::from(body)).unwrap();
        async move {
            let resp = app.oneshot(req).await.unwrap();
            let status = resp.status();
            let bytes = resp.into_body().collect().await.unwrap().to_bytes();
            (
                status,
                serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null),
            )
        }
    };

    let (s, v) = put(
        "/api/v1/files?name=fw.bin&version=1.2",
        b"hello world".to_vec(),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    assert_eq!(v["size_bytes"], 11);
    assert_eq!(
        v["sha256"],
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    );
    assert_eq!(v["file_type"], "1 Firmware Upgrade Image");
    let id: Uuid = v["id"].as_str().unwrap().parse().unwrap();

    assert_eq!(
        put("/api/v1/files?name=fw.bin", b"x".to_vec()).await.0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        put("/api/v1/files?name=empty", Vec::new()).await.0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(
        put("/api/v1/files?name=big", vec![0; 2000]).await.0,
        StatusCode::PAYLOAD_TOO_LARGE
    );
    // Limit changes at runtime (runtime settings) -> every clone follows.
    files.set_max_bytes(4096);
    let (s, v) = put("/api/v1/files?name=big", vec![0; 2000]).await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    let big = v["id"].as_str().unwrap().to_owned();
    let (s, _) = call(&app, "DELETE", &format!("/api/v1/files/{big}"), None, None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    files.set_max_bytes(1024);
    assert_eq!(
        put("/api/v1/files?name=bigger", vec![0; 2000]).await.0,
        StatusCode::PAYLOAD_TOO_LARGE
    );
    assert_eq!(
        put("/api/v1/files?name=a/b", b"x".to_vec()).await.0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    let on_disk: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(
        on_disk,
        [std::ffi::OsString::from(id.to_string())],
        "no partial files left"
    );

    let (s, v) = call(&app, "GET", "/api/v1/files", None, None).await;
    assert_eq!(
        (s, v["items"].as_array().unwrap().len()),
        (StatusCode::OK, 1)
    );

    // Device-facing server: signed link + Range request.
    let fs_app = file_server(store.clone(), files, DEFAULT_TENANT, None);
    let url = signer.url(id, "fw.bin", device);
    let path = url.strip_prefix("http://files.test").unwrap().to_owned();
    let get = |p: String, range: Option<&'static str>| {
        let fs_app = fs_app.clone();
        async move {
            let mut req = Request::get(p);
            if let Some(r) = range {
                req = req.header("range", r);
            }
            let resp = fs_app
                .oneshot(req.body(Body::empty()).unwrap())
                .await
                .unwrap();
            let status = resp.status();
            (status, resp.into_body().collect().await.unwrap().to_bytes())
        }
    };
    let (s, body) = get(path.clone(), Some("bytes=0-4")).await;
    assert_eq!((s, &body[..]), (StatusCode::PARTIAL_CONTENT, &b"hello"[..]));
    let (s, body) = get(path.clone(), None).await;
    assert_eq!((s, &body[..]), (StatusCode::OK, &b"hello world"[..]));
    let forged = path.replace("&s=", "&s=00");
    assert_eq!(get(forged, None).await.0, StatusCode::FORBIDDEN);
    let wrong_name = path.replace("/fw.bin?", "/other.bin?");
    assert_eq!(get(wrong_name, None).await.0, StatusCode::NOT_FOUND);
    let events = store.list_events(device, 10).await.unwrap();
    let downloads: Vec<_> = events
        .iter()
        .filter(|e| e.kind == "file_download")
        .collect();
    assert_eq!(downloads.len(), 2);
    // Newest first: whole file, then range.
    assert_eq!(
        (
            &downloads[0].detail["bytes"],
            &downloads[0].detail["complete"]
        ),
        (&json!(11), &json!(true))
    );
    assert_eq!(
        (&downloads[1].detail["bytes"], &downloads[1].detail["range"]),
        (&json!(5), &json!("bytes=0-4"))
    );

    let (s, _) = call(&app, "DELETE", &format!("/api/v1/files/{id}"), None, None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert!(std::fs::read_dir(&dir).unwrap().next().is_none());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn preregistration_and_status_changes() {
    let (_c, _store, app, id) = setup(None).await;
    let body =
        json!({"oui": "00AA00", "product_class": "Box", "serial_number": "NEW1", "tags": ["lab"]});
    let (s, v) = call(&app, "POST", "/api/v1/devices", Some(body.clone()), None).await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    assert_eq!(
        (v["status"].as_str(), v["tags"][0].as_str()),
        (Some("active"), Some("lab"))
    );
    let (s, _) = call(&app, "POST", "/api/v1/devices", Some(body), None).await;
    assert_eq!(s, StatusCode::OK, "pre-registering twice is idempotent");
    let (s, _) = call(
        &app,
        "POST",
        "/api/v1/devices",
        Some(json!({"oui": "", "serial_number": "x"})),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);

    let uri = format!("/api/v1/devices/{id}");
    let (s, _) = call(&app, "PATCH", &uri, Some(json!({"status": "broken"})), None).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    let (s, v) = call(
        &app,
        "PATCH",
        &uri,
        Some(json!({"status": "quarantined"})),
        None,
    )
    .await;
    assert_eq!(
        (s, v["status"].as_str()),
        (StatusCode::OK, Some("quarantined"))
    );
    let (_, v) = call(&app, "GET", "/api/v1/audit", None, None).await;
    assert_eq!(v["items"][0]["action"], "device.status");
    assert_eq!(v["items"][0]["detail"]["from"], "active");
}

#[tokio::test]
async fn usp_preregistration() {
    let (_c, _store, app, _) = setup(None).await;
    let body = json!({"endpoint_id": "os::012345-AABBCCDDEEFF", "tags": ["lab"]});
    let (s, v) = call(&app, "POST", "/api/v1/devices", Some(body.clone()), None).await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    assert_eq!(
        (v["protocol"].as_str(), v["endpoint_id"].as_str()),
        (Some("usp"), Some("os::012345-AABBCCDDEEFF"))
    );
    let (s, _) = call(&app, "POST", "/api/v1/devices", Some(body), None).await;
    assert_eq!(s, StatusCode::OK);
    for bad in ["no-scheme", "os::a/b", "os::a+b", "os::#"] {
        let (s, _) = call(
            &app,
            "POST",
            "/api/v1/devices",
            Some(json!({ "endpoint_id": bad })),
            None,
        )
        .await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{bad}");
    }
    // Broker account management off unless configured.
    let uri = format!("/api/v1/devices/{}/mqtt-credentials", v_id(&app).await);
    let (s, v) = call(&app, "POST", &uri, None, None).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{v}");
}

async fn v_id(app: &Router) -> String {
    let (_, v) = call(app, "GET", "/api/v1/devices", None, None).await;
    v["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["protocol"] == "usp")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[tokio::test]
async fn secrets_are_redacted() {
    let (_c, _store, app, id) = setup(None).await;
    let body = json!({"kind": "download", "payload": {"url": "http://f/x.bin", "file_type": "1 Firmware Upgrade Image", "password": "hunter2"}});
    let (s, v) = call(
        &app,
        "POST",
        &format!("/api/v1/devices/{id}/tasks"),
        Some(body),
        None,
    )
    .await;
    assert_eq!(
        s,
        StatusCode::UNPROCESSABLE_ENTITY,
        "without --secrets-key passwords are refused: {v}"
    );
    let (_, v) = call(&app, "GET", "/api/v1/audit", None, None).await;
    assert!(
        !v.to_string().contains("hunter2"),
        "audit log must not leak secrets"
    );
    let (_, v) = call(
        &app,
        "GET",
        &format!("/api/v1/devices/{id}/tasks"),
        None,
        None,
    )
    .await;
    assert!(!v.to_string().contains("hunter2"));
}

/// AddObject parameters never secret (only SPV values sealed).
/// Plain ones accepted for a USP device.
#[tokio::test]
async fn add_object_parameters_cannot_be_secret() {
    let (_c, _store, app, _id) = setup(None).await;
    let (s, v) = call(
        &app,
        "POST",
        "/api/v1/devices",
        Some(json!({ "endpoint_id": "os::012345-AABBCCDDEE01" })),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    let usp = v_id(&app).await;
    let uri = format!("/api/v1/devices/{usp}/tasks");
    let add = |secret: bool| {
        json!({"kind": "add_object", "payload": {"object": "Device.WireGuard.Peer.",
            "params": [{"name": "PresharedKey", "value": "hunter2", "secret": secret}]}})
    };
    let (s, v) = call(&app, "POST", &uri, Some(add(true)), None).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert_eq!(v["error"], "AddObject parameters cannot be secret");
    let (s, v) = call(&app, "POST", &uri, Some(add(false)), None).await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    // Old form without parameters still works.
    let plain = json!({"kind": "add_object", "payload": {"object": "Device.NAT.PortMapping."}});
    let (s, v) = call(&app, "POST", &uri, Some(plain), None).await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
}

/// ADR-104: device shows start of its XMPP session.
/// XMPP login: removable (zero-touch issues it again), not settable by hand.
#[tokio::test]
async fn xmpp_session_time_and_removing_the_xmpp_login() {
    let (_c, store, app, id) = setup(None).await;
    let (s, v) = call(&app, "GET", &format!("/api/v1/devices/{id}"), None, None).await;
    assert_eq!(s, StatusCode::OK);
    assert!(v["xmpp_connected_at"].is_null(), "{v}");

    let at = time::OffsetDateTime::now_utc()
        .replace_nanosecond(0)
        .unwrap();
    store.set_xmpp_connected(id, at).await.unwrap();
    let (_, v) = call(&app, "GET", &format!("/api/v1/devices/{id}"), None, None).await;
    let shown = v["xmpp_connected_at"].as_str().unwrap();
    assert_eq!(
        time::OffsetDateTime::parse(shown, &time::format_description::well_known::Rfc3339).unwrap(),
        at
    );
    let (_, v) = call(&app, "GET", "/api/v1/devices", None, None).await;
    assert!(v["items"][0]["xmpp_connected_at"].is_string(), "{v}");
    assert!(
        v["items"][0]["xmpp_jid"].is_null(),
        "this process does not run the XMPP server, so it cannot name the session: {v}"
    );

    // Both go: the login + the one being provisioned.
    let sealed = |kind: &str| dhonomos_store::SealedCredential {
        device_id: id,
        kind: kind.into(),
        username: id.to_string(),
        ciphertext: vec![1, 2, 3],
        nonce: vec![4, 5, 6],
        key_id: "k1".into(),
    };
    store.put_credential(&sealed("xmpp")).await.unwrap();
    store.put_credential(&sealed("xmpp_pending")).await.unwrap();
    let (_, v) = call(
        &app,
        "GET",
        &format!("/api/v1/devices/{id}/credentials"),
        None,
        None,
    )
    .await;
    let kinds: Vec<&str> = v["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["kind"].as_str().unwrap())
        .collect();
    assert_eq!(kinds, ["xmpp", "xmpp_pending"]);
    let uri = format!("/api/v1/devices/{id}/credentials/xmpp");
    let (s, _) = call(&app, "DELETE", &uri, None, None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert!(store.list_credentials(id).await.unwrap().is_empty());
    let (s, _) = call(&app, "DELETE", &uri, None, None).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "nothing left to remove");
    let (s, _) = call(
        &app,
        "PUT",
        &uri,
        Some(json!({"username": "a", "password": "b"})),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND, "Dhonomos makes the password");
    let (s, v) = call(
        &app,
        "DELETE",
        &format!("/api/v1/devices/{id}/credentials/mqtt"),
        None,
        None,
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{v}");
}

/// Reachability: UDP CR address + last wake record on the device (list + detail).
/// Filter selects by them.
#[tokio::test]
async fn reachability_and_the_last_wake_on_the_device() {
    let (_c, store, app, id) = setup(None).await;
    let uri = format!("/api/v1/devices/{id}");
    let (s, v) = call(&app, "GET", &uri, None, None).await;
    assert_eq!(s, StatusCode::OK);
    for key in [
        "xmpp_jid",
        "udp_cr_address",
        "udp_cr_seen_at",
        "last_wake_at",
        "last_wake_method",
        "last_wake_outcome",
    ] {
        assert!(v[key].is_null(), "{key} is null until known: {v}");
    }

    assert!(
        store
            .set_udp_cr_address(DEFAULT_TENANT, id, "198.51.100.7:50000")
            .await
            .unwrap()
    );
    let (_, v) = call(&app, "GET", &uri, None, None).await;
    assert_eq!(v["udp_cr_address"], "198.51.100.7:50000");
    assert!(v["udp_cr_seen_at"].is_string(), "{v}");
    let (_, v) = call(&app, "GET", "/api/v1/devices", None, None).await;
    assert_eq!(v["items"][0]["udp_cr_address"], "198.51.100.7:50000");

    // API wake: no CR URL on this device -> nothing sent, device says so.
    let (s, v) = call(
        &app,
        "POST",
        &format!("{uri}/connection-request"),
        None,
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        v["connection_request"],
        "skipped: no connection request URL"
    );
    let (_, v) = call(&app, "GET", &uri, None, None).await;
    assert!(v["last_wake_at"].is_string(), "{v}");
    assert!(v["last_wake_method"].is_null(), "nothing was sent: {v}");
    assert_eq!(v["last_wake_outcome"], "skipped: no connection request URL");
    let (_, v) = call(&app, "GET", "/api/v1/devices", None, None).await;
    assert_eq!(
        v["items"][0]["last_wake_outcome"],
        "skipped: no connection request URL"
    );

    // Tasks that wake the device -> recorded too.
    store
        .upsert_cwmp_device(
            DEFAULT_TENANT,
            &CwmpIdentity {
                oui: "001122".into(),
                product_class: "Box".into(),
                serial_number: "SN1".into(),
            },
            &InformUpdate {
                connection_request_url: Some("http://127.0.0.1:1/cr".into()),
                ..InformUpdate::default()
            },
        )
        .await
        .unwrap();
    let (s, v) = call(
        &app,
        "POST",
        &format!("{uri}/tasks"),
        Some(json!({ "kind": "reboot" })),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    assert!(
        v["connection_request"]
            .as_str()
            .unwrap()
            .starts_with("failed: "),
        "{v}"
    );
    let (_, v) = call(&app, "GET", &uri, None, None).await;
    let outcome = v["last_wake_outcome"].as_str().unwrap();
    assert!(outcome.starts_with("failed: "), "refused port: {v}");
    assert!(v["last_wake_method"].is_null(), "{v}");

    // Filter fields.
    let enc = |f: &str| {
        f.bytes()
            .map(|b| match b {
                b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'_' | b'-' => {
                    (b as char).to_string()
                }
                _ => format!("%{b:02X}"),
            })
            .collect::<String>()
    };
    let total = |f: &str| {
        let app = app.clone();
        let uri = format!("/api/v1/devices?filter={}", enc(f));
        let f = f.to_owned();
        async move {
            let (s, v) = call(&app, "GET", &uri, None, None).await;
            assert_eq!(s, StatusCode::OK, "{f}: {v}");
            v["total"].as_i64().unwrap()
        }
    };
    assert_eq!(total("udp_cr = true").await, 1);
    assert_eq!(total("udp_cr = false").await, 0);
    assert_eq!(total("xmpp_connected = true").await, 0);
    assert_eq!(total("xmpp_connected = false").await, 1);
    store
        .set_xmpp_connected(id, time::OffsetDateTime::now_utc())
        .await
        .unwrap();
    assert_eq!(total("xmpp_connected = true and udp_cr = true").await, 1);
    let (s, v) = call(
        &app,
        "GET",
        &format!("/api/v1/devices?filter={}", enc("xmpp_connected = soon")),
        None,
        None,
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert!(
        v["error"].as_str().unwrap().contains("true or false"),
        "{v}"
    );
}

/// `xmpp_jid` = full JID of the live session in the XMPP server of this process.
/// Session end -> null again.
#[tokio::test]
async fn the_xmpp_jid_of_a_live_session() {
    use base64::Engine as _;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    const DOMAIN: &str = "xmpp.test";
    let (_c, store, _plain_app, id) = setup(None).await;
    let secrets = std::sync::Arc::new(
        dhonomos_core::SecretBox::from_base64("MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=", "k1")
            .unwrap(),
    );
    let (ciphertext, nonce) = secrets.seal_credential(id, b"xmpp-secret").unwrap();
    store
        .put_credential(&dhonomos_store::SealedCredential {
            device_id: id,
            kind: "xmpp".into(),
            username: id.to_string(),
            ciphertext,
            nonce,
            key_id: "k1".into(),
        })
        .await
        .unwrap();
    let ck = rcgen::generate_simple_self_signed(vec![DOMAIN.to_owned()]).unwrap();
    let resolver =
        dhonomos_pki::tls::CertResolver::from_pem(&ck.cert.pem(), &ck.signing_key.serialize_pem())
            .unwrap();
    let server = dhonomos_xmpp::XmppServer::new(
        dhonomos_xmpp::XmppConfig::new(DOMAIN),
        std::sync::Arc::new(dhonomos_core::XmppAccounts::new(
            store.clone(),
            DEFAULT_TENANT,
            secrets,
        )),
        dhonomos_xmpp::tls_acceptor(resolver).unwrap(),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    {
        let server = server.clone();
        tokio::spawn(async move { server.serve(listener, std::future::pending()).await });
    }
    let app = router(
        store.clone(),
        ApiConfig {
            tenant_id: DEFAULT_TENANT,
            xmpp: Some(server.clone()),
            ..ApiConfig::default()
        },
    );
    let uri = format!("/api/v1/devices/{id}");
    let (_, v) = call(&app, "GET", &uri, None, None).await;
    assert!(v["xmpp_jid"].is_null(), "not connected: {v}");

    // Device login like xmppc: STARTTLS, SASL PLAIN, bind.
    async fn until<S: tokio::io::AsyncRead + Unpin>(io: &mut S, seen: &mut String, marker: &str) {
        while !seen.contains(marker) {
            let mut buf = [0u8; 2048];
            let n = io.read(&mut buf).await.unwrap();
            assert!(
                n > 0,
                "connection closed while waiting for {marker}: {seen}"
            );
            seen.push_str(&String::from_utf8_lossy(&buf[..n]));
        }
    }
    let open = format!(
        "<?xml version='1.0'?><stream:stream to='{DOMAIN}' xmlns='jabber:client' \
         xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>"
    );
    let mut tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    tcp.write_all(open.as_bytes()).await.unwrap();
    let mut seen = String::new();
    until(&mut tcp, &mut seen, "</stream:features>").await;
    tcp.write_all(b"<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
        .await
        .unwrap();
    seen.clear();
    until(&mut tcp, &mut seen, "<proceed").await;
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ck.cert.der().clone()).unwrap();
    let config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let mut io = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config))
        .connect(rustls_pki_types::ServerName::try_from(DOMAIN).unwrap(), tcp)
        .await
        .unwrap();
    io.write_all(open.as_bytes()).await.unwrap();
    seen.clear();
    until(&mut io, &mut seen, "</stream:features>").await;
    let plain = base64::engine::general_purpose::STANDARD.encode(format!("\0{id}\0xmpp-secret"));
    io.write_all(
        format!("<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>{plain}</auth>")
            .as_bytes(),
    )
    .await
    .unwrap();
    seen.clear();
    until(&mut io, &mut seen, "<success").await;
    io.write_all(open.as_bytes()).await.unwrap();
    seen.clear();
    until(&mut io, &mut seen, "</stream:features>").await;
    io.write_all(b"<iq type='set' id='b1'><bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/></iq>")
        .await
        .unwrap();
    seen.clear();
    until(&mut io, &mut seen, "</iq>").await;
    let bound = seen
        .split("<jid>")
        .nth(1)
        .and_then(|r| r.split("</jid>").next())
        .unwrap()
        .to_owned();
    assert!(bound.starts_with(&format!("{id}@{DOMAIN}/")), "{bound}");

    let (_, v) = call(&app, "GET", &uri, None, None).await;
    assert_eq!(v["xmpp_jid"], bound.as_str(), "{v}");
    assert!(v["xmpp_connected_at"].is_string(), "{v}");
    let (_, v) = call(&app, "GET", "/api/v1/devices", None, None).await;
    assert_eq!(v["items"][0]["xmpp_jid"], bound.as_str(), "{v}");

    // Session end -> no JID, no session time.
    io.write_all(b"</stream:stream>").await.unwrap();
    for _ in 0..100 {
        if !server.is_connected(&dhonomos_core::account_of(id)) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let (_, v) = call(&app, "GET", &uri, None, None).await;
    assert!(v["xmpp_jid"].is_null(), "{v}");
}

#[tokio::test]
async fn credentials_and_encrypted_task_secrets() {
    let (_c, store, plain_app, id) = setup(None).await;
    let uri = format!("/api/v1/devices/{id}/credentials/acs_auth");
    let body = json!({"username": "cpe-SN1", "password": "s3cr3t"});
    let (s, v) = call(&plain_app, "PUT", &uri, Some(body.clone()), None).await;
    assert_eq!(
        s,
        StatusCode::UNPROCESSABLE_ENTITY,
        "no key configured: {v}"
    );

    let secrets = std::sync::Arc::new(
        dhonomos_core::SecretBox::from_base64("MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=", "k1")
            .unwrap(),
    );
    let app = router(
        store.clone(),
        ApiConfig {
            bearer_token: None,
            tenant_id: DEFAULT_TENANT,
            waker: None,
            usp: None,
            metrics: None,
            metrics_ingest: None,
            files: None,
            secrets: Some(secrets.clone()),
            broker: None,
            ca: None,
            presets: Default::default(),
            presets_in_db: false,
            alarm_rules: Default::default(),
            alarm_rules_file: None,
            secure_cookies: false,
            session_hours: 0.into(),
            session_idle_minutes: 0.into(),
            trusted_proxies: Vec::new(),
            public_url: None,
            rate_limit: 0.into(),
            oidc: None,
            totp: Default::default(),
            xmpp: None,
            wireguard: Default::default(),
            shutdown: None,
            server_settings: Default::default(),
            settings_hooks: Default::default(),
        },
    );
    let (s, _) = call(&app, "PUT", &uri, Some(body), None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (_, v) = call(
        &app,
        "GET",
        &format!("/api/v1/devices/{id}/credentials"),
        None,
        None,
    )
    .await;
    assert_eq!(v["items"][0]["username"], "cpe-SN1");
    assert!(!v.to_string().contains("s3cr3t"));
    let sealed = store.get_credential(id, "acs_auth").await.unwrap().unwrap();
    assert_eq!(
        secrets
            .open_credential(id, &sealed.ciphertext, &sealed.nonce)
            .unwrap(),
        b"s3cr3t"
    );
    let (s, _) = call(
        &app,
        "PUT",
        &format!("/api/v1/devices/{id}/credentials/bogus"),
        Some(json!({"username": "a", "password": "b"})),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // Task passwords: encrypted at rest, masked in output; refused without key.
    let task = json!({"kind": "download", "payload": {"url": "http://f/x", "file_type": "1 Firmware Upgrade Image", "password": "hunter2"}});
    let tasks = format!("/api/v1/devices/{id}/tasks");
    let (s, _) = call(&plain_app, "POST", &tasks, Some(task.clone()), None).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    let (s, v) = call(&app, "POST", &tasks, Some(task), None).await;
    assert_eq!(
        (s, v["payload"]["password"].as_str()),
        (StatusCode::CREATED, Some("********"))
    );
    let stored = store
        .get_task(v["id"].as_str().unwrap().parse().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert!(
        stored.payload["password"]
            .as_str()
            .unwrap()
            .starts_with("enc:v2:")
    );
    // Bound to the task: opens as this task's only.
    let mut opened = stored.payload.clone();
    secrets
        .decrypt_fields(
            &mut opened,
            &dhonomos_core::secrets::task_context(stored.id),
        )
        .unwrap();
    assert_eq!(opened["password"], "hunter2");
    let mut elsewhere = stored.payload.clone();
    assert!(
        secrets
            .decrypt_fields(
                &mut elsewhere,
                &dhonomos_core::secrets::task_context(Uuid::now_v7())
            )
            .is_err()
    );

    let (s, _) = call(&app, "DELETE", &uri, None, None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _) = call(&app, "DELETE", &uri, None, None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn supported_model_and_usp_only_tasks() {
    let (_c, store, app, id) = setup(None).await;
    let uri = format!("/api/v1/devices/{id}/supported-model");
    let (s, _) = call(&app, "GET", &uri, None, None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let model = json!({ "objects": [{ "path": "Device.", "commands": [{ "name": "Reboot()" }] }] });
    let mid = store
        .put_supported_model("fp-1", "usp", &model)
        .await
        .unwrap();
    assert_eq!(
        store
            .put_supported_model("fp-1", "usp", &json!({}))
            .await
            .unwrap(),
        mid,
        "first model per fingerprint wins"
    );
    store.link_supported_model(id, mid).await.unwrap();
    let (s, v) = call(&app, "GET", &uri, None, None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["fingerprint"], "fp-1");
    assert_eq!(v["objects"][0]["commands"][0]["name"], "Reboot()");

    // Fixture device = CWMP; Operate = USP only.
    let (s, v) = call(
        &app,
        "POST",
        &format!("/api/v1/devices/{id}/tasks"),
        Some(json!({ "kind": "operate", "payload": { "command": "Device.IP.Diagnostics.IPPing()" } })),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
}

/// `POST /devices/{id}/data-model/refresh`: operators only, USP Agents only.
/// No USP service running (none in these tests) -> cached models dropped,
/// refresh queued for the next Agent connection.
#[tokio::test]
async fn data_model_refresh_discards_the_cached_model() {
    let admin = "admin-token";
    let (_c, store, app, cwmp) = setup(Some(admin)).await;
    let refresh = |id: Uuid| format!("/api/v1/devices/{id}/data-model/refresh");
    let usp = store
        .preregister_usp_device(DEFAULT_TENANT, "os::refresh-agent", &[])
        .await
        .unwrap()
        .id;
    store
        .update_device_info(
            usp,
            &dhonomos_store::DeviceInfo {
                software_version: Some("1.0".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let fingerprint =
        dhonomos_core::usp::firmware_fingerprint(&store.get_device(usp).await.unwrap().unwrap())
            .unwrap();
    let model = json!({ "objects": [{ "path": "Device." }] });
    let mid = store
        .put_supported_model(&fingerprint, "usp", &model)
        .await
        .unwrap();
    store.link_supported_model(usp, mid).await.unwrap();
    // Device's own copy goes too.
    let own = dhonomos_store::device_fingerprint(usp);
    store
        .replace_supported_model(&own, "usp", &model)
        .await
        .unwrap();
    let supported = format!("/api/v1/devices/{usp}/supported-model");
    assert_eq!(
        call(&app, "GET", &supported, None, Some(admin)).await.0,
        StatusCode::OK
    );

    // Roles: viewer refused, operator allowed.
    let mut keys = Vec::new();
    for role in ["viewer", "operator"] {
        let (s, k) = call(
            &app,
            "POST",
            "/api/v1/api-keys",
            Some(json!({ "name": role, "role": role })),
            Some(admin),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED, "{k}");
        keys.push(k["key"].as_str().unwrap().to_owned());
    }
    let (viewer, operator) = (keys[0].as_str(), keys[1].as_str());
    let (s, v) = call(&app, "POST", &refresh(usp), None, Some(viewer)).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    assert_eq!(
        call(&app, "GET", &supported, None, Some(admin)).await.0,
        StatusCode::OK,
        "a refused request changes nothing"
    );

    // Unknown device + CWMP device (no data model to read from an Agent).
    let (s, _) = call(&app, "POST", &refresh(Uuid::now_v7()), None, Some(operator)).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, v) = call(&app, "POST", &refresh(cwmp), None, Some(operator)).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert_eq!(
        v["error"],
        "only USP Agents have a supported data model to refresh"
    );

    // Agent not connected -> both models dropped, next connection reads it.
    let (s, v) = call(&app, "POST", &refresh(usp), None, Some(operator)).await;
    assert_eq!(
        (s, v["status"].as_str()),
        (StatusCode::ACCEPTED, Some("queued")),
        "{v}"
    );
    assert_eq!(store.supported_model_id(&fingerprint).await.unwrap(), None);
    assert_eq!(store.supported_model_id(&own).await.unwrap(), None);
    assert_eq!(
        call(&app, "GET", &supported, None, Some(admin)).await.0,
        StatusCode::NOT_FOUND
    );
    let (_, audit) = call(
        &app,
        "GET",
        "/api/v1/audit?action=device.data_model.refresh",
        None,
        Some(admin),
    )
    .await;
    assert_eq!(audit["items"].as_array().unwrap().len(), 1, "{audit}");
    assert_eq!(audit["items"][0]["target_id"], usp.to_string());
    assert_eq!(audit["items"][0]["detail"]["status"], "queued");
}

#[tokio::test]
async fn usp_agent_certificates() {
    let (_c, store, plain_app, cwmp_id) = setup(None).await;
    let usp = store
        .preregister_usp_device(DEFAULT_TENANT, "os::cert-agent", &[])
        .await
        .unwrap()
        .id;
    let uri = |id: Uuid| format!("/api/v1/devices/{id}/certificate");
    let (s, _) = call(&plain_app, "POST", &uri(usp), None, None).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "issuance is off without a CA");

    let ca = std::sync::Arc::new(dhonomos_pki::Ca::generate("Test CA").unwrap());
    let app = router(
        store.clone(),
        ApiConfig {
            tenant_id: DEFAULT_TENANT,
            ca: Some(ca.clone()),
            presets: Default::default(),
            presets_in_db: false,
            alarm_rules: Default::default(),
            secure_cookies: false,
            session_hours: 0.into(),
            session_idle_minutes: 0.into(),
            trusted_proxies: Vec::new(),
            public_url: None,
            ..ApiConfig::default()
        },
    );
    let (s, v) = call(&app, "POST", &uri(usp), Some(json!({ "days": 30 })), None).await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    assert!(v["private_key"].as_str().unwrap().contains("PRIVATE KEY"));
    assert_eq!(
        v["client_pem"].as_str().unwrap(),
        format!(
            "{}{}",
            v["certificate"].as_str().unwrap(),
            v["private_key"].as_str().unwrap()
        ),
        "ready to install: the certificate, then the key"
    );
    assert_eq!(v["ca_certificate"], ca.cert_pem());
    let pem = v["certificate"].as_str().unwrap();
    let (_, der) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).unwrap();
    assert_eq!(
        dhonomos_pki::endpoint_ids(&der.contents),
        vec!["os::cert-agent"]
    );
    let (_, audit) = call(&app, "GET", "/api/v1/audit", None, None).await;
    assert_eq!(audit["items"][0]["action"], "device.certificate.issue");
    assert!(!audit.to_string().contains("PRIVATE KEY"));

    // From a CSR -> no key returned.
    let key = rcgen::KeyPair::generate().unwrap();
    let csr = rcgen::CertificateParams::new(Vec::<String>::new())
        .unwrap()
        .serialize_request(&key)
        .unwrap()
        .pem()
        .unwrap();
    let (s, v) = call(
        &app,
        "POST",
        &uri(usp),
        Some(json!({ "csr": csr, "days": 365 })),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    assert!(v["private_key"].is_null());
    assert!(v["client_pem"].is_null(), "no key, nothing to install");
    let (s, _) = call(
        &app,
        "POST",
        &uri(usp),
        Some(json!({ "csr": "junk" })),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    for days in [0, 3651] {
        let (s, _) = call(&app, "POST", &uri(usp), Some(json!({ "days": days })), None).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    }
    let (s, _) = call(&app, "POST", &uri(cwmp_id), None, None).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "CWMP devices get none");

    // Issued certificates listed (newest first), without keys.
    let list = format!("/api/v1/devices/{usp}/certificates");
    let (_, v) = call(&app, "GET", &list, None, None).await;
    let items = v["items"].as_array().unwrap().clone();
    assert_eq!(items.len(), 2, "{v}");
    assert_eq!(
        (
            items[0]["from_csr"].as_bool(),
            items[1]["from_csr"].as_bool()
        ),
        (Some(true), Some(false))
    );
    assert!(items.iter().all(|c| c["state"] == "valid"));
    assert_eq!(items[1]["sha256"].as_str().unwrap().len(), 64);
    assert!(!v.to_string().contains("PRIVATE KEY"));
    // 30-day cert about to expire; 365-day cert replaces it.
    let (_, v) = call(
        &app,
        "GET",
        "/api/v1/certificates/expiring?days=60",
        None,
        None,
    )
    .await;
    assert_eq!(
        v["items"],
        json!([]),
        "a newer certificate replaces it: {v}"
    );
    let (_, v) = call(
        &app,
        "GET",
        "/api/v1/certificates/expiring?days=400",
        None,
        None,
    )
    .await;
    assert_eq!(v["items"][0]["device"], "os::cert-agent", "{v}");

    let cert = items[0]["id"].as_str().unwrap();
    let revoke = format!("/api/v1/devices/{usp}/certificates/{cert}/revoke");
    let (s, v) = call(
        &app,
        "POST",
        &revoke,
        Some(json!({ "reason": "device stolen" })),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        (
            v["state"].as_str(),
            v["revoke_reason"].as_str(),
            v["revoked_by"].as_str()
        ),
        (Some("revoked"), Some("device stolen"), Some("anonymous"))
    );
    assert_eq!(
        store.revoked_fingerprints(DEFAULT_TENANT).await.unwrap(),
        vec![items[0]["sha256"].as_str().unwrap().to_owned()]
    );
    let (_, v) = call(
        &app,
        "GET",
        "/api/v1/certificates/expiring?days=400",
        None,
        None,
    )
    .await;
    assert_eq!(
        v["items"].as_array().unwrap().len(),
        1,
        "the revoked one is not expiring: {v}"
    );
    let other = format!("/api/v1/devices/{cwmp_id}/certificates/{cert}/revoke");
    let (s, _) = call(&app, "POST", &other, None, None).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "a certificate of another device");
    let (_, audit) = call(&app, "GET", "/api/v1/audit", None, None).await;
    assert_eq!(audit["items"][0]["action"], "device.certificate.revoke");
}

/// Router with a CA + admin token.
fn ca_app(store: &Store, admin: &str) -> (Router, std::sync::Arc<dhonomos_pki::Ca>) {
    let ca = std::sync::Arc::new(dhonomos_pki::Ca::generate("Test CA").unwrap());
    let app = router(
        store.clone(),
        ApiConfig {
            bearer_token: Some(admin.into()),
            tenant_id: DEFAULT_TENANT,
            ca: Some(ca.clone()),
            ..ApiConfig::default()
        },
    );
    (app, ca)
}

/// Like `call`, for non-JSON answers: status, headers, raw body.
async fn call_raw(
    app: &Router,
    method: &str,
    uri: &str,
    body: Value,
    token: &str,
) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let (status, headers) = (resp.status(), resp.headers().clone());
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, headers, bytes.to_vec())
}

/// One file of an encrypted zip.
fn unzip(zip: &[u8], name: &str, password: &str) -> Result<String, zip::result::ZipError> {
    use std::io::Read as _;
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(zip)).unwrap();
    let mut file = archive.by_name_decrypt(name, password.as_bytes())?;
    let mut text = String::new();
    file.read_to_string(&mut text).unwrap();
    Ok(text)
}

/// PEM blocks of a text: `(label, DER)`.
fn pem_blocks(text: &str) -> Vec<(String, Vec<u8>)> {
    x509_parser::pem::Pem::iter_from_buffer(text.as_bytes())
        .map(|p| {
            let p = p.unwrap();
            (p.label, p.contents)
        })
        .collect()
}

async fn api_key(app: &Router, admin: &str, role: &str, scope: Option<Value>) -> String {
    let (s, k) = call(
        app,
        "POST",
        "/api/v1/api-keys",
        Some(json!({ "name": format!("{role}-{}", Uuid::now_v7()), "role": role, "scope": scope })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{k}");
    k["key"].as_str().unwrap().to_owned()
}

/// `POST /certificates/bundle`: keys + certs for many devices in 1 encrypted zip.
/// Recorded like single issues, EndpointIDs bound, nothing secret kept.
#[tokio::test]
async fn certificate_bundle_for_many_agents() {
    let admin = "admin-token";
    let (_c, store, _plain, _cwmp) = setup(Some(admin)).await;
    let (app, ca) = ca_app(&store, admin);
    let password = "correct horse battery staple";

    // 1 pre-registered via API, never connected; 2 connected.
    // Last 2: EndpointIDs with clashing directory names.
    let (s, v) = call(
        &app,
        "POST",
        "/api/v1/devices",
        Some(json!({ "endpoint_id": "os::012345-AABBCCDDEEFF" })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    let pre = v["id"].as_str().unwrap().to_owned();
    let mut ids = vec![("os::012345-AABBCCDDEEFF".to_owned(), pre.clone())];
    for eid in ["os::dup/1", "os::dup:1"] {
        let id = store
            .upsert_usp_device(DEFAULT_TENANT, eid, None)
            .await
            .unwrap()
            .id;
        ids.push((eid.to_owned(), id.to_string()));
    }

    // Both ways to name devices, in 1 request.
    let (s, headers, zip) = call_raw(
        &app,
        "POST",
        "/api/v1/certificates/bundle",
        json!({
            "device_ids": [pre, ids[1].1],
            "endpoint_ids": ["os::dup:1"],
            "password": password,
        }),
        admin,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{}", String::from_utf8_lossy(&zip));
    assert_eq!(headers["content-type"], "application/zip");
    assert_eq!(headers["cache-control"], "no-store");
    let disposition = headers["content-disposition"].to_str().unwrap();
    assert!(
        disposition.starts_with("attachment; filename=\"usp-agent-certificates-20")
            && disposition.ends_with("Z.zip\""),
        "{disposition}"
    );

    // Opens with the password only.
    assert!(unzip(&zip, "ca.pem", "not the right password").is_err());
    assert!(unzip(&zip, "ca.pem", "").is_err());
    {
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(&zip[..])).unwrap();
        assert!(
            archive.by_name("ca.pem").is_err(),
            "no password, no content"
        );
    }
    assert_eq!(unzip(&zip, "ca.pem", password).unwrap(), ca.cert_pem());
    let readme = unzip(&zip, "README.txt", password).unwrap();
    assert!(
        readme.contains("client.pem") && readme.contains("0600"),
        "{readme}"
    );
    assert!(readme.contains("Delete this bundle"), "{readme}");

    // Manifest: 1 row per device, fingerprint of the cert in its directory.
    let manifest = unzip(&zip, "manifest.csv", password).unwrap();
    let mut rows = manifest.trim_end().split("\r\n");
    assert_eq!(
        rows.next().unwrap(),
        "endpoint_id,device_id,device_serial_number,certificate_serial,sha256_fingerprint,\
         not_before,not_after,directory"
    );
    let rows: Vec<Vec<&str>> = rows.map(|r| r.split(',').collect()).collect();
    assert_eq!(rows.len(), 3, "{manifest}");
    for (eid, id) in &ids {
        let row = rows.iter().find(|r| r[0] == eid).unwrap();
        assert_eq!(row[1], id);
        let dir = row[7];
        assert!(
            dir.chars()
                .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c)),
            "{dir}"
        );

        // client.pem: certificate, then its key (format of `obuspa -a`).
        let client = unzip(&zip, &format!("{dir}/client.pem"), password).unwrap();
        let cert_only = unzip(&zip, &format!("{dir}/cert.pem"), password).unwrap();
        let blocks = pem_blocks(&client);
        assert_eq!(
            blocks.iter().map(|b| b.0.as_str()).collect::<Vec<_>>(),
            ["CERTIFICATE", "PRIVATE KEY"],
            "{dir}"
        );
        assert!(client.starts_with(&cert_only), "cert.pem is the first part");
        assert_eq!(pem_blocks(&cert_only).len(), 1);
        let der = &blocks[0].1;
        assert_eq!(dhonomos_pki::endpoint_ids(der), [eid.as_str()]);
        assert_eq!(dhonomos_pki::fingerprint(der), row[4]);
        let (_, cert) = x509_parser::parse_x509_certificate(der).unwrap();
        let (_, ca_cert) = x509_parser::pem::parse_x509_pem(ca.cert_pem().as_bytes()).unwrap();
        let ca_cert = ca_cert.parse_x509().unwrap();
        assert_eq!(cert.issuer(), ca_cert.subject());
        // Key belongs to the certificate.
        let key = rcgen::KeyPair::from_der_and_sign_algo(
            &rustls_pki_types::PrivateKeyDer::try_from(blocks[1].1.as_slice()).unwrap(),
            &rcgen::PKCS_ECDSA_P256_SHA256,
        )
        .unwrap();
        assert_eq!(
            key.public_key_raw(),
            cert.public_key().subject_public_key.data.as_ref()
        );
        // Default: 3 years.
        let days = (cert.validity().not_after.timestamp() - cert.validity().not_before.timestamp())
            / 86_400;
        assert!((1095..=1096).contains(&days), "{days}");
    }
    let dirs: std::collections::BTreeSet<&str> = rows.iter().map(|r| r[7]).collect();
    assert_eq!(
        dirs.len(),
        3,
        "every device has its own directory: {manifest}"
    );
    assert_eq!(
        rows.iter().find(|r| r[0] == "os::dup/1").unwrap()[7],
        "os__dup_1"
    );
    assert_eq!(
        rows.iter().find(|r| r[0] == "os::dup:1").unwrap()[7],
        "os__dup_1-2"
    );

    // Recorded like single issues: listed, expiring, EndpointID bound; never a key.
    for (eid, id) in &ids {
        let (_, v) = call(
            &app,
            "GET",
            &format!("/api/v1/devices/{id}/certificates"),
            None,
            Some(admin),
        )
        .await;
        let items = v["items"].as_array().unwrap();
        assert_eq!(items.len(), 1, "{eid}: {v}");
        let row = rows.iter().find(|r| r[0] == eid).unwrap();
        assert_eq!(items[0]["sha256"], row[4]);
        assert_eq!(items[0]["serial"], row[3]);
        assert_eq!(
            (
                items[0]["state"].as_str(),
                items[0]["from_csr"].as_bool(),
                items[0]["issued_by"].as_str()
            ),
            (Some("valid"), Some(false), Some("api-token"))
        );
        assert!(!v.to_string().contains("PRIVATE KEY"));
    }
    let (_, v) = call(
        &app,
        "GET",
        "/api/v1/certificates/expiring?days=1100",
        None,
        Some(admin),
    )
    .await;
    assert_eq!(v["items"].as_array().unwrap().len(), 3, "{v}");
    let mut bound = store
        .certificate_bound_endpoints(DEFAULT_TENANT)
        .await
        .unwrap();
    bound.sort();
    assert_eq!(bound, ["os::012345-AABBCCDDEEFF", "os::dup/1", "os::dup:1"]);

    // Audit record: who, which EndpointIDs, which fingerprints; no secrets.
    let (_, audit) = call(
        &app,
        "GET",
        "/api/v1/audit?action=certificate.bundle",
        None,
        Some(admin),
    )
    .await;
    let entries = audit["items"].as_array().unwrap();
    assert_eq!(entries.len(), 1, "{audit}");
    assert_eq!(entries[0]["actor"], "api-token");
    assert_eq!(entries[0]["detail"]["count"], 3);
    let listed = entries[0]["detail"]["certificates"].as_array().unwrap();
    for (eid, _) in &ids {
        let row = rows.iter().find(|r| r[0] == eid).unwrap();
        assert!(
            listed
                .iter()
                .any(|c| c["endpoint_id"] == eid.as_str() && c["sha256"] == row[4]),
            "{eid} in {audit}"
        );
    }
    let everything = audit.to_string();
    assert!(!everything.contains("PRIVATE KEY") && !everything.contains(password));

    // Custom validity + 2nd bundle for a device that has one (nothing revoked).
    let (s, _, zip) = call_raw(
        &app,
        "POST",
        "/api/v1/certificates/bundle",
        json!({ "endpoint_ids": ["os::dup:1"], "days": 30, "password": password }),
        admin,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let manifest = unzip(&zip, "manifest.csv", password).unwrap();
    let row: Vec<&str> = manifest
        .trim_end()
        .lines()
        .nth(1)
        .unwrap()
        .split(',')
        .collect();
    let issued = time::OffsetDateTime::now_utc();
    let not_after =
        time::OffsetDateTime::parse(row[6], &time::format_description::well_known::Rfc3339)
            .unwrap();
    assert!(
        (28..=31).contains(&(not_after - issued).whole_days()),
        "{manifest}"
    );
    let (_, v) = call(
        &app,
        "GET",
        &format!("/api/v1/devices/{}/certificates", ids[2].1),
        None,
        Some(admin),
    )
    .await;
    assert_eq!(v["items"].as_array().unwrap().len(), 2);
    assert!(
        v["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|c| c["state"] == "valid")
    );
}

/// Bundles: admins without device scope only. No usable request -> nothing issued.
/// Every refusal -> no certificate, no audit record.
#[tokio::test]
async fn certificate_bundle_requests_are_checked_first() {
    let admin = "admin-token";
    let (_c, store, _plain, cwmp) = setup(Some(admin)).await;
    let (app, _ca) = ca_app(&store, admin);
    let password = "correct horse battery staple";
    let usp = store
        .preregister_usp_device(DEFAULT_TENANT, "os::checked", &[])
        .await
        .unwrap()
        .id;
    let old = store
        .preregister_usp_device(DEFAULT_TENANT, "os::retired", &[])
        .await
        .unwrap()
        .id;
    let (s, v) = call(
        &app,
        "PATCH",
        &format!("/api/v1/devices/{old}"),
        Some(json!({ "status": "retired" })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let bundle = "/api/v1/certificates/bundle";
    let nothing_issued = || {
        let (app, store) = (app.clone(), store.clone());
        async move {
            for id in [usp, old] {
                assert!(store.device_certificates(id).await.unwrap().is_empty());
            }
            let (_, audit) = call(
                &app,
                "GET",
                "/api/v1/audit?action=certificate.bundle",
                None,
                Some("admin-token"),
            )
            .await;
            assert_eq!(audit["items"], json!([]));
        }
    };

    // Roles: viewer + operator (also with device scope) refused.
    let viewer = api_key(&app, admin, "viewer", None).await;
    let operator = api_key(&app, admin, "operator", None).await;
    let scoped = api_key(&app, admin, "operator", Some(json!({ "tags": ["east"] }))).await;
    let body = json!({ "device_ids": [usp], "password": password });
    for token in [&viewer, &operator, &scoped] {
        let (s, v) = call(&app, "POST", bundle, Some(body.clone()), Some(token)).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    }
    let (s, _) = call(&app, "POST", bundle, Some(body.clone()), None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    // Admin cannot have a device scope -> fleet-wide check never meets one.
    let (s, v) = call(
        &app,
        "POST",
        "/api/v1/api-keys",
        Some(json!({ "name": "x", "role": "admin", "scope": { "tags": ["east"] } })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    nothing_issued().await;

    // Unusable passwords, validity, sizes.
    let unusable = |label: &'static str, body: Value| {
        let app = app.clone();
        async move {
            let (s, v) = call(&app, "POST", bundle, Some(body), Some("admin-token")).await;
            assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{label}: {v}");
            v["error"].as_str().unwrap().to_owned()
        }
    };
    let e = unusable(
        "short password",
        json!({ "device_ids": [usp], "password": "eleven char" }),
    )
    .await;
    assert!(e.contains("at least 12 characters"), "{e}");
    assert!(!e.contains("eleven char"), "the password is not echoed");
    unusable("no password", json!({ "device_ids": [usp] })).await;
    unusable(
        "huge password",
        json!({ "device_ids": [usp], "password": "x".repeat(1025) }),
    )
    .await;
    for days in [0, 3651] {
        unusable(
            "days",
            json!({ "device_ids": [usp], "days": days, "password": password }),
        )
        .await;
    }
    unusable("no devices", json!({ "password": password })).await;
    unusable(
        "unknown field",
        json!({ "device_ids": [usp], "password": password, "format": "tar" }),
    )
    .await;
    let e = unusable(
        "too many",
        json!({
            "device_ids": (0..1001).map(|_| Uuid::now_v7()).collect::<Vec<_>>(),
            "password": password,
        }),
    )
    .await;
    assert!(e.contains("at most 1000"), "{e}");
    let e = unusable(
        "too many targets",
        json!({
            "targets": (0..1001).map(|i| json!({ "endpoint_id": format!("os::t{i}") })).collect::<Vec<_>>(),
            "create_missing": true,
            "password": password,
        }),
    )
    .await;
    assert!(e.contains("at most 1000"), "{e}");
    let e = unusable(
        "too many, in both lists",
        json!({
            "device_ids": (0..500).map(|_| Uuid::now_v7()).collect::<Vec<_>>(),
            "endpoint_ids": (0..501).map(|i| format!("os::{i}")).collect::<Vec<_>>(),
            "password": password,
        }),
    )
    .await;
    assert!(e.contains("at most 1000"), "{e}");
    // Body over the limit -> refused as such.
    let (s, _, _) = call_raw(
        &app,
        "POST",
        bundle,
        json!({ "endpoint_ids": [ "x".repeat(600 << 10) ], "password": password }),
        admin,
    )
    .await;
    assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE);
    nothing_issued().await;

    // Devices that cannot get one, named at once; the valid one gets nothing either.
    // CWMP device is fine (= `os::001122-SN1`).
    // Request fails -> not registered as that Agent either.
    let stranger = Uuid::now_v7();
    let e = unusable(
        "bad targets",
        json!({
            "device_ids": [usp, stranger, cwmp, old],
            "endpoint_ids": ["os::nobody", "os::checked", "os::retired"],
            "password": password,
        }),
    )
    .await;
    for expected in [
        format!("device {stranger} not found"),
        format!("device {old} is retired"),
        "endpoint_id \"os::nobody\" not found".to_owned(),
        "endpoint_id \"os::checked\" duplicates another entry".to_owned(),
        "endpoint_id \"os::retired\" is retired".to_owned(),
    ] {
        assert!(e.contains(&expected), "{expected} in {e}");
    }
    assert!(!e.contains(&cwmp.to_string()), "{e}");
    assert!(e.starts_with("no certificates were issued"), "{e}");
    nothing_issued().await;
    assert!(
        store
            .find_usp_device(DEFAULT_TENANT, "os::001122-SN1")
            .await
            .unwrap()
            .is_none(),
        "a refused request registers nothing"
    );

    // Document describes it, for admins.
    let (_, doc) = call(&app, "GET", "/api/v1/openapi.json", None, None).await;
    let op = &doc["paths"]["/api/v1/certificates/bundle"]["post"];
    assert_eq!(op["operationId"], "issue_certificate_bundle", "{op}");
    assert!(
        op["description"].as_str().unwrap().contains("`admin` role"),
        "{op}"
    );
    assert!(op["responses"]["200"]["content"]["application/zip"].is_object());
    assert!(doc["components"]["schemas"]["BundleRequest"].is_object());

    // No CA -> endpoint off, like the single issue.
    let plain = router(
        store.clone(),
        ApiConfig {
            bearer_token: Some(admin.into()),
            tenant_id: DEFAULT_TENANT,
            ..ApiConfig::default()
        },
    );
    let (s, _) = call(&plain, "POST", bundle, Some(body), Some(admin)).await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // Clean request after all those -> goes through.
    let (s, _, zip) = call_raw(
        &app,
        "POST",
        bundle,
        json!({ "endpoint_ids": ["os::checked"], "password": password }),
        admin,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert!(
        unzip(&zip, "manifest.csv", password)
            .unwrap()
            .contains("os::checked")
    );
    assert_eq!(store.device_certificates(usp).await.unwrap().len(), 1);
    assert!(store.device_certificates(old).await.unwrap().is_empty());
}

/// `POST /devices/bulk`: every entry reported, dry run writes nothing,
/// existing devices left alone, only operators may pre-register.
#[tokio::test]
async fn bulk_preregistration_reports_every_entry() {
    let admin = "admin-token";
    let (_c, store, app, cwmp) = setup(Some(admin)).await;
    let bulk = "/api/v1/devices/bulk";
    store
        .preregister_usp_device(DEFAULT_TENANT, "os::known-1", &["old".into()])
        .await
        .unwrap();
    let devices = json!([
        { "endpoint_id": " os::B01408-AAA1 " },
        { "oui": "b01408", "serial_number": " AAA2 " },
        { "endpoint_id": "os::B01408-AAA2" },
        { "endpoint_id": "os::known-1" },
        { "endpoint_id": "no-scheme" },
        { "endpoint_id": "os::a/b" },
        { "oui": "B0140", "serial_number": "S1" },
        { "oui": "B01408", "serial_number": "has space" },
        { "oui": "B01408" },
        {},
        { "endpoint_id": "os::x", "serial_number": "S1" },
        { "oui": "00AA00", "product_class": "Box", "serial_number": "C-1" },
        { "oui": "00AA00", "product_class": "", "serial_number": "C-2" },
        { "oui": "001122", "product_class": "Box", "serial_number": "SN1" },
        { "oui": "00AA00", "product_class": "Box" },
        { "endpoint_id": "os::x", "product_class": "Box" },
    ]);
    let count = || {
        let app = app.clone();
        async move {
            let (_, v) = call(&app, "GET", "/api/v1/devices", None, Some(admin)).await;
            v["total"].as_i64().unwrap()
        }
    };
    let before = count().await;
    assert_eq!(before, 2, "the CWMP device of the setup and os::known-1");

    // Dry run: same report, nothing written, nothing audited.
    let (s, dry) = call(
        &app,
        "POST",
        bulk,
        Some(json!({ "devices": devices, "tags": ["lte", " lab "], "dry_run": true })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{dry}");
    assert_eq!(dry["dry_run"], true);
    assert_eq!(
        (
            &dry["total"],
            &dry["added"],
            &dry["exists"],
            &dry["invalid"]
        ),
        (&json!(16), &json!(4), &json!(2), &json!(10)),
        "{dry}"
    );
    assert_eq!(count().await, before, "a dry run writes nothing");
    let (_, audit) = call(
        &app,
        "GET",
        "/api/v1/audit?action=device.preregister_bulk",
        None,
        Some(admin),
    )
    .await;
    assert_eq!(audit["items"], json!([]));

    let row = |report: &Value, i: usize| report["results"][i].clone();
    let status = |report: &Value| {
        report["results"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["status"].as_str().unwrap().to_owned())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        status(&dry),
        [
            "added", "added", "invalid", "exists", "invalid", "invalid", "invalid", "invalid",
            "invalid", "invalid", "invalid", "added", "added", "exists", "invalid", "invalid"
        ]
    );
    assert_eq!(row(&dry, 0)["endpoint_id"], "os::B01408-AAA1");
    assert_eq!(row(&dry, 0)["protocol"], "usp");
    assert!(row(&dry, 0)["device_id"].is_null(), "nothing exists yet");
    assert_eq!(
        row(&dry, 1)["endpoint_id"],
        "os::B01408-AAA2",
        "OUI and serial number: the OUI in capitals, both trimmed"
    );
    assert_eq!(row(&dry, 2)["index"], 2);
    assert!(
        row(&dry, 2)["error"]
            .as_str()
            .unwrap()
            .contains("duplicates an earlier entry"),
        "{dry}"
    );
    assert_eq!(row(&dry, 3)["device_status"], "active");
    assert!(row(&dry, 3)["device_id"].is_string());
    for (i, expected) in [
        (4, "endpoint_id must look like"),
        (5, "endpoint_id must look like"),
        (6, "oui must be 6 hexadecimal digits"),
        (7, "serial_number must be"),
        (8, "endpoint_id, or oui and serial_number, is required"),
        (9, "endpoint_id, or oui and serial_number, is required"),
        (10, "not both"),
        (14, "oui and serial_number are required"),
        (15, "not both"),
    ] {
        let r = row(&dry, i);
        assert!(r["error"].as_str().unwrap().contains(expected), "{i}: {r}");
        assert!(
            r["protocol"].is_null(),
            "an invalid entry names nothing: {r}"
        );
    }
    assert_eq!(
        (
            row(&dry, 11)["protocol"].as_str(),
            row(&dry, 11)["oui"].as_str()
        ),
        (Some("cwmp"), Some("00AA00"))
    );
    assert_eq!(
        row(&dry, 12)["product_class"],
        "",
        "CWMP without a product class"
    );
    assert_eq!(row(&dry, 13)["status"], "exists");
    assert_eq!(row(&dry, 13)["device_id"], json!(cwmp));

    // Not a dry run.
    let (s, real) = call(
        &app,
        "POST",
        bulk,
        Some(json!({ "devices": devices, "tags": ["lte", " lab "] })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{real}");
    assert_eq!(real["dry_run"], false);
    assert_eq!(status(&real), status(&dry), "the dry run said what happens");
    assert_eq!(count().await, before + 4);
    let created = row(&real, 0)["device_id"].as_str().unwrap().to_owned();
    let (_, d) = call(
        &app,
        "GET",
        &format!("/api/v1/devices/{created}"),
        None,
        Some(admin),
    )
    .await;
    assert_eq!(
        (
            d["protocol"].as_str(),
            d["endpoint_id"].as_str(),
            d["status"].as_str()
        ),
        (Some("usp"), Some("os::B01408-AAA1"), Some("active"))
    );
    assert_eq!(d["tags"], json!(["lab", "lte"]), "tags trimmed and sorted");
    let (_, v) = call(&app, "GET", "/api/v1/devices?q=C-1", None, Some(admin)).await;
    assert_eq!(v["items"][0]["protocol"], "cwmp");
    assert_eq!(v["items"][0]["tags"], json!(["lab", "lte"]));
    // Existing devices keep what they had.
    let (_, v) = call(&app, "GET", "/api/v1/devices?q=known-1", None, Some(admin)).await;
    assert_eq!(v["items"][0]["tags"], json!(["old"]));
    assert_eq!(row(&real, 3)["device_id"], v["items"][0]["id"]);

    let (_, audit) = call(
        &app,
        "GET",
        "/api/v1/audit?action=device.preregister_bulk",
        None,
        Some(admin),
    )
    .await;
    let entries = audit["items"].as_array().unwrap();
    assert_eq!(entries.len(), 1, "{audit}");
    assert_eq!(entries[0]["detail"]["count"], 4);
    assert_eq!(entries[0]["detail"]["exists"], 2);
    assert_eq!(entries[0]["actor"], "api-token");

    // Again: all exist now -> nothing more audited.
    let (_, again) = call(
        &app,
        "POST",
        bulk,
        Some(json!({ "devices": devices })),
        Some(admin),
    )
    .await;
    assert_eq!(
        (&again["added"], &again["exists"], &again["invalid"]),
        (&json!(0), &json!(6), &json!(10))
    );
    assert_eq!(count().await, before + 4);
    let (_, audit) = call(
        &app,
        "GET",
        "/api/v1/audit?action=device.preregister_bulk",
        None,
        Some(admin),
    )
    .await;
    assert_eq!(audit["items"].as_array().unwrap().len(), 1);

    // Unusable requests as a whole.
    for (label, body) in [
        ("empty", json!({ "devices": [] })),
        ("no devices", json!({})),
        (
            "unknown field",
            json!({ "devices": [{ "endpoint_id": "os::z", "x": 1 }] }),
        ),
        (
            "unknown request field",
            json!({ "devices": [{ "endpoint_id": "os::z" }], "force": true }),
        ),
        (
            "bad tag",
            json!({ "devices": [{ "endpoint_id": "os::z" }], "tags": [""] }),
        ),
        (
            "too many tags",
            json!({ "devices": [{ "endpoint_id": "os::z" }], "tags": (0..51).map(|i| format!("t{i}")).collect::<Vec<_>>() }),
        ),
        (
            "too many",
            json!({ "devices": (0..10_001).map(|i| json!({ "endpoint_id": format!("os::n{i}") })).collect::<Vec<_>>() }),
        ),
    ] {
        let (s, v) = call(&app, "POST", bulk, Some(body), Some(admin)).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{label}: {v}");
    }
    assert_eq!(count().await, before + 4, "nothing was added by those");

    // Limit = 10,000, in 1 request.
    let many: Vec<Value> = (0..10_000)
        .map(|i| json!({ "endpoint_id": format!("os::many-{i}") }))
        .collect();
    let (s, v) = call(
        &app,
        "POST",
        bulk,
        Some(json!({ "devices": many })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!((&v["added"], &v["exists"]), (&json!(10_000), &json!(0)));
    assert_eq!(count().await, before + 4 + 10_000);

    // Roles: operator allowed; viewer, scoped account, anonymous refused.
    let viewer = api_key(&app, admin, "viewer", None).await;
    let operator = api_key(&app, admin, "operator", None).await;
    let scoped = api_key(&app, admin, "operator", Some(json!({ "tags": ["east"] }))).await;
    let body = json!({ "devices": [{ "endpoint_id": "os::by-operator" }], "tags": ["ops"] });
    for token in [&viewer, &scoped] {
        let (s, v) = call(&app, "POST", bulk, Some(body.clone()), Some(token)).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    }
    let (s, _) = call(&app, "POST", bulk, Some(body.clone()), None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, v) = call(&app, "POST", bulk, Some(body), Some(&operator)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["added"], 1);
    let (_, audit) = call(
        &app,
        "GET",
        "/api/v1/audit?action=device.preregister_bulk&actor=key:operator",
        None,
        Some(admin),
    )
    .await;
    assert!(audit["items"].as_array().is_some(), "{audit}");

    let (_, doc) = call(&app, "GET", "/api/v1/openapi.json", None, None).await;
    let op = &doc["paths"]["/api/v1/devices/bulk"]["post"];
    assert_eq!(op["operationId"], "preregister_devices", "{op}");
    assert!(
        op["description"]
            .as_str()
            .unwrap()
            .contains("`operator` role")
    );
    assert!(doc["components"]["schemas"]["BulkRequest"].is_object());
    assert!(doc["components"]["schemas"]["BulkReport"].is_object());
}

/// Zip manifest as `(endpoint_id, device_id)` rows.
fn manifest_rows(zip: &[u8], password: &str) -> Vec<(String, String)> {
    let manifest = unzip(zip, "manifest.csv", password).unwrap();
    manifest
        .trim_end()
        .split("\r\n")
        .skip(1)
        .map(|r| {
            let cells: Vec<&str> = r.split(',').collect();
            (cells[0].to_owned(), cells[1].to_owned())
        })
        .collect()
}

/// Bundle for never-connected devices: named by EndpointID or OUI + serial number.
/// Registered together with their certs, only when the whole request is good.
#[tokio::test]
async fn certificate_bundle_for_devices_that_never_connected() {
    let admin = "admin-token";
    let (_c, store, _plain, _cwmp) = setup(Some(admin)).await;
    let (app, _ca) = ca_app(&store, admin);
    let password = "correct horse battery staple";
    let bundle = "/api/v1/certificates/bundle";
    let known = store
        .preregister_usp_device(DEFAULT_TENANT, "os::B01408-KNOWN", &["kept".into()])
        .await
        .unwrap()
        .id;
    let exists = |eid: &'static str| {
        let store = store.clone();
        async move {
            store
                .find_usp_device(DEFAULT_TENANT, eid)
                .await
                .unwrap()
                .is_some()
        }
    };
    let audits = || {
        let app = app.clone();
        async move {
            let (_, v) = call(
                &app,
                "GET",
                "/api/v1/audit?action=certificate.bundle",
                None,
                Some("admin-token"),
            )
            .await;
            v["items"].as_array().unwrap().len()
        }
    };

    // No `create_missing` -> Agents must exist, nothing made.
    let body = json!({
        "targets": [
            { "oui": "b01408", "serial_number": "LTE-1" },
            { "endpoint_id": "os::raw-1" },
            { "oui": "B01408", "serial_number": "KNOWN" },
        ],
        "password": password,
    });
    let (s, v) = call(&app, "POST", bundle, Some(body.clone()), Some(admin)).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    let e = v["error"].as_str().unwrap();
    assert!(e.contains("target 1 (\"b01408 LTE-1\") not found"), "{e}");
    assert!(e.contains("target 2 (\"os::raw-1\") not found"), "{e}");
    assert!(!e.contains("target 3"), "the existing Agent is fine: {e}");
    assert!(!exists("os::B01408-LTE-1").await && !exists("os::raw-1").await);

    // 1 bad entry -> all refused, good ones not registered.
    let mut bad = body.clone();
    bad["create_missing"] = json!(true);
    bad["targets"]
        .as_array_mut()
        .unwrap()
        .push(json!({ "oui": "XYZ", "serial_number": "S" }));
    bad["targets"]
        .as_array_mut()
        .unwrap()
        .push(json!({ "endpoint_id": "os::a/b" }));
    bad["targets"]
        .as_array_mut()
        .unwrap()
        .push(json!({ "endpoint_id": "os::raw-1", "oui": "B01408" }));
    let (s, v) = call(&app, "POST", bundle, Some(bad), Some(admin)).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    let e = v["error"].as_str().unwrap();
    assert!(e.contains("oui must be 6 hexadecimal digits"), "{e}");
    assert!(e.contains("endpoint_id must look like"), "{e}");
    assert!(e.contains("not both"), "{e}");
    assert!(!exists("os::B01408-LTE-1").await && !exists("os::raw-1").await);
    // Bad tag -> refused before anything is done, too.
    let mut bad_tag = body.clone();
    bad_tag["create_missing"] = json!(true);
    bad_tag["tags"] = json!([""]);
    let (s, _) = call(&app, "POST", bundle, Some(bad_tag), Some(admin)).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(!exists("os::B01408-LTE-1").await);
    assert_eq!(audits().await, 0);

    // Good: missing Agents registered with the tags, existing one used.
    let mut good = body;
    good["create_missing"] = json!(true);
    good["tags"] = json!(["factory", "batch-1"]);
    let (s, headers, zip) = call_raw(&app, "POST", bundle, good.clone(), admin).await;
    assert_eq!(s, StatusCode::OK, "{}", String::from_utf8_lossy(&zip));
    assert_eq!(headers["x-certificates-issued"], "3");
    assert_eq!(headers["x-devices-created"], "2");
    let rows = manifest_rows(&zip, password);
    assert_eq!(
        rows.iter().map(|r| r.0.as_str()).collect::<Vec<_>>(),
        ["os::B01408-KNOWN", "os::B01408-LTE-1", "os::raw-1"]
    );
    assert_eq!(
        rows[0].1,
        known.to_string(),
        "the Agent that existed is used"
    );
    for (eid, id) in &rows {
        let (_, d) = call(
            &app,
            "GET",
            &format!("/api/v1/devices/{id}"),
            None,
            Some(admin),
        )
        .await;
        assert_eq!(d["endpoint_id"], eid.as_str(), "{d}");
        assert_eq!(d["protocol"], "usp");
        let expected = if eid == "os::B01408-KNOWN" {
            json!(["kept"])
        } else {
            json!(["batch-1", "factory"])
        };
        assert_eq!(d["tags"], expected, "{eid}");
        let certs = store
            .device_certificates(id.parse().unwrap())
            .await
            .unwrap();
        assert_eq!(certs.len(), 1, "{eid}");
    }
    let mut bound = store
        .certificate_bound_endpoints(DEFAULT_TENANT)
        .await
        .unwrap();
    bound.sort();
    assert_eq!(bound, ["os::B01408-KNOWN", "os::B01408-LTE-1", "os::raw-1"]);
    let (_, audit) = call(
        &app,
        "GET",
        "/api/v1/audit?action=certificate.bundle",
        None,
        Some(admin),
    )
    .await;
    let detail = &audit["items"][0]["detail"];
    assert_eq!(
        (&detail["count"], &detail["created"]),
        (&json!(3), &json!(2))
    );
    let created = detail["created_devices"].as_array().unwrap();
    assert_eq!(created.len(), 2, "{detail}");
    for eid in ["os::B01408-LTE-1", "os::raw-1"] {
        assert!(created.iter().any(|d| d["endpoint_id"] == eid), "{detail}");
    }
    assert!(!audit.to_string().contains("PRIVATE KEY"));

    // Same request again -> nothing created, same Agents.
    let (s, headers, zip) = call_raw(&app, "POST", bundle, good, admin).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(headers["x-devices-created"], "0");
    let again = manifest_rows(&zip, password);
    assert_eq!(
        again.iter().map(|r| &r.1).collect::<Vec<_>>(),
        rows.iter().map(|r| &r.1).collect::<Vec<_>>()
    );
    let (_, v) = call(
        &app,
        "GET",
        "/api/v1/devices?protocol=usp",
        None,
        Some(admin),
    )
    .await;
    assert_eq!(v["total"], 3, "three Agents, none made twice: {v}");
}

/// CWMP device -> certificate for the Agent it stands for (`os::<OUI>-<serial>`).
#[tokio::test]
async fn cwmp_devices_get_certificates_for_the_agent_they_stand_for() {
    let admin = "admin-token";
    let (_c, store, _plain, cwmp) = setup(Some(admin)).await;
    let (app, _ca) = ca_app(&store, admin);
    let password = "correct horse battery staple";
    let bundle = "/api/v1/certificates/bundle";
    // Setup CWMP device: OUI 001122, serial SN1; give it tags.
    let (s, v) = call(
        &app,
        "PATCH",
        &format!("/api/v1/devices/{cwmp}"),
        Some(json!({ "tags": ["east", "lab"] })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");

    let (s, headers, zip) = call_raw(
        &app,
        "POST",
        bundle,
        json!({ "device_ids": [cwmp], "password": password }),
        admin,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{}", String::from_utf8_lossy(&zip));
    assert_eq!(headers["x-devices-created"], "1");
    let rows = manifest_rows(&zip, password);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].0, "os::001122-SN1");
    assert_ne!(rows[0].1, cwmp.to_string(), "the Agent is its own device");
    let (_, agent) = call(
        &app,
        "GET",
        &format!("/api/v1/devices/{}", rows[0].1),
        None,
        Some(admin),
    )
    .await;
    assert_eq!(
        (agent["protocol"].as_str(), agent["tags"].clone()),
        (Some("usp"), json!(["east", "lab"])),
        "the CWMP device's tags are copied"
    );
    assert_eq!(
        store.device_certificates(cwmp).await.unwrap().len(),
        0,
        "the certificate belongs to the Agent"
    );
    // CWMP device still there, unchanged.
    let (_, c) = call(
        &app,
        "GET",
        &format!("/api/v1/devices/{cwmp}"),
        None,
        Some(admin),
    )
    .await;
    assert_eq!(
        (c["protocol"].as_str(), c["status"].as_str()),
        (Some("cwmp"), Some("active"))
    );

    // Again: Agent exists now -> used, not made twice.
    let (s, headers, zip) = call_raw(
        &app,
        "POST",
        bundle,
        json!({ "device_ids": [cwmp], "password": password }),
        admin,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(headers["x-devices-created"], "0");
    assert_eq!(manifest_rows(&zip, password)[0].1, rows[0].1);
    let (_, v) = call(
        &app,
        "GET",
        "/api/v1/devices?protocol=usp",
        None,
        Some(admin),
    )
    .await;
    assert_eq!(v["total"], 1);

    // CWMP device + its Agent = 1 device.
    let (s, v) = call(
        &app,
        "POST",
        bundle,
        Some(json!({ "device_ids": [cwmp, rows[0].1], "password": password })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        v["error"]
            .as_str()
            .unwrap()
            .contains("duplicates another entry")
    );

    // Refused: CWMP device whose serial cannot go into an EndpointID; retired device.
    let odd = store
        .preregister_cwmp_device(
            DEFAULT_TENANT,
            &CwmpIdentity {
                oui: "00AA00".into(),
                product_class: "Box".into(),
                serial_number: "S N/1".into(),
            },
            &[],
        )
        .await
        .unwrap()
        .id;
    let gone = store
        .preregister_cwmp_device(
            DEFAULT_TENANT,
            &CwmpIdentity {
                oui: "00AA00".into(),
                product_class: "Box".into(),
                serial_number: "GONE".into(),
            },
            &[],
        )
        .await
        .unwrap()
        .id;
    store
        .set_device_status(DEFAULT_TENANT, gone, "retired")
        .await
        .unwrap();
    let (s, v) = call(
        &app,
        "POST",
        bundle,
        Some(json!({ "device_ids": [odd, gone], "password": password })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    let e = v["error"].as_str().unwrap();
    assert!(
        e.contains(&format!("device {odd} cannot be given an EndpointID")),
        "{e}"
    );
    assert!(e.contains(&format!("device {gone} is retired")), "{e}");
    assert!(
        store
            .find_usp_device(DEFAULT_TENANT, "os::00AA00-GONE")
            .await
            .unwrap()
            .is_none()
    );
}

/// Filter names the devices: all matches, retired left out, max 1,000.
#[tokio::test]
async fn certificate_bundle_for_the_devices_a_filter_matches() {
    let admin = "admin-token";
    let (_c, store, _plain, cwmp) = setup(Some(admin)).await;
    let (app, _ca) = ca_app(&store, admin);
    let password = "correct horse battery staple";
    let bundle = "/api/v1/certificates/bundle";
    let (s, v) = call(
        &app,
        "POST",
        "/api/v1/devices/bulk",
        Some(json!({
            "devices": [
                { "endpoint_id": "os::batch-a" },
                { "endpoint_id": "os::batch-b" },
                { "endpoint_id": "os::batch-c" },
                { "endpoint_id": "os::other" },
            ],
            "tags": ["batch"],
        })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let id_of = |i: usize| v["results"][i]["device_id"].as_str().unwrap().to_owned();
    // `other`: no tag; `batch-c`: retired.
    let (s, _) = call(
        &app,
        "PATCH",
        &format!("/api/v1/devices/{}", id_of(3)),
        Some(json!({ "tags": [] })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = call(
        &app,
        "PATCH",
        &format!("/api/v1/devices/{}", id_of(2)),
        Some(json!({ "status": "retired" })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    let (s, headers, zip) = call_raw(
        &app,
        "POST",
        bundle,
        json!({ "filter": "tag = batch", "password": password }),
        admin,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{}", String::from_utf8_lossy(&zip));
    assert_eq!(headers["x-certificates-issued"], "2");
    assert_eq!(headers["x-devices-created"], "0");
    assert_eq!(
        manifest_rows(&zip, password)
            .iter()
            .map(|r| r.0.clone())
            .collect::<Vec<_>>(),
        ["os::batch-a", "os::batch-b"],
        "retired devices are left out"
    );

    // Filter + names: overlap = 1 device.
    // Filter matches CWMP devices too (they stand for their Agents).
    let (s, headers, zip) = call_raw(
        &app,
        "POST",
        bundle,
        json!({
            "filter": "tag = batch or protocol = cwmp",
            "endpoint_ids": ["os::batch-a", "os::other"],
            "device_ids": [id_of(1)],
            "password": password,
        }),
        admin,
    )
    .await;
    // `batch-a`: by `endpoint_ids` + filter (fine); `batch-b`: by ID + filter (fine).
    // ID + EndpointID of 1 device, both named explicitly -> refused.
    assert_eq!(s, StatusCode::OK, "{}", String::from_utf8_lossy(&zip));
    assert_eq!(headers["x-certificates-issued"], "4");
    assert_eq!(
        headers["x-devices-created"], "1",
        "the Agent of the CWMP device"
    );
    assert_eq!(
        manifest_rows(&zip, password)
            .iter()
            .map(|r| r.0.clone())
            .collect::<Vec<_>>(),
        ["os::001122-SN1", "os::batch-a", "os::batch-b", "os::other"]
    );
    let _ = cwmp;

    // Filter: matches nothing, does not parse, blank.
    for (label, body) in [
        (
            "nothing",
            json!({ "filter": "tag = nothing-has-this", "password": password }),
        ),
        (
            "syntax",
            json!({ "filter": "tag = ", "password": password }),
        ),
        (
            "injection",
            json!({ "filter": "tag = batch) or (status = retired", "password": password }),
        ),
        ("blank", json!({ "filter": "   ", "password": password })),
    ] {
        let (s, v) = call(&app, "POST", bundle, Some(body), Some(admin)).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{label}: {v}");
    }

    // > 1,000 matches -> refused, not cut short.
    let many: Vec<Value> = (0..1001)
        .map(|i| json!({ "endpoint_id": format!("os::cap-{i}") }))
        .collect();
    let (s, _) = call(
        &app,
        "POST",
        "/api/v1/devices/bulk",
        Some(json!({ "devices": many, "tags": ["cap"] })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, v) = call(
        &app,
        "POST",
        bundle,
        Some(json!({ "filter": "tag = cap", "password": password })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert!(
        v["error"]
            .as_str()
            .unwrap()
            .contains("matches 1001 devices; at most 1000"),
        "{v}"
    );
    let (_, audit) = call(
        &app,
        "GET",
        "/api/v1/audit?action=certificate.bundle",
        None,
        Some(admin),
    )
    .await;
    assert_eq!(
        audit["items"].as_array().unwrap().len(),
        2,
        "only the good ones"
    );
}

/// `POST /devices/{id}/certificate`: 3 years by default.
/// Generated key returned as `client_pem`, ready to install.
#[tokio::test]
async fn single_certificate_defaults_to_three_years_with_client_pem() {
    let admin = "admin-token";
    let (_c, store, _plain, _cwmp) = setup(Some(admin)).await;
    let (app, _ca) = ca_app(&store, admin);
    let usp = store
        .preregister_usp_device(DEFAULT_TENANT, "os::single", &[])
        .await
        .unwrap()
        .id;
    let uri = format!("/api/v1/devices/{usp}/certificate");
    let (s, v) = call(&app, "POST", &uri, None, Some(admin)).await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    let not_after = time::OffsetDateTime::parse(
        v["not_after"].as_str().unwrap(),
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap();
    let days = (not_after - time::OffsetDateTime::now_utc()).whole_days();
    assert!((1094..=1095).contains(&days), "{days}");
    let client = v["client_pem"].as_str().unwrap();
    let blocks = pem_blocks(client);
    assert_eq!(
        blocks.iter().map(|b| b.0.as_str()).collect::<Vec<_>>(),
        ["CERTIFICATE", "PRIVATE KEY"]
    );
    assert_eq!(dhonomos_pki::endpoint_ids(&blocks[0].1), ["os::single"]);
    assert_eq!(
        client,
        format!(
            "{}{}",
            v["certificate"].as_str().unwrap(),
            v["private_key"].as_str().unwrap()
        )
    );
    let (s, v) = call(&app, "POST", &uri, Some(json!({ "days": 90 })), Some(admin)).await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    let not_after = time::OffsetDateTime::parse(
        v["not_after"].as_str().unwrap(),
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap();
    assert!((89..=90).contains(&(not_after - time::OffsetDateTime::now_utc()).whole_days()));
}

/// Certs of a deleted device stay valid -> device delete revokes them + keeps records.
/// -> still refused, still found + revocable by fingerprint.
#[tokio::test]
async fn deleting_a_device_revokes_its_certificates() {
    let admin = "admin-token";
    let (_c, store, _plain, _cwmp) = setup(Some(admin)).await;
    let (app, _ca) = ca_app(&store, admin);
    let doomed = store
        .preregister_usp_device(DEFAULT_TENANT, "os::doomed", &[])
        .await
        .unwrap()
        .id;
    let kept = store
        .preregister_usp_device(DEFAULT_TENANT, "os::kept", &[])
        .await
        .unwrap()
        .id;
    let mut fingerprints = Vec::new();
    for (device, days) in [(doomed, 30), (doomed, 365), (kept, 365)] {
        let (s, v) = call(
            &app,
            "POST",
            &format!("/api/v1/devices/{device}/certificate"),
            Some(json!({ "days": days })),
            Some(admin),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED, "{v}");
        fingerprints.push(v["sha256"].as_str().unwrap().to_owned());
    }
    assert!(
        store
            .revoked_fingerprints(DEFAULT_TENANT)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        store
            .certificate_bound_endpoints(DEFAULT_TENANT)
            .await
            .unwrap()
            .len(),
        2
    );

    // Only a retired device can be deleted.
    let uri = format!("/api/v1/devices/{doomed}");
    let (s, _) = call(&app, "DELETE", &uri, None, Some(admin)).await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert!(
        store
            .revoked_fingerprints(DEFAULT_TENANT)
            .await
            .unwrap()
            .is_empty()
    );
    let (s, v) = call(
        &app,
        "PATCH",
        &uri,
        Some(json!({ "status": "retired" })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, _) = call(&app, "DELETE", &uri, None, Some(admin)).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _) = call(&app, "GET", &uri, None, Some(admin)).await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // Both certs of deleted device in revoked set, its EndpointID unbound.
    // Other device untouched.
    let mut revoked = store.revoked_fingerprints(DEFAULT_TENANT).await.unwrap();
    revoked.sort();
    let mut expected = fingerprints[..2].to_vec();
    expected.sort();
    assert_eq!(revoked, expected);
    assert_eq!(
        store
            .certificate_bound_endpoints(DEFAULT_TENANT)
            .await
            .unwrap(),
        ["os::kept"]
    );
    let (s, v) = call(
        &app,
        "GET",
        "/api/v1/certificates/expiring?days=400",
        None,
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["items"].as_array().unwrap().len(), 1, "{v}");
    assert_eq!(v["items"][0]["device"], "os::kept");
    assert_eq!(v["items"][0]["state"], "valid");

    let (_, audit) = call(
        &app,
        "GET",
        "/api/v1/audit?action=device.delete",
        None,
        Some(admin),
    )
    .await;
    let entry = &audit["items"][0];
    assert_eq!(entry["target_id"], doomed.to_string());
    assert_eq!(entry["detail"]["certificates_revoked"], 2, "{audit}");
    assert_eq!(entry["detail"]["endpoint_id"], "os::doomed");

    // Record still there -> revoke by fingerprint (no-op, records who revoked).
    let (s, v) = call(
        &app,
        "POST",
        "/api/v1/certificates/revoke",
        Some(json!({ "sha256": fingerprints[0] })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["known"], true);
    assert_eq!(v["device_id"], Value::Null);
    assert_eq!(v["endpoint_id"], "os::doomed");
    assert_eq!(v["revoke_reason"], "device deleted");
    assert_eq!(v["revoked_by"], "api-token");
}

/// `POST /devices/delete`: admins only; all ids checked before any delete.
/// Not retired -> refused unless `retire` set.
/// Deleted devices: certs revoked (+ kept), files removed, each deletion audited.
#[tokio::test]
async fn deleting_many_devices() {
    let admin = "admin-token";
    let (_c, store, _plain, cwmp) = setup(Some(admin)).await;
    let (files, dir) = temp_files();
    let app = router(
        store.clone(),
        ApiConfig {
            bearer_token: Some(admin.into()),
            tenant_id: DEFAULT_TENANT,
            files: Some(files),
            ca: Some(std::sync::Arc::new(
                dhonomos_pki::Ca::generate("Test CA").unwrap(),
            )),
            ..ApiConfig::default()
        },
    );
    let uri = "/api/v1/devices/delete";
    let mut usp = Vec::new();
    for eid in ["os::bulk-a", "os::bulk-b", "os::keep"] {
        usp.push(
            store
                .preregister_usp_device(DEFAULT_TENANT, eid, &[])
                .await
                .unwrap()
                .id,
        );
    }
    let [active, retired, keep] = usp[..] else {
        panic!("three devices")
    };

    // Certificates: 2 for `active`, 1 each for the others.
    let mut fingerprints = std::collections::HashMap::new();
    for (device, days) in [(active, 30), (active, 365), (retired, 365), (keep, 365)] {
        let (s, v) = call(
            &app,
            "POST",
            &format!("/api/v1/devices/{device}/certificate"),
            Some(json!({ "days": days })),
            Some(admin),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED, "{v}");
        fingerprints
            .entry(device)
            .or_insert_with(Vec::new)
            .push(v["sha256"].as_str().unwrap().to_owned());
    }
    let (s, v) = call(
        &app,
        "PATCH",
        &format!("/api/v1/devices/{retired}"),
        Some(json!({ "status": "retired" })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");

    // Config file of the CWMP device (content on disk) + 1 of no device.
    let mut stored = Vec::new();
    for (name, device) in [("cwmp.cfg", Some(cwmp)), ("fw.bin", None)] {
        let id = Uuid::now_v7();
        std::fs::write(dir.join(id.to_string()), b"secret").unwrap();
        store
            .insert_file(&dhonomos_store::NewFile {
                id,
                tenant_id: DEFAULT_TENANT,
                name: name.into(),
                file_type: "3 Vendor Configuration File".into(),
                size_bytes: 6,
                sha256: vec![0; 32],
                version: None,
                device_id: device,
            })
            .await
            .unwrap();
        stored.push(id);
    }
    let [cwmp_file, firmware] = stored[..] else {
        panic!("two files")
    };

    let exists = |id: Uuid| {
        let app = app.clone();
        async move {
            call(
                &app,
                "GET",
                &format!("/api/v1/devices/{id}"),
                None,
                Some(admin),
            )
            .await
            .0 == StatusCode::OK
        }
    };
    let revoked = async || store.revoked_fingerprints(DEFAULT_TENANT).await.unwrap();
    let audit = async |action: &str| {
        call(
            &app,
            "GET",
            &format!("/api/v1/audit?action={action}"),
            None,
            Some(admin),
        )
        .await
        .1["items"]
            .as_array()
            .unwrap()
            .iter()
            // Filter = prefix: `device.delete` also finds `device.delete_bulk`.
            .filter(|e| e["action"] == action)
            .cloned()
            .collect::<Vec<_>>()
    };
    // Nothing changed: every device there, as it was.
    let untouched = async || {
        for id in [cwmp, active, retired, keep] {
            assert!(exists(id).await, "{id} is gone");
        }
        let (_, v) = call(
            &app,
            "GET",
            &format!("/api/v1/devices/{active}"),
            None,
            Some(admin),
        )
        .await;
        assert_eq!(v["status"], "active", "{v}");
        assert!(revoked().await.is_empty());
        assert!(store.get_file(cwmp_file).await.unwrap().is_some());
        assert!(audit("device.delete").await.is_empty());
        assert!(audit("device.delete_bulk").await.is_empty());
    };
    let body = json!({ "device_ids": [retired], "retire": false });

    // Roles: admins only; operator, viewer (also with device scope), no login -> refused.
    let viewer = api_key(&app, admin, "viewer", None).await;
    let operator = api_key(&app, admin, "operator", None).await;
    let scoped = api_key(&app, admin, "operator", Some(json!({ "tags": ["east"] }))).await;
    for token in [&viewer, &operator, &scoped] {
        let (s, v) = call(&app, "POST", uri, Some(body.clone()), Some(token)).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    }
    let (s, _) = call(&app, "POST", uri, Some(body.clone()), None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    untouched().await;

    // Requests that cannot be used.
    let id_list = |n: usize| (0..n).map(|_| Uuid::now_v7()).collect::<Vec<_>>();
    for (label, bad, expected) in [
        (
            "no devices",
            json!({ "device_ids": [] }),
            "must not be empty",
        ),
        (
            "too many",
            json!({ "device_ids": id_list(1001) }),
            "at most 1000",
        ),
        (
            "listed twice",
            json!({ "device_ids": [retired, keep, retired] }),
            &retired.to_string(),
        ),
        ("no list", json!({ "retire": true }), "device_ids"),
        (
            "unknown field",
            json!({ "device_ids": [retired], "everything": true }),
            "everything",
        ),
        ("not a UUID", json!({ "device_ids": ["SN1"] }), "UUID"),
        (
            "retire is not a flag",
            json!({ "device_ids": [retired], "retire": "yes" }),
            "retire",
        ),
    ] {
        let (s, v) = call(&app, "POST", uri, Some(bad), Some(admin)).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{label}: {v}");
        assert!(
            v["error"].as_str().unwrap().contains(expected),
            "{label}: {v}"
        );
    }
    // 1,000 allowed: refused only because none exists; error lists first 20.
    let many = id_list(1000);
    let (s, v) = call(
        &app,
        "POST",
        uri,
        Some(json!({ "device_ids": many })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    let error = v["error"].as_str().unwrap();
    assert!(error.starts_with("unknown devices"), "{error}");
    assert!(error.contains(&many[19].to_string()), "{error}");
    assert!(!error.contains(&many[20].to_string()), "{error}");
    assert!(error.contains("and 980 more"), "{error}");

    // 1 unknown device -> everything else kept, retired or not, with or without `retire`.
    let ghost = Uuid::now_v7();
    for retire in [false, true] {
        let (s, v) = call(
            &app,
            "POST",
            uri,
            Some(json!({ "device_ids": [retired, ghost, keep], "retire": retire })),
            Some(admin),
        )
        .await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
        let error = v["error"].as_str().unwrap();
        assert!(error.contains("nothing was deleted"), "{error}");
        assert!(error.contains(&ghost.to_string()), "{error}");
        assert!(!error.contains(&keep.to_string()), "{error}");
    }
    untouched().await;

    // No `retire` -> devices not retired named + refused; retired one not.
    // Nothing retired or deleted.
    for retire in [json!(false), Value::Null] {
        let mut body = json!({ "device_ids": [active, retired, cwmp] });
        if !retire.is_null() {
            body["retire"] = retire;
        }
        let (s, v) = call(&app, "POST", uri, Some(body), Some(admin)).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
        let error = v["error"].as_str().unwrap();
        assert!(error.contains("not retired"), "{error}");
        assert!(error.contains(&format!("{active} (os::bulk-a)")), "{error}");
        assert!(error.contains(&format!("{cwmp} (SN1)")), "{error}");
        assert!(!error.contains(&retired.to_string()), "{error}");
    }
    untouched().await;

    // Retired device deleted as is: no retirement, its cert revoked + kept.
    let (s, v) = call(&app, "POST", uri, Some(body), Some(admin)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        v,
        json!({ "deleted": 1, "certificates_revoked": 1, "files": 0 })
    );
    assert!(!exists(retired).await);
    assert_eq!(revoked().await, fingerprints[&retired]);

    // `retire` -> devices in service retired + deleted: certs, files, all.
    // Device not named: untouched.
    let (s, v) = call(
        &app,
        "POST",
        uri,
        Some(json!({ "device_ids": [cwmp, active], "retire": true })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        v,
        json!({ "deleted": 2, "certificates_revoked": 2, "files": 1 })
    );
    assert!(!exists(cwmp).await);
    assert!(!exists(active).await);
    assert!(exists(keep).await);
    let mut expected: Vec<String> = fingerprints[&retired]
        .iter()
        .chain(&fingerprints[&active])
        .cloned()
        .collect();
    expected.sort();
    let mut all_revoked = revoked().await;
    all_revoked.sort();
    assert_eq!(all_revoked, expected);
    assert!(!all_revoked.contains(&fingerprints[&keep][0]));
    assert_eq!(
        store
            .certificate_bound_endpoints(DEFAULT_TENANT)
            .await
            .unwrap(),
        ["os::keep"]
    );
    assert!(store.get_file(cwmp_file).await.unwrap().is_none());
    assert!(!dir.join(cwmp_file.to_string()).exists());
    assert!(store.get_file(firmware).await.unwrap().is_some());
    assert!(dir.join(firmware.to_string()).exists());

    // Once gone: naming them again -> error, nothing changed.
    let (s, v) = call(
        &app,
        "POST",
        uri,
        Some(json!({ "device_ids": [cwmp, keep], "retire": true })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert!(exists(keep).await);

    // 1 `device.delete` record per device + 1 summary per request.
    let deletions = audit("device.delete").await;
    assert_eq!(deletions.len(), 3, "{deletions:?}");
    for (id, eid, serial, retired_first, certificates, file_count) in [
        (retired, Some("os::bulk-b"), None, false, 1, 0),
        (cwmp, None, Some("SN1"), true, 0, 1),
        (active, Some("os::bulk-a"), None, true, 2, 0),
    ] {
        let entry = deletions
            .iter()
            .find(|e| e["target_id"] == id.to_string())
            .unwrap_or_else(|| panic!("no record for {id}: {deletions:?}"));
        assert_eq!(entry["actor"], "api-token", "{entry}");
        let detail = &entry["detail"];
        assert_eq!(detail["bulk"], true, "{entry}");
        assert_eq!(detail["retired_first"], retired_first, "{entry}");
        assert_eq!(detail["endpoint_id"], json!(eid), "{entry}");
        assert_eq!(detail["serial_number"], json!(serial), "{entry}");
        assert_eq!(detail["certificates_revoked"], certificates, "{entry}");
        assert_eq!(detail["files"], file_count, "{entry}");
    }
    let summaries = audit("device.delete_bulk").await;
    assert_eq!(summaries.len(), 2, "{summaries:?}");
    // Newest first.
    let detail = &summaries[0]["detail"];
    assert_eq!(
        (
            &detail["requested"],
            &detail["deleted"],
            &detail["retired"],
            &detail["certificates_revoked"],
            &detail["files"],
            &detail["complete"],
        ),
        (
            &json!(2),
            &json!(2),
            &json!(2),
            &json!(2),
            &json!(1),
            &json!(true)
        ),
        "{summaries:?}"
    );
    assert_eq!(detail["sample"].as_array().unwrap().len(), 2);
    let detail = &summaries[1]["detail"];
    assert_eq!(
        (&detail["deleted"], &detail["retired"]),
        (&json!(1), &json!(0))
    );
    // Refused requests -> no record. Retire-first not audited as status change:
    // the only record is the `PATCH` above.
    assert_eq!(audit("device.status").await.len(), 1);
    let _ = std::fs::remove_dir_all(dir);
}

/// `POST /certificates/revoke`: admins only. Cert without record -> recorded as revoked;
/// with record -> revoked. MTP revoked set has both.
#[tokio::test]
async fn certificates_are_revoked_by_fingerprint() {
    let admin = "admin-token";
    let (_c, store, _plain, _cwmp) = setup(Some(admin)).await;
    let (app, _ca) = ca_app(&store, admin);
    let usp = store
        .preregister_usp_device(DEFAULT_TENANT, "os::known", &[])
        .await
        .unwrap()
        .id;
    let (s, v) = call(
        &app,
        "POST",
        &format!("/api/v1/devices/{usp}/certificate"),
        None,
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    let known = v["sha256"].as_str().unwrap().to_owned();
    let lost = "0123456789abcdef".repeat(4);
    let uri = "/api/v1/certificates/revoke";
    let body = json!({ "sha256": lost, "endpoint_id": "os::lost", "reason": "record lost" });

    // Roles: viewer, operator (also with device scope), no login -> refused.
    let viewer = api_key(&app, admin, "viewer", None).await;
    let operator = api_key(&app, admin, "operator", None).await;
    let scoped = api_key(&app, admin, "operator", Some(json!({ "tags": ["east"] }))).await;
    for token in [&viewer, &operator, &scoped] {
        let (s, v) = call(&app, "POST", uri, Some(body.clone()), Some(token)).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    }
    let (s, _) = call(&app, "POST", uri, Some(body.clone()), None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let admin_key = api_key(&app, admin, "admin", None).await;
    assert!(
        store
            .revoked_fingerprints(DEFAULT_TENANT)
            .await
            .unwrap()
            .is_empty(),
        "the refusals revoked nothing"
    );
    let (_, audit) = call(
        &app,
        "GET",
        "/api/v1/audit?action=certificate.revoke",
        None,
        Some(admin),
    )
    .await;
    assert_eq!(audit["items"], json!([]));

    // Unusable requests.
    for (label, bad) in [
        ("short", json!({ "sha256": "abcd" })),
        ("not hex", json!({ "sha256": "zz".repeat(32) })),
        ("missing", json!({})),
        ("empty", json!({ "sha256": "" })),
        (
            "long endpoint",
            json!({ "sha256": lost, "endpoint_id": "e".repeat(257) }),
        ),
        (
            "control",
            json!({ "sha256": lost, "endpoint_id": "os::a\nb" }),
        ),
        (
            "long reason",
            json!({ "sha256": lost, "reason": "r".repeat(1025) }),
        ),
        ("unknown field", json!({ "sha256": lost, "serial": "1" })),
    ] {
        let (s, v) = call(&app, "POST", uri, Some(bad), Some(&admin_key)).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{label}: {v}");
    }
    assert!(
        store
            .revoked_fingerprints(DEFAULT_TENANT)
            .await
            .unwrap()
            .is_empty()
    );

    // Fingerprint with no record -> recorded as revoked.
    let (s, v) = call(&app, "POST", uri, Some(body.clone()), Some(&admin_key)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["known"], false);
    assert_eq!(v["sha256"], lost);
    assert_eq!(v["endpoint_id"], "os::lost");
    assert_eq!(v["revoke_reason"], "record lost");
    assert!(v["revoked_by"].as_str().unwrap().contains("key"), "{v}");
    for field in ["device_id", "serial", "not_after"] {
        assert_eq!(v[field], Value::Null, "{field}: {v}");
    }
    assert!(v["revoked_at"].is_string());
    assert_eq!(
        store.revoked_fingerprints(DEFAULT_TENANT).await.unwrap(),
        [lost.as_str()]
    );
    let (_, audit) = call(
        &app,
        "GET",
        "/api/v1/audit?action=certificate.revoke",
        None,
        Some(admin),
    )
    .await;
    let entry = &audit["items"][0];
    assert_eq!(entry["target_type"], "certificate");
    assert_eq!(entry["target_id"], v["id"]);
    assert_eq!(entry["detail"]["sha256"], lost);
    assert_eq!(entry["detail"]["known"], false);
    assert_eq!(entry["detail"]["reason"], "record lost");

    // Again, upper case + colons (openssl format) -> no change.
    let colons = lost
        .to_uppercase()
        .as_bytes()
        .chunks(2)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join(":");
    let (s, again) = call(
        &app,
        "POST",
        uri,
        Some(json!({ "sha256": colons, "reason": "other" })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{again}");
    assert_eq!(again["known"], true);
    assert_eq!(again["id"], v["id"]);
    assert_eq!(again["revoked_at"], v["revoked_at"]);
    assert_eq!(again["revoke_reason"], "record lost", "the first stands");
    assert_eq!(
        store
            .revoked_fingerprints(DEFAULT_TENANT)
            .await
            .unwrap()
            .len(),
        1
    );

    // Cert issued by Dhonomos -> revoked like via its device.
    assert_eq!(
        store
            .certificate_bound_endpoints(DEFAULT_TENANT)
            .await
            .unwrap(),
        ["os::known"]
    );
    let (s, v) = call(
        &app,
        "POST",
        uri,
        Some(json!({ "sha256": known, "reason": "stolen" })),
        Some(&admin_key),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["known"], true);
    assert_eq!(v["device_id"], usp.to_string());
    assert_eq!(v["endpoint_id"], "os::known");
    assert!(!v["serial"].as_str().unwrap().is_empty());
    assert!(v["not_after"].is_string());
    let (_, list) = call(
        &app,
        "GET",
        &format!("/api/v1/devices/{usp}/certificates"),
        None,
        Some(admin),
    )
    .await;
    assert_eq!(list["items"][0]["state"], "revoked", "{list}");
    assert_eq!(list["items"][0]["revoke_reason"], "stolen");
    let mut revoked = store.revoked_fingerprints(DEFAULT_TENANT).await.unwrap();
    revoked.sort();
    let mut expected = vec![lost, known];
    expected.sort();
    assert_eq!(revoked, expected);
    assert!(
        store
            .certificate_bound_endpoints(DEFAULT_TENANT)
            .await
            .unwrap()
            .is_empty()
    );
    let (_, doc) = call(&app, "GET", "/api/v1/openapi.json", None, None).await;
    assert_eq!(
        doc["paths"]["/api/v1/certificates/revoke"]["post"]["operationId"],
        "revoke_certificate_by_fingerprint",
        "{doc}"
    );
}

#[tokio::test]
async fn bulk_jobs() {
    let (_c, store, app, id) = setup(None).await;
    let target = json!({ "oui": "001122" });
    let (s, v) = call(
        &app,
        "POST",
        "/api/v1/jobs/preview",
        Some(json!({ "target": target })),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["count"], 1);
    assert_eq!(v["sample"][0]["id"], id.to_string());
    let (s, _) = call(
        &app,
        "POST",
        "/api/v1/jobs/preview",
        Some(json!({ "target": { "ouii": "x" } })),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "unknown filter fields");

    let body = |policy: Value| {
        json!({ "name": "reboot all", "target": target, "task": { "kind": "reboot" },
                "policy": policy, "start": false })
    };
    let (s, v) = call(
        &app,
        "POST",
        "/api/v1/jobs",
        Some(body(json!({ "stages": [50] }))),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    let (s, v) = call(
        &app,
        "POST",
        "/api/v1/jobs",
        Some(body(json!({ "stages": [10, 100], "batch_size": 5 }))),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    assert_eq!(v["state"], "draft");
    let job = v["id"].as_str().unwrap().to_owned();

    let ctl = |action: &str| format!("/api/v1/jobs/{job}/{action}");
    let (s, _) = call(&app, "POST", &ctl("resume"), None, None).await;
    assert_eq!(s, StatusCode::CONFLICT, "a draft cannot resume");
    let (s, v) = call(&app, "POST", &ctl("start"), None, None).await;
    assert_eq!((s, v["state"].as_str()), (StatusCode::OK, Some("running")));
    assert_eq!(
        (v["total"].as_i64(), v["stage_limit"].as_i64()),
        (Some(1), Some(1))
    );
    assert_eq!(v["counts"]["queued"], 1);

    // Engine dispatches -> member shows up with its task.
    let engine = dhonomos_jobs::Engine::new(store.clone(), None, std::time::Duration::from_secs(1));
    engine.tick_job(job.parse().unwrap()).await.unwrap();
    let (_, v) = call(
        &app,
        "GET",
        &format!("/api/v1/jobs/{job}/devices?state=dispatched&limit=5&offset=0"),
        None,
        None,
    )
    .await;
    assert_eq!(v["items"][0]["state"], "dispatched");
    let (_, tasks) = call(
        &app,
        "GET",
        &format!("/api/v1/devices/{id}/tasks"),
        None,
        None,
    )
    .await;
    assert!(
        tasks["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["kind"] == "reboot")
    );

    let (s, _) = call(&app, "POST", &ctl("pause"), None, None).await;
    assert_eq!(s, StatusCode::OK);
    let (s, v) = call(&app, "POST", &ctl("cancel"), None, None).await;
    assert_eq!(
        (s, v["state"].as_str()),
        (StatusCode::OK, Some("cancelled"))
    );
    let (_, tasks) = call(
        &app,
        "GET",
        &format!("/api/v1/devices/{id}/tasks"),
        None,
        None,
    )
    .await;
    let reboot = tasks["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["kind"] == "reboot")
        .unwrap();
    assert_eq!(
        reboot["state"], "cancelled",
        "pending job tasks are cancelled"
    );
    let (_, v) = call(&app, "GET", "/api/v1/jobs", None, None).await;
    assert_eq!(v["items"][0]["counts"]["cancelled"], 1);
    let (s, _) = call(&app, "POST", &ctl("explode"), None, None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn script_dry_run_returns_the_trace_and_changes_nothing() {
    let (_c, store, _, id) = setup(None).await;
    let presets = dhonomos_core::Presets::from_yaml(
        r#"
presets:
  - name: uptime-check
    when: { events: ["1 BOOT"] }
    script_source: |
      pub fn main(device, args) {
          let up = device.get("Device.DeviceInfo.UpTime");
          device.log(`uptime ${up.unwrap_or("?")}`);
          device.set("Device.WiFi.SSID.1.SSID", `Home-${device.serial}`);
          device.tag("checked");
      }
"#,
    )
    .unwrap();
    let app = router(
        store.clone(),
        ApiConfig {
            tenant_id: DEFAULT_TENANT,
            presets: presets.into(),
            ..ApiConfig::default()
        },
    );
    let (s, dry) = call(
        &app,
        "POST",
        "/api/v1/presets/dry-run",
        Some(json!({ "device_id": id, "events": ["1 BOOT"] })),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{dry}");
    let item = &dry["items"][0];
    assert_eq!(
        (item["kind"].as_str(), item["script"].as_bool()),
        (Some("set_parameter_values"), Some(true))
    );
    assert_eq!(item["payload"]["values"][0]["value"], "Home-SN1");
    let trace = &dry["scripts"][0];
    assert_eq!(trace["logs"], json!(["uptime 42"]));
    assert_eq!(trace["tags_added"], json!(["checked"]));
    // Dry run -> nothing queued, tagged or recorded.
    assert!(store.list_tasks(id, 10).await.unwrap().is_empty());
    assert!(store.get_device(id).await.unwrap().unwrap().tags.is_empty());
    assert!(
        store
            .list_events(id, 10)
            .await
            .unwrap()
            .iter()
            .all(|e| e.kind != "script")
    );
}

#[tokio::test]
async fn preset_dry_run_matches_real_runs() {
    let (_c, store, _, id) = setup(None).await;
    let presets = dhonomos_core::Presets::from_yaml(
        r#"
presets:
  - name: first-contact
    when: { events: ["0 BOOTSTRAP"] }
    once: true
    priority: 5
    run:
      - kind: set_parameter_values
        payload: { values: [ { name: Device.ManagementServer.PeriodicInformInterval, value: "3600", type: unsignedInt } ] }
      - kind: reboot
  - name: every-boot
    when: { events: ["1 BOOT"], oui: "001122", software_version: "1\\..*" }
    run:
      - kind: get_parameter_values
        payload: { names: [Device.DeviceInfo.] }
  - name: other-model
    when: { product_class: Other }
    run: [ { kind: factory_reset } ]
"#,
    )
    .unwrap();
    let app = router(
        store.clone(),
        ApiConfig {
            tenant_id: DEFAULT_TENANT,
            presets: presets.clone().into(),
            ..ApiConfig::default()
        },
    );
    let (_, listed) = call(&app, "GET", "/api/v1/presets", None, None).await;
    assert_eq!(listed["items"].as_array().unwrap().len(), 3);

    let events = ["0 BOOTSTRAP", "1 BOOT"];
    let body = json!({ "device_id": id, "events": events });
    let (s, dry) = call(
        &app,
        "POST",
        "/api/v1/presets/dry-run",
        Some(body.clone()),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{dry}");
    let planned: Vec<(String, String, Value, i64)> = dry["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| {
            assert_eq!(i["would_queue"], true);
            (
                format!("preset:{}", i["preset"].as_str().unwrap()),
                i["kind"].as_str().unwrap().to_owned(),
                i["payload"].clone(),
                i["priority"].as_i64().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        planned.len(),
        3,
        "two from first-contact, one from every-boot"
    );

    // Real Inform, same events -> queues exactly that.
    let codes: Vec<_> = events
        .iter()
        .map(|e| dhonomos_cwmp_codec::EventCode::parse(e))
        .collect();
    let ctx = dhonomos_core::MatchContext {
        events: &codes,
        oui: "001122",
        product_class: "Box",
        software_version: Some("1.0"),
        tags: &[],
        new_device: false,
        attributes: &serde_json::Value::Null,
        serial: "SN1",
        protocol: "cwmp",
    };
    let n = dhonomos_core::presets::enqueue_matching(
        &store,
        DEFAULT_TENANT,
        &presets,
        id,
        &ctx,
        "2026-10-04T00:00:00Z",
    )
    .await
    .unwrap();
    assert_eq!(n, 3);
    let (_, tasks) = call(
        &app,
        "GET",
        &format!("/api/v1/devices/{id}/tasks"),
        None,
        None,
    )
    .await;
    let mut real: Vec<(String, String, Value, i64)> = tasks["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|t| {
            t["created_by"]
                .as_str()
                .is_some_and(|c| c.starts_with("preset:"))
        })
        .map(|t| {
            (
                t["created_by"].as_str().unwrap().to_owned(),
                t["kind"].as_str().unwrap().to_owned(),
                t["payload"].clone(),
                t["priority"].as_i64().unwrap(),
            )
        })
        .collect();
    let mut planned = planned;
    planned.sort_by(|a, b| format!("{a:?}").cmp(&format!("{b:?}")));
    real.sort_by(|a, b| format!("{a:?}").cmp(&format!("{b:?}")));
    assert_eq!(planned, real, "dry run = real run");

    // `once` presets do not repeat; others would.
    let (_, again) = call(&app, "POST", "/api/v1/presets/dry-run", Some(body), None).await;
    let would: Vec<(String, bool)> = again["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| {
            (
                i["preset"].as_str().unwrap().to_owned(),
                i["would_queue"].as_bool().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        would,
        vec![
            ("first-contact".to_owned(), false),
            ("first-contact".to_owned(), false),
            ("every-boot".to_owned(), true)
        ]
    );
}

#[tokio::test]
async fn bulkdata_collection_and_series() {
    use std::io::Write as _;

    let (_c, store, _, id) = setup(None).await;
    let signer = dhonomos_core::FileSigner::new(
        b"k".to_vec(),
        "http://files.test",
        std::time::Duration::from_secs(3600),
    );
    let files = dhonomos_api::FilesConfig::new(
        std::env::temp_dir(),
        signer.clone(),
        1024,
        Default::default(),
    );
    let ingest = dhonomos_core::MetricsIngest::new(store.clone(), 30, 2);
    ingest.maintain().await.unwrap();
    let app = router(
        store.clone(),
        ApiConfig {
            tenant_id: DEFAULT_TENANT,
            files: Some(files.clone()),
            ..ApiConfig::default()
        },
    );
    let fs_app = dhonomos_api::file_server(store.clone(), files, DEFAULT_TENANT, Some(ingest));
    let post = |path: String, body: Vec<u8>, gzip: bool| {
        let fs_app = fs_app.clone();
        async move {
            let mut req = Request::post(path).header("content-type", "application/json");
            if gzip {
                req = req.header("content-encoding", "gzip");
            }
            fs_app
                .oneshot(req.body(Body::from(body)).unwrap())
                .await
                .unwrap()
                .status()
        }
    };

    let (_, v) = call(
        &app,
        "GET",
        &format!("/api/v1/devices/{id}/bulkdata-url"),
        None,
        None,
    )
    .await;
    let url = v["url"].as_str().unwrap().to_owned();
    assert_eq!(url, signer.bulkdata_url(id));
    let path = url.strip_prefix("http://files.test").unwrap().to_owned();

    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let report = |t: i64, noise: i64| {
        json!({ "CollectionTime": t, "Device.WiFi.Radio.1.Stats.Noise": noise,
                "Device.DeviceInfo.UpTime": t - now + 100_000 })
    };
    let body = json!({ "Report": [report(now - 7200, -90), report(now - 3600, -94)] });
    assert_eq!(
        post(path.clone(), body.to_string().into_bytes(), false).await,
        StatusCode::NO_CONTENT
    );
    // Gzip, ObjectHierarchy encoding.
    let tree = json!({ "Report": [ { "CollectionTime": now - 60,
        "Device": { "WiFi": { "Radio": { "1": { "Stats": { "Noise": -98 } } } } } } ] });
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gz.write_all(tree.to_string().as_bytes()).unwrap();
    assert_eq!(
        post(path.clone(), gz.finish().unwrap(), true).await,
        StatusCode::NO_CONTENT
    );

    let other = format!(
        "/bulkdata/{}/{}",
        Uuid::now_v7(),
        path.rsplit('/').next().unwrap()
    );
    assert_eq!(
        post(other, b"{}".to_vec(), false).await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        post(path.clone(), b"junk".to_vec(), false).await,
        StatusCode::BAD_REQUEST
    );

    let (_, v) = call(
        &app,
        "GET",
        &format!("/api/v1/devices/{id}/metrics"),
        None,
        None,
    )
    .await;
    let paths: Vec<&str> = v["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["path"].as_str().unwrap())
        .collect();
    assert_eq!(
        paths,
        [
            "Device.DeviceInfo.UpTime",
            "Device.WiFi.Radio.1.Stats.Noise"
        ]
    );
    assert_eq!(v["items"][1]["last_value"], -98.0, "latest sample wins");

    let (s, v) = call(
        &app,
        "GET",
        &format!(
            "/api/v1/devices/{id}/metrics/series?path=Device.WiFi.Radio.1.Stats.Noise&step=86400"
        ),
        None,
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let pts = v["points"].as_array().unwrap();
    let count: i64 = pts.iter().map(|p| p["count"].as_i64().unwrap()).sum();
    let min = pts
        .iter()
        .map(|p| p["min"].as_f64().unwrap())
        .fold(f64::MAX, f64::min);
    assert_eq!((count, min), (3, -98.0));
    let (s, _) = call(
        &app,
        "GET",
        &format!("/api/v1/devices/{id}/metrics/series?path=x&from=yesterday"),
        None,
        None,
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn backups_replacement_and_deletion() {
    let (_c, store, app, old) = setup(None).await;
    let new = store
        .upsert_cwmp_device(
            DEFAULT_TENANT,
            &CwmpIdentity {
                oui: "001122".into(),
                product_class: "Box".into(),
                serial_number: "SN2".into(),
            },
            &InformUpdate::default(),
        )
        .await
        .unwrap()
        .id;
    let backups = format!("/api/v1/devices/{old}/config-backups");
    let (s, v) = call(&app, "POST", &backups, None, None).await;
    assert_eq!(s, StatusCode::CONFLICT, "no writability known yet: {v}");

    let p = |path: &str, value: &str, writable: Option<bool>| ParamUpdate {
        path: path.into(),
        value: Some(value.into()),
        writable,
        ..ParamUpdate::default()
    };
    store
        .upsert_params(
            old,
            &[
                p("Device.WiFi.SSID.1.SSID", "home", Some(true)),
                p(
                    "Device.WiFi.AccessPoint.1.Security.KeyPassphrase",
                    "",
                    Some(true),
                ),
                p(
                    "Device.ManagementServer.PeriodicInformInterval",
                    "60",
                    Some(true),
                ),
            ],
        )
        .await
        .unwrap();
    store.add_tags(old, &["vip".into()]).await.unwrap();

    let (s, v) = call(
        &app,
        "POST",
        &backups,
        Some(json!({ "label": "before" })),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    assert_eq!(v["count"], 1, "secrets and unit settings are left out");
    assert_eq!(v["notes"]["skipped_secrets"], 1);
    let backup = v["id"].as_str().unwrap().to_owned();

    // Drift: SSID changed since.
    store
        .upsert_params(old, &[p("Device.WiFi.SSID.1.SSID", "guest", None)])
        .await
        .unwrap();
    let (_, d) = call(
        &app,
        "GET",
        &format!("/api/v1/config-backups/{backup}/diff"),
        None,
        None,
    )
    .await;
    assert_eq!(d["changed"][0]["current"], "guest");

    // Restore onto old unit -> 1 SPV with the saved value.
    let (s, r) = call(
        &app,
        "POST",
        &format!("/api/v1/config-backups/{backup}/restore"),
        None,
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{r}");
    let task = r["tasks"][0].as_str().unwrap();
    let (_, t) = call(&app, "GET", &format!("/api/v1/tasks/{task}"), None, None).await;
    assert_eq!(t["payload"]["values"][0]["value"], "home");

    // Replacement: new unit gets tags + config; old one retired.
    let (s, r) = call(
        &app,
        "POST",
        &format!("/api/v1/devices/{old}/replace"),
        Some(json!({ "new_device_id": new })),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{r}");
    let (_, n) = call(&app, "GET", &format!("/api/v1/devices/{new}"), None, None).await;
    assert_eq!(n["tags"], json!(["vip"]));
    let (_, tasks) = call(
        &app,
        "GET",
        &format!("/api/v1/devices/{new}/tasks"),
        None,
        None,
    )
    .await;
    assert_eq!(
        tasks["items"][0]["payload"]["values"][0]["value"], "guest",
        "current values move over"
    );
    let (_, o) = call(&app, "GET", &format!("/api/v1/devices/{old}"), None, None).await;
    assert_eq!(o["status"], "retired");

    // Deletion: retired devices only, everything goes.
    let (s, _) = call(
        &app,
        "DELETE",
        &format!("/api/v1/devices/{new}"),
        None,
        None,
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT);
    let (s, _) = call(
        &app,
        "DELETE",
        &format!("/api/v1/devices/{old}"),
        None,
        None,
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _) = call(&app, "GET", &format!("/api/v1/devices/{old}"), None, None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert!(store.get_params(old, "").await.unwrap().is_empty());
    let (s, _) = call(
        &app,
        "GET",
        &format!("/api/v1/config-backups/{backup}"),
        None,
        None,
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND, "backups go with the device");
}

#[tokio::test]
async fn alarms_raise_clear_notify_and_ack() {
    use dhonomos_core::alarms::{AlarmEngine, AlarmRules, Webhooks};

    let (_c, store, _, id) = setup(None).await;
    // Webhook receiver.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<(String, String)>(8);
    let hook = axum::Router::new().route(
        "/hook",
        axum::routing::post(move |headers: axum::http::HeaderMap, body: String| {
            let tx = tx.clone();
            async move {
                let sig = headers["x-dhonomos-signature"].to_str().unwrap().to_owned();
                tx.send((sig, body)).await.unwrap();
                StatusCode::NO_CONTENT
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let hook_addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, hook).await });

    let rules = AlarmRules::from_yaml(
        r#"
alarms:
  - name: offline-30m
    severity: major
    when: { offline_minutes: 30 }
  - name: boot-storm
    severity: warning
    when: { event: inform, detail: { events: ["1 BOOT"] }, count: 2, within_minutes: 60 }
"#,
    )
    .unwrap();
    let engine = AlarmEngine::new(
        store.clone(),
        DEFAULT_TENANT,
        rules.clone(),
        Webhooks {
            urls: vec![format!("http://{hook_addr}/hook")],
            secret: "s3cret".into(),
        },
    );
    assert_eq!(
        engine.evaluate().await.unwrap(),
        (0, 0),
        "fresh device: nothing"
    );

    // Silent for 1 h + booted twice.
    sqlx::query("UPDATE devices SET last_contact_at = now() - interval '1 hour' WHERE id = $1")
        .bind(id)
        .execute(store.pool())
        .await
        .unwrap();
    for _ in 0..2 {
        store
            .record_event(
                DEFAULT_TENANT,
                Some(id),
                "inform",
                &json!({ "events": ["1 BOOT"] }),
            )
            .await
            .unwrap();
    }
    assert_eq!(engine.evaluate().await.unwrap(), (2, 0));
    assert_eq!(
        engine.evaluate().await.unwrap(),
        (0, 0),
        "one active alarm per rule"
    );
    let (sig, body) = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(sig, dhonomos_core::webhook::signature("s3cret", &body));
    let payload: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(payload["type"], "alarm.raised");

    let app = router(
        store.clone(),
        ApiConfig {
            tenant_id: DEFAULT_TENANT,
            alarm_rules: rules.into(),
            ..ApiConfig::default()
        },
    );
    let (_, v) = call(&app, "GET", "/api/v1/alarms?state=active", None, None).await;
    assert_eq!(v["items"].as_array().unwrap().len(), 2);
    assert_eq!(
        (
            v["active"]["major"].as_i64(),
            v["active"]["warning"].as_i64()
        ),
        (Some(1), Some(1))
    );
    let offline = v["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["rule"] == "offline-30m")
        .unwrap();
    assert!(
        offline["message"]
            .as_str()
            .unwrap()
            .starts_with("No contact for 6")
    );
    let (s, acked) = call(
        &app,
        "POST",
        &format!("/api/v1/alarms/{}/ack", offline["id"].as_str().unwrap()),
        None,
        None,
    )
    .await;
    assert_eq!(
        (s, acked["acked_by"].as_str()),
        (StatusCode::OK, Some("anonymous"))
    );
    let (_, r) = call(&app, "GET", "/api/v1/alarm-rules", None, None).await;
    assert_eq!(r["items"].as_array().unwrap().len(), 2);

    // Contact again -> offline alarm clears.
    sqlx::query("UPDATE devices SET last_contact_at = now() WHERE id = $1")
        .bind(id)
        .execute(store.pool())
        .await
        .unwrap();
    assert_eq!(engine.evaluate().await.unwrap(), (0, 1));
    let (_, v) = call(&app, "GET", "/api/v1/alarms?state=cleared", None, None).await;
    assert_eq!(v["items"][0]["rule"], "offline-30m");
}

/// Minimal SMTP relay: forwards headers + body of each received message.
async fn fake_smtp() -> (u16, tokio::sync::mpsc::Receiver<String>) {
    use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = tokio::sync::mpsc::channel(16);
    tokio::spawn(async move {
        while let Ok((s, _)) = listener.accept().await {
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut r = BufReader::new(s);
                r.get_mut().write_all(b"220 test\r\n").await.unwrap();
                let mut line = String::new();
                while r.read_line(&mut line).await.unwrap_or(0) > 0 {
                    let cmd = line.trim_end().to_owned();
                    line.clear();
                    if cmd == "DATA" {
                        r.get_mut().write_all(b"354 go\r\n").await.unwrap();
                        let mut msg = String::new();
                        loop {
                            let mut l = String::new();
                            if r.read_line(&mut l).await.unwrap_or(0) == 0 || l == ".\r\n" {
                                break;
                            }
                            msg.push_str(&l);
                        }
                        tx.send(msg).await.unwrap();
                        r.get_mut().write_all(b"250 queued\r\n").await.unwrap();
                    } else if cmd == "QUIT" {
                        r.get_mut().write_all(b"221 bye\r\n").await.unwrap();
                        return;
                    } else {
                        r.get_mut().write_all(b"250 ok\r\n").await.unwrap();
                    }
                }
            });
        }
    });
    (port, rx)
}

#[tokio::test]
async fn alarms_are_emailed_by_severity() {
    use base64::Engine as _;
    use dhonomos_core::alarms::{AlarmEmail, AlarmEngine, AlarmRules, Webhooks};

    let (_c, store, _, _) = setup(None).await;
    let (port, mut mails) = fake_smtp().await;
    let rules = AlarmRules::from_yaml(
        r#"
alarms:
  - { name: offline, severity: major, when: { offline_minutes: 30 } }
  - { name: offline-minor, severity: minor, when: { offline_minutes: 30 } }
"#,
    )
    .unwrap();
    let engine = AlarmEngine::new(store.clone(), DEFAULT_TENANT, rules, Webhooks::default())
        .with_email(AlarmEmail {
            smtp: dhonomos_core::mail::SmtpConfig {
                host: "127.0.0.1".into(),
                port,
                security: dhonomos_core::mail::Security::None,
                username: None,
                password: None,
                from: "dhonomos@isp.example".into(),
                to: vec!["noc@isp.example".into()],
                ca_pem: None,
            },
            min_severity: "major".into(),
        });
    sqlx::query("UPDATE devices SET last_contact_at = now() - interval '1 hour'")
        .execute(store.pool())
        .await
        .unwrap();
    assert_eq!(engine.evaluate().await.unwrap(), (2, 0));
    let mail = tokio::time::timeout(std::time::Duration::from_secs(5), mails.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(
        mail.contains("Subject: [Dhonomos] major offline raised: SN1\r\n"),
        "{mail}"
    );
    let body: String = mail
        .split("\r\n\r\n")
        .nth(1)
        .unwrap()
        .split("\r\n")
        .collect();
    let body = String::from_utf8(
        base64::engine::general_purpose::STANDARD
            .decode(body)
            .unwrap(),
    )
    .unwrap();
    assert!(body.contains("Message:  No contact for 6"), "{body}");
    // Minor alarm stays below the e-mail threshold.
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(500), mails.recv())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn reloading_alarm_rules_clears_alarms_of_removed_rules() {
    use dhonomos_core::alarms::{AlarmEngine, AlarmRules, Webhooks};

    let (_c, store, _, _) = setup(None).await;
    let rules = dhonomos_core::Shared::new(
        AlarmRules::from_yaml(
            "alarms: [{ name: offline, severity: major, when: { offline_minutes: 30 } }]",
        )
        .unwrap(),
    );
    let engine = AlarmEngine::new(
        store.clone(),
        DEFAULT_TENANT,
        rules.clone(),
        Webhooks::default(),
    );
    sqlx::query("UPDATE devices SET last_contact_at = now() - interval '1 hour'")
        .execute(store.pool())
        .await
        .unwrap();
    assert_eq!(engine.evaluate().await.unwrap(), (1, 0));
    // Rule renamed in file + reloaded -> old rule's alarm clears.
    rules.replace(
        AlarmRules::from_yaml(
            "alarms: [{ name: offline-2, severity: major, when: { offline_minutes: 30 } }]",
        )
        .unwrap(),
    );
    assert_eq!(engine.evaluate().await.unwrap(), (1, 1));
    assert_eq!(
        store.active_alarm_rules(DEFAULT_TENANT).await.unwrap(),
        ["offline-2"]
    );
}

#[tokio::test]
async fn alarm_silences_and_storms() {
    use dhonomos_core::alarms::{AlarmEngine, AlarmRules, Webhooks};

    let (_c, store, _, first) = setup(None).await;
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Value>(16);
    let hook = axum::Router::new().route(
        "/hook",
        axum::routing::post(move |body: String| {
            let tx = tx.clone();
            async move {
                tx.send(serde_json::from_str(&body).unwrap()).await.unwrap();
                StatusCode::NO_CONTENT
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let hook_addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, hook).await });

    let mut devices = vec![first];
    for (class, serial) in [
        ("Box", "SN2"),
        ("Box", "SN3"),
        ("Box", "SN4"),
        ("Other", "SNX"),
    ] {
        let d = store
            .upsert_cwmp_device(
                DEFAULT_TENANT,
                &CwmpIdentity {
                    oui: "001122".into(),
                    product_class: class.into(),
                    serial_number: serial.into(),
                },
                &InformUpdate::default(),
            )
            .await
            .unwrap()
            .id;
        devices.push(d);
    }
    let other = devices[4];
    let rules = AlarmRules::from_yaml(
        r#"
storm_threshold: 2
alarms:
  - name: offline-30m
    severity: major
    when: { offline_minutes: 30 }
"#,
    )
    .unwrap();
    let engine = AlarmEngine::new(
        store.clone(),
        DEFAULT_TENANT,
        rules.clone(),
        Webhooks {
            urls: vec![format!("http://{hook_addr}/hook")],
            secret: String::new(),
        },
    );
    let app = router(
        store.clone(),
        ApiConfig {
            tenant_id: DEFAULT_TENANT,
            alarm_rules: rules.into(),
            ..ApiConfig::default()
        },
    );

    // A maintenance window for the "Other" devices.
    let (s, silence) = call(
        &app,
        "POST",
        "/api/v1/alarm-silences",
        Some(json!({
            "rule": "offline-30m",
            "devices": { "product_class": "Other" },
            "duration_minutes": 60,
            "comment": "CHG-42 OLT swap",
        })),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{silence}");
    assert_eq!(
        (silence["state"].as_str(), silence["created_by"].as_str()),
        (Some("active"), Some("anonymous"))
    );
    for bad in [
        json!({ "rule": "nope", "duration_minutes": 5 }),
        json!({ "rule": "offline-30m" }),
        json!({ "duration_minutes": 60 * 24 * 31 }),
        json!({ "ends_at": "2020-01-01T00:00:00Z" }),
    ] {
        let (s, _) = call(
            &app,
            "POST",
            "/api/v1/alarm-silences",
            Some(bad.clone()),
            None,
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{bad}");
    }

    // All offline: 4 notified alarms > storm threshold 2.
    sqlx::query("UPDATE devices SET last_contact_at = now() - interval '1 hour'")
        .execute(store.pool())
        .await
        .unwrap();
    assert_eq!(engine.evaluate().await.unwrap(), (5, 0));
    let storm = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (
            storm["type"].as_str(),
            storm["state"].as_str(),
            storm["count"].as_i64()
        ),
        (Some("alarm.storm"), Some("raised"), Some(4))
    );
    assert!(
        storm["alarms"]
            .as_array()
            .unwrap()
            .iter()
            .all(|a| a["device_id"] != json!(other)),
        "the silenced device is not notified"
    );
    let (_, v) = call(
        &app,
        "GET",
        &format!("/api/v1/alarms?device_id={other}"),
        None,
        None,
    )
    .await;
    assert_eq!(
        v["items"][0]["silenced_by"], silence["id"],
        "still recorded"
    );

    // Ended silence stays on record.
    let (s, ended) = call(
        &app,
        "DELETE",
        &format!("/api/v1/alarm-silences/{}", silence["id"].as_str().unwrap()),
        None,
        None,
    )
    .await;
    assert_eq!(
        (s, ended["state"].as_str()),
        (StatusCode::OK, Some("ended"))
    );
    let (_, v) = call(&app, "GET", "/api/v1/alarm-silences", None, None).await;
    assert!(v["items"].as_array().unwrap().is_empty());
    let (_, v) = call(&app, "GET", "/api/v1/alarm-silences?all=true", None, None).await;
    assert_eq!(v["items"].as_array().unwrap().len(), 1);

    // Back online: 4 notified alarms clear as 1 storm; silenced one quietly.
    sqlx::query("UPDATE devices SET last_contact_at = now()")
        .execute(store.pool())
        .await
        .unwrap();
    assert_eq!(engine.evaluate().await.unwrap(), (0, 5));
    let storm = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (storm["state"].as_str(), storm["count"].as_i64()),
        (Some("cleared"), Some(4))
    );
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(500), rx.recv())
            .await
            .is_err(),
        "no other webhooks"
    );
}

#[tokio::test]
async fn vendor_configuration_file_backups() {
    let (_c, store, _, id) = setup(None).await;
    let dir = std::env::temp_dir().join(format!("dhonomos-cfg-{}", Uuid::now_v7()));
    std::fs::create_dir_all(&dir).unwrap();
    let signer = dhonomos_core::FileSigner::new(
        b"k".to_vec(),
        "http://files.test",
        std::time::Duration::from_secs(3600),
    );
    let files = dhonomos_api::FilesConfig::new(dir.clone(), signer, 1 << 20, Default::default());
    let app = router(
        store.clone(),
        ApiConfig {
            tenant_id: DEFAULT_TENANT,
            files: Some(files.clone()),
            ..ApiConfig::default()
        },
    );
    let fs_app = dhonomos_api::file_server(store.clone(), files, DEFAULT_TENANT, None);

    let (s, v) = call(
        &app,
        "POST",
        &format!("/api/v1/devices/{id}/config-files"),
        None,
        None,
    )
    .await;
    assert_eq!(s, StatusCode::ACCEPTED, "{v}");
    let (_, t) = call(
        &app,
        "GET",
        &format!("/api/v1/tasks/{}", v["task_id"].as_str().unwrap()),
        None,
        None,
    )
    .await;
    assert_eq!(t["kind"], "upload");
    // Signed link belongs to the device: API shows the target, not the signature.
    let shown = t["payload"]["url"].as_str().unwrap();
    assert!(shown.ends_with("?********"), "{shown}");
    assert!(!shown.contains("s="), "{shown}");
    let url = store
        .get_task(v["task_id"].as_str().unwrap().parse().unwrap())
        .await
        .unwrap()
        .unwrap()
        .payload["url"]
        .as_str()
        .unwrap()
        .to_owned();
    let path = url.strip_prefix("http://files.test").unwrap().to_owned();

    // CPE PUTs its config to the signed link.
    let put = |p: String, body: &'static [u8]| {
        let fs_app = fs_app.clone();
        async move {
            fs_app
                .oneshot(Request::put(p).body(Body::from(body)).unwrap())
                .await
                .unwrap()
                .status()
        }
    };
    assert_eq!(put(path.clone(), b"<config/>").await, StatusCode::CREATED);
    assert_eq!(
        put(path.clone(), b"<config/>").await,
        StatusCode::CONFLICT,
        "one upload per link"
    );
    assert_eq!(
        put(path.replace("&s=", "&s=00"), b"x").await,
        StatusCode::FORBIDDEN
    );

    let (_, list) = call(
        &app,
        "GET",
        &format!("/api/v1/devices/{id}/config-files"),
        None,
        None,
    )
    .await;
    let f = &list["items"][0];
    assert_eq!(f["id"], v["file_id"]);
    assert_eq!(f["file_type"], "3 Vendor Configuration File");
    assert_eq!(f["size_bytes"], 9);
    assert!(f["name"].as_str().unwrap().starts_with("SN1-config-"));
    // Restore = ordinary download of that file.
    let (s, _) = call(
        &app,
        "POST",
        &format!("/api/v1/devices/{id}/tasks"),
        Some(json!({ "kind": "download", "payload": { "file_id": f["id"] } })),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);

    // Log upload: own file type + list, not mixed with config files.
    let (s, v) = call(
        &app,
        "POST",
        &format!("/api/v1/devices/{id}/log-files"),
        None,
        None,
    )
    .await;
    assert_eq!(s, StatusCode::ACCEPTED, "{v}");
    let (_, t) = call(
        &app,
        "GET",
        &format!("/api/v1/tasks/{}", v["task_id"].as_str().unwrap()),
        None,
        None,
    )
    .await;
    assert_eq!(t["payload"]["file_type"], "2 Vendor Log File");
    let log_path = store
        .get_task(v["task_id"].as_str().unwrap().parse().unwrap())
        .await
        .unwrap()
        .unwrap()
        .payload["url"]
        .as_str()
        .unwrap()
        .strip_prefix("http://files.test")
        .unwrap()
        .to_owned();
    assert!(log_path.contains("?k=log&"), "{log_path}");
    // Kind is signed: log link without it or config link with it -> refused.
    assert_eq!(
        put(log_path.replace("k=log&", ""), b"x").await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        put(path.replace('?', "?k=log&"), b"x").await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        put(log_path.clone(), b"boot ok\n").await,
        StatusCode::CREATED
    );
    let (_, logs) = call(
        &app,
        "GET",
        &format!("/api/v1/devices/{id}/log-files"),
        None,
        None,
    )
    .await;
    assert_eq!(logs["items"].as_array().unwrap().len(), 1);
    let l = &logs["items"][0];
    assert_eq!(
        (&l["id"], &l["file_type"], &l["size_bytes"]),
        (&v["file_id"], &json!("2 Vendor Log File"), &json!(8))
    );
    assert!(l["name"].as_str().unwrap().starts_with("SN1-log-"));
    // Operators read it back via API.
    let resp = app
        .clone()
        .oneshot(
            Request::get(format!(
                "/api/v1/files/{}/content",
                l["id"].as_str().unwrap()
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()["cache-control"],
        "no-store",
        "stored files can be backups with secrets: no cached copy"
    );
    let disposition = resp.headers()["content-disposition"]
        .to_str()
        .unwrap()
        .to_owned();
    assert!(
        disposition.starts_with("attachment; filename=\"SN1-log-"),
        "{disposition}"
    );
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"boot ok\n");
    let (_, configs) = call(
        &app,
        "GET",
        &format!("/api/v1/devices/{id}/config-files"),
        None,
        None,
    )
    .await;
    assert_eq!(
        configs["items"].as_array().unwrap().len(),
        1,
        "no logs here"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn wifi_view_and_neighbor_scan() {
    let (_c, store, app, id) = setup(None).await;
    let p = |path: &str, value: &str| ParamUpdate {
        path: path.into(),
        value: Some(value.into()),
        ..ParamUpdate::default()
    };
    store
        .upsert_params(
            id,
            &[
                p("Device.WiFi.Radio.1.Channel", "11"),
                p("Device.WiFi.SSID.1.SSID", "home"),
                p(
                    "Device.WiFi.AccessPoint.1.SSIDReference",
                    "Device.WiFi.SSID.1",
                ),
                p(
                    "Device.WiFi.AccessPoint.1.AssociatedDevice.1.MACAddress",
                    "aa:bb:cc:dd:ee:ff",
                ),
            ],
        )
        .await
        .unwrap();
    let uri = format!("/api/v1/devices/{id}/wifi");
    let (s, v) = call(&app, "GET", &uri, None, None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["radios"][0]["channel"], 11);
    assert_eq!(v["networks"][0]["stations"][0]["mac"], "aa:bb:cc:dd:ee:ff");
    assert!(v["neighbor_scan"].is_null());

    // Finished neighbour scan shows up.
    let (s, t) = call(
        &app,
        "POST",
        &format!("/api/v1/devices/{id}/tasks"),
        Some(json!({ "kind": "diagnostic", "payload": { "test": "wifi_neighbors" }, "connection_request": false })),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{t}");
    let task = store.next_task(id).await.unwrap().unwrap();
    store
        .complete_task(
            id,
            task.id,
            Ok(json!({ "test": "wifi_neighbors", "result": { "neighbors": [ { "ssid": "cafe", "channel": 6 } ] } })),
        )
        .await
        .unwrap();
    let (_, v) = call(&app, "GET", &uri, None, None).await;
    assert_eq!(v["neighbor_scan"]["neighbors"][0]["ssid"], "cafe");
}

/// POST with a session cookie.
async fn call_cookie(
    app: &Router,
    method: &str,
    uri: &str,
    body: Option<Value>,
    cookie: Option<&str>,
) -> (StatusCode, Value, Option<String>) {
    let mut req = Request::builder().method(method).uri(uri);
    if let Some(c) = cookie {
        req = req.header("cookie", c);
    }
    let req = match body {
        Some(b) => req
            .header("content-type", "application/json")
            .body(Body::from(b.to_string())),
        None => req.body(Body::empty()),
    }
    .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let set_cookie = resp
        .headers()
        .get("set-cookie")
        .map(|v| v.to_str().unwrap().to_owned());
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        set_cookie,
    )
}

#[tokio::test]
async fn accounts_sessions_roles_and_api_keys() {
    let (_c, store, app, id) = setup(None).await;
    // No accounts yet -> open (development); first account closes it.
    let (s, v) = call(
        &app,
        "POST",
        "/api/v1/users",
        Some(json!({ "username": "alice", "password": "correct horse battery", "role": "admin" })),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    let (s, _) = call(&app, "GET", "/api/v1/devices", None, None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "accounts exist now");

    // Login: session cookie (HttpOnly, SameSite=Strict).
    let (s, _, _) = call_cookie(
        &app,
        "POST",
        "/api/v1/auth/login",
        Some(json!({ "username": "alice", "password": "nope" })),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, me, cookie) = call_cookie(
        &app,
        "POST",
        "/api/v1/auth/login",
        Some(json!({ "username": "alice", "password": "correct horse battery" })),
        None,
    )
    .await;
    assert_eq!((s, me["role"].as_str()), (StatusCode::OK, Some("admin")));
    let cookie = cookie.unwrap();
    assert!(cookie.contains("HttpOnly") && cookie.contains("SameSite=Strict"));
    let session = cookie.split(';').next().unwrap().to_owned();
    let (s, me, _) = call_cookie(&app, "GET", "/api/v1/auth/me", None, Some(&session)).await;
    assert_eq!(
        (s, me["name"].as_str(), me["via"].as_str()),
        (StatusCode::OK, Some("alice"), Some("session"))
    );

    // Viewer key: read, no change. Operator key: change, no admin.
    let mut keys = Vec::new();
    for role in ["viewer", "operator"] {
        let (s, k, _) = call_cookie(
            &app,
            "POST",
            "/api/v1/api-keys",
            Some(json!({ "name": format!("{role} tool"), "role": role })),
            Some(&session),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED, "{k}");
        keys.push(k["key"].as_str().unwrap().to_owned());
    }
    let (viewer, operator) = (keys[0].as_str(), keys[1].as_str());
    let task = json!({ "kind": "reboot", "connection_request": false });
    let tasks = format!("/api/v1/devices/{id}/tasks");
    assert_eq!(
        call(&app, "GET", "/api/v1/devices", None, Some(viewer))
            .await
            .0,
        StatusCode::OK
    );
    let (s, v) = call(&app, "POST", &tasks, Some(task.clone()), Some(viewer)).await;
    assert_eq!(
        (s, v["error"].as_str()),
        (StatusCode::FORBIDDEN, Some("this needs the operator role"))
    );
    assert_eq!(
        call(&app, "POST", &tasks, Some(task), Some(operator))
            .await
            .0,
        StatusCode::CREATED
    );
    assert_eq!(
        call(&app, "GET", "/api/v1/users", None, Some(operator))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(&app, "GET", "/metrics", None, Some(viewer)).await.0,
        StatusCode::OK,
        "viewers may read metrics"
    );

    // Audit log names who acted.
    let (_, audit) = call(&app, "GET", "/api/v1/audit", None, Some(viewer)).await;
    let actors: Vec<&str> = audit["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["actor"].as_str().unwrap())
        .collect();
    assert!(
        actors.contains(&"key:operator tool") && actors.contains(&"alice"),
        "{actors:?}"
    );

    // Revoked keys stop working; disabled user -> sessions end.
    let (_, list, _) = call_cookie(&app, "GET", "/api/v1/api-keys", None, Some(&session)).await;
    let vid = list["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["name"] == "viewer tool")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        call_cookie(
            &app,
            "DELETE",
            &format!("/api/v1/api-keys/{vid}"),
            None,
            Some(&session)
        )
        .await
        .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        call(&app, "GET", "/api/v1/devices", None, Some(viewer))
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    let alice = store
        .user_by_name(DEFAULT_TENANT, "alice")
        .await
        .unwrap()
        .unwrap();
    store
        .update_user(alice.id, None, Some(true), None, None)
        .await
        .unwrap();
    assert_eq!(
        call_cookie(&app, "GET", "/api/v1/auth/me", None, Some(&session))
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );

    // Repeated failures -> name locked for a while.
    for _ in 0..5 {
        call_cookie(
            &app,
            "POST",
            "/api/v1/auth/login",
            Some(json!({ "username": "bob", "password": "x" })),
            None,
        )
        .await;
    }
    let (s, _, _) = call_cookie(
        &app,
        "POST",
        "/api/v1/auth/login",
        Some(json!({ "username": "bob", "password": "x" })),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn overview_figures() {
    let (_c, store, app, id) = setup(None).await;
    store
        .record_event(DEFAULT_TENANT, Some(id), "inform", &json!({}))
        .await
        .unwrap();
    let (s, v) = call(&app, "GET", "/api/v1/overview", None, None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["active"], 1);
    assert_eq!(v["online"]["m15"], 1);
    assert_eq!(v["by_protocol"]["cwmp"], 1);
    assert_eq!(v["sessions_per_minute"][0]["n"], 1);
    assert_eq!(v["versions"][0]["version"], "1.0");
}

#[tokio::test]
async fn device_search() {
    let (_c, store, app, _) = setup(None).await;
    for (serial, version) in [("ABC100", "2.0"), ("ABC101", "2.0"), ("XYZ_1", "1.0")] {
        store
            .upsert_cwmp_device(
                DEFAULT_TENANT,
                &CwmpIdentity {
                    oui: "001122".into(),
                    product_class: "Box".into(),
                    serial_number: serial.into(),
                },
                &InformUpdate {
                    software_version: Some(version.into()),
                    ..InformUpdate::default()
                },
            )
            .await
            .unwrap();
    }
    let get = |q: &str| {
        let app = app.clone();
        let q = q.to_owned();
        async move {
            call(&app, "GET", &format!("/api/v1/devices?{q}"), None, None)
                .await
                .1
        }
    };
    let v = get("q=abc1").await;
    assert_eq!(
        (v["total"].as_i64(), v["items"].as_array().unwrap().len()),
        (Some(2), 2)
    );
    assert_eq!(
        get("software_version=1.0").await["total"],
        2,
        "fixture SN1 is 1.0 too"
    );
    assert_eq!(get("q=_").await["total"], 1, "underscore is literal");
    assert_eq!(get("q=%25").await["total"], 0, "percent is literal");
    let page = get("limit=2&offset=2").await;
    assert_eq!(
        (
            page["total"].as_i64(),
            page["items"].as_array().unwrap().len()
        ),
        (Some(4), 2)
    );
    assert_eq!(get("protocol=usp").await["total"], 0);
}

#[tokio::test]
async fn server_sent_events() {
    let (_c, store, app, id) = setup(None).await;
    let resp = app
        .clone()
        .oneshot(
            Request::get(format!("/api/v1/stream?device_id={id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(resp.headers()["content-type"], "text/event-stream");
    let mut body = resp.into_body();
    let mut text = String::new();
    let mut read_until = async |needle: &str, text: &mut String| {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        while !text.contains(needle) {
            let frame = tokio::time::timeout_at(deadline, body.frame())
                .await
                .expect("stream stalled")
                .unwrap()
                .unwrap();
            if let Ok(data) = frame.into_data() {
                text.push_str(&String::from_utf8_lossy(&data));
            }
        }
    };
    read_until("event: ready", &mut text).await;
    store
        .record_event(
            DEFAULT_TENANT,
            Some(id),
            "inform",
            &json!({ "events": ["2 PERIODIC"] }),
        )
        .await
        .unwrap();
    read_until("event: device_event", &mut text).await;
    assert!(text.contains("2 PERIODIC"), "{text}");
    drop(read_until);
    // 2 more polls re-read the overlap window: event must not come again.
    let more = tokio::time::timeout(std::time::Duration::from_millis(2500), async {
        while let Some(Ok(frame)) = body.frame().await {
            if let Ok(data) = frame.into_data() {
                text.push_str(&String::from_utf8_lossy(&data));
            }
        }
    })
    .await;
    assert!(more.is_err(), "the stream stays open");
    assert_eq!(
        text.matches("event: device_event").count(),
        1,
        "no repeats from the overlap"
    );
}

/// Event stream ends at server shutdown.
#[tokio::test]
async fn server_sent_events_end_at_shutdown() {
    let admin = "admin-token";
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let (_c, _store, app, _) = setup_with_shutdown(Some(admin), Some(stop_rx)).await;
    let resp = app
        .clone()
        .oneshot(
            Request::get("/api/v1/stream")
                .header("authorization", format!("Bearer {admin}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let mut body = resp.into_body();
    let mut text = String::new();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    while !text.contains("event: ready") {
        let frame = tokio::time::timeout_at(deadline, body.frame())
            .await
            .expect("stream stalled")
            .unwrap()
            .unwrap();
        if let Ok(data) = frame.into_data() {
            text.push_str(&String::from_utf8_lossy(&data));
        }
    }
    stop_tx.send(true).unwrap();
    let ended = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        while let Some(frame) = body.frame().await {
            frame.unwrap();
        }
    })
    .await;
    assert!(ended.is_ok(), "the stream ends");
}

/// Raw response text (CSV exports); `token` may be empty.
async fn call_text(app: &Router, uri: &str, token: &str) -> (StatusCode, String) {
    let mut req = Request::get(uri);
    if !token.is_empty() {
        req = req.header("authorization", format!("Bearer {token}"));
    }
    let req = req.body(Body::empty()).unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&body).into_owned())
}

#[tokio::test]
async fn device_scopes_hide_and_protect_devices() {
    let admin = "admin-token";
    let (_c, store, app, outside) = setup(Some(admin)).await;
    // 2nd device inside scope "east".
    let inside = store
        .upsert_cwmp_device(
            DEFAULT_TENANT,
            &CwmpIdentity {
                oui: "001122".into(),
                product_class: "Box".into(),
                serial_number: "SN2".into(),
            },
            &InformUpdate::default(),
        )
        .await
        .unwrap()
        .id;
    let (s, v) = call(
        &app,
        "PATCH",
        &format!("/api/v1/devices/{inside}"),
        Some(json!({ "tags": ["east"], "attributes": { "region": "busan" } })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");

    // Scopes: viewers + operators only, must not be empty.
    for (role, scope, why) in [
        (
            "admin",
            json!({ "tags": ["east"] }),
            "admins cannot have a device scope",
        ),
        ("operator", json!({}), "an empty scope"),
        ("operator", json!({ "status": "active" }), "unknown field"),
        ("operator", json!({ "protocol": "coap" }), "scope protocol"),
    ] {
        let (s, v) = call(
            &app,
            "POST",
            "/api/v1/api-keys",
            Some(json!({ "name": "bad", "role": role, "scope": scope })),
            Some(admin),
        )
        .await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
        assert!(v["error"].as_str().unwrap().contains(why), "{v}");
    }
    let (s, k) = call(
        &app,
        "POST",
        "/api/v1/api-keys",
        Some(json!({ "name": "east", "role": "operator",
                     "scope": { "tags": ["east"], "attributes": { "region": "busan" } } })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{k}");
    assert_eq!(k["scope"]["tags"], json!(["east"]));
    let east = k["key"].as_str().unwrap().to_owned();
    let east = east.as_str();
    let (_, me) = call(&app, "GET", "/api/v1/auth/me", None, Some(east)).await;
    assert_eq!(
        (me["role"].as_str(), &me["scope"]["attributes"]),
        (Some("operator"), &json!({ "region": "busan" }))
    );

    // Lists, search, overview, exports -> devices inside only.
    let (_, v) = call(&app, "GET", "/api/v1/devices", None, Some(east)).await;
    assert_eq!(v["total"], 1, "{v}");
    assert_eq!(v["items"][0]["id"], json!(inside));
    let (_, v) = call(&app, "GET", "/api/v1/devices", None, Some(admin)).await;
    assert_eq!(v["total"], 2);
    let (_, v) = call(&app, "GET", "/api/v1/overview", None, Some(east)).await;
    assert_eq!(v["active"], 1, "{v}");
    let (s, csv) = call_text(&app, "/api/v1/devices/export.csv", east).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        csv.split("\r\n").filter(|l| !l.is_empty()).count(),
        2,
        "{csv}"
    );
    assert!(!csv.contains(&outside.to_string()));

    // Device outside -> same answer as a nonexistent one.
    let (s, _) = call(
        &app,
        "GET",
        &format!("/api/v1/devices/{inside}"),
        None,
        Some(east),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, v) = call(
        &app,
        "GET",
        &format!("/api/v1/devices/{outside}"),
        None,
        Some(east),
    )
    .await;
    assert_eq!(
        (s, v["error"].as_str()),
        (StatusCode::NOT_FOUND, Some("device not found"))
    );

    // Edits must not move a device out of the scope.
    let (s, v) = call(
        &app,
        "PATCH",
        &format!("/api/v1/devices/{inside}"),
        Some(json!({ "tags": ["west"] })),
        Some(east),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    let (s, _) = call(
        &app,
        "PATCH",
        &format!("/api/v1/devices/{inside}"),
        Some(json!({ "attributes": { "region": null } })),
        Some(east),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    let (s, v) = call(
        &app,
        "PATCH",
        &format!("/api/v1/devices/{inside}"),
        Some(json!({ "tags": ["east", "vip"], "attributes": { "plan": "gold" } })),
        Some(east),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");

    // Fleet-wide operations need an unscoped caller.
    for (method, uri) in [
        ("POST", "/api/v1/devices"),
        ("POST", "/api/v1/devices/attributes/import"),
        ("PUT", "/api/v1/files"),
        (
            "DELETE",
            "/api/v1/files/00000000-0000-0000-0000-000000000000",
        ),
        ("GET", "/metrics"),
    ] {
        let (s, v) = call(&app, method, uri, Some(json!({})), Some(east)).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{method} {uri}: {v}");
    }

    // Jobs: scoped target narrowed; jobs reaching outside invisible.
    let job = |target: Value| json!({ "name": "reboot", "target": target, "task": { "kind": "reboot" }, "start": false });
    let (_, v) = call(
        &app,
        "POST",
        "/api/v1/jobs/preview",
        Some(json!({ "target": {} })),
        Some(east),
    )
    .await;
    assert_eq!(v["count"], 1, "{v}");
    let (s, v) = call(
        &app,
        "POST",
        "/api/v1/jobs/preview",
        Some(json!({ "target": { "attributes": { "region": "ulsan" } } })),
        Some(east),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    let (s, own) = call(
        &app,
        "POST",
        "/api/v1/jobs",
        Some(job(json!({}))),
        Some(east),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{own}");
    assert_eq!(own["target"]["tags"], json!(["east"]));
    assert_eq!(own["created_by"], "key:east");
    let (_, wide) = call(
        &app,
        "POST",
        "/api/v1/jobs",
        Some(job(json!({}))),
        Some(admin),
    )
    .await;
    let (_, v) = call(&app, "GET", "/api/v1/jobs", None, Some(east)).await;
    let ids: Vec<&Value> = v["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|j| &j["id"])
        .collect();
    assert_eq!(ids, vec![&own["id"]]);
    let (_, v) = call(&app, "GET", "/api/v1/jobs", None, Some(admin)).await;
    assert_eq!(v["items"].as_array().unwrap().len(), 2);

    // Silences: same.
    let silence = json!({ "devices": {}, "duration_minutes": 60 });
    let (s, mine) = call(
        &app,
        "POST",
        "/api/v1/alarm-silences",
        Some(silence.clone()),
        Some(east),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{mine}");
    assert_eq!(mine["devices"]["tags"], json!(["east"]));
    let (_, theirs) = call(
        &app,
        "POST",
        "/api/v1/alarm-silences",
        Some(silence),
        Some(admin),
    )
    .await;
    let (_, v) = call(&app, "GET", "/api/v1/alarm-silences", None, Some(east)).await;
    assert_eq!(v["items"].as_array().unwrap().len(), 1);

    // Alarms of devices outside -> not listed.
    for d in [inside, outside] {
        store
            .raise_alarm(
                DEFAULT_TENANT,
                d,
                "offline",
                "major",
                "offline",
                &json!({}),
                None,
            )
            .await
            .unwrap();
    }
    let (_, v) = call(&app, "GET", "/api/v1/alarms", None, Some(east)).await;
    assert_eq!(v["items"].as_array().unwrap().len(), 1, "{v}");
    assert_eq!(v["items"][0]["device_id"], json!(inside));
    assert_eq!(v["active"], json!({ "major": 1 }));
    let alarm_outside = store
        .list_alarms(DEFAULT_TENANT, None, Some(outside), None, 1)
        .await
        .unwrap()[0]
        .id;

    // Any path naming 1 hidden object -> same answer as unknown ID.
    // Every path of the API document, with an object of its kind.
    let (_, task) = call(
        &app,
        "POST",
        &format!("/api/v1/devices/{outside}/tasks"),
        Some(json!({ "kind": "reboot", "connection_request": false })),
        Some(admin),
    )
    .await;
    let backup = store
        .create_backup(DEFAULT_TENANT, outside, "b", &json!([]), None)
        .await
        .unwrap();
    let hidden = |path: &str| -> Option<String> {
        let id = if path.starts_with("/api/v1/devices/{id}") {
            outside.to_string()
        } else if path.starts_with("/api/v1/tasks/{id}") {
            task["id"].as_str()?.to_owned()
        } else if path.starts_with("/api/v1/config-backups/{id}") {
            backup.to_string()
        } else if path.starts_with("/api/v1/jobs/{id}") {
            wide["id"].as_str()?.to_owned()
        } else if path.starts_with("/api/v1/alarm-silences/{id}") {
            theirs["id"].as_str()?.to_owned()
        } else if path.starts_with("/api/v1/alarms/{id}") {
            alarm_outside.to_string()
        } else {
            return None;
        };
        Some(id)
    };
    let (_, doc) = call(&app, "GET", "/api/v1/openapi.json", None, None).await;
    let mut checked = 0;
    for (path, ops) in doc["paths"].as_object().unwrap() {
        let Some(id) = hidden(path) else { continue };
        for method in ops.as_object().unwrap().keys() {
            let fill = |id: &str| {
                path.replace("{id}", id)
                    .replace("{kind}", "acs_auth")
                    .replace("{action}", "pause")
            };
            let unknown = Uuid::now_v7().to_string();
            let m = method.to_uppercase();
            let (s1, v1) = call(&app, &m, &fill(&id), Some(json!({})), Some(east)).await;
            let (s2, v2) = call(&app, &m, &fill(&unknown), Some(json!({})), Some(east)).await;
            assert!(!s1.is_success(), "{m} {path} reached a hidden object: {v1}");
            assert_eq!((s1, v1), (s2, v2), "{m} {path} tells hidden from unknown");
            checked += 1;
        }
    }
    assert!(checked >= 30, "only {checked} operations checked");
    // Hidden objects untouched.
    let (_, t) = call(
        &app,
        "GET",
        &format!("/api/v1/tasks/{}", task["id"].as_str().unwrap()),
        None,
        Some(admin),
    )
    .await;
    assert_eq!(t["state"], "pending");
    let (_, v) = call(&app, "GET", "/api/v1/alarm-silences", None, Some(admin)).await;
    assert!(
        v["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|x| x["state"] == "active")
    );
    // Event stream refuses a hidden device too.
    let (s, _) = call(
        &app,
        "GET",
        &format!("/api/v1/stream?device_id={outside}"),
        None,
        Some(east),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // Audit log: scoped caller sees own actions only.
    let (_, v) = call(&app, "GET", "/api/v1/audit", None, Some(east)).await;
    let items = v["items"].as_array().unwrap();
    assert!(!items.is_empty());
    assert!(items.iter().all(|a| a["actor"] == "key:east"), "{v}");

    // Users: scope survives logins, removable with null.
    let (s, u) = call(
        &app,
        "POST",
        "/api/v1/users",
        Some(
            json!({ "username": "bob", "password": "correct horse battery", "role": "viewer",
                     "scope": { "product_class": "Box" } }),
        ),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{u}");
    assert_eq!(u["scope"], json!({ "product_class": "Box" }));
    let user = format!("/api/v1/users/{}", u["id"].as_str().unwrap());
    let (s, v) = call(
        &app,
        "PATCH",
        &user,
        Some(json!({ "role": "admin" })),
        Some(admin),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::UNPROCESSABLE_ENTITY,
        "a scoped user cannot become admin: {v}"
    );
    let (s, v) = call(
        &app,
        "PATCH",
        &user,
        Some(json!({ "role": "admin", "scope": null })),
        Some(admin),
    )
    .await;
    assert_eq!((s, &v["scope"]), (StatusCode::OK, &Value::Null), "{v}");
}

#[tokio::test]
async fn downloads_are_throttled_limited_and_logged() {
    use dhonomos_api::{DownloadLimits, FilesConfig, file_server};
    use dhonomos_core::FileSigner;

    let (_c, store, _, device) = setup(None).await;
    let dir = std::env::temp_dir().join(format!("dhonomos-files-{}", Uuid::now_v7()));
    std::fs::create_dir_all(&dir).unwrap();
    let id = Uuid::now_v7();
    let content = vec![7u8; 256 * 1024];
    std::fs::write(dir.join(id.to_string()), &content).unwrap();
    store
        .insert_file(&dhonomos_store::NewFile {
            id,
            tenant_id: DEFAULT_TENANT,
            name: "fw.bin".into(),
            file_type: "1 Firmware Upgrade Image".into(),
            size_bytes: content.len() as i64,
            sha256: vec![0; 32],
            version: None,
            device_id: None,
        })
        .await
        .unwrap();
    let signer = FileSigner::new(
        b"k".to_vec(),
        "http://files.test",
        std::time::Duration::from_secs(3600),
    );
    let path = signer
        .url(id, "fw.bin", device)
        .strip_prefix("http://files.test")
        .unwrap()
        .to_owned();
    let app = file_server(
        store.clone(),
        FilesConfig::new(
            dir.clone(),
            signer,
            1 << 20,
            DownloadLimits {
                total_rate: None,
                per_download_rate: Some(512 * 1024),
                max_concurrent: Some(1),
            },
        ),
        DEFAULT_TENANT,
        None,
    );
    let request = || Request::get(path.clone()).body(Body::empty()).unwrap();

    // 256 KiB at 512 KiB/s, 128 KiB burst -> ~0.25 s.
    let started = std::time::Instant::now();
    let resp = app.clone().oneshot(request()).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    // 1 download at a time: 2nd one waits.
    let busy = app.clone().oneshot(request()).await.unwrap();
    assert_eq!(busy.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(busy.headers()["retry-after"], "60");
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body.len(), content.len());
    let took = started.elapsed();
    assert!(
        took >= std::time::Duration::from_millis(200),
        "not throttled: {took:?}"
    );

    // Download abandoned by device -> logged incomplete, slot freed.
    let resp = app.clone().oneshot(request()).await.unwrap();
    let mut stream = resp.into_body().into_data_stream();
    use futures_util::StreamExt as _;
    stream.next().await.unwrap().unwrap();
    drop(stream);
    let mut logged = Vec::new();
    for _ in 0..50 {
        logged = store.list_events(device, 10).await.unwrap();
        if logged.iter().filter(|e| e.kind == "file_download").count() == 2 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let downloads: Vec<_> = logged
        .iter()
        .filter(|e| e.kind == "file_download")
        .collect();
    assert_eq!(downloads.len(), 2, "{logged:?}");
    assert_eq!(downloads[0].detail["complete"], json!(false));
    assert!(downloads[0].detail["bytes"].as_u64().unwrap() < content.len() as u64);
    assert_eq!(downloads[1].detail["complete"], json!(true));
    assert_eq!(downloads[1].detail["bytes"], json!(content.len()));
    assert_eq!(
        app.clone().oneshot(request()).await.unwrap().status(),
        StatusCode::OK
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Real HTTP server -> whole download logged complete.
/// hyper stops polling a body after Content-Length bytes -> stream end never seen there.
#[tokio::test]
async fn whole_download_over_http_is_logged_complete() {
    use dhonomos_api::{DownloadLimits, FilesConfig, file_server};
    use dhonomos_core::FileSigner;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let (_c, store, _, device) = setup(None).await;
    let dir = std::env::temp_dir().join(format!("dhonomos-files-{}", Uuid::now_v7()));
    std::fs::create_dir_all(&dir).unwrap();
    let id = Uuid::now_v7();
    let content = vec![9u8; 300 * 1024];
    std::fs::write(dir.join(id.to_string()), &content).unwrap();
    store
        .insert_file(&dhonomos_store::NewFile {
            id,
            tenant_id: DEFAULT_TENANT,
            name: "fw.bin".into(),
            file_type: "1 Firmware Upgrade Image".into(),
            size_bytes: content.len() as i64,
            sha256: vec![0; 32],
            version: None,
            device_id: None,
        })
        .await
        .unwrap();
    let signer = FileSigner::new(
        b"k".to_vec(),
        "http://files.test",
        std::time::Duration::from_secs(3600),
    );
    let path = signer
        .url(id, "fw.bin", device)
        .strip_prefix("http://files.test")
        .unwrap()
        .to_owned();
    let app = file_server(
        store.clone(),
        FilesConfig::new(
            dir.clone(),
            signer,
            1 << 20,
            DownloadLimits {
                total_rate: None,
                per_download_rate: None,
                max_concurrent: None,
            },
        ),
        DEFAULT_TENANT,
        None,
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    // Device plain HTTP/1.1 GET, read to the end.
    let mut tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    tcp.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: files.test\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await
    .unwrap();
    let mut response = Vec::new();
    tcp.read_to_end(&mut response).await.unwrap();
    let head_end = response.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    assert!(response.starts_with(b"HTTP/1.1 200"));
    assert_eq!(response.len() - head_end, content.len());

    let mut downloads = Vec::new();
    for _ in 0..50 {
        downloads = store
            .list_events(device, 10)
            .await
            .unwrap()
            .into_iter()
            .filter(|e| e.kind == "file_download")
            .collect();
        if !downloads.is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(downloads.len(), 1);
    assert_eq!(
        (
            &downloads[0].detail["bytes"],
            &downloads[0].detail["complete"]
        ),
        (&json!(content.len()), &json!(true))
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// File server over HTTPS (cert from files): signed `https://` link downloads via TLS.
/// TLS port does not answer plain HTTP.
#[tokio::test]
async fn signed_download_over_https() {
    use dhonomos_api::{DownloadLimits, FilesConfig, TlsListener, file_server};
    use dhonomos_core::FileSigner;
    use rustls_pki_types::{CertificateDer, ServerName};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let (_c, store, _, device) = setup(None).await;
    let dir = std::env::temp_dir().join(format!("dhonomos-files-{}", Uuid::now_v7()));
    std::fs::create_dir_all(&dir).unwrap();
    let id = Uuid::now_v7();
    let content: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(dir.join(id.to_string()), &content).unwrap();
    store
        .insert_file(&dhonomos_store::NewFile {
            id,
            tenant_id: DEFAULT_TENANT,
            name: "fw.bin".into(),
            file_type: "1 Firmware Upgrade Image".into(),
            size_bytes: content.len() as i64,
            sha256: vec![0; 32],
            version: None,
            device_id: None,
        })
        .await
        .unwrap();

    // Cert + key read from PEM files, like the binary.
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let (cert_path, key_path) = (dir.join("files-cert.pem"), dir.join("files-key.pem"));
    std::fs::write(&cert_path, ck.cert.pem()).unwrap();
    std::fs::write(&key_path, ck.signing_key.serialize_pem()).unwrap();
    let resolver = dhonomos_pki::tls::CertResolver::from_files(&cert_path, &key_path).unwrap();
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let server_config = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(server_config));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let base = format!("https://localhost:{port}");
    let signer = FileSigner::new(
        b"k".to_vec(),
        base.clone(),
        std::time::Duration::from_secs(3600),
    );
    let url = signer.url(id, "fw.bin", device);
    assert!(url.starts_with(&format!("{base}/files/")), "{url}");
    let path = url.strip_prefix(&base).unwrap().to_owned();
    let app = file_server(
        store.clone(),
        FilesConfig::new(dir.clone(), signer, 1 << 20, DownloadLimits::default()),
        DEFAULT_TENANT,
        None,
    );
    let tls_listener = TlsListener::new(listener, acceptor).unwrap();
    tokio::spawn(async move { axum::serve(tls_listener, app).await.unwrap() });

    // Device HTTPS GET of the signed link, trusts the file server cert.
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(ck.cert.der().to_vec()))
        .unwrap();
    let client_config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(client_config));
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    let mut tls = connector
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .unwrap();
    tls.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await
    .unwrap();
    let mut response = Vec::new();
    // Peer closes without close_notify -> read ends with error; data all there by then.
    let _ = tls.read_to_end(&mut response).await;
    let head_end = response.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    assert!(
        response.starts_with(b"HTTP/1.1 200"),
        "{:?}",
        &response[..head_end]
    );
    assert_eq!(&response[head_end..], &content[..]);

    // Client not trusting the cert -> no file.
    let untrusting = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(rustls::RootCertStore::empty())
    .with_no_client_auth();
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    assert!(
        tokio_rustls::TlsConnector::from(std::sync::Arc::new(untrusting))
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
            .is_err()
    );

    // Plain HTTP on TLS port -> no file.
    let mut plain = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .unwrap();
    plain
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let mut answer = Vec::new();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        plain.read_to_end(&mut answer),
    )
    .await;
    assert!(
        !answer
            .windows(content.len().min(64))
            .any(|w| w == &content[..64])
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// File server = test server of download + upload diagnostics.
/// Signed link serves exactly the signed size; upload counted + dropped.
#[tokio::test]
async fn diagnostic_test_links_on_the_file_server() {
    use dhonomos_api::{FilesConfig, file_server};
    use dhonomos_core::FileSigner;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let (_c, store, _, device) = setup(None).await;
    let dir = std::env::temp_dir().join(format!("dhonomos-files-{}", Uuid::now_v7()));
    std::fs::create_dir_all(&dir).unwrap();
    let signer = FileSigner::new(
        b"k".to_vec(),
        "http://files.test",
        std::time::Duration::from_secs(3600),
    );
    let rel = |url: String| url.strip_prefix("http://files.test").unwrap().to_owned();
    let down = rel(signer.diag_download_url(device, 200_000));
    let up = rel(signer.diag_upload_url(device));
    let app = file_server(
        store.clone(),
        FilesConfig::new(dir.clone(), signer, 1 << 20, Default::default()),
        DEFAULT_TENANT,
        None,
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let exchange = async |head: String, body: Vec<u8>| {
        let mut tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        tcp.write_all(head.as_bytes()).await.unwrap();
        tcp.write_all(&body).await.unwrap();
        let mut out = Vec::new();
        tcp.read_to_end(&mut out).await.unwrap();
        let end = out.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
        (
            String::from_utf8_lossy(&out[..end]).into_owned(),
            out.len() - end,
        )
    };
    let get = |p: &str| format!("GET {p} HTTP/1.1\r\nHost: f\r\nConnection: close\r\n\r\n");

    let (head, len) = exchange(get(&down), Vec::new()).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(len, 200_000);
    // Size is part of the signature.
    let (head, _) = exchange(get(&down.replace("/200000?", "/300000?")), Vec::new()).await;
    assert!(head.starts_with("HTTP/1.1 403"), "{head}");

    let put = |p: &str, n: usize| {
        format!("PUT {p} HTTP/1.1\r\nHost: f\r\nContent-Length: {n}\r\nConnection: close\r\n\r\n")
    };
    let (head, _) = exchange(put(&up, 150_000), vec![7u8; 150_000]).await;
    assert!(head.starts_with("HTTP/1.1 204"), "{head}");
    let (head, _) = exchange(put(&up.replace("&s=", "&s=00"), 1), vec![1]).await;
    assert!(head.starts_with("HTTP/1.1 403"), "{head}");
    // Nothing kept.
    assert!(store.list_device_files(device).await.unwrap().is_empty());
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// What a test reads back from the log.
#[derive(Clone, Default)]
struct LogBuf(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for LogBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Request refused by file server (here: wrong link signature) -> logged with source,
/// once per source, however often repeated.
#[tokio::test]
async fn a_refused_file_request_is_logged_with_the_source_address() {
    use dhonomos_api::{FilesConfig, PeerAddr, file_server};
    use dhonomos_core::FileSigner;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let logs = LogBuf::default();
    let capture = logs.clone();
    let _guard = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_ansi(false)
            .with_max_level(tracing::Level::INFO)
            .with_writer(move || capture.clone())
            .finish(),
    );
    let (_c, store, _, device) = setup(None).await;
    let dir = std::env::temp_dir().join(format!("dhonomos-files-{}", Uuid::now_v7()));
    std::fs::create_dir_all(&dir).unwrap();
    let signer = FileSigner::new(
        b"k".to_vec(),
        "http://files.test",
        std::time::Duration::from_secs(3600),
    );
    let up = signer
        .diag_upload_url(device)
        .strip_prefix("http://files.test")
        .unwrap()
        .replace("&s=", "&s=00");
    let app = file_server(
        store.clone(),
        FilesConfig::new(dir.clone(), signer, 1 << 20, Default::default()),
        DEFAULT_TENANT,
        None,
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<PeerAddr>(),
        )
        .await
        .unwrap()
    });
    // Own loopback address: log limiter shared by the process.
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.bind("127.0.0.71:0".parse().unwrap()).unwrap();
    let mut tcp = socket.connect(addr).await.unwrap();
    for _ in 0..2 {
        tcp.write_all(
            format!("PUT {up} HTTP/1.1\r\nHost: f\r\nContent-Length: 1\r\n\r\nx").as_bytes(),
        )
        .await
        .unwrap();
        let mut head = [0u8; 12];
        tcp.read_exact(&mut head).await.unwrap();
        assert_eq!(&head, b"HTTP/1.1 403", "{}", String::from_utf8_lossy(&head));
        let mut rest = [0u8; 1024];
        let _ =
            tokio::time::timeout(std::time::Duration::from_millis(100), tcp.read(&mut rest)).await;
    }
    let log = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    let lines: Vec<&str> = log.lines().filter(|l| l.contains("refused")).collect();
    assert_eq!(lines.len(), 1, "{log}");
    assert!(lines[0].contains("INFO"), "{}", lines[0]);
    assert!(
        lines[0].contains("request refused listener=files remote=127.0.0.71:"),
        "{}",
        lines[0]
    );
    assert!(lines[0].contains("reason=bad_signature"), "{}", lines[0]);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn presets_are_edited_with_revisions_and_history() {
    let (_c, store, file_mode, id) = setup(None).await;
    // Presets from a file are read-only here.
    let (s, v) = call(
        &file_mode,
        "PUT",
        "/api/v1/presets/x",
        Some(json!({ "definition": { "run": [{ "kind": "reboot" }] } })),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    let (_, v) = call(&file_mode, "GET", "/api/v1/presets", None, None).await;
    assert_eq!(v["source"], "file");

    let presets = dhonomos_core::Shared::<dhonomos_core::Presets>::default();
    let app = router(
        store.clone(),
        ApiConfig {
            tenant_id: DEFAULT_TENANT,
            presets: presets.clone(),
            presets_in_db: true,
            ..ApiConfig::default()
        },
    );
    let wifi = json!({
        "when": { "events": ["1 BOOT"] },
        "script_source": "pub fn main(d, a) { d.set(\"Device.WiFi.SSID.1.SSID\", `${a[\"prefix\"]}-${d.serial}`); }",
        "args": { "prefix": "Home" },
    });
    let put = |name: &str, body: Value| {
        let app = app.clone();
        let uri = format!("/api/v1/presets/{name}");
        async move { call(&app, "PUT", &uri, Some(body), None).await }
    };
    let (s, v) = put("wifi", json!({ "definition": wifi, "revision": 0 })).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        (v["revision"].as_i64(), v["updated_by"].as_str()),
        (Some(1), Some("anonymous"))
    );
    assert_eq!(presets.get().len(), 1, "loaded right away");
    // Create again or save stale revision -> refused.
    let (s, _) = put("wifi", json!({ "definition": wifi, "revision": 0 })).await;
    assert_eq!(s, StatusCode::CONFLICT);
    // Invalid presets never stored: script must compile, names cannot change.
    let (s, v) = put(
        "bad",
        json!({ "definition": { "script_source": "pub fn main(d, a) { let = ; }" } }),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert!(v["error"].as_str().unwrap().contains("bad"), "{v}");
    let (s, _) = put(
        "wifi",
        json!({ "definition": { "name": "other", "run": [{ "kind": "reboot" }] } }),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    let (s, v) = call(
        &app,
        "POST",
        "/api/v1/presets/validate",
        Some(json!({ "name": "t", "script": "x.rn" })),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        v["error"].as_str().unwrap().contains("script_source"),
        "{v}"
    );

    // Dry runs: stored presets or a draft.
    let dry = |body: Value| {
        let app = app.clone();
        async move {
            call(&app, "POST", "/api/v1/presets/dry-run", Some(body), None)
                .await
                .1
        }
    };
    let v = dry(json!({ "device_id": id, "events": ["1 BOOT"] })).await;
    assert_eq!(
        v["items"][0]["payload"]["values"][0]["value"], "Home-SN1",
        "{v}"
    );
    let mut draft = wifi.clone();
    draft["name"] = json!("wifi");
    draft["args"]["prefix"] = json!("Lab");
    let v = dry(json!({ "device_id": id, "events": ["1 BOOT"], "draft": draft })).await;
    assert_eq!(
        v["items"][0]["payload"]["values"][0]["value"], "Lab-SN1",
        "{v}"
    );

    // Disable -> kept, no longer matches.
    let mut off = wifi.clone();
    off["enabled"] = json!(false);
    let (s, v) = put("wifi", json!({ "definition": off, "revision": 1 })).await;
    assert_eq!(
        (s, v["enabled"].as_bool(), v["revision"].as_i64()),
        (StatusCode::OK, Some(false), Some(2))
    );
    let v = dry(json!({ "device_id": id, "events": ["1 BOOT"] })).await;
    assert_eq!(v["items"], json!([]));
    let (s, _) = put("wifi", json!({ "definition": wifi, "revision": 1 })).await;
    assert_eq!(s, StatusCode::CONFLICT, "stale revision");

    // YAML import: validated as a whole, reports what changes.
    let yaml = "presets:\n  - name: inform\n    when: { events: ['0 BOOTSTRAP'] }\n    once: true\n    run:\n      - kind: reboot\n  - name: tag-gold\n    when: { attributes: { plan: gold } }\n    script_source: 'pub fn main(d, a) { d.tag(\"gold\"); }'\n";
    let (s, v) = call(
        &app,
        "POST",
        "/api/v1/presets/import",
        Some(json!({ "yaml": yaml, "dry_run": true })),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["created"], json!(["inform", "tag-gold"]));
    assert_eq!(
        store.list_presets(DEFAULT_TENANT).await.unwrap().len(),
        1,
        "dry run"
    );
    let (_, v) = call(
        &app,
        "POST",
        "/api/v1/presets/import",
        Some(json!({ "yaml": yaml })),
        None,
    )
    .await;
    assert_eq!(v["created"], json!(["inform", "tag-gold"]));
    let (_, v) = call(
        &app,
        "POST",
        "/api/v1/presets/import",
        Some(json!({ "yaml": yaml })),
        None,
    )
    .await;
    assert_eq!(
        (&v["created"], &v["unchanged"]),
        (&json!([]), &json!(["inform", "tag-gold"]))
    );
    let (s, v) = call(
        &app,
        "POST",
        "/api/v1/presets/import",
        Some(json!({ "yaml": "presets:\n  - name: x\n" })),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert_eq!(presets.get().len(), 2, "wifi is disabled");

    // Export -> preset file that loads again.
    let (s, text) = call_text(&app, "/api/v1/presets/export.yaml", "").await;
    assert_eq!(s, StatusCode::OK);
    let back = dhonomos_core::presets::parse_list(&text).unwrap();
    assert_eq!(back.len(), 3, "{text}");
    assert!(back.iter().any(|p| p.name == "wifi" && !p.enabled));

    // History + deletion.
    let (s, _) = call(
        &app,
        "DELETE",
        "/api/v1/presets/wifi?revision=1",
        None,
        None,
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT);
    let (s, _) = call(
        &app,
        "DELETE",
        "/api/v1/presets/wifi?revision=2",
        None,
        None,
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _) = call(&app, "DELETE", "/api/v1/presets/wifi", None, None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (_, v) = call(&app, "GET", "/api/v1/presets/wifi/history", None, None).await;
    let revs: Vec<(i64, bool)> = v["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| {
            (
                c["revision"].as_i64().unwrap(),
                c["deleted"].as_bool().unwrap(),
            )
        })
        .collect();
    assert_eq!(revs, vec![(3, true), (2, false), (1, false)]);
    let audit = store
        .list_audit(DEFAULT_TENANT, &Default::default(), 20)
        .await
        .unwrap();
    for action in ["preset.save", "preset.import", "preset.delete"] {
        assert!(audit.iter().any(|a| a.action == action), "{action}");
    }

    // Other process sees the change via revision counter.
    let other = dhonomos_core::Shared::<dhonomos_core::Presets>::default();
    let watcher = tokio::spawn(dhonomos_core::presets::watch_stored(
        store.clone(),
        DEFAULT_TENANT,
        other.clone(),
        std::time::Duration::from_millis(50),
        None,
    ));
    for _ in 0..100 {
        if other.get().len() == 2 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(other.get().len(), 2);
    call(&app, "DELETE", "/api/v1/presets/inform", None, None).await;
    for _ in 0..100 {
        if other.get().len() == 1 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(other.get().len(), 1, "followed the deletion");
    watcher.abort();
}

#[tokio::test]
async fn filter_expressions_in_search_export_and_jobs() {
    let (_c, store, app, sn1) = setup(None).await;
    let sn2 = store
        .upsert_cwmp_device(
            DEFAULT_TENANT,
            &CwmpIdentity {
                oui: "001122".into(),
                product_class: "Box".into(),
                serial_number: "SN2".into(),
            },
            &InformUpdate::default(),
        )
        .await
        .unwrap()
        .id;
    store.add_tags(sn2, &["east".to_owned()]).await.unwrap();
    let enc = |f: &str| {
        f.bytes()
            .map(|b| match b {
                b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'_' | b'-' => {
                    (b as char).to_string()
                }
                _ => format!("%{b:02X}"),
            })
            .collect::<String>()
    };
    let search = |f: &str| {
        let app = app.clone();
        let uri = format!("/api/v1/devices?filter={}", enc(f));
        async move { call(&app, "GET", &uri, None, None).await }
    };
    // SN1 has Device.DeviceInfo.UpTime = 42 (setup).
    let (s, v) = search(r#"param."Device.DeviceInfo.UpTime" >= 40 or tag = east"#).await;
    assert_eq!((s, &v["total"]), (StatusCode::OK, &json!(2)), "{v}");
    let (_, v) = search("product_class = Box and not tag = east").await;
    assert_eq!(
        (v["total"].as_i64(), &v["items"][0]["id"]),
        (Some(1), &json!(sn1))
    );
    // Combined with other parameters.
    let (_, v) = call(
        &app,
        "GET",
        &format!("/api/v1/devices?q=SN2&filter={}", enc("oui = 001122")),
        None,
        None,
    )
    .await;
    assert_eq!(v["total"], 1);
    // Mistakes explained, with position.
    let (s, v) = search("product_class = Box and").await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert!(v["error"].as_str().unwrap().contains("at character"), "{v}");

    // CSV export honours it.
    let (s, csv) = call_text(
        &app,
        &format!("/api/v1/devices/export.csv?filter={}", enc("tag = east")),
        "",
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        csv.split("\r\n").filter(|l| !l.is_empty()).count(),
        2,
        "{csv}"
    );
    assert!(csv.contains("SN2"));

    // Job targets: previewed + snapshotted at job start.
    let target = json!({ "expression": "param.Device.DeviceInfo.UpTime > 10" });
    let (_, v) = call(
        &app,
        "POST",
        "/api/v1/jobs/preview",
        Some(json!({ "target": target })),
        None,
    )
    .await;
    assert_eq!(
        (v["count"].as_i64(), &v["sample"][0]["id"]),
        (Some(1), &json!(sn1)),
        "{v}"
    );
    let (s, job) = call(
        &app,
        "POST",
        "/api/v1/jobs",
        Some(json!({ "name": "uptime", "target": target, "task": { "kind": "reboot" } })),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{job}");
    assert_eq!(job["total"], 1);
    let (_, v) = call(
        &app,
        "POST",
        "/api/v1/jobs/preview",
        Some(json!({ "target": { "expression": "tag = nobody" } })),
        None,
    )
    .await;
    assert_eq!(
        v["count"], 0,
        "an expression matching nothing selects nothing"
    );
    let (s, _) = call(
        &app,
        "POST",
        "/api/v1/jobs/preview",
        Some(json!({ "target": { "expression": "colour = red" } })),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);

    // Silences keep to the fixed conditions.
    let (s, v) = call(
        &app,
        "POST",
        "/api/v1/alarm-silences",
        Some(json!({ "devices": { "expression": "tag = east" }, "duration_minutes": 5 })),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
}

#[tokio::test]
async fn audit_log_filters_and_pages() {
    let (_c, _store, app, id) = setup(None).await;
    for tags in [json!(["a"]), json!(["b"]), json!(["c"])] {
        call(
            &app,
            "PATCH",
            &format!("/api/v1/devices/{id}"),
            Some(json!({ "tags": tags })),
            None,
        )
        .await;
    }
    call(
        &app,
        "POST",
        "/api/v1/jobs",
        Some(json!({ "name": "r", "target": {}, "task": { "kind": "reboot" }, "start": false })),
        None,
    )
    .await;
    let get = |q: &str| {
        let app = app.clone();
        let uri = format!("/api/v1/audit?{q}");
        async move { call(&app, "GET", &uri, None, None).await }
    };
    let (_, v) = get("action=device.").await;
    let items = v["items"].as_array().unwrap().clone();
    assert_eq!(items.len(), 3, "{v}");
    assert!(items.iter().all(|a| a["action"] == "device.update"));
    let (_, v) = get(&format!("target={id}&limit=2")).await;
    assert_eq!(v["items"].as_array().unwrap().len(), 2);
    // Next page continues below the last ID.
    let last = v["items"][1]["id"].as_i64().unwrap();
    let (_, v) = get(&format!("target={id}&before={last}")).await;
    assert_eq!(v["items"].as_array().unwrap().len(), 1);
    assert!(v["items"][0]["id"].as_i64().unwrap() < last);
    let (_, v) = get("actor=anonymous&action=job.").await;
    assert_eq!(v["items"][0]["action"], "job.create");
    let (_, v) = get("actor=nobody").await;
    assert_eq!(v["items"], json!([]));
    // `%` in the prefix is literal.
    let (_, v) = get("action=%25").await;
    assert_eq!(v["items"], json!([]));
    let (_, v) = get("since=2999-01-01T00:00:00Z").await;
    assert_eq!(v["items"], json!([]));
    let (s, _) = get("since=yesterday").await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn audit_log_is_shipped_in_order_and_resumes() {
    use dhonomos_core::audit_export::{AuditSink, ship_once};
    use std::sync::atomic::{AtomicBool, Ordering};
    let (_c, store, _app, _id) = setup(None).await;
    for i in 0..3 {
        store
            .record_audit(
                DEFAULT_TENANT,
                "alice",
                "device.update",
                "device",
                Some("d1"),
                &json!({ "n": i }),
            )
            .await
            .unwrap();
    }
    let (tx, mut rx) = tokio::sync::mpsc::channel::<(String, String)>(8);
    let fail_first = std::sync::Arc::new(AtomicBool::new(true));
    let hook = axum::Router::new().route(
        "/audit",
        axum::routing::post({
            let fail_first = fail_first.clone();
            move |headers: axum::http::HeaderMap, body: String| {
                let tx = tx.clone();
                let fail = fail_first.swap(false, Ordering::SeqCst);
                async move {
                    if fail {
                        return StatusCode::SERVICE_UNAVAILABLE;
                    }
                    let sig = headers["x-dhonomos-signature"].to_str().unwrap().to_owned();
                    tx.send((sig, body)).await.unwrap();
                    StatusCode::NO_CONTENT
                }
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, hook).await });
    let sink = AuditSink {
        url: format!("http://{addr}/audit"),
        secret: "k".into(),
    };

    // Receiver fails -> nothing counts as shipped.
    assert!(ship_once(&store, DEFAULT_TENANT, &sink).await.is_err());
    assert_eq!(
        store
            .audit_export_position(DEFAULT_TENANT, &sink.url)
            .await
            .unwrap(),
        0
    );
    // Then all sent, in order, signed.
    assert_eq!(ship_once(&store, DEFAULT_TENANT, &sink).await.unwrap(), 3);
    let (sig, body) = rx.recv().await.unwrap();
    assert_eq!(sig, dhonomos_core::webhook::signature("k", &body));
    let v: Value = serde_json::from_str(&body).unwrap();
    let ns: Vec<i64> = v["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["detail"]["n"].as_i64().unwrap())
        .collect();
    assert_eq!(ns, vec![0, 1, 2]);
    assert_eq!(v["records"][0]["actor"], "alice");
    // Caught up -> nothing more; new record sent on its own.
    assert_eq!(ship_once(&store, DEFAULT_TENANT, &sink).await.unwrap(), 0);
    store
        .record_audit(
            DEFAULT_TENANT,
            "bob",
            "preset.save",
            "preset",
            Some("wifi"),
            &json!({}),
        )
        .await
        .unwrap();
    assert_eq!(ship_once(&store, DEFAULT_TENANT, &sink).await.unwrap(), 1);
    let (_, body) = rx.recv().await.unwrap();
    assert!(
        body.contains("preset.save") && !body.contains("device.update"),
        "{body}"
    );
}

#[tokio::test]
async fn web_hardening_headers_origin_and_last_admin() {
    let (_c, _store, app, id) = setup(None).await;
    // Security headers on API + UI responses; API bodies not cached.
    let resp = app
        .clone()
        .oneshot(Request::get("/api/v1/devices").body(Body::empty()).unwrap())
        .await
        .unwrap();
    let h = resp.headers();
    assert_eq!(h["x-frame-options"], "DENY");
    assert_eq!(h["x-content-type-options"], "nosniff");
    assert_eq!(h["referrer-policy"], "no-referrer");
    assert_eq!(
        h["content-security-policy"],
        "default-src 'none'; frame-ancestors 'none'"
    );
    assert_eq!(h["cache-control"], "no-store");

    // First admin, then sessions.
    call(
        &app,
        "POST",
        "/api/v1/users",
        Some(json!({ "username": "root", "password": "correct horse battery", "role": "admin" })),
        None,
    )
    .await;
    let (_, _, cookie) = call_cookie(
        &app,
        "POST",
        "/api/v1/auth/login",
        Some(json!({ "username": "root", "password": "correct horse battery" })),
        None,
    )
    .await;
    let session = cookie.unwrap().split(';').next().unwrap().to_owned();
    let send = |origin: Option<&'static str>, fwd: Option<&'static str>| {
        let app = app.clone();
        let session = session.clone();
        async move {
            let mut req = Request::post(format!("/api/v1/devices/{id}/tasks"))
                .header("host", "acs.example.net")
                .header("cookie", session)
                .header("content-type", "application/json");
            if let Some(o) = origin {
                req = req.header("origin", o);
            }
            if let Some(f) = fwd {
                req = req.header("x-forwarded-host", f);
            }
            let body =
                Body::from(json!({ "kind": "reboot", "connection_request": false }).to_string());
            app.oneshot(req.body(body).unwrap()).await.unwrap().status()
        }
    };
    assert_eq!(
        send(Some("https://evil.example"), None).await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(send(Some("null"), None).await, StatusCode::FORBIDDEN);
    assert_eq!(
        send(Some("https://acs.example.net"), None).await,
        StatusCode::CREATED
    );
    assert_eq!(
        send(None, None).await,
        StatusCode::CREATED,
        "non-browser clients send no Origin"
    );
    // X-Forwarded-Host vouches for an Origin only if a trusted proxy sent it (ADR-103).
    // Here no trusted proxy -> anyone could have written it.
    assert_eq!(
        send(Some("https://ops.example.net"), Some("ops.example.net")).await,
        StatusCode::FORBIDDEN
    );

    // Last enabled admin: cannot be removed, disabled or demoted.
    let (_, users, _) = call_cookie(&app, "GET", "/api/v1/users", None, Some(&session)).await;
    let root = users["items"][0]["id"].as_str().unwrap().to_owned();
    for (method, body) in [
        ("PATCH", Some(json!({ "role": "operator" }))),
        ("PATCH", Some(json!({ "disabled": true }))),
        ("DELETE", None),
    ] {
        let (s, v, _) = call_cookie(
            &app,
            method,
            &format!("/api/v1/users/{root}"),
            body,
            Some(&session),
        )
        .await;
        assert_eq!(s, StatusCode::CONFLICT, "{method}: {v}");
    }
    // With a 2nd admin -> allowed.
    call_cookie(
        &app,
        "POST",
        "/api/v1/users",
        Some(json!({ "username": "second", "password": "correct horse battery", "role": "admin" })),
        Some(&session),
    )
    .await;
    let (s, _, _) = call_cookie(
        &app,
        "PATCH",
        &format!("/api/v1/users/{root}"),
        Some(json!({ "role": "operator" })),
        Some(&session),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
}

/// Account made outside this process (other API instance) -> open dev mode closed at once.
/// Cached "no accounts" must not keep it open (audit M-1).
#[tokio::test]
async fn accounts_made_elsewhere_close_the_open_api() {
    let (_c, store, app, _) = setup(None).await;
    let (s, _) = call(&app, "GET", "/api/v1/devices", None, None).await;
    assert_eq!(s, StatusCode::OK, "no accounts yet: open");
    let (s, _) = call(&app, "GET", "/api/v1/devices", None, None).await;
    assert_eq!(s, StatusCode::OK);
    store
        .create_user(DEFAULT_TENANT, "made-elsewhere", "!sso", "viewer")
        .await
        .unwrap();
    let (s, v) = call(&app, "GET", "/api/v1/devices", None, None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "{v}");
}

const SECRETS_KEY: &str = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";

fn secret_box() -> std::sync::Arc<dhonomos_core::SecretBox> {
    std::sync::Arc::new(dhonomos_core::SecretBox::from_base64(SECRETS_KEY, "k1").unwrap())
}

/// Secrets in `values[]`: masked in every output, ciphertext bound to its task (+ job),
/// callers cannot submit ciphertext (audit M-3).
#[tokio::test]
async fn secret_values_are_masked_bound_to_their_row_and_never_taken_as_input() {
    use dhonomos_core::secrets::{job_context, task_context};
    let (_c, store, _, id) = setup(None).await;
    let secrets = secret_box();
    let app = router(
        store.clone(),
        ApiConfig {
            tenant_id: DEFAULT_TENANT,
            secrets: Some(secrets.clone()),
            ..ApiConfig::default()
        },
    );
    let tasks = format!("/api/v1/devices/{id}/tasks");
    let spv = |value: &str| {
        json!({ "kind": "set_parameter_values", "payload": { "values": [
            { "name": "Device.WiFi.AccessPoint.1.Security.KeyPassphrase",
              "value": value, "secret": true },
            { "name": "Device.WiFi.SSID.1.SSID", "value": "visible" },
        ] } })
    };
    let (s, v) = call(&app, "POST", &tasks, Some(spv("wifi-s3cret")), None).await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    assert_eq!(v["payload"]["values"][0]["value"], "********");
    assert_eq!(v["payload"]["values"][1]["value"], "visible");
    let task_id: Uuid = v["id"].as_str().unwrap().parse().unwrap();

    // Not in task output, job-independent lists or audit trail, not even as ciphertext.
    let (_, one) = call(&app, "GET", &format!("/api/v1/tasks/{task_id}"), None, None).await;
    let (_, list) = call(&app, "GET", &tasks, None, None).await;
    let (_, audit) = call(&app, "GET", "/api/v1/audit", None, None).await;
    for out in [&v, &one, &list, &audit] {
        let out = out.to_string();
        assert!(
            !out.contains("wifi-s3cret") && !out.contains("enc:"),
            "{out}"
        );
    }
    assert_eq!(one["payload"]["values"][0]["value"], "********");

    // Sealed for this task: ciphertext opens nowhere else.
    let stored = store.get_task(task_id).await.unwrap().unwrap().payload;
    let sealed = stored["values"][0]["value"].as_str().unwrap().to_owned();
    assert!(sealed.starts_with("enc:v2:"), "{sealed}");
    let mut opened = stored.clone();
    secrets
        .decrypt_fields(&mut opened, &task_context(task_id))
        .unwrap();
    assert_eq!(opened["values"][0]["value"], "wifi-s3cret");
    let mut elsewhere = stored.clone();
    assert!(
        secrets
            .decrypt_fields(&mut elsewhere, &task_context(Uuid::now_v7()))
            .is_err()
    );

    // Ciphertext never accepted as input, either form, tasks or jobs.
    for bad in [
        sealed.as_str(),
        "enc:v1:AAAAAAAAAAAAAAAAAAAAAAAA",
        "enc:anything",
    ] {
        let (s, v) = call(&app, "POST", &tasks, Some(spv(bad)), None).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
        assert!(v["error"].as_str().unwrap().contains("enc:"), "{v}");
        let download = json!({ "kind": "download",
            "payload": { "url": "http://f/x.bin", "password": bad } });
        let (s, v) = call(&app, "POST", &tasks, Some(download.clone()), None).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
        let job = json!({ "name": "copy", "target": { "oui": "001122" }, "task": download });
        let (s, v) = call(&app, "POST", "/api/v1/jobs", Some(job), None).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    }
    let (_, list) = call(&app, "GET", &tasks, None, None).await;
    assert_eq!(
        list["items"].as_array().unwrap().len(),
        1,
        "nothing was queued"
    );

    // Job: masked, sealed for the job, sealed again for each member's task.
    let job = json!({ "name": "fw", "target": { "oui": "001122" }, "start": true,
        "task": { "kind": "download",
                  "payload": { "url": "http://f/x.bin", "username": "u", "password": "hunter2" } } });
    let (s, v) = call(&app, "POST", "/api/v1/jobs", Some(job.clone()), None).await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    assert_eq!(v["task"]["payload"]["password"], "********");
    let job_id: Uuid = v["id"].as_str().unwrap().parse().unwrap();
    let (_, listed) = call(&app, "GET", "/api/v1/jobs", None, None).await;
    let (_, audit) = call(&app, "GET", "/api/v1/audit", None, None).await;
    for out in [&v, &listed, &audit] {
        assert!(!out.to_string().contains("hunter2") && !out.to_string().contains("enc:"));
    }
    let mut payload = store.get_job(job_id).await.unwrap().unwrap().task_payload;
    assert!(payload["password"].as_str().unwrap().starts_with("enc:v2:"));
    let sealed_for_job = payload.clone();
    secrets
        .decrypt_fields(&mut payload, &job_context(job_id))
        .unwrap();
    assert_eq!(payload["password"], "hunter2");
    let mut as_task = sealed_for_job.clone();
    assert!(
        secrets
            .decrypt_fields(&mut as_task, &task_context(task_id))
            .is_err()
    );

    let engine = dhonomos_jobs::Engine::new(store.clone(), None, std::time::Duration::from_secs(1))
        .with_secrets(secrets.clone());
    engine.tick_job(job_id).await.unwrap();
    let member = store
        .list_tasks(id, 10)
        .await
        .unwrap()
        .into_iter()
        .find(|t| t.job_id == Some(job_id))
        .expect("dispatched");
    assert_ne!(member.payload, sealed_for_job, "not the job's ciphertext");
    let mut for_task = member.payload.clone();
    secrets
        .decrypt_fields(&mut for_task, &task_context(member.id))
        .unwrap();
    assert_eq!(for_task["password"], "hunter2");
    let mut wrong = member.payload.clone();
    assert!(
        secrets
            .decrypt_fields(&mut wrong, &job_context(job_id))
            .is_err()
    );

    // Engine that cannot open the secrets -> job paused, secrets not passed on.
    let (s, v) = call(&app, "POST", "/api/v1/jobs", Some(job), None).await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    let blind_job: Uuid = v["id"].as_str().unwrap().parse().unwrap();
    let blind = dhonomos_jobs::Engine::new(store.clone(), None, std::time::Duration::from_secs(1));
    blind.tick_job(blind_job).await.unwrap();
    let (_, v) = call(
        &app,
        "GET",
        &format!("/api/v1/jobs/{blind_job}"),
        None,
        None,
    )
    .await;
    assert_eq!(v["state"], "paused", "{v}");
    assert!(v["reason"].as_str().unwrap().contains("secrets"), "{v}");
    assert!(
        store
            .list_tasks(id, 10)
            .await
            .unwrap()
            .iter()
            .all(|t| t.job_id != Some(blind_job))
    );
}

fn temp_files() -> (dhonomos_api::FilesConfig, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("dhonomos-files-{}", Uuid::now_v7()));
    std::fs::create_dir_all(&dir).unwrap();
    let files = dhonomos_api::FilesConfig::new(
        dir.clone(),
        dhonomos_core::FileSigner::new(
            b"k".to_vec(),
            "http://files.test",
            std::time::Duration::from_secs(3600),
        ),
        1 << 20,
        Default::default(),
    );
    (files, dir)
}

/// IDs of the files `GET /files` shows `token`, sorted.
async fn file_ids(app: &Router, token: &str) -> Vec<String> {
    let (s, v) = call(app, "GET", "/api/v1/files", None, Some(token)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let mut ids: Vec<String> = v["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["id"].as_str().unwrap().to_owned())
        .collect();
    ids.sort();
    ids
}

/// Device upload -> back to that device only, hidden from callers whose scope
/// excludes the device, deleted with it (audit M-2, L-7).
#[tokio::test]
async fn device_uploaded_files_stay_with_their_device() {
    let admin = "admin-token";
    let (_c, store, _, outside) = setup(Some(admin)).await;
    let inside = store
        .upsert_cwmp_device(
            DEFAULT_TENANT,
            &CwmpIdentity {
                oui: "001122".into(),
                product_class: "Box".into(),
                serial_number: "SN2".into(),
            },
            &InformUpdate::default(),
        )
        .await
        .unwrap()
        .id;
    store.add_tags(inside, &["east".into()]).await.unwrap();
    let (files, dir) = temp_files();
    let app = router(
        store.clone(),
        ApiConfig {
            bearer_token: Some(admin.into()),
            tenant_id: DEFAULT_TENANT,
            files: Some(files),
            ..ApiConfig::default()
        },
    );
    let (s, k) = call(
        &app,
        "POST",
        "/api/v1/api-keys",
        Some(json!({ "name": "east", "role": "operator", "scope": { "tags": ["east"] } })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{k}");
    let east = k["key"].as_str().unwrap().to_owned();
    let east = east.as_str();

    // Config backup of each device + 1 firmware image.
    let mut ids = Vec::new();
    for (name, device) in [
        ("outside.cfg", Some(outside)),
        ("inside.cfg", Some(inside)),
        ("fw.bin", None),
    ] {
        let id = Uuid::now_v7();
        std::fs::write(dir.join(id.to_string()), b"secret").unwrap();
        store
            .insert_file(&dhonomos_store::NewFile {
                id,
                tenant_id: DEFAULT_TENANT,
                name: name.into(),
                file_type: "3 Vendor Configuration File".into(),
                size_bytes: 6,
                sha256: vec![0; 32],
                version: None,
                device_id: device,
            })
            .await
            .unwrap();
        ids.push(id);
    }
    let [outside_cfg, inside_cfg, firmware] = ids[..] else {
        panic!("three files")
    };

    // GET /files: scoped caller does not see (or learn the serial of) the outside device's.
    let sorted = |v: &[Uuid]| {
        let mut v: Vec<String> = v.iter().map(Uuid::to_string).collect();
        v.sort();
        v
    };
    assert_eq!(file_ids(&app, east).await, sorted(&[inside_cfg, firmware]));
    assert_eq!(
        file_ids(&app, admin).await,
        sorted(&[outside_cfg, inside_cfg, firmware])
    );

    // Tasks: other device's file refused, for scoped callers + admins alike.
    let download = |file: Uuid| json!({ "kind": "download", "payload": { "file_id": file } });
    let inside_tasks = format!("/api/v1/devices/{inside}/tasks");
    for token in [east, admin] {
        let (s, v) = call(
            &app,
            "POST",
            &inside_tasks,
            Some(download(outside_cfg)),
            Some(token),
        )
        .await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
        assert!(
            v["error"]
                .as_str()
                .unwrap()
                .contains("uploaded by a device"),
            "{v}"
        );
    }
    for file in [inside_cfg, firmware] {
        let (s, v) = call(
            &app,
            "POST",
            &inside_tasks,
            Some(download(file)),
            Some(east),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED, "{v}");
    }
    // Own backup -> back to its source device.
    let (s, v) = call(
        &app,
        "POST",
        &format!("/api/v1/devices/{outside}/tasks"),
        Some(download(outside_cfg)),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{v}");

    // Jobs: only with a target of exactly that device.
    let job = |file: Uuid, target: Value| json!({ "name": "restore", "target": target, "task": download(file), "start": false });
    let (s, v) = call(
        &app,
        "POST",
        "/api/v1/jobs",
        Some(job(inside_cfg, json!({ "tags": ["east"] }))),
        Some(east),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    let (s, v) = call(
        &app,
        "POST",
        "/api/v1/jobs",
        Some(job(outside_cfg, json!({ "device_ids": [inside] }))),
        Some(east),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    let (s, v) = call(
        &app,
        "POST",
        "/api/v1/jobs",
        Some(job(inside_cfg, json!({ "device_ids": [inside] }))),
        Some(east),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    let (s, v) = call(
        &app,
        "POST",
        "/api/v1/jobs",
        Some(job(firmware, json!({ "tags": ["east"] }))),
        Some(east),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{v}");

    // Device delete -> its uploads deleted, content included; rest stays.
    let device_uri = format!("/api/v1/devices/{outside}");
    let (s, _) = call(
        &app,
        "PATCH",
        &device_uri,
        Some(json!({ "status": "retired" })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = call(&app, "DELETE", &device_uri, None, Some(admin)).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert!(store.get_file(outside_cfg).await.unwrap().is_none());
    assert!(!dir.join(outside_cfg.to_string()).exists());
    assert!(store.get_file(inside_cfg).await.unwrap().is_some());
    assert!(dir.join(inside_cfg.to_string()).exists());
    assert!(store.get_file(firmware).await.unwrap().is_some());
    assert_eq!(file_ids(&app, admin).await, sorted(&[inside_cfg, firmware]));
    let _ = std::fs::remove_dir_all(dir);
}

/// Viewers see the upload target, not the signed link that lets anyone write to it.
/// No fetch of the non-expiring BulkData link (audit L-8).
#[tokio::test]
async fn viewers_do_not_get_write_links() {
    let admin = "admin-token";
    let (_c, store, _, id) = setup(Some(admin)).await;
    let (files, dir) = temp_files();
    let app = router(
        store.clone(),
        ApiConfig {
            bearer_token: Some(admin.into()),
            tenant_id: DEFAULT_TENANT,
            files: Some(files),
            ..ApiConfig::default()
        },
    );
    let mut keys = Vec::new();
    for role in ["viewer", "operator"] {
        let (s, k) = call(
            &app,
            "POST",
            "/api/v1/api-keys",
            Some(json!({ "name": role, "role": role })),
            Some(admin),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED, "{k}");
        keys.push(k["key"].as_str().unwrap().to_owned());
    }
    let (viewer, operator) = (keys[0].as_str(), keys[1].as_str());

    let (s, v) = call(
        &app,
        "POST",
        &format!("/api/v1/devices/{id}/config-files"),
        None,
        Some(operator),
    )
    .await;
    assert_eq!(s, StatusCode::ACCEPTED, "{v}");
    let task = v["task_id"].as_str().unwrap().to_owned();
    let signed = store
        .get_task(task.parse().unwrap())
        .await
        .unwrap()
        .unwrap()
        .payload["url"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(signed.contains("&s=") || signed.contains("?s="), "{signed}");
    let signature = signed.rsplit("s=").next().unwrap();
    for token in [viewer, operator, admin] {
        let (_, t) = call(
            &app,
            "GET",
            &format!("/api/v1/tasks/{task}"),
            None,
            Some(token),
        )
        .await;
        let shown = t["payload"]["url"].as_str().unwrap();
        assert!(shown.starts_with("http://files.test/uploads/"), "{shown}");
        assert!(shown.ends_with("?********"), "{shown}");
        let (_, list) = call(
            &app,
            "GET",
            &format!("/api/v1/devices/{id}/tasks"),
            None,
            Some(token),
        )
        .await;
        assert!(!list.to_string().contains(signature), "{list}");
    }
    let (_, audit) = call(&app, "GET", "/api/v1/audit", None, Some(admin)).await;
    assert!(!audit.to_string().contains(signature));

    let bulkdata = format!("/api/v1/devices/{id}/bulkdata-url");
    let (s, v) = call(&app, "GET", &bulkdata, None, Some(viewer)).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    assert!(!v.to_string().contains("bulkdata/"));
    let (s, v) = call(&app, "GET", &bulkdata, None, Some(operator)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(v["url"].as_str().unwrap().contains("/bulkdata/"));
    let _ = std::fs::remove_dir_all(dir);
}

// ---------------------------------------------------------------------------
// Audit 2026-10-11: preset secrets (NEW-1), signed links in task payloads (NEW-2),
// uploads and diagnostic links (L-9, L-10), single sign-on (L-11), public routes (L-12),
// credential lifecycle (L-13).
// ---------------------------------------------------------------------------

/// Preset with a Wi-Fi passphrase (`values[]` entry marked `secret`) + a file server
/// password in 2 tasks.
fn secret_preset(ssid: &str, wifi: &str, file_pw: &str) -> Value {
    json!({
        "when": { "events": ["1 BOOT"] },
        "run": [
            { "kind": "set_parameter_values", "payload": { "values": [
                { "name": "Device.WiFi.AccessPoint.1.Security.KeyPassphrase",
                  "value": wifi, "secret": true },
                { "name": "Device.WiFi.SSID.1.SSID", "value": ssid },
            ] } },
            { "kind": "download", "payload": {
                "url": "http://f/fw.bin", "username": "dl", "password": file_pw } },
        ],
    })
}

/// Preset secrets write-only: sealed at rest for their row, masked in every output
/// (list, one, history, export, audit, dry runs), kept by sending the mask back,
/// sealed again for each task a preset queues.
#[tokio::test]
async fn preset_secrets_are_sealed_masked_and_kept_by_the_mask() {
    use dhonomos_core::secrets::{preset_context, task_context};
    let admin = "admin-token";
    let (_c, store, _, device) = setup(Some(admin)).await;
    let secrets = secret_box();
    let presets = dhonomos_core::Shared::<dhonomos_core::Presets>::default();
    let app = router(
        store.clone(),
        ApiConfig {
            bearer_token: Some(admin.into()),
            tenant_id: DEFAULT_TENANT,
            secrets: Some(secrets.clone()),
            presets: presets.clone(),
            presets_in_db: true,
            ..ApiConfig::default()
        },
    );
    let (s, k) = call(
        &app,
        "POST",
        "/api/v1/api-keys",
        Some(json!({ "name": "viewer", "role": "viewer" })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{k}");
    let viewer = k["key"].as_str().unwrap().to_owned();
    let put = |name: &str, definition: Value, revision: i64| {
        let (app, uri) = (app.clone(), format!("/api/v1/presets/{name}"));
        async move {
            call(
                &app,
                "PUT",
                &uri,
                Some(json!({ "definition": definition, "revision": revision })),
                Some(admin),
            )
            .await
        }
    };
    let import = |yaml: &str| {
        let (app, yaml) = (app.clone(), yaml.to_owned());
        async move {
            call(
                &app,
                "POST",
                "/api/v1/presets/import",
                Some(json!({ "yaml": yaml })),
                Some(admin),
            )
            .await
        }
    };

    // No --secrets-key -> preset with a password refused, like a task with one.
    let keyless = router(
        store.clone(),
        ApiConfig {
            bearer_token: Some(admin.into()),
            tenant_id: DEFAULT_TENANT,
            presets_in_db: true,
            ..ApiConfig::default()
        },
    );
    let (s, v) = call(
        &keyless,
        "PUT",
        "/api/v1/presets/wifi",
        Some(json!({ "definition": secret_preset("Home", "wifi-s3cret", "file-pw") })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert!(
        v["error"].as_str().unwrap().contains("--secrets-key"),
        "{v}"
    );
    assert!(store.list_presets(DEFAULT_TENANT).await.unwrap().is_empty());
    let (s, _) = call(
        &keyless,
        "PUT",
        "/api/v1/presets/plain",
        Some(json!({ "definition": { "run": [{ "kind": "reboot" }] } })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "no secret, no key needed");
    call(
        &keyless,
        "DELETE",
        "/api/v1/presets/plain",
        None,
        Some(admin),
    )
    .await;

    // Create: answer already shows the mask.
    let (s, v) = put("wifi", secret_preset("Home", "wifi-s3cret", "file-pw"), 0).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let secret_slots = |def: &Value| {
        (
            def["run"][0]["payload"]["values"][0]["value"].clone(),
            def["run"][1]["payload"]["password"].clone(),
        )
    };
    assert_eq!(
        secret_slots(&v["definition"]),
        (json!("********"), json!("********"))
    );
    assert_eq!(
        v["definition"]["run"][0]["payload"]["values"][1]["value"],
        "Home"
    );
    assert_eq!(v["definition"]["run"][1]["payload"]["username"], "dl");

    // Viewer never sees a secret, in any output.
    let outputs = async || {
        let uri = |p: &str| format!("/api/v1/presets{p}");
        let (_, list) = call(&app, "GET", &uri(""), None, Some(&viewer)).await;
        let (_, one) = call(&app, "GET", &uri("/wifi"), None, Some(&viewer)).await;
        let (_, history) = call(&app, "GET", &uri("/wifi/history"), None, Some(&viewer)).await;
        let (_, yaml) = call_text(&app, &uri("/export.yaml"), &viewer).await;
        let (_, audit) = call(&app, "GET", "/api/v1/audit", None, Some(&viewer)).await;
        let (_, dry) = call_json(
            &app,
            "POST",
            &uri("/dry-run"),
            json!({ "device_id": device, "events": ["1 BOOT"] }),
            admin,
        )
        .await;
        let draft = json!({ "device_id": device, "events": ["1 BOOT"], "draft": {
            "name": "wifi", "when": { "events": ["1 BOOT"] },
            "run": [{ "kind": "download", "payload": { "url": "http://f/x", "password": "draft-pw" } }] } });
        let (_, dry_draft) = call_json(&app, "POST", &uri("/dry-run"), draft, admin).await;
        [
            list.to_string(),
            one.to_string(),
            history.to_string(),
            yaml,
            audit.to_string(),
            dry.to_string(),
            dry_draft.to_string(),
        ]
    };
    let shown = outputs().await;
    for out in &shown {
        for secret in ["wifi-s3cret", "file-pw", "draft-pw", "enc:"] {
            assert!(!out.contains(secret), "{secret} in {out}");
        }
    }
    assert!(
        shown[0].contains("********") && shown[3].contains("********"),
        "{shown:?}"
    );
    assert!(shown[5].contains("********"), "dry run: {}", shown[5]);

    // At rest: sealed for the row; history keeps no ciphertext at all.
    let row = store.list_presets(DEFAULT_TENANT).await.unwrap().remove(0);
    let text = row.definition.to_string();
    assert!(
        !text.contains("wifi-s3cret") && !text.contains("file-pw"),
        "{text}"
    );
    assert_eq!(text.matches("enc:v2:").count(), 2, "{text}");
    let opened = |def: &Value, id: Uuid| {
        let mut spv = def["run"][0]["payload"].clone();
        secrets
            .decrypt_fields(&mut spv, &preset_context(id, 0))
            .unwrap();
        let mut dl = def["run"][1]["payload"].clone();
        secrets
            .decrypt_fields(&mut dl, &preset_context(id, 1))
            .unwrap();
        (spv["values"][0]["value"].clone(), dl["password"].clone())
    };
    assert_eq!(
        opened(&row.definition, row.id),
        (json!("wifi-s3cret"), json!("file-pw"))
    );
    let history = store
        .preset_history(DEFAULT_TENANT, "wifi", 10)
        .await
        .unwrap();
    assert!(
        !history[0]
            .definition
            .as_ref()
            .unwrap()
            .to_string()
            .contains("enc:")
    );
    let mut elsewhere = row.definition["run"][1]["payload"].clone();
    assert!(
        secrets
            .decrypt_fields(&mut elsewhere, &preset_context(Uuid::now_v7(), 1))
            .is_err(),
        "the ciphertext is bound to its preset"
    );

    // Edit with mask -> stored value kept (+ the preset's row).
    let (_, current) = call(&app, "GET", "/api/v1/presets/wifi", None, Some(admin)).await;
    let mut edit = current["definition"].clone();
    edit["run"][0]["payload"]["values"][1]["value"] = json!("Home2");
    let (s, v) = put("wifi", edit, 1).await;
    assert_eq!(
        (s, v["revision"].as_i64()),
        (StatusCode::OK, Some(2)),
        "{v}"
    );
    let kept = store.list_presets(DEFAULT_TENANT).await.unwrap().remove(0);
    assert_eq!(kept.id, row.id);
    assert_eq!(
        opened(&kept.definition, kept.id),
        (json!("wifi-s3cret"), json!("file-pw"))
    );
    assert_eq!(
        kept.definition["run"][0]["payload"]["values"][1]["value"],
        "Home2"
    );

    // Change 1 secret -> other one kept.
    let mut edit = v["definition"].clone();
    edit["run"][1]["payload"]["password"] = json!("new-pw");
    let (s, v) = put("wifi", edit, 2).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let changed = store.list_presets(DEFAULT_TENANT).await.unwrap().remove(0);
    assert_eq!(
        opened(&changed.definition, changed.id),
        (json!("wifi-s3cret"), json!("new-pw"))
    );

    // Mask where nothing stored -> refused, says where; same for ciphertext.
    let mut edit = v["definition"].clone();
    edit["run"].as_array_mut().unwrap().push(json!({ "kind": "upload", "payload": {
        "file_type": "1 Vendor Configuration File", "url": "http://f/up", "password": "********" } }));
    let (s, v) = put("wifi", edit, 3).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert!(
        v["error"].as_str().unwrap().contains("run[2].password"),
        "{v}"
    );
    // Mask keeps stored secret only while task sends it to the same place (X-8).
    // Changed URL, task kind or parameter name -> secret needed again.
    let (_, current) = call(&app, "GET", "/api/v1/presets/wifi", None, Some(admin)).await;
    type Change = fn(&mut Value);
    let cases: [(&str, Change, &str, &str); 4] = [
        (
            "another server",
            |d| d["run"][1]["payload"]["url"] = json!("http://evil.example/fw.bin"),
            "run[1].password",
            "the URL changed",
        ),
        (
            "another path",
            |d| d["run"][1]["payload"]["url"] = json!("http://f/elsewhere.bin"),
            "run[1].password",
            "the URL changed",
        ),
        (
            "another kind of task",
            |d| d["run"][1]["kind"] = json!("upload"),
            "run[1].password",
            "the task kind changed",
        ),
        (
            "another parameter",
            |d| {
                d["run"][0]["payload"]["values"][0]["name"] = json!("Device.WiFi.SSID.1.SSID");
            },
            "run[0].values[0].value",
            "the parameter name changed",
        ),
    ];
    for (label, change, slot, reason) in cases {
        let mut edit = current["definition"].clone();
        change(&mut edit);
        let (s, v) = put("wifi", edit, 3).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{label}: {v}");
        assert_eq!(
            v["error"].as_str(),
            Some(format!("re-enter the secret for {slot}: {reason}").as_str()),
            "{label}"
        );
    }
    // Typing the secret again -> new destination accepted.
    // Fields that do not decide the destination: free to change, mask kept.
    let mut edit = current["definition"].clone();
    edit["run"][1]["payload"]["username"] = json!("other-user");
    let (s, v) = put("wifi", edit, 3).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let mut edit = v["definition"].clone();
    edit["run"][1]["payload"]["url"] = json!("http://f/moved.bin");
    edit["run"][1]["payload"]["password"] = json!("new-pw");
    let (s, v) = put("wifi", edit, 4).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let mut edit = v["definition"].clone();
    edit["run"][1]["payload"]["url"] = json!("http://f/fw.bin");
    edit["run"][1]["payload"]["password"] = json!("new-pw");
    let (s, v) = put("wifi", edit, 5).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["revision"].as_i64(), Some(6));
    let (s, v) = put("wifi", secret_preset("Home", "enc:v2:AAAA", "x"), 6).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    let (s, v) = put("copy", secret_preset("Home", "********", "x"), 0).await;
    assert_eq!(
        s,
        StatusCode::UNPROCESSABLE_ENTITY,
        "a new preset has nothing to keep: {v}"
    );
    assert_eq!(store.list_presets(DEFAULT_TENANT).await.unwrap().len(), 1);

    // Import: masked export of same presets -> no change; edited -> secrets kept;
    // as new preset -> refused as a whole; plain secrets sealed.
    let (_, yaml) = call_text(&app, "/api/v1/presets/export.yaml", admin).await;
    let (s, v) = import(&yaml).await;
    assert_eq!(
        (s, &v["unchanged"]),
        (StatusCode::OK, &json!(["wifi"])),
        "{v}"
    );
    let edited = "presets:\n  - name: wifi\n    when: { events: ['1 BOOT'] }\n    priority: 7\n    run:\n      - kind: set_parameter_values\n        payload:\n          values:\n            - { name: Device.WiFi.AccessPoint.1.Security.KeyPassphrase, value: '********', secret: true }\n            - { name: Device.WiFi.SSID.1.SSID, value: Home2 }\n      - kind: download\n        payload: { url: 'http://f/fw.bin', username: dl, password: '********' }\n";
    let (s, v) = import(edited).await;
    assert_eq!(
        (s, &v["updated"]),
        (StatusCode::OK, &json!(["wifi"])),
        "{v}"
    );
    let imported = store.list_presets(DEFAULT_TENANT).await.unwrap().remove(0);
    assert_eq!(
        opened(&imported.definition, imported.id),
        (json!("wifi-s3cret"), json!("new-pw"))
    );
    let new_masked = "presets:\n  - name: ok-one\n    run: [ { kind: reboot } ]\n  - name: copied\n    run:\n      - kind: download\n        payload: { url: 'http://f/x', password: '********' }\n";
    let (s, v) = import(new_masked).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    let msg = v["error"].as_str().unwrap();
    assert!(
        msg.contains("copied") && msg.contains("run[0].password"),
        "{msg}"
    );
    assert_eq!(
        store.list_presets(DEFAULT_TENANT).await.unwrap().len(),
        1,
        "nothing is stored when one fails"
    );
    let plain = "presets:\n  - name: imported\n    run:\n      - kind: download\n        payload: { url: 'http://f/y', password: imported-pw }\n";
    let (s, v) = import(plain).await;
    assert_eq!(
        (s, &v["created"]),
        (StatusCode::OK, &json!(["imported"])),
        "{v}"
    );
    let stored = store.list_presets(DEFAULT_TENANT).await.unwrap();
    assert!(
        !serde_json::to_string(&stored.iter().map(|p| &p.definition).collect::<Vec<_>>())
            .unwrap()
            .contains("imported-pw")
    );
    for out in outputs().await {
        assert!(
            !out.contains("imported-pw") && !out.contains("enc:"),
            "{out}"
        );
    }

    // Firing: each task gets own sealed secrets -> open to the plaintext sent to device.
    assert_eq!(presets.get().len(), 2);
    let events = [dhonomos_cwmp_codec::EventCode::parse("1 BOOT")];
    let ctx = dhonomos_core::MatchContext {
        events: &events,
        oui: "001122",
        product_class: "Box",
        software_version: Some("1.0"),
        tags: &[],
        new_device: false,
        attributes: &serde_json::Value::Null,
        serial: "SN1",
        protocol: "cwmp",
    };
    let queued = dhonomos_core::presets::enqueue_matching(
        &store,
        DEFAULT_TENANT,
        &presets.get(),
        device,
        &ctx,
        "boot-1",
    )
    .await
    .unwrap();
    assert_eq!(queued, 3);
    let tasks = store.list_tasks(device, 50).await.unwrap();
    let plain_of = |t: &dhonomos_store::Task| {
        assert!(t.payload.to_string().contains("enc:v2:"), "{}", t.payload);
        assert!(!t.payload.to_string().contains("s3cret"));
        let mut p = t.payload.clone();
        secrets.decrypt_fields(&mut p, &task_context(t.id)).unwrap();
        p
    };
    let spv = tasks
        .iter()
        .find(|t| t.kind == "set_parameter_values")
        .unwrap();
    let p = plain_of(spv);
    assert_eq!(p["values"][0]["value"], "wifi-s3cret");
    assert_eq!(p["values"][1]["value"], "Home2");
    let mut passwords: Vec<String> = tasks
        .iter()
        .filter(|t| t.kind == "download")
        .map(|t| plain_of(t)["password"].as_str().unwrap().to_owned())
        .collect();
    passwords.sort();
    assert_eq!(passwords, ["imported-pw", "new-pw"]);
    let mut as_stored = spv.payload.clone();
    assert!(
        secrets
            .decrypt_fields(&mut as_stored, &preset_context(row.id, 0))
            .is_err(),
        "the task's ciphertext is not the preset's"
    );
    let (_, list) = call(
        &app,
        "GET",
        &format!("/api/v1/devices/{device}/tasks"),
        None,
        Some(&viewer),
    )
    .await;
    let list = list.to_string();
    assert!(!list.contains("wifi-s3cret") && !list.contains("new-pw") && !list.contains("enc:"));
    // Same preset fired again, same boot -> nothing new queued (idempotent).
    let again = dhonomos_core::presets::enqueue_matching(
        &store,
        DEFAULT_TENANT,
        &presets.get(),
        device,
        &ctx,
        "boot-1",
    )
    .await
    .unwrap();
    assert_eq!(again, 0);
}

/// POST/PUT with bearer token, JSON answer.
async fn call_json(
    app: &Router,
    method: &str,
    uri: &str,
    body: Value,
    token: &str,
) -> (StatusCode, Value) {
    call(app, method, uri, Some(body), Some(token)).await
}

/// Presets from a file: secrets as in the file; API shows the mask.
#[tokio::test]
async fn file_presets_hide_their_secrets_too() {
    let (_c, store, _, _) = setup(None).await;
    let presets = dhonomos_core::Presets::from_yaml(
        "presets:\n  - name: lab\n    run:\n      - kind: download\n        payload: { url: 'http://f/x', username: u, password: file-secret }\n",
    )
    .unwrap();
    let app = router(
        store.clone(),
        ApiConfig {
            tenant_id: DEFAULT_TENANT,
            presets: presets.into(),
            ..ApiConfig::default()
        },
    );
    let (_, v) = call(&app, "GET", "/api/v1/presets", None, None).await;
    assert_eq!(
        v["items"][0]["definition"]["run"][0]["payload"]["password"],
        "********"
    );
    assert_eq!(
        v["items"][0]["definition"]["run"][0]["payload"]["username"],
        "u"
    );
    let (_, yaml) = call_text(&app, "/api/v1/presets/export.yaml", "").await;
    assert!(
        yaml.contains("********") && !yaml.contains("file-secret"),
        "{yaml}"
    );
    // Written back as preset file -> mask not taken for a password.
    let err = dhonomos_core::Presets::from_yaml(&yaml)
        .map(|_| ())
        .expect_err("the mask is not a secret");
    assert!(err.to_string().contains("mask"), "{err}");
}

/// Signed test links + other write links in task payloads hidden from readers
/// (audit NEW-2): diagnostic `params.url`, Operate command `URL`.
#[tokio::test]
async fn signed_links_in_diagnostic_and_operate_tasks_are_hidden() {
    let admin = "admin-token";
    let (_c, store, _, device) = setup(Some(admin)).await;
    let app = router(
        store.clone(),
        ApiConfig {
            bearer_token: Some(admin.into()),
            tenant_id: DEFAULT_TENANT,
            ..ApiConfig::default()
        },
    );
    let (_, k) = call(
        &app,
        "POST",
        "/api/v1/api-keys",
        Some(json!({ "name": "viewer", "role": "viewer" })),
        Some(admin),
    )
    .await;
    let viewer = k["key"].as_str().unwrap().to_owned();
    let signed = "http://files.test:7548/diag/d/1000?e=4102444800&s=0123abcd";
    let tasks = format!("/api/v1/devices/{device}/tasks");
    let (s, v) = call(
        &app,
        "POST",
        &tasks,
        Some(json!({ "kind": "diagnostic", "connection_request": false,
                     "payload": { "test": "download", "params": { "url": signed, "dscp": "10" } } })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    assert_eq!(
        v["payload"]["params"]["url"],
        "http://files.test:7548/diag/d/1000?********"
    );
    assert_eq!(v["payload"]["params"]["dscp"], "10");
    let id = v["id"].as_str().unwrap().to_owned();
    // What is sent to the device: untouched.
    let stored = store.get_task(id.parse().unwrap()).await.unwrap().unwrap();
    assert_eq!(stored.payload["params"]["url"], signed);
    for token in [&viewer[..], admin] {
        let (_, one) = call(
            &app,
            "GET",
            &format!("/api/v1/tasks/{id}"),
            None,
            Some(token),
        )
        .await;
        let (_, list) = call(&app, "GET", &tasks, None, Some(token)).await;
        let (_, audit) = call(&app, "GET", "/api/v1/audit", None, Some(token)).await;
        for out in [one.to_string(), list.to_string(), audit.to_string()] {
            assert!(
                !out.contains("0123abcd") && !out.contains("e=4102444800"),
                "{out}"
            );
        }
    }
}

/// 1 HTTP exchange with a file server, fresh connection -> head + body.
/// Server may answer before reading the whole request -> connection reset;
/// what arrived before is returned (empty head if nothing).
async fn http_exchange(
    addr: std::net::SocketAddr,
    head: String,
    body: Vec<u8>,
) -> (String, Vec<u8>) {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let mut tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (mut rd, mut wr) = tcp.split();
    let send = async {
        let _ = wr.write_all(head.as_bytes()).await;
        let _ = wr.write_all(&body).await;
    };
    let mut out = Vec::new();
    let receive = async {
        let mut chunk = [0u8; 8192];
        while let Ok(n) = rd.read(&mut chunk).await {
            if n == 0 {
                break;
            }
            out.extend_from_slice(&chunk[..n]);
        }
    };
    tokio::join!(send, receive);
    match out.windows(4).position(|w| w == b"\r\n\r\n") {
        Some(end) => (
            String::from_utf8_lossy(&out[..end + 4]).into_owned(),
            out[end + 4..].to_vec(),
        ),
        None => (String::new(), Vec::new()),
    }
}

/// Open connection, send `request`, read to end of response head.
/// Connection stays open; caller holds or drops it.
async fn open_with_head(
    addr: std::net::SocketAddr,
    request: String,
) -> (tokio::net::TcpStream, String) {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let mut tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    tcp.write_all(request.as_bytes()).await.unwrap();
    let mut seen = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = tcp.read(&mut chunk).await.unwrap();
        assert!(n > 0, "closed before the response head: {seen:?}");
        seen.extend_from_slice(&chunk[..n]);
        if let Some(end) = seen.windows(4).position(|w| w == b"\r\n\r\n") {
            return (tcp, String::from_utf8_lossy(&seen[..end + 4]).into_owned());
        }
    }
}

/// Many requests for 1 upload link at once (device retrying) -> exactly 1 file kept, whole.
/// Nobody deletes or mixes up the file of the winning request (L-9).
#[tokio::test]
async fn concurrent_puts_on_one_upload_link_keep_the_winners_file() {
    use dhonomos_api::{FilesConfig, file_server};
    use dhonomos_core::{FileSigner, UploadKind};
    use sha2::{Digest as _, Sha256};
    let (_c, store, _, device) = setup(None).await;
    let dir = std::env::temp_dir().join(format!("dhonomos-files-{}", Uuid::now_v7()));
    std::fs::create_dir_all(&dir).unwrap();
    let signer = FileSigner::new(
        b"k".to_vec(),
        "http://files.test",
        std::time::Duration::from_secs(3600),
    );
    let links: Vec<(Uuid, String)> = (0..4)
        .map(|_| {
            let upload = Uuid::now_v7();
            let url = signer.upload_url(device, upload, UploadKind::Config);
            (
                upload,
                url.strip_prefix("http://files.test").unwrap().to_owned(),
            )
        })
        .collect();
    let app = file_server(
        store.clone(),
        FilesConfig::new(dir.clone(), signer, 4 << 20, Default::default()),
        DEFAULT_TENANT,
        None,
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    for (upload, link) in &links {
        // 8 different bodies on the same link, all at once.
        let bodies: Vec<Vec<u8>> = (1..=8u8)
            .map(|i| vec![i; 700_000 + usize::from(i)])
            .collect();
        let answers = futures_util::future::join_all(bodies.iter().map(|b| {
            let head = format!(
                "PUT {link} HTTP/1.1\r\nHost: f\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                b.len()
            );
            http_exchange(addr, head, b.clone())
        }))
        .await;
        let created = answers
            .iter()
            .filter(|(h, _)| h.starts_with("HTTP/1.1 201"))
            .count();
        let conflicts = answers
            .iter()
            .filter(|(h, _)| h.starts_with("HTTP/1.1 409"))
            .count();
        assert_eq!(
            created,
            1,
            "{:?}",
            answers.iter().map(|a| &a.0).collect::<Vec<_>>()
        );
        assert_eq!(
            created + conflicts + answers.iter().filter(|(h, _)| h.is_empty()).count(),
            bodies.len(),
            "everyone else is told it is taken (or lost the connection): {:?}",
            answers
                .iter()
                .map(|a| a.0.lines().next())
                .collect::<Vec<_>>()
        );

        // Kept file = 1 of the bodies, whole, matches the DB.
        let file = store.get_file(*upload).await.unwrap().expect("registered");
        let on_disk = std::fs::read(dir.join(upload.to_string())).expect("the file is in place");
        assert!(
            bodies.contains(&on_disk),
            "a mix of bodies, {} bytes",
            on_disk.len()
        );
        assert_eq!(file.size_bytes as usize, on_disk.len());
        assert_eq!(file.sha256, Sha256::digest(&on_disk).to_vec());
        // Late request -> told taken, file stays.
        let (head, _) = http_exchange(
            addr,
            format!(
                "PUT {link} HTTP/1.1\r\nHost: f\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            ),
            Vec::new(),
        )
        .await;
        assert!(head.starts_with("HTTP/1.1 409"), "{head}");
        assert_eq!(
            std::fs::read(dir.join(upload.to_string())).unwrap(),
            on_disk
        );
    }
    // Only the 4 files: no `.part` leftovers of losing requests.
    let names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names.len(), links.len(), "{names:?}");
    assert!(names.iter().all(|n| !n.ends_with(".part")), "{names:?}");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Diagnostic test links: max 1 h, 2 transfers at a time per device (64 total).
/// More -> 503 until a transfer ends (L-10).
#[tokio::test]
async fn diagnostic_links_expire_sooner_and_serve_a_few_transfers_at_a_time() {
    use dhonomos_api::{FilesConfig, file_server};
    use dhonomos_core::FileSigner;
    let (_c, store, _, device) = setup(None).await;
    let dir = std::env::temp_dir().join(format!("dhonomos-files-{}", Uuid::now_v7()));
    std::fs::create_dir_all(&dir).unwrap();
    let signer = FileSigner::new(
        b"k".to_vec(),
        "http://files.test",
        std::time::Duration::from_secs(24 * 3600),
    );
    let rel = |url: String| url.strip_prefix("http://files.test").unwrap().to_owned();
    let seconds_left = |url: &str| {
        let e: u64 = url
            .split("e=")
            .nth(1)
            .and_then(|r| r.split('&').next())
            .and_then(|e| e.parse().ok())
            .unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        e.saturating_sub(now)
    };
    let big = rel(signer.diag_download_url(device, 1_000_000_000));
    let up = rel(signer.diag_upload_url(device));
    let elsewhere = rel(signer.diag_download_url(Uuid::now_v7(), 1_000));
    assert!(seconds_left(&big) <= 3600 && seconds_left(&up) <= 3600);
    assert!(
        seconds_left(&signer.url(device, "fw.bin", device)) > 20 * 3600,
        "file links keep the link lifetime"
    );
    let app = file_server(
        store.clone(),
        FilesConfig::new(dir.clone(), signer, 1 << 20, Default::default()),
        DEFAULT_TENANT,
        None,
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let get = |p: &str| format!("GET {p} HTTP/1.1\r\nHost: f\r\nConnection: close\r\n\r\n");
    let put = |p: &str, n: usize| {
        format!("PUT {p} HTTP/1.1\r\nHost: f\r\nContent-Length: {n}\r\nConnection: close\r\n\r\n")
    };

    // 2 big downloads nobody reads to the end -> hold the device's 2 slots.
    let (first, head) = open_with_head(addr, get(&big)).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let (second, head) = open_with_head(addr, get(&big)).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let (_, head) = open_with_head(addr, get(&big)).await;
    assert!(head.starts_with("HTTP/1.1 503"), "{head}");
    assert!(
        head.to_ascii_lowercase().contains("retry-after: 30"),
        "{head}"
    );
    // Uploads share the device slots; other devices not held back.
    let (_, head) = open_with_head(addr, put(&up, 10)).await;
    assert!(head.starts_with("HTTP/1.1 503"), "{head}");
    let (_other, head) = open_with_head(addr, get(&elsewhere)).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    // Bad signature -> still 403, not 503.
    let (_, head) = open_with_head(addr, get(&big.replace("&s=", "&s=00"))).await;
    assert!(head.starts_with("HTTP/1.1 403"), "{head}");

    // Ended transfer frees its slot.
    drop(first);
    let mut served = false;
    for _ in 0..50 {
        let (conn, head) = open_with_head(addr, get(&big)).await;
        if head.starts_with("HTTP/1.1 200") {
            served = true;
            drop(conn);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(served, "the slot was never given back");
    drop(second);
    let mut idle = false;
    for _ in 0..50 {
        let (head, _) = http_exchange(addr, put(&up, 3), vec![1; 3]).await;
        if head.starts_with("HTTP/1.1 204") {
            idle = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(idle, "the download slots were never given back");

    // Uploads hold slots while being received.
    let mut holding = Vec::new();
    for _ in 0..2 {
        use tokio::io::AsyncWriteExt as _;
        let mut tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        tcp.write_all(put(&up, 1_000_000).as_bytes()).await.unwrap();
        tcp.write_all(&[1u8; 100]).await.unwrap();
        holding.push(tcp);
    }
    let mut refused = false;
    for _ in 0..50 {
        let (head, _) = http_exchange(addr, put(&up, 3), vec![1; 3]).await;
        if head.starts_with("HTTP/1.1 503") {
            refused = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(refused, "two slow uploads should fill the device's slots");
    drop(holding);
    let mut freed = false;
    for _ in 0..50 {
        let (head, _) = http_exchange(addr, put(&up, 3), vec![1; 3]).await;
        if head.starts_with("HTTP/1.1 204") {
            freed = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(freed, "the upload slots were never given back");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Login + SSO routes: burst per client address, then 429; nothing else affected.
/// Login with huge password -> refused before any hashing (L-12).
#[tokio::test]
async fn public_auth_routes_are_limited_per_address() {
    let (_c, _store, app, _) = setup(None).await;
    let as_client = |ip: &str, method: &str, uri: &str, body: Option<Value>| {
        let addr = std::net::SocketAddr::new(ip.parse().unwrap(), 4000);
        let mut req = Request::builder()
            .method(method)
            .uri(uri)
            .extension(axum::extract::ConnectInfo(addr));
        let body = match body {
            Some(b) => {
                req = req.header("content-type", "application/json");
                Body::from(b.to_string())
            }
            None => Body::empty(),
        };
        let (app, req) = (app.clone(), req.body(body).unwrap());
        async move {
            let resp = app.oneshot(req).await.unwrap();
            let retry = resp.headers().contains_key("retry-after");
            (resp.status(), retry)
        }
    };
    let (s, _) = as_client(
        "10.20.30.1",
        "POST",
        "/api/v1/auth/login",
        Some(json!({ "username": "kim", "password": "x".repeat(5000) })),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);

    let mut limited_at = None;
    for i in 0..60 {
        let (s, retry) = as_client("10.20.30.1", "GET", "/api/v1/auth/oidc/login", None).await;
        if s == StatusCode::TOO_MANY_REQUESTS {
            assert!(retry, "429 says when to come back");
            limited_at = Some(i);
            break;
        }
        assert_eq!(s, StatusCode::NOT_FOUND, "single sign-on is not configured");
    }
    let at = limited_at.expect("a burst, then 429");
    assert!((29..=34).contains(&at), "burst of about 30, not {at}");
    // Same address cannot log in either, but nothing hashed for it.
    let (s, retry) = as_client(
        "10.20.30.1",
        "POST",
        "/api/v1/auth/login",
        Some(json!({ "username": "kim", "password": "wrong password" })),
    )
    .await;
    assert_eq!((s, retry), (StatusCode::TOO_MANY_REQUESTS, true));
    // Other addresses + routes that cost nothing -> not affected.
    let (s, _) = as_client("10.20.30.2", "GET", "/api/v1/auth/oidc/login", None).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = as_client("10.20.30.1", "GET", "/api/v1/auth/config", None).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = as_client("10.20.30.1", "GET", "/api/v1/devices", None).await;
    assert_eq!(s, StatusCode::OK, "open development mode: no accounts yet");
}

fn oidc_test_config(idp: &MockIdp) -> dhonomos_api::OidcConfig {
    dhonomos_api::OidcConfig {
        issuer: idp.issuer.clone(),
        client_id: "dhonomos".into(),
        client_secret: Some("s3".into()),
        redirect_url: "http://dhonomos.test/api/v1/auth/oidc/callback".into(),
        scopes: "openid profile groups".into(),
        username_claim: "preferred_username".into(),
        role_claim: "groups".into(),
        admin: vec!["dhonomos-admins".into()],
        operator: vec!["noc".into()],
        viewer: Vec::new(),
    }
}

/// Request from client address `ip`.
fn from_ip(ip: &str, uri: &str, cookie: Option<&str>) -> Request<Body> {
    let mut req = Request::get(uri).extension(axum::extract::ConnectInfo(
        std::net::SocketAddr::new(ip.parse().unwrap(), 4000),
    ));
    if let Some(c) = cookie {
        req = req.header("cookie", c);
    }
    req.body(Body::empty()).unwrap()
}

/// Start a login in the browser at `ip`, set what the provider says about the user.
/// Returns `state` + the cookie pair the browser got.
async fn sso_start(app: &Router, idp: &MockIdp, ip: &str, claims: Value) -> (String, String) {
    let resp = app
        .clone()
        .oneshot(from_ip(ip, "/api/v1/auth/oidc/login", None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FOUND);
    let loc = resp.headers()["location"].to_str().unwrap().to_owned();
    let cookie = resp
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap().to_owned())
        .find(|c| c.starts_with("dhonomos_oidc="))
        .expect("the start sets the state cookie");
    assert!(
        cookie.contains("HttpOnly")
            && cookie.contains("SameSite=Lax")
            && cookie.contains("Max-Age=600"),
        "{cookie}"
    );
    let param = |k: &str| {
        loc.split(['?', '&'])
            .find_map(|kv| kv.strip_prefix(&format!("{k}=")))
            .unwrap()
            .to_owned()
    };
    *idp.challenge.lock().unwrap() = param("code_challenge");
    let mut all = json!({
        "iss": idp.issuer, "aud": "dhonomos", "nonce": param("nonce"),
        "exp": time::OffsetDateTime::now_utc().unix_timestamp() + 300,
    });
    for (k, v) in claims.as_object().unwrap() {
        all[k] = v.clone();
    }
    *idp.claims.lock().unwrap() = all;
    (param("state"), cookie.split(';').next().unwrap().to_owned())
}

/// What the browser got back from the callback.
struct SsoEnd {
    location: String,
    cookies: Vec<String>,
}

impl SsoEnd {
    /// Session cookie pair, if login succeeded.
    fn session(&self) -> Option<String> {
        self.cookies
            .iter()
            .find(|c| c.starts_with("dhonomos_session="))
            .map(|c| c.split(';').next().unwrap().to_owned())
    }

    /// Reason shown on the login page, if failed.
    fn error(&self) -> String {
        self.location
            .strip_prefix("/login?sso_error=")
            .unwrap_or_default()
            .replace("%20", " ")
    }
}

async fn sso_callback(app: &Router, ip: &str, state: &str, cookie: Option<&str>) -> SsoEnd {
    let resp = app
        .clone()
        .oneshot(from_ip(
            ip,
            &format!("/api/v1/auth/oidc/callback?code=good-code&state={state}"),
            cookie,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FOUND);
    SsoEnd {
        location: resp.headers()["location"].to_str().unwrap().to_owned(),
        cookies: resp
            .headers()
            .get_all("set-cookie")
            .iter()
            .map(|v| v.to_str().unwrap().to_owned())
            .collect(),
    }
}

/// Account = provider + user subject, not a changeable name.
/// Login ends in the browser that began it (L-11).
#[tokio::test]
async fn single_sign_on_accounts_follow_the_provider_identity_and_the_browser() {
    let (_c, store, _, _) = setup(None).await;
    let idp = mock_idp().await;
    let app = router(
        store.clone(),
        ApiConfig {
            tenant_id: DEFAULT_TENANT,
            oidc: Some(oidc_test_config(&idp)),
            ..ApiConfig::default()
        },
    );
    let whoami = |session: String| {
        let app = app.clone();
        async move {
            let (s, me, _) =
                call_cookie(&app, "GET", "/api/v1/auth/me", None, Some(&session)).await;
            assert_eq!(s, StatusCode::OK);
            (
                me["name"].as_str().unwrap().to_owned(),
                me["role"].as_str().unwrap().to_owned(),
            )
        }
    };
    let sign_in = |ip: &'static str, claims: Value| {
        let (app, idp) = (app.clone(), &idp);
        async move {
            let (state, cookie) = sso_start(&app, idp, ip, claims).await;
            sso_callback(&app, ip, &state, Some(&cookie)).await
        }
    };
    let issuer = idp.issuer.clone();
    let user_with = |sub: &'static str| {
        let (store, issuer) = (store.clone(), issuer.clone());
        async move {
            store
                .user_by_oidc(DEFAULT_TENANT, &issuer, sub)
                .await
                .unwrap()
        }
    };

    // Login tied to the browser: no cookie or other browser's -> refused,
    // neither uses up the login.
    let kim = json!({ "sub": "u-1", "preferred_username": "kim", "groups": ["noc"] });
    let (state, cookie) = sso_start(&app, &idp, "10.2.0.1", kim.clone()).await;
    let end = sso_callback(&app, "10.2.0.9", &state, None).await;
    assert!(
        end.error().contains("did not start in this browser"),
        "{}",
        end.location
    );
    assert!(end.session().is_none());
    let other_cookie = "dhonomos_oidc=AAAA-another-browsers-hash".to_owned();
    let end = sso_callback(&app, "10.2.0.9", &state, Some(&other_cookie)).await;
    assert!(
        end.error().contains("did not start in this browser"),
        "{}",
        end.location
    );
    assert!(
        end.cookies
            .iter()
            .any(|c| c.starts_with("dhonomos_oidc=;") && c.contains("Max-Age=0")),
        "the cookie is cleared whatever happened: {:?}",
        end.cookies
    );
    assert!(user_with("u-1").await.is_none());
    let end = sso_callback(&app, "10.2.0.1", &state, Some(&cookie)).await;
    assert_eq!(end.location, "/", "{}", end.location);
    let session = end.session().expect("logged in");
    assert_eq!(
        whoami(session.clone()).await,
        ("sso:kim".into(), "operator".into())
    );
    assert!(
        end.cookies
            .iter()
            .any(|c| c.starts_with("dhonomos_oidc=;") && c.contains("Max-Age=0")),
        "{:?}",
        end.cookies
    );
    let account = user_with("u-1").await.expect("the identity is attached");
    assert_eq!(account.username, "sso:kim");
    // Used once.
    let end = sso_callback(&app, "10.2.0.1", &state, Some(&cookie)).await;
    assert!(
        end.error().contains("expired or was already used"),
        "{}",
        end.location
    );

    // Same person, other name -> same account.
    let end = sign_in(
        "10.2.0.2",
        json!({ "sub": "u-1", "preferred_username": "kim-renamed", "groups": ["noc"] }),
    )
    .await;
    assert_eq!(whoami(end.session().expect("logged in")).await.0, "sso:kim");
    assert!(
        store
            .user_by_name(DEFAULT_TENANT, "sso:kim-renamed")
            .await
            .unwrap()
            .is_none()
    );
    // Other person with kim's old name -> refused, no account for them.
    let end = sign_in(
        "10.2.0.3",
        json!({ "sub": "u-2", "preferred_username": "kim", "groups": ["noc"] }),
    )
    .await;
    assert!(end.session().is_none());
    assert!(end.error().contains("another identity"), "{}", end.location);
    assert!(user_with("u-2").await.is_none());

    // Account made before identities were kept -> gets one at next login, once.
    store
        .create_user(DEFAULT_TENANT, "sso:old", "!sso", "viewer")
        .await
        .unwrap();
    let end = sign_in(
        "10.2.0.4",
        json!({ "sub": "u-9", "preferred_username": "old", "groups": ["noc"] }),
    )
    .await;
    assert_eq!(
        whoami(end.session().expect("logged in")).await,
        ("sso:old".into(), "operator".into()),
        "the role follows the provider"
    );
    assert_eq!(user_with("u-9").await.unwrap().username, "sso:old");
    let end = sign_in(
        "10.2.0.5",
        json!({ "sub": "u-10", "preferred_username": "old", "groups": ["noc"] }),
    )
    .await;
    assert!(end.session().is_none());
    assert!(end.error().contains("another identity"), "{}", end.location);
    // Local account with such a name -> never taken over.
    store
        .create_user(
            DEFAULT_TENANT,
            "sso:local",
            &dhonomos_api::hash_password("correct horse battery").unwrap(),
            "admin",
        )
        .await
        .unwrap();
    let end = sign_in(
        "10.2.0.6",
        json!({ "sub": "u-20", "preferred_username": "local", "groups": ["noc"] }),
    )
    .await;
    assert!(end.session().is_none());
    assert!(
        end.error().contains("not a single sign-on account"),
        "{}",
        end.location
    );

    // E-mail names a new account only if provider verified it.
    let end = sign_in(
        "10.2.0.7",
        json!({ "sub": "u-30", "email": "boss@example.org", "groups": ["noc"] }),
    )
    .await;
    assert_eq!(whoami(end.session().unwrap()).await.0, "sso:u-30");
    let end = sign_in(
        "10.2.0.8",
        json!({ "sub": "u-31", "email": "boss@example.org", "email_verified": true, "groups": ["noc"] }),
    )
    .await;
    assert_eq!(
        whoami(end.session().unwrap()).await.0,
        "sso:boss@example.org"
    );
    let end = sign_in(
        "10.2.0.10",
        json!({ "groups": ["noc"], "preferred_username": "x" }),
    )
    .await;
    assert!(end.error().contains("no subject"), "{}", end.location);

    // Disabled account -> refused, even with matching identity.
    store
        .update_user(account.id, None, Some(true), None, None)
        .await
        .unwrap();
    let end = sign_in("10.2.0.11", kim.clone()).await;
    assert!(end.session().is_none());
    assert!(end.error().contains("disabled"), "{}", end.location);

    // Logins in progress limited per address: 21st start refused.
    for _ in 0..20 {
        sso_start(&app, &idp, "10.3.0.1", kim.clone()).await;
    }
    let resp = app
        .clone()
        .oneshot(from_ip("10.3.0.1", "/api/v1/auth/oidc/login", None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert!(
        String::from_utf8_lossy(&body).contains("too many logins started"),
        "{body:?}"
    );
    let resp = app
        .clone()
        .oneshot(from_ip("10.3.0.2", "/api/v1/auth/oidc/login", None))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FOUND,
        "other addresses are not affected"
    );
}

/// New password -> other sessions of the account end.
/// API keys follow their creator account: disabled -> stop, enabled -> back,
/// deleted -> deleted (L-13).
#[tokio::test]
async fn password_changes_end_other_sessions_and_keys_follow_their_creator() {
    let admin = "admin-token";
    let (_c, store, app, _) = setup(Some(admin)).await;
    for (name, password) in [
        ("alice", "correct horse battery"),
        ("carol", "staple battery horse"),
    ] {
        let (s, v) = call(
            &app,
            "POST",
            "/api/v1/users",
            Some(json!({ "username": name, "password": password, "role": "admin" })),
            Some(admin),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED, "{v}");
    }
    let login = |name: &str, password: &str| {
        let (app, body) = (
            app.clone(),
            json!({ "username": name, "password": password }),
        );
        async move {
            let (s, _, cookie) =
                call_cookie(&app, "POST", "/api/v1/auth/login", Some(body), None).await;
            (s, cookie.map(|c| c.split(';').next().unwrap().to_owned()))
        }
    };
    let alive = |session: &str| {
        let (app, session) = (app.clone(), session.to_owned());
        async move {
            call_cookie(&app, "GET", "/api/v1/auth/me", None, Some(&session))
                .await
                .0
                == StatusCode::OK
        }
    };
    let users = |key: &str| {
        let (app, key) = (app.clone(), key.to_owned());
        async move { call(&app, "GET", "/api/v1/users", None, Some(&key)).await.0 }
    };
    let (_, a1) = login("alice", "correct horse battery").await;
    let (_, a2) = login("alice", "correct horse battery").await;
    let (a1, a2) = (a1.unwrap(), a2.unwrap());
    assert!(alive(&a1).await && alive(&a2).await);
    let alice = store
        .user_by_name(DEFAULT_TENANT, "alice")
        .await
        .unwrap()
        .unwrap();
    let carol = store
        .user_by_name(DEFAULT_TENANT, "carol")
        .await
        .unwrap()
        .unwrap();

    // Own password change -> every other session out, current one kept.
    let (s, v, _) = call_cookie(
        &app,
        "PATCH",
        &format!("/api/v1/users/{}", alice.id),
        Some(json!({ "password": "a brand new passphrase" })),
        Some(&a1),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(
        alive(&a1).await,
        "the session the change was made from stays"
    );
    assert!(!alive(&a2).await, "any other session ends");
    assert_eq!(
        login("alice", "correct horse battery").await.0,
        StatusCode::UNAUTHORIZED
    );
    let (s, a3) = login("alice", "a brand new passphrase").await;
    assert_eq!(s, StatusCode::OK);
    // Set by someone else -> all sessions end.
    let (s, _) = call(
        &app,
        "PATCH",
        &format!("/api/v1/users/{}", alice.id),
        Some(json!({ "password": "reset by the admin" })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert!(!alive(&a1).await && !alive(&a3.unwrap()).await);

    // Keys follow their creator account (also via a key that makes keys).
    let (_, c1) = login("carol", "staple battery horse").await;
    let c1 = c1.unwrap();
    let (s, k, _) = call_cookie(
        &app,
        "POST",
        "/api/v1/api-keys",
        Some(json!({ "name": "carol's", "role": "admin" })),
        Some(&c1),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{k}");
    let carols = k["key"].as_str().unwrap().to_owned();
    let (s, k) = call(
        &app,
        "POST",
        "/api/v1/api-keys",
        Some(json!({ "name": "made by carol's key", "role": "admin" })),
        Some(&carols),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{k}");
    let grandchild = k["key"].as_str().unwrap().to_owned();
    let (s, k) = call(
        &app,
        "POST",
        "/api/v1/api-keys",
        Some(json!({ "name": "made with the token", "role": "admin" })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{k}");
    let tokens = k["key"].as_str().unwrap().to_owned();
    for key in [&carols, &grandchild, &tokens] {
        assert_eq!(users(key).await, StatusCode::OK);
    }

    let disable = |disabled: bool| {
        let (app, id) = (app.clone(), carol.id);
        async move {
            call(
                &app,
                "PATCH",
                &format!("/api/v1/users/{id}"),
                Some(json!({ "disabled": disabled })),
                Some(admin),
            )
            .await
            .0
        }
    };
    assert_eq!(disable(true).await, StatusCode::OK);
    assert_eq!(
        users(&carols).await,
        StatusCode::UNAUTHORIZED,
        "her key stops"
    );
    assert_eq!(
        users(&grandchild).await,
        StatusCode::UNAUTHORIZED,
        "so does the one it made"
    );
    assert_eq!(
        users(&tokens).await,
        StatusCode::OK,
        "not tied to an account"
    );
    assert!(!alive(&c1).await);
    assert_eq!(disable(false).await, StatusCode::OK);
    assert_eq!(
        users(&carols).await,
        StatusCode::OK,
        "enabled again, working again"
    );
    assert_eq!(users(&grandchild).await, StatusCode::OK);

    let (s, _) = call(
        &app,
        "DELETE",
        &format!("/api/v1/users/{}", carol.id),
        None,
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(users(&carols).await, StatusCode::UNAUTHORIZED);
    assert_eq!(users(&grandchild).await, StatusCode::UNAUTHORIZED);
    assert_eq!(users(&tokens).await, StatusCode::OK);
    let (_, list) = call(&app, "GET", "/api/v1/api-keys", None, Some(admin)).await;
    let names: Vec<&str> = list["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["made with the token"], "{list}");
}

// ---------------------------------------------------------------------------------------
// Two-factor authentication (ADR-100)
// ---------------------------------------------------------------------------------------

const TF_PASSWORD: &str = "correct horse battery";

/// Authenticator code for `secret_b32` at `unix` s: RFC 6238 written out again
/// -> tests do not trust the server's own code.
fn totp_at(secret_b32: &str, unix: u64) -> String {
    let secret = data_encoding::BASE32_NOPAD
        .decode(secret_b32.as_bytes())
        .unwrap();
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &secret);
    let mac = ring::hmac::sign(&key, &(unix / 30).to_be_bytes());
    let mac = mac.as_ref();
    let offset = (mac[19] & 0x0f) as usize;
    let word = u32::from_be_bytes([
        mac[offset] & 0x7f,
        mac[offset + 1],
        mac[offset + 2],
        mac[offset + 3],
    ]);
    format!("{:06}", word % 1_000_000)
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Authenticator code now.
fn totp_now(secret_b32: &str) -> String {
    totp_at(secret_b32, unix_now())
}

/// 6-digit code != any code the server accepts now.
fn totp_wrong(secret_b32: &str) -> String {
    let t = unix_now();
    let valid = [t - 30, t, t + 30].map(|t| totp_at(secret_b32, t));
    (0..1_000_000)
        .map(|n| format!("{n:06}"))
        .find(|c| !valid.contains(c))
        .unwrap()
}

/// API with accounts, secrets key, admin requirement as given.
struct Tf {
    _c: ContainerAsync<Postgres>,
    store: Store,
    app: Router,
    port: u16,
}

impl Tf {
    async fn new(require_admin: bool) -> Self {
        Self::with(require_admin, Some(secret_box()), None, None).await
    }

    /// Roles in `roles` must use two-factor auth.
    async fn roles(roles: &[&str]) -> Self {
        Self::with_roles(
            roles.iter().map(|r| (*r).to_owned()).collect(),
            Some(secret_box()),
            None,
            None,
        )
        .await
    }

    async fn with(
        require_admin: bool,
        secrets: Option<std::sync::Arc<dhonomos_core::SecretBox>>,
        token: Option<&str>,
        oidc: Option<dhonomos_api::OidcConfig>,
    ) -> Self {
        let roles = if require_admin {
            vec!["admin".to_owned()]
        } else {
            Vec::new()
        };
        Self::with_roles(roles, secrets, token, oidc).await
    }

    async fn with_roles(
        require_roles: Vec<String>,
        secrets: Option<std::sync::Arc<dhonomos_core::SecretBox>>,
        token: Option<&str>,
        oidc: Option<dhonomos_api::OidcConfig>,
    ) -> Self {
        let c = Postgres::default()
            .with_tag("17-alpine")
            .start()
            .await
            .unwrap();
        let port = c.get_host_port_ipv4(5432).await.unwrap();
        let store = Store::connect(
            &format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres"),
            4,
        )
        .await
        .unwrap();
        store.migrate().await.unwrap();
        let app = router(
            store.clone(),
            ApiConfig {
                tenant_id: DEFAULT_TENANT,
                bearer_token: token.map(Into::into),
                secrets,
                oidc,
                totp: dhonomos_api::TotpConfig {
                    require_roles,
                    issuer: String::new(),
                },
                ..ApiConfig::default()
            },
        );
        Self {
            _c: c,
            store,
            app,
            port,
        }
    }

    async fn user(&self, name: &str, role: &str) -> Uuid {
        self.store
            .create_user(
                DEFAULT_TENANT,
                name,
                &dhonomos_api::hash_password(TF_PASSWORD).unwrap(),
                role,
            )
            .await
            .unwrap()
    }

    /// `POST /auth/login` -> session cookie pair if one was made.
    async fn login(
        &self,
        name: &str,
        password: &str,
        totp: Option<&str>,
    ) -> (StatusCode, Value, Option<String>) {
        let mut body = json!({ "username": name, "password": password });
        if let Some(t) = totp {
            body["totp"] = json!(t);
        }
        let (s, v, cookie) =
            call_cookie(&self.app, "POST", "/api/v1/auth/login", Some(body), None).await;
        (
            s,
            v,
            cookie.map(|c| c.split(';').next().unwrap().to_owned()),
        )
    }

    /// Session of `name`, password only.
    async fn session(&self, name: &str) -> String {
        let (s, v, cookie) = self.login(name, TF_PASSWORD, None).await;
        assert_eq!(s, StatusCode::OK, "{v}");
        cookie.unwrap()
    }

    async fn call(
        &self,
        session: &str,
        method: &str,
        uri: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let (s, v, _) = call_cookie(&self.app, method, uri, body, Some(session)).await;
        (s, v)
    }

    /// Set up + turn on two-factor auth -> secret + recovery codes.
    async fn enroll(&self, session: &str) -> (String, Vec<String>) {
        let (s, v) = self
            .call(session, "POST", "/api/v1/auth/totp/setup", Some(json!({})))
            .await;
        assert_eq!(s, StatusCode::OK, "{v}");
        let secret = v["secret"].as_str().unwrap().to_owned();
        let (s, v) = self
            .call(
                session,
                "POST",
                "/api/v1/auth/totp/enable",
                Some(json!({ "code": totp_now(&secret) })),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{v}");
        let codes = v["recovery_codes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c.as_str().unwrap().to_owned())
            .collect();
        (secret, codes)
    }

    /// Forget the last used code -> current one usable again
    /// (tests cannot wait 30 s between logins).
    async fn forget_used_codes(&self) {
        let pool = sqlx::PgPool::connect(&format!(
            "postgres://postgres:postgres@127.0.0.1:{}/postgres",
            self.port
        ))
        .await
        .unwrap();
        sqlx::query("UPDATE user_totp SET last_step = NULL")
            .execute(&pool)
            .await
            .unwrap();
    }

    async fn audit_actions(&self) -> Vec<(String, String)> {
        self.store
            .list_audit(DEFAULT_TENANT, &Default::default(), 100)
            .await
            .unwrap()
            .into_iter()
            .map(|a| (a.action, a.actor))
            .collect()
    }
}

/// Setup, turn on, login with code, code good once.
#[tokio::test]
async fn totp_setup_enable_and_login_with_a_code_that_works_once() {
    let tf = Tf::new(false).await;
    tf.user("kim", "operator").await;
    let first = tf.session("kim").await;
    let other = tf.session("kim").await;
    let (s, me) = tf.call(&first, "GET", "/api/v1/auth/me", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        (
            me["totp_enabled"].clone(),
            me["totp_required"].clone(),
            me["totp_available"].clone()
        ),
        (json!(false), json!(false), json!(true)),
        "{me}"
    );

    // Setup returns the secret 3 ways; not active yet.
    let (s, v) = tf
        .call(&first, "POST", "/api/v1/auth/totp/setup", None)
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let secret = v["secret"].as_str().unwrap().to_owned();
    assert_eq!(secret.len(), 32);
    assert!(
        secret
            .bytes()
            .all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b))
    );
    assert_eq!(
        v["otpauth_uri"],
        format!(
            "otpauth://totp/Dhonomos:kim?secret={secret}&issuer=Dhonomos&algorithm=SHA1&digits=6&period=30"
        )
    );
    assert!(v["qr_svg"].as_str().unwrap().starts_with("<svg "));
    let (s, v, _) = tf.login("kim", TF_PASSWORD, None).await;
    assert_eq!(s, StatusCode::OK, "still no code asked for: {v}");

    // Wrong code -> not on; right one -> on + recovery codes shown once.
    let (s, v) = tf
        .call(
            &first,
            "POST",
            "/api/v1/auth/totp/enable",
            Some(json!({ "code": totp_wrong(&secret) })),
        )
        .await;
    assert_eq!(
        (s, v["error"].as_str()),
        (StatusCode::FORBIDDEN, Some("wrong authentication code"))
    );
    let (s, v) = tf
        .call(
            &first,
            "POST",
            "/api/v1/auth/totp/enable",
            Some(json!({ "code": totp_now(&secret), "extra": 1 })),
        )
        .await;
    assert_eq!(
        s,
        StatusCode::UNPROCESSABLE_ENTITY,
        "unknown fields are refused: {v}"
    );
    let (s, v) = tf
        .call(
            &first,
            "POST",
            "/api/v1/auth/totp/enable",
            Some(json!({ "code": totp_now(&secret) })),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let codes = v["recovery_codes"].as_array().unwrap();
    assert_eq!(codes.len(), 10);
    assert!(codes.iter().all(|c| c.as_str().unwrap().len() == 19));
    // Other sessions end; the one that did it stays.
    assert_eq!(
        tf.call(&other, "GET", "/api/v1/auth/me", None).await.0,
        StatusCode::UNAUTHORIZED
    );
    let (s, me) = tf.call(&first, "GET", "/api/v1/auth/me", None).await;
    assert_eq!(
        (s, me["totp_enabled"].clone()),
        (StatusCode::OK, json!(true))
    );
    // Nothing waiting -> enable again has nothing to confirm.
    let (s, _) = tf
        .call(
            &first,
            "POST",
            "/api/v1/auth/totp/enable",
            Some(json!({ "code": totp_now(&secret) })),
        )
        .await;
    assert_eq!(s, StatusCode::CONFLICT);

    // Code that turned it on cannot log in (once = once); list shows it.
    let (s, _, _) = tf.login("kim", TF_PASSWORD, Some(&totp_now(&secret))).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "the enabling code is used");
    tf.forget_used_codes().await;

    // Login: password alone not enough, says so, no session made.
    let (s, v, cookie) = tf.login("kim", TF_PASSWORD, None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(
        v,
        json!({ "error": "totp required", "totp_required": true })
    );
    assert!(cookie.is_none());
    // Wrong password -> plain failure, whatever else is sent.
    let (s, v, _) = tf.login("kim", "wrong password!", None).await;
    assert_eq!(
        (s, v["error"].as_str()),
        (StatusCode::UNAUTHORIZED, Some("wrong username or password"))
    );
    let (s, v, _) = tf
        .login("kim", "wrong password!", Some(&totp_now(&secret)))
        .await;
    let generic = "wrong username, password or authentication code";
    assert_eq!(
        (s, v["error"].as_str()),
        (StatusCode::UNAUTHORIZED, Some(generic))
    );
    let (s, v, cookie) = tf
        .login("kim", TF_PASSWORD, Some(&totp_wrong(&secret)))
        .await;
    assert_eq!(
        (s, v["error"].as_str()),
        (StatusCode::UNAUTHORIZED, Some(generic))
    );
    assert!(cookie.is_none());

    // Right code logs in (spaces as the app shows them are OK) ...
    let code = totp_now(&secret);
    let spaced = format!("{} {}", &code[..3], &code[3..]);
    let (s, v, cookie) = tf.login("kim", TF_PASSWORD, Some(&spaced)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let session = cookie.unwrap();
    let (_, me) = tf.call(&session, "GET", "/api/v1/auth/me", None).await;
    assert_eq!(me["totp_enabled"], true);
    // ... once: same code again + code of the step before -> refused ...
    let (s, _, _) = tf.login("kim", TF_PASSWORD, Some(&code)).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "replay");
    let older = totp_at(&secret, unix_now() - 30);
    let (s, _, _) = tf.login("kim", TF_PASSWORD, Some(&older)).await;
    assert_eq!(
        s,
        StatusCode::UNAUTHORIZED,
        "an older step cannot come back"
    );
    // Not a code at all.
    let (s, _, _) = tf.login("kim", TF_PASSWORD, Some("hello")).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    // ... next step's code accepted (phone may run ahead).
    let ahead = totp_at(&secret, unix_now() + 30);
    let (s, _, _) = tf.login("kim", TF_PASSWORD, Some(&ahead)).await;
    assert_eq!(s, StatusCode::OK);

    // Wrong codes count like wrong passwords: 5 -> name locked, even for the right code.
    tf.forget_used_codes().await;
    for _ in 0..5 {
        tf.login("kim", TF_PASSWORD, Some(&totp_wrong(&secret)))
            .await;
    }
    let (s, v, _) = tf.login("kim", TF_PASSWORD, Some(&totp_now(&secret))).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS, "{v}");
}

/// Recovery codes: 1 use each, any spelling, audited, replaced on request.
#[tokio::test]
async fn recovery_codes_work_once_and_are_replaced_on_request() {
    let tf = Tf::new(false).await;
    tf.user("kim", "operator").await;
    let session = tf.session("kim").await;
    let (secret, codes) = tf.enroll(&session).await;
    tf.forget_used_codes().await;

    // Lower case, no dashes, as a person might type.
    let typed = codes[0].to_lowercase().replace('-', "");
    let (s, v, cookie) = tf.login("kim", TF_PASSWORD, Some(&typed)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let session2 = cookie.unwrap();
    let (s, _, _) = tf.login("kim", TF_PASSWORD, Some(&codes[0])).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "a recovery code works once");
    let (s, _, _) = tf.login("kim", TF_PASSWORD, Some(&codes[1])).await;
    assert_eq!(s, StatusCode::OK, "the others still do");
    let (s, _, _) = tf
        .login("kim", TF_PASSWORD, Some("ABCD-EFGH-JKLM-NPQR"))
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "a code nobody has");

    // Use is audited (as the person), separate from the login.
    let audit = tf.audit_actions().await;
    assert!(
        audit.contains(&("auth.recovery_code_used".into(), "kim".into())),
        "{audit:?}"
    );
    let (_, entries) = tf
        .call(&session2, "GET", "/api/v1/audit?limit=100", None)
        .await;
    let used = entries["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["action"] == "auth.recovery_code_used")
        .unwrap();
    assert_eq!(used["detail"]["codes_left"], 8);
    assert!(
        entries["items"].as_array().unwrap().iter().any(|a| {
            a["action"] == "auth.login" && a["detail"]["second_factor"] == "recovery_code"
        }),
        "{entries}"
    );

    // New codes: need an app code (not a recovery code), replace all.
    let uri = "/api/v1/auth/totp/recovery-codes";
    let (s, _) = tf
        .call(&session2, "POST", uri, Some(json!({ "code": codes[2] })))
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = tf
        .call(
            &session2,
            "POST",
            uri,
            Some(json!({ "code": totp_wrong(&secret) })),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    tf.forget_used_codes().await;
    let (s, v) = tf
        .call(
            &session2,
            "POST",
            uri,
            Some(json!({ "code": totp_now(&secret) })),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let fresh: Vec<String> = v["recovery_codes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap().to_owned())
        .collect();
    assert_eq!(fresh.len(), 10);
    assert!(fresh.iter().all(|c| !codes.contains(c)));
    let (s, _, _) = tf.login("kim", TF_PASSWORD, Some(&codes[3])).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "the old codes are gone");
    let (s, _, _) = tf.login("kim", TF_PASSWORD, Some(&fresh[0])).await;
    assert_eq!(s, StatusCode::OK);
    assert!(
        tf.audit_actions()
            .await
            .contains(&("totp.recovery_codes".into(), "kim".into()))
    );

    // No two-factor auth -> nothing to make codes for.
    tf.user("lee", "viewer").await;
    let lee = tf.session("lee").await;
    let (s, _) = tf
        .call(&lee, "POST", uri, Some(json!({ "code": "123456" })))
        .await;
    assert_eq!(s, StatusCode::CONFLICT);
}

/// New device: set up by holder of a current code, replaces old one only after proof.
/// Setup waiting too long -> gone.
#[tokio::test]
async fn a_new_device_replaces_the_old_after_it_proves_itself() {
    let tf = Tf::new(false).await;
    tf.user("kim", "operator").await;
    let session = tf.session("kim").await;
    let (old_secret, codes) = tf.enroll(&session).await;
    tf.forget_used_codes().await;
    let setup = "/api/v1/auth/totp/setup";

    // Two-factor on -> setup needs a current code.
    let (s, _) = tf.call(&session, "POST", setup, Some(json!({}))).await;
    assert_eq!(s, StatusCode::CONFLICT);
    let (s, _) = tf
        .call(
            &session,
            "POST",
            setup,
            Some(json!({ "code": totp_wrong(&old_secret) })),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    // Recovery code works too (phone lost), used up.
    let (s, v) = tf
        .call(&session, "POST", setup, Some(json!({ "code": codes[0] })))
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let new_secret = v["secret"].as_str().unwrap().to_owned();
    assert_ne!(new_secret, old_secret);
    // Until the new app proves itself -> old one still logs in.
    let (s, _, _) = tf
        .login("kim", TF_PASSWORD, Some(&totp_now(&old_secret)))
        .await;
    assert_eq!(s, StatusCode::OK, "the old device keeps working");
    let (s, _) = tf
        .call(
            &session,
            "POST",
            "/api/v1/auth/totp/enable",
            Some(json!({ "code": totp_wrong(&new_secret) })),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, v) = tf
        .call(
            &session,
            "POST",
            "/api/v1/auth/totp/enable",
            Some(json!({ "code": totp_now(&new_secret) })),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let new_codes = v["recovery_codes"].as_array().unwrap().clone();
    assert_eq!(new_codes.len(), 10);
    tf.forget_used_codes().await;
    let (s, _, _) = tf
        .login("kim", TF_PASSWORD, Some(&totp_now(&old_secret)))
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "the old device is replaced");
    let (s, _, _) = tf.login("kim", TF_PASSWORD, Some(&codes[1])).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "so are the old recovery codes");
    tf.forget_used_codes().await;
    let (s, _, _) = tf
        .login("kim", TF_PASSWORD, Some(&totp_now(&new_secret)))
        .await;
    assert_eq!(s, StatusCode::OK);

    // Setup waiting > 1 h -> gone; new setup replaces old.
    let (_, v) = tf
        .call(
            &session,
            "POST",
            setup,
            Some(json!({ "code": new_codes[0] })),
        )
        .await;
    let stale = v["secret"].as_str().unwrap().to_owned();
    let pool = sqlx::PgPool::connect(&format!(
        "postgres://postgres:postgres@127.0.0.1:{}/postgres",
        tf.port
    ))
    .await
    .unwrap();
    sqlx::query("UPDATE user_totp SET pending_at = now() - interval '2 hours'")
        .execute(&pool)
        .await
        .unwrap();
    let (s, _) = tf
        .call(
            &session,
            "POST",
            "/api/v1/auth/totp/enable",
            Some(json!({ "code": totp_now(&stale) })),
        )
        .await;
    assert_eq!(s, StatusCode::CONFLICT, "the setup timed out");
}

/// Admin without two-factor -> can only set it up, until on.
#[tokio::test]
async fn admins_must_enroll_before_doing_anything_else() {
    let tf = Tf::new(true).await;
    tf.user("root", "admin").await;
    let ops_id = tf.user("ops", "operator").await;
    let root = tf.session("root").await;

    // Logged in, enroll only.
    let (s, me) = tf.call(&root, "GET", "/api/v1/auth/me", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        (me["totp_required"].clone(), me["totp_enabled"].clone()),
        (json!(true), json!(false)),
        "{me}"
    );
    for (method, uri, body) in [
        ("GET", "/api/v1/devices", None),
        ("GET", "/api/v1/users", None),
        (
            "POST",
            "/api/v1/users",
            Some(json!({ "username": "x", "password": "correct horse battery", "role": "viewer" })),
        ),
        (
            "POST",
            "/api/v1/api-keys",
            Some(json!({ "name": "k", "role": "admin" })),
        ),
        ("GET", "/api/v1/audit", None),
        ("GET", "/api/v1/stream", None),
        (
            "POST",
            "/api/v1/auth/totp/disable",
            Some(json!({ "password": TF_PASSWORD, "code": "123456" })),
        ),
        (
            "POST",
            "/api/v1/auth/totp/recovery-codes",
            Some(json!({ "code": "123456" })),
        ),
    ] {
        let (s, v) = tf.call(&root, method, uri, body).await;
        assert_eq!(
            (s, v["error"].as_str()),
            (
                StatusCode::FORBIDDEN,
                Some("two-factor enrollment required")
            ),
            "{method} {uri}"
        );
    }
    // Public routes + logout open to it.
    let (s, _, _) = call_cookie(&tf.app, "GET", "/api/v1/auth/config", None, Some(&root)).await;
    assert_eq!(s, StatusCode::OK);
    let (s, _, _) = call_cookie(&tf.app, "GET", "/api/v1/openapi.json", None, Some(&root)).await;
    assert_eq!(s, StatusCode::OK);
    let spare = tf.session("root").await;
    let (s, _, _) = call_cookie(&tf.app, "POST", "/api/v1/auth/logout", None, Some(&spare)).await;
    assert_eq!(s, StatusCode::NO_CONTENT);

    // Setup + confirm work -> same session full afterwards.
    let (root_secret, _) = tf.enroll(&root).await;
    let (s, v) = tf.call(&root, "GET", "/api/v1/devices", None).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (_, me) = tf.call(&root, "GET", "/api/v1/auth/me", None).await;
    assert_eq!(
        (me["totp_required"].clone(), me["totp_enabled"].clone()),
        (json!(true), json!(true))
    );
    // Next login asks for the code (no enroll-only session any more).
    tf.forget_used_codes().await;
    let (s, v, _) = tf.login("root", TF_PASSWORD, None).await;
    assert_eq!(
        (s, v["totp_required"].clone()),
        (StatusCode::UNAUTHORIZED, json!(true))
    );

    // Operator not asked; promoted to admin -> open session = enroll-only at next request
    // (role read every time).
    let ops = tf.session("ops").await;
    assert_eq!(
        tf.call(&ops, "GET", "/api/v1/devices", None).await.0,
        StatusCode::OK
    );
    let (s, v) = tf
        .call(
            &root,
            "PATCH",
            &format!("/api/v1/users/{ops_id}"),
            Some(json!({ "role": "admin" })),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, v) = tf.call(&ops, "GET", "/api/v1/devices", None).await;
    assert_eq!(
        (s, v["error"].as_str()),
        (
            StatusCode::FORBIDDEN,
            Some("two-factor enrollment required")
        )
    );
    let (ops_secret, _) = tf.enroll(&ops).await;
    assert_eq!(
        tf.call(&ops, "GET", "/api/v1/devices", None).await.0,
        StatusCode::OK
    );
    // Demoted -> not asked any more, keeps what it has.
    let (s, _) = tf
        .call(
            &root,
            "PATCH",
            &format!("/api/v1/users/{ops_id}"),
            Some(json!({ "role": "viewer" })),
        )
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        tf.call(&ops, "GET", "/api/v1/devices", None).await.0,
        StatusCode::OK
    );
    let (_, me) = tf.call(&ops, "GET", "/api/v1/auth/me", None).await;
    assert_eq!(
        (me["totp_required"].clone(), me["totp_enabled"].clone()),
        (json!(false), json!(true))
    );
    let (s, _) = tf
        .call(
            &root,
            "PATCH",
            &format!("/api/v1/users/{ops_id}"),
            Some(json!({ "role": "admin" })),
        )
        .await;
    assert_eq!(s, StatusCode::OK);

    // Admin cannot turn it off while required; others can.
    tf.forget_used_codes().await;
    let (s, v) = tf
        .call(
            &root,
            "POST",
            "/api/v1/auth/totp/disable",
            Some(json!({ "password": TF_PASSWORD, "code": totp_now(&root_secret) })),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    assert!(
        v["error"]
            .as_str()
            .unwrap()
            .contains("--require-totp-roles"),
        "{v}"
    );

    // Other admin resets it (lost phone) -> account signed out, enrolls again.
    let users = tf.call(&ops, "GET", "/api/v1/users", None).await.1;
    let root_id = users["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["username"] == "root")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        users["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|u| u["totp_enabled"].clone())
            .collect::<Vec<_>>(),
        [json!(true), json!(true)],
        "the list shows who has it: {users}"
    );
    let reset = format!("/api/v1/users/{root_id}/totp");
    let (s, v) = tf.call(&ops, "DELETE", &reset, None).await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{v}");
    assert_eq!(
        tf.call(&root, "GET", "/api/v1/auth/me", None).await.0,
        StatusCode::UNAUTHORIZED
    );
    let (s, v) = tf.call(&ops, "DELETE", &reset, None).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "nothing left to reset: {v}");
    let root = tf.session("root").await;
    let (s, v) = tf.call(&root, "GET", "/api/v1/devices", None).await;
    assert_eq!(
        (s, v["error"].as_str()),
        (
            StatusCode::FORBIDDEN,
            Some("two-factor enrollment required")
        )
    );
    // Nobody resets own (disable + new-device exist for that).
    let (s, _) = tf
        .call(
            &ops,
            "DELETE",
            &format!("/api/v1/users/{ops_id}/totp"),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::CONFLICT);
    // Only admins reset.
    tf.user("lee", "operator").await;
    let lee = tf.session("lee").await;
    let (s, _) = tf.call(&lee, "DELETE", &reset, None).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = tf
        .call(
            &ops,
            "DELETE",
            &format!("/api/v1/users/{}/totp", Uuid::now_v7()),
            None,
        )
        .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let _ = ops_secret;

    let audit = tf.audit_actions().await;
    assert!(
        audit.contains(&("totp.enable".into(), "root".into())),
        "{audit:?}"
    );
    assert!(
        audit.contains(&("totp.reset".into(), "ops".into())),
        "{audit:?}"
    );
}

/// Requirement off -> admins not forced; may use it + turn it off.
/// Anyone may turn it off with password + code.
#[tokio::test]
async fn two_factor_is_optional_without_the_requirement_and_turned_off_with_password_and_code() {
    let tf = Tf::new(false).await;
    tf.user("root", "admin").await;
    tf.user("kim", "operator").await;
    let root = tf.session("root").await;
    assert_eq!(
        tf.call(&root, "GET", "/api/v1/users", None).await.0,
        StatusCode::OK
    );
    let (_, me) = tf.call(&root, "GET", "/api/v1/auth/me", None).await;
    assert_eq!(me["totp_required"], false, "{me}");

    let disable = "/api/v1/auth/totp/disable";
    let kim = tf.session("kim").await;
    let (s, _) = tf
        .call(
            &kim,
            "POST",
            disable,
            Some(json!({ "password": TF_PASSWORD, "code": "123456" })),
        )
        .await;
    assert_eq!(s, StatusCode::CONFLICT, "not on");
    let (secret, codes) = tf.enroll(&kim).await;
    tf.forget_used_codes().await;
    // Password + code both needed; answer does not say which is wrong.
    let (s, v1) = tf
        .call(
            &kim,
            "POST",
            disable,
            Some(json!({ "password": "wrong password", "code": totp_now(&secret) })),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, v2) = tf
        .call(
            &kim,
            "POST",
            disable,
            Some(json!({ "password": TF_PASSWORD, "code": totp_wrong(&secret) })),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    assert_eq!(v1, v2);
    let (s, _) = tf
        .call(
            &kim,
            "POST",
            disable,
            Some(json!({ "password": TF_PASSWORD, "code": totp_now(&secret), "x": 1 })),
        )
        .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    // Recovery code counts as a code (phone lost).
    let (s, v) = tf
        .call(
            &kim,
            "POST",
            disable,
            Some(json!({ "password": TF_PASSWORD, "code": codes[0] })),
        )
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{v:?}");
    let (s, _, _) = tf.login("kim", TF_PASSWORD, None).await;
    assert_eq!(s, StatusCode::OK, "no code asked for any more");
    assert!(
        tf.audit_actions()
            .await
            .contains(&("totp.disable".into(), "kim".into()))
    );
    // Its recovery codes gone with it -> no way in.
    let (s, _, _) = tf.login("kim", TF_PASSWORD, Some(&codes[1])).await;
    assert_eq!(
        s,
        StatusCode::OK,
        "the field is ignored when no code is needed"
    );

    // Admin may use it + turn it off while not required.
    let (root_secret, _) = tf.enroll(&root).await;
    tf.forget_used_codes().await;
    let (s, _) = tf
        .call(
            &root,
            "POST",
            disable,
            Some(json!({ "password": TF_PASSWORD, "code": totp_now(&root_secret) })),
        )
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
}

/// No two-factor for: no secrets key, SSO accounts, callers that are not a login session.
#[tokio::test]
async fn two_factor_needs_a_secrets_key_a_local_account_and_a_login_session() {
    // No key -> nothing to set up, clear refusal.
    let tf = Tf::with(false, None, Some("tok"), None).await;
    tf.user("kim", "operator").await;
    let kim = tf.session("kim").await;
    let (s, v) = tf.call(&kim, "POST", "/api/v1/auth/totp/setup", None).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert!(
        v["error"].as_str().unwrap().contains("--secrets-key"),
        "{v}"
    );
    let (_, me) = tf.call(&kim, "GET", "/api/v1/auth/me", None).await;
    assert_eq!(me["totp_available"], false);

    // Static token + API keys belong to no account.
    let tf = Tf::with(true, Some(secret_box()), Some("tok"), None).await;
    let (s, v) = call(
        &tf.app,
        "POST",
        "/api/v1/auth/totp/setup",
        None,
        Some("tok"),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    let key = api_key(&tf.app, "tok", "admin", None).await;
    let (s, _) = call(&tf.app, "POST", "/api/v1/auth/totp/setup", None, Some(&key)).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = call(
        &tf.app,
        "DELETE",
        &format!("/api/v1/users/{}/totp", Uuid::now_v7()),
        None,
        Some("tok"),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND, "the token may reset (admin)");
}

/// Requirement = password logins of local accounts. Not asked: SSO sessions, API token,
/// API keys (also admin key made by an enrolled admin).
#[tokio::test]
async fn single_sign_on_the_api_token_and_api_keys_are_not_asked_for_two_factor() {
    let idp = mock_idp().await;
    let tf = Tf::with(
        true,
        Some(secret_box()),
        Some("tok"),
        Some(oidc_test_config(&idp)),
    )
    .await;

    // SSO admin: full session, no two-factor setup.
    let (state, cookie) = sso_start(
        &tf.app,
        &idp,
        "10.4.0.1",
        json!({ "sub": "boss", "preferred_username": "boss", "groups": ["dhonomos-admins"] }),
    )
    .await;
    let end = sso_callback(&tf.app, "10.4.0.1", &state, Some(&cookie)).await;
    let sso = end.session().expect("logged in");
    let (s, me) = tf.call(&sso, "GET", "/api/v1/auth/me", None).await;
    assert_eq!((s, me["role"].clone()), (StatusCode::OK, json!("admin")));
    assert_eq!(
        (
            me["totp_required"].clone(),
            me["totp_enabled"].clone(),
            me["totp_available"].clone()
        ),
        (json!(false), json!(false), json!(false)),
        "{me}"
    );
    assert_eq!(
        tf.call(&sso, "GET", "/api/v1/users", None).await.0,
        StatusCode::OK
    );
    let (s, v) = tf.call(&sso, "POST", "/api/v1/auth/totp/setup", None).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert!(
        v["error"].as_str().unwrap().contains("single sign-on"),
        "{v}"
    );

    // Local admin held to it; its keys + the token are not.
    tf.user("root", "admin").await;
    let root = tf.session("root").await;
    assert_eq!(
        tf.call(&root, "GET", "/api/v1/users", None).await.0,
        StatusCode::FORBIDDEN
    );
    tf.enroll(&root).await;
    let admin_key = api_key(&tf.app, "tok", "admin", None).await;
    let (s, _) = call(&tf.app, "GET", "/api/v1/users", None, Some(&admin_key)).await;
    assert_eq!(s, StatusCode::OK, "API keys are machine credentials");
    let (s, _) = call(&tf.app, "GET", "/api/v1/users", None, Some("tok")).await;
    assert_eq!(s, StatusCode::OK);
    // Password users: own sessions checked, whoever else uses a key.
    let (s, v, _) = tf.login("root", TF_PASSWORD, None).await;
    assert_eq!(
        (s, v["totp_required"].clone()),
        (StatusCode::UNAUTHORIZED, json!(true))
    );
}

// ---------------------------------------------------------------------------------------
// The UI behind a reverse proxy on the internet (ADR-103)
// ---------------------------------------------------------------------------------------

const EXPOSED_PASSWORD: &str = "correct horse battery";

/// One request from `peer` (IPv4) with extra headers.
/// Server socket address matters: the proxy tests are about it.
/// -> status, JSON body (null if none), response headers.
async fn call_from(
    app: &Router,
    peer: &str,
    method: &str,
    uri: &str,
    headers: &[(&str, &str)],
    body: Option<Value>,
) -> (StatusCode, Value, axum::http::HeaderMap) {
    let mut req = Request::builder().method(method).uri(uri);
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let mut req = match body {
        Some(b) => req
            .header("content-type", "application/json")
            .body(Body::from(b.to_string())),
        None => req.body(Body::empty()),
    }
    .unwrap();
    let addr: std::net::SocketAddr = format!("{peer}:40000").parse().unwrap();
    req.extensions_mut()
        .insert(axum::extract::ConnectInfo(addr));
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        headers,
    )
}

/// `name=value` of the first `Set-Cookie` of a response.
fn set_cookie_pair(headers: &axum::http::HeaderMap) -> String {
    headers["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned()
}

/// API over `store`, trusts a proxy on 127.0.0.1, changed by `tweak`.
fn behind_proxy(store: &Store, tweak: impl FnOnce(&mut ApiConfig)) -> Router {
    let mut cfg = ApiConfig {
        tenant_id: DEFAULT_TENANT,
        trusted_proxies: vec!["127.0.0.1/32".parse().unwrap()],
        ..ApiConfig::default()
    };
    tweak(&mut cfg);
    router(store.clone(), cfg)
}

async fn add_account(store: &Store, name: &str, role: &str) -> Uuid {
    store
        .create_user(
            DEFAULT_TENANT,
            name,
            &dhonomos_api::hash_password(EXPOSED_PASSWORD).unwrap(),
            role,
        )
        .await
        .unwrap()
}

/// X-1: no accounts + no token -> open for direct callers, never for a proxied request,
/// however it shows it.
#[tokio::test]
async fn open_mode_is_never_granted_through_a_proxy() {
    let (_c, store, direct, _) = setup(None).await;
    let get = |app: &Router, peer: &str, uri: &str, headers: &[(&str, &str)]| {
        let (app, peer, uri) = (app.clone(), peer.to_owned(), uri.to_owned());
        let headers: Vec<(String, String)> = headers
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        async move {
            let headers: Vec<(&str, &str)> = headers
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();
            let (s, v, _) = call_from(&app, &peer, "GET", &uri, &headers, None).await;
            (s, v)
        }
    };

    // Direct call -> open (development).
    let (s, v) = get(&direct, "127.0.0.1", "/api/v1/auth/me", &[]).await;
    assert_eq!((s, v["via"].as_str()), (StatusCode::OK, Some("open")));
    // Any proxy header -> closed, on every route that needs a login.
    for (name, value) in [
        ("forwarded", "for=203.0.113.7;proto=https"),
        ("x-forwarded-for", "203.0.113.7"),
        ("x-forwarded-host", "rms.example.org"),
        ("x-forwarded-proto", "https"),
        ("x-real-ip", "203.0.113.7"),
    ] {
        for uri in ["/api/v1/auth/me", "/api/v1/devices", "/metrics"] {
            let (s, v) = get(&direct, "127.0.0.1", uri, &[(name, value)]).await;
            assert_eq!(s, StatusCode::UNAUTHORIZED, "{name} {uri}: {v}");
            assert!(
                v["error"]
                    .as_str()
                    .unwrap()
                    .contains("no accounts exist; create an admin account on the server"),
                "{name} {uri}: {v}"
            );
        }
    }
    // First account cannot be made via proxy either.
    let (s, _, _) = call_from(
        &direct,
        "127.0.0.1",
        "POST",
        "/api/v1/users",
        &[("x-forwarded-for", "203.0.113.7")],
        Some(json!({ "username": "intruder", "password": EXPOSED_PASSWORD, "role": "admin" })),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert!(!store.has_users().await.unwrap());

    // Trusted proxy configured -> its request = proxied, even without headers;
    // from any other address (direct caller) not.
    let behind = behind_proxy(&store, |_| {});
    let (s, _) = get(&behind, "127.0.0.1", "/api/v1/devices", &[]).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "the trusted proxy itself");
    let (s, _) = get(&behind, "10.9.9.9", "/api/v1/devices", &[]).await;
    assert_eq!(s, StatusCode::OK, "a direct caller");
    let (s, _) = get(
        &behind,
        "10.9.9.9",
        "/api/v1/devices",
        &[("x-forwarded-for", "203.0.113.7")],
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "headers from anyone count");

    // Account exists -> ordinary answer.
    add_account(&store, "root", "admin").await;
    let (s, v) = get(
        &direct,
        "127.0.0.1",
        "/api/v1/devices",
        &[("x-forwarded-for", "203.0.113.7")],
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(v["error"], "log in, or send a bearer token or API key");
}

/// X-3: limits + lockouts per client address = the one a trusted proxy forwards.
/// Not believed: what the visitor wrote left of it, what an untrusted peer writes.
#[tokio::test]
async fn limits_and_lockouts_follow_the_client_a_trusted_proxy_forwards() {
    let (_c, store, _, _) = setup(None).await;
    add_account(&store, "alice", "admin").await;
    let idp = mock_idp().await;
    let app = behind_proxy(&store, |c| {
        c.rate_limit = 2.into();
        c.oidc = Some(dhonomos_api::OidcConfig {
            issuer: idp.issuer.clone(),
            client_id: "dhonomos".into(),
            client_secret: None,
            redirect_url: "http://dhonomos.test/api/v1/auth/oidc/callback".into(),
            scopes: "openid".into(),
            username_claim: "preferred_username".into(),
            role_claim: "groups".into(),
            admin: vec!["*".into()],
            operator: Vec::new(),
            viewer: Vec::new(),
        });
    });
    let via = |peer: &str, xff: &str| {
        let (app, peer, xff) = (app.clone(), peer.to_owned(), xff.to_owned());
        move |method: &'static str, uri: &'static str, body: Option<Value>| {
            let (app, peer, xff) = (app.clone(), peer.clone(), xff.clone());
            async move {
                let (s, v, h) =
                    call_from(&app, &peer, method, uri, &[("x-forwarded-for", &xff)], body).await;
                (s, v, h)
            }
        }
    };
    let login = |peer: &str, xff: &str, password: &str| {
        let send = via(peer, xff);
        let body = json!({ "username": "alice", "password": password });
        async move { send("POST", "/api/v1/auth/login", Some(body)).await.0 }
    };

    // Login lockout: per name + client address -> a visitor locks out only themselves.
    for _ in 0..5 {
        assert_eq!(
            login("127.0.0.1", "203.0.113.1", "wrong").await,
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        login("127.0.0.1", "203.0.113.1", EXPOSED_PASSWORD).await,
        StatusCode::TOO_MANY_REQUESTS,
        "locked, even with the right password"
    );
    assert_eq!(
        login("127.0.0.1", "203.0.113.2", EXPOSED_PASSWORD).await,
        StatusCode::OK,
        "another visitor behind the same proxy is not locked"
    );
    // Visitor text left of the proxy-appended address -> not believed.
    assert_eq!(
        login("127.0.0.1", "203.0.113.2, 203.0.113.1", EXPOSED_PASSWORD).await,
        StatusCode::TOO_MANY_REQUESTS,
        "the client is the right-most address, whatever is spoofed before it"
    );
    // Peer not a trusted proxy = the client; its header ignored.
    for i in 0..5 {
        assert_eq!(
            login("198.51.100.9", &format!("203.0.113.{}", 100 + i), "wrong").await,
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        login("198.51.100.9", "203.0.113.200", "wrong").await,
        StatusCode::TOO_MANY_REQUESTS,
        "a new forwarded address does not give an untrusted peer a fresh count"
    );

    // Public route rate limit per client: 1 visitor cannot use up everyone's.
    let busy = via("127.0.0.1", "203.0.113.50");
    let mut limited = 0;
    for _ in 0..45 {
        if busy("POST", "/api/v1/auth/login", Some(json!({}))).await.0
            == StatusCode::TOO_MANY_REQUESTS
        {
            limited += 1;
        }
    }
    assert!(
        limited > 0,
        "45 requests in a moment are too many for one client"
    );
    let calm = via("127.0.0.1", "203.0.113.51");
    assert_eq!(
        calm("POST", "/api/v1/auth/login", Some(json!({}))).await.0,
        StatusCode::UNPROCESSABLE_ENTITY,
        "another client still gets through"
    );

    // Failed auth limited per client too.
    let noisy = via("127.0.0.1", "203.0.113.60");
    let mut limited = 0;
    for _ in 0..14 {
        if noisy("GET", "/api/v1/devices", None).await.0 == StatusCode::TOO_MANY_REQUESTS {
            limited += 1;
        }
    }
    assert!(limited > 0);
    let quiet = via("127.0.0.1", "203.0.113.61");
    assert_eq!(
        quiet("GET", "/api/v1/devices", None).await.0,
        StatusCode::UNAUTHORIZED
    );

    // SSO logins in progress: 20 per client, not 20 for the whole proxy.
    let sso = via("127.0.0.1", "203.0.113.70");
    for i in 0..20 {
        let (s, _, _) = sso("GET", "/api/v1/auth/oidc/login", None).await;
        assert_eq!(s, StatusCode::FOUND, "login {i}");
    }
    assert_eq!(
        sso("GET", "/api/v1/auth/oidc/login", None).await.0,
        StatusCode::TOO_MANY_REQUESTS
    );
    let other = via("127.0.0.1", "203.0.113.71");
    assert_eq!(
        other("GET", "/api/v1/auth/oidc/login", None).await.0,
        StatusCode::FOUND
    );
}

/// X-3: cross-site request check with trusted proxy `X-Forwarded-Host` +
/// `X-Forwarded-Proto`, and with `--public-url`.
#[tokio::test]
async fn forwarded_host_scheme_and_the_public_url_decide_the_origin_check() {
    let (_c, store, _, id) = setup(None).await;
    add_account(&store, "root", "admin").await;
    let plain = behind_proxy(&store, |_| {});
    let public = behind_proxy(&store, |c| {
        c.public_url = Some("https://rms.example.org".parse().unwrap());
    });
    let session = |app: Router| async move {
        let (s, _, h) = call_from(
            &app,
            "127.0.0.1",
            "POST",
            "/api/v1/auth/login",
            &[("x-forwarded-for", "203.0.113.7")],
            Some(json!({ "username": "root", "password": EXPOSED_PASSWORD })),
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        set_cookie_pair(&h)
    };
    let (cookie_plain, cookie_public) =
        (session(plain.clone()).await, session(public.clone()).await);
    let change = |app: &Router, cookie: &str, peer: &str, headers: &[(&str, &str)]| {
        let (app, peer, cookie) = (app.clone(), peer.to_owned(), cookie.to_owned());
        let headers: Vec<(String, String)> = headers
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        async move {
            let mut all = vec![
                ("cookie", cookie.as_str()),
                ("x-forwarded-for", "203.0.113.7"),
            ];
            all.extend(headers.iter().map(|(k, v)| (k.as_str(), v.as_str())));
            call_from(
                &app,
                &peer,
                "POST",
                &format!("/api/v1/devices/{id}/tasks"),
                &all,
                Some(json!({ "kind": "reboot", "connection_request": false })),
            )
            .await
            .0
        }
    };

    // Proxy rewrites Host -> its X-Forwarded-Host counts; reported scheme must = Origin's.
    let ops = [
        ("host", "127.0.0.1:8080"),
        ("x-forwarded-host", "ops.example.net"),
        ("x-forwarded-proto", "https"),
    ];
    let with_origin = |origin: &'static str| {
        let mut h = ops.to_vec();
        h.push(("origin", origin));
        h
    };
    assert_eq!(
        change(
            &plain,
            &cookie_plain,
            "127.0.0.1",
            &with_origin("https://ops.example.net")
        )
        .await,
        StatusCode::CREATED
    );
    assert_eq!(
        change(
            &plain,
            &cookie_plain,
            "127.0.0.1",
            &with_origin("http://ops.example.net")
        )
        .await,
        StatusCode::FORBIDDEN,
        "the proxy says https"
    );
    assert_eq!(
        change(
            &plain,
            &cookie_plain,
            "127.0.0.1",
            &with_origin("https://evil.example")
        )
        .await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        change(
            &plain,
            &cookie_plain,
            "198.51.100.9",
            &with_origin("https://ops.example.net")
        )
        .await,
        StatusCode::FORBIDDEN,
        "an untrusted peer's X-Forwarded-Host vouches for nothing"
    );
    // Proxy that keeps Host -> works without host forwarding headers.
    assert_eq!(
        change(
            &plain,
            &cookie_plain,
            "127.0.0.1",
            &[
                ("host", "rms.example.org"),
                ("origin", "https://rms.example.org")
            ]
        )
        .await,
        StatusCode::CREATED
    );

    // Public URL set -> only that address is this site, whatever Host + forwarded headers say.
    let host_ok = |origin: &'static str| vec![("host", "127.0.0.1:8080"), ("origin", origin)];
    assert_eq!(
        change(
            &public,
            &cookie_public,
            "127.0.0.1",
            &host_ok("https://rms.example.org")
        )
        .await,
        StatusCode::CREATED
    );
    for bad in [
        "http://rms.example.org",
        "https://rms.example.org:8443",
        "https://evil.example",
        "https://rms.example.org.evil.example",
        "null",
    ] {
        assert_eq!(
            change(&public, &cookie_public, "127.0.0.1", &host_ok(bad)).await,
            StatusCode::FORBIDDEN,
            "{bad}"
        );
    }
    assert_eq!(
        change(
            &public,
            &cookie_public,
            "127.0.0.1",
            &[
                ("host", "evil.example"),
                ("x-forwarded-host", "evil.example"),
                ("origin", "https://evil.example")
            ]
        )
        .await,
        StatusCode::FORBIDDEN,
        "neither Host nor X-Forwarded-Host can vouch for another Origin"
    );
    // Reads + requests without Origin -> not checked.
    assert_eq!(
        change(&public, &cookie_public, "127.0.0.1", &[("host", "x")]).await,
        StatusCode::CREATED
    );
}

/// X-7: `--secure-cookies` -> session cookie `__Host-` prefixed, old name no session.
/// Proxy says HTTPS -> cookie Secure.
#[tokio::test]
async fn the_session_cookie_has_the_host_prefix_with_secure_cookies() {
    let (_c, store, _, _) = setup(None).await;
    add_account(&store, "root", "admin").await;
    let secure = behind_proxy(&store, |c| c.secure_cookies = true);
    let xff = [("x-forwarded-for", "203.0.113.7")];
    let login = json!({ "username": "root", "password": EXPOSED_PASSWORD });
    let (s, _, h) = call_from(
        &secure,
        "127.0.0.1",
        "POST",
        "/api/v1/auth/login",
        &xff,
        Some(login.clone()),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let cookie = h["set-cookie"].to_str().unwrap().to_owned();
    assert!(cookie.starts_with("__Host-dhonomos_session="), "{cookie}");
    for want in ["; Secure", "; Path=/", "; HttpOnly", "; SameSite=Strict"] {
        assert!(cookie.contains(want), "{cookie}");
    }
    assert!(!cookie.contains("Domain"), "{cookie}");
    let pair = set_cookie_pair(&h);
    let me = |app: &Router, cookie: &str| {
        let (app, cookie) = (app.clone(), cookie.to_owned());
        async move {
            call_from(
                &app,
                "127.0.0.1",
                "GET",
                "/api/v1/auth/me",
                &[("x-forwarded-for", "203.0.113.7"), ("cookie", &cookie)],
                None,
            )
            .await
            .0
        }
    };
    assert_eq!(me(&secure, &pair).await, StatusCode::OK);
    // Old name with same token -> no session (a sibling domain could set it).
    let token = pair.split_once('=').unwrap().1;
    assert_eq!(
        me(&secure, &format!("dhonomos_session={token}")).await,
        StatusCode::UNAUTHORIZED
    );
    // Logout clears the prefixed cookie + the old name.
    let (s, _, h) = call_from(
        &secure,
        "127.0.0.1",
        "POST",
        "/api/v1/auth/logout",
        &[("x-forwarded-for", "203.0.113.7"), ("cookie", &pair)],
        None,
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let cleared: Vec<&str> = h
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap())
        .collect();
    assert_eq!(cleared.len(), 2, "{cleared:?}");
    assert!(
        cleared[0].starts_with("__Host-dhonomos_session=;")
            && cleared[0].contains("Max-Age=0")
            && cleared[0].contains("; Secure"),
        "{cleared:?}"
    );
    assert!(cleared[1].starts_with("dhonomos_session=;") && cleared[1].contains("Max-Age=0"));
    assert_eq!(
        me(&secure, &pair).await,
        StatusCode::UNAUTHORIZED,
        "the session ended"
    );

    // Account screens find the session by the same name: enrolling ends other sessions
    // of the account, not the enrolling one.
    add_account(&store, "ops", "operator").await;
    let ops_login = json!({ "username": "ops", "password": EXPOSED_PASSWORD });
    let with_keys = behind_proxy(&store, |c| {
        c.secure_cookies = true;
        c.secrets = Some(secret_box());
    });
    let session_of = |h: &axum::http::HeaderMap| set_cookie_pair(h);
    let (_, _, h) = call_from(
        &with_keys,
        "127.0.0.1",
        "POST",
        "/api/v1/auth/login",
        &xff,
        Some(ops_login.clone()),
    )
    .await;
    let first = session_of(&h);
    let (_, _, h) = call_from(
        &with_keys,
        "127.0.0.1",
        "POST",
        "/api/v1/auth/login",
        &xff,
        Some(ops_login),
    )
    .await;
    let other = session_of(&h);
    let call_with = |cookie: String, uri: &'static str, body: Option<Value>| {
        let app = with_keys.clone();
        async move {
            let (s, v, _) = call_from(
                &app,
                "127.0.0.1",
                if body.is_some() { "POST" } else { "GET" },
                uri,
                &[("x-forwarded-for", "203.0.113.7"), ("cookie", &cookie)],
                body,
            )
            .await;
            (s, v)
        }
    };
    let (s, v) = call_with(first.clone(), "/api/v1/auth/totp/setup", Some(json!({}))).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let code = totp_now(v["secret"].as_str().unwrap());
    let (s, v) = call_with(
        first.clone(),
        "/api/v1/auth/totp/enable",
        Some(json!({ "code": code })),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        call_with(first, "/api/v1/auth/me", None).await.0,
        StatusCode::OK,
        "the session that enrolled stays"
    );
    assert_eq!(
        call_with(other, "/api/v1/auth/me", None).await.0,
        StatusCode::UNAUTHORIZED,
        "another session of the account ends"
    );

    // No --secure-cookies -> old name; Secure only if a trusted proxy says visitor used HTTPS.
    let lax = behind_proxy(&store, |_| {});
    let (_, _, h) = call_from(
        &lax,
        "127.0.0.1",
        "POST",
        "/api/v1/auth/login",
        &xff,
        Some(login.clone()),
    )
    .await;
    let cookie = h["set-cookie"].to_str().unwrap().to_owned();
    assert!(
        cookie.starts_with("dhonomos_session=") && !cookie.contains("Secure"),
        "{cookie}"
    );
    let (_, _, h) = call_from(
        &lax,
        "127.0.0.1",
        "POST",
        "/api/v1/auth/login",
        &[
            ("x-forwarded-for", "203.0.113.7"),
            ("x-forwarded-proto", "https"),
        ],
        Some(login.clone()),
    )
    .await;
    let cookie = h["set-cookie"].to_str().unwrap().to_owned();
    assert!(
        cookie.starts_with("dhonomos_session=") && cookie.contains("; Secure"),
        "{cookie}"
    );
    // Untrusted peer's X-Forwarded-Proto -> not believed.
    let (_, _, h) = call_from(
        &lax,
        "198.51.100.9",
        "POST",
        "/api/v1/auth/login",
        &[
            ("x-forwarded-for", "203.0.113.7"),
            ("x-forwarded-proto", "https"),
        ],
        Some(login),
    )
    .await;
    assert!(!h["set-cookie"].to_str().unwrap().contains("Secure"));
}

/// X-4: attempt counted before checked -> concurrent requests cannot all pass the limit.
#[tokio::test]
async fn concurrent_logins_cannot_exceed_the_attempt_limit() {
    let (_c, store, _, _) = setup(None).await;
    add_account(&store, "alice", "admin").await;
    let app = router(
        store.clone(),
        ApiConfig {
            tenant_id: DEFAULT_TENANT,
            ..ApiConfig::default()
        },
    );
    let attempts = (0..16).map(|_| {
        call_from(
            &app,
            "203.0.113.9",
            "POST",
            "/api/v1/auth/login",
            &[],
            Some(json!({ "username": "alice", "password": "wrong" })),
        )
    });
    let answers: Vec<StatusCode> = futures_util::future::join_all(attempts)
        .await
        .into_iter()
        .map(|a| a.0)
        .collect();
    let checked = answers
        .iter()
        .filter(|s| **s == StatusCode::UNAUTHORIZED)
        .count();
    let refused = answers
        .iter()
        .filter(|s| **s == StatusCode::TOO_MANY_REQUESTS)
        .count();
    assert_eq!((checked, refused), (5, 11), "{answers:?}");
}

/// X-5, X-11: 5 tries per name + client address, 50 per name over all addresses.
#[tokio::test]
async fn one_client_cannot_lock_a_name_for_everyone_but_many_are_capped() {
    let (_c, store, _, _) = setup(None).await;
    add_account(&store, "alice", "admin").await;
    add_account(&store, "bob", "admin").await;
    let app = router(
        store.clone(),
        ApiConfig {
            tenant_id: DEFAULT_TENANT,
            ..ApiConfig::default()
        },
    );
    let try_login = |name: &'static str, client: String, password: &'static str| {
        let app = app.clone();
        async move {
            call_from(
                &app,
                &client,
                "POST",
                "/api/v1/auth/login",
                &[],
                Some(json!({ "username": name, "password": password })),
            )
            .await
            .0
        }
    };
    for _ in 0..5 {
        assert_eq!(
            try_login("alice", "203.0.113.1".into(), "wrong").await,
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        try_login("alice", "203.0.113.1".into(), EXPOSED_PASSWORD).await,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        try_login("alice", "203.0.113.2".into(), EXPOSED_PASSWORD).await,
        StatusCode::OK,
        "the name is not locked for another address"
    );
    assert_eq!(
        try_login("bob", "203.0.113.1".into(), EXPOSED_PASSWORD).await,
        StatusCode::OK,
        "nor is another name locked for the address"
    );

    // Guessing over many addresses capped per name: 1 try each from 50 addresses,
    // then even the right password refused.
    let guesses = (0..50).map(|i| try_login("bob", format!("10.1.0.{}", i + 1), "wrong"));
    let answers = futures_util::future::join_all(guesses).await;
    assert!(
        answers.iter().all(|s| *s == StatusCode::UNAUTHORIZED),
        "{answers:?}"
    );
    assert_eq!(
        try_login("bob", "203.0.113.77".into(), EXPOSED_PASSWORD).await,
        StatusCode::TOO_MANY_REQUESTS,
        "the ceiling over all addresses"
    );
    assert_eq!(
        try_login("alice", "203.0.113.77".into(), EXPOSED_PASSWORD).await,
        StatusCode::OK,
        "other names are not affected"
    );
}

/// X-4, X-10: two-factor screens count tries before checking, in a table of their own
/// (nothing shared with the login's).
#[tokio::test]
async fn two_factor_tries_are_counted_at_once_and_in_their_own_table() {
    let tf = Tf::new(false).await;
    tf.user("kim", "operator").await;
    tf.user("lee", "operator").await;
    let session = tf.session("kim").await;
    let (secret, _) = tf.enroll(&session).await;

    // 12 wrong codes at once: 5 checked, rest refused unchecked.
    let wrong = totp_wrong(&secret);
    let answers: Vec<StatusCode> = futures_util::future::join_all((0..12).map(|_| {
        tf.call(
            &session,
            "POST",
            "/api/v1/auth/totp/recovery-codes",
            Some(json!({ "code": wrong })),
        )
    }))
    .await
    .into_iter()
    .map(|a| a.0)
    .collect();
    let count = |want: StatusCode| answers.iter().filter(|s| **s == want).count();
    assert_eq!(
        (
            count(StatusCode::FORBIDDEN),
            count(StatusCode::TOO_MANY_REQUESTS)
        ),
        (5, 7),
        "{answers:?}"
    );
    tf.forget_used_codes().await;
    let (s, _) = tf
        .call(
            &session,
            "POST",
            "/api/v1/auth/totp/recovery-codes",
            Some(json!({ "code": totp_now(&secret) })),
        )
        .await;
    assert_eq!(
        s,
        StatusCode::TOO_MANY_REQUESTS,
        "locked, even for the right code"
    );
    // Login has its own table: owner still logs in with password + code.
    let (s, v, _) = tf.login("kim", TF_PASSWORD, Some(&totp_now(&secret))).await;
    assert_eq!(s, StatusCode::OK, "{v}");

    // Other way round: failed logins do not lock the account screens.
    let lee = tf.session("lee").await;
    let (lee_secret, _) = tf.enroll(&lee).await;
    for _ in 0..5 {
        assert_eq!(
            tf.login("lee", "wrong password", None).await.0,
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        tf.login("lee", "wrong password", None).await.0,
        StatusCode::TOO_MANY_REQUESTS
    );
    tf.forget_used_codes().await;
    let (s, v) = tf
        .call(
            &lee,
            "POST",
            "/api/v1/auth/totp/recovery-codes",
            Some(json!({ "code": totp_now(&lee_secret) })),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");

    // Login name like the old key of the screens' table -> locks nothing there.
    for _ in 0..5 {
        assert_eq!(
            tf.login("totp:lee", "x", None).await.0,
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        tf.login("totp:lee", "x", None).await.0,
        StatusCode::TOO_MANY_REQUESTS
    );
    tf.forget_used_codes().await;
    let (s, v) = tf
        .call(
            &lee,
            "POST",
            "/api/v1/auth/totp/recovery-codes",
            Some(json!({ "code": totp_now(&lee_secret) })),
        )
        .await;
    assert_eq!(
        s,
        StatusCode::OK,
        "totp:lee has nothing to do with lee's screens: {v}"
    );
}

/// X-6: each role in `--require-totp-roles` must enroll before anything else.
#[tokio::test]
async fn the_two_factor_requirement_covers_every_listed_role() {
    let tf = Tf::roles(&["admin", "operator"]).await;
    tf.user("boss", "admin").await;
    tf.user("ops", "operator").await;
    tf.user("view", "viewer").await;

    let ops = tf.session("ops").await;
    let (_, me) = tf.call(&ops, "GET", "/api/v1/auth/me", None).await;
    assert_eq!(
        (me["totp_required"].clone(), me["totp_enabled"].clone()),
        (json!(true), json!(false)),
        "{me}"
    );
    let (s, v) = tf.call(&ops, "GET", "/api/v1/devices", None).await;
    assert_eq!(
        (s, v["error"].as_str()),
        (
            StatusCode::FORBIDDEN,
            Some("two-factor enrollment required")
        )
    );
    let (s, _) = tf
        .call(&ops, "POST", "/api/v1/auth/totp/setup", Some(json!({})))
        .await;
    assert_eq!(s, StatusCode::OK, "enrolling stays open");
    let boss = tf.session("boss").await;
    assert_eq!(
        tf.call(&boss, "GET", "/api/v1/devices", None).await.0,
        StatusCode::FORBIDDEN,
        "the admin too"
    );
    // Role not listed -> not asked.
    let view = tf.session("view").await;
    assert_eq!(
        tf.call(&view, "GET", "/api/v1/devices", None).await.0,
        StatusCode::OK
    );

    // Enrolled -> same session complete; requirement cannot be turned off.
    let (secret, _) = tf.enroll(&ops).await;
    assert_eq!(
        tf.call(&ops, "GET", "/api/v1/devices", None).await.0,
        StatusCode::OK
    );
    tf.forget_used_codes().await;
    let (s, v) = tf
        .call(
            &ops,
            "POST",
            "/api/v1/auth/totp/disable",
            Some(json!({ "password": TF_PASSWORD, "code": totp_now(&secret) })),
        )
        .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{v}");
    assert!(
        v["error"]
            .as_str()
            .unwrap()
            .contains("--require-totp-roles"),
        "{v}"
    );
    // Viewer may turn it on + off.
    let (secret, _) = tf.enroll(&view).await;
    tf.forget_used_codes().await;
    let (s, v) = tf
        .call(
            &view,
            "POST",
            "/api/v1/auth/totp/disable",
            Some(json!({ "password": TF_PASSWORD, "code": totp_now(&secret) })),
        )
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT, "{v}");

    // Viewer role can be listed too.
    let tf = Tf::roles(&["viewer"]).await;
    tf.user("view", "viewer").await;
    tf.user("boss", "admin").await;
    let view = tf.session("view").await;
    assert_eq!(
        tf.call(&view, "GET", "/api/v1/devices", None).await.0,
        StatusCode::FORBIDDEN
    );
    let boss = tf.session("boss").await;
    assert_eq!(
        tf.call(&boss, "GET", "/api/v1/devices", None).await.0,
        StatusCode::OK,
        "admin is not in this list"
    );
}

/// X-7: session unused for `session_idle_minutes` -> ends.
/// `last_seen_at` written max 1/min.
#[tokio::test]
async fn idle_sessions_end_and_last_seen_is_written_at_most_once_a_minute() {
    let (c, store, _, _) = setup(None).await;
    add_account(&store, "root", "admin").await;
    let pool = sqlx::PgPool::connect(&format!(
        "postgres://postgres:postgres@127.0.0.1:{}/postgres",
        c.get_host_port_ipv4(5432).await.unwrap()
    ))
    .await
    .unwrap();
    let app_with = |minutes: i64| {
        router(
            store.clone(),
            ApiConfig {
                tenant_id: DEFAULT_TENANT,
                session_idle_minutes: minutes.into(),
                ..ApiConfig::default()
            },
        )
    };
    let app = app_with(30);
    let (_, _, cookie) = call_cookie(
        &app,
        "POST",
        "/api/v1/auth/login",
        Some(json!({ "username": "root", "password": EXPOSED_PASSWORD })),
        None,
    )
    .await;
    let session = cookie.unwrap().split(';').next().unwrap().to_owned();
    let me = |app: Router| {
        let session = session.clone();
        async move {
            call_cookie(&app, "GET", "/api/v1/auth/me", None, Some(&session))
                .await
                .0
        }
    };
    let last_seen = async || -> f64 {
        sqlx::query_scalar("SELECT extract(epoch FROM last_seen_at)::float8 FROM sessions")
            .fetch_one(&pool)
            .await
            .unwrap()
    };
    let age = async |secs: f64| {
        sqlx::query("UPDATE sessions SET last_seen_at = now() - make_interval(secs => $1)")
            .bind(secs)
            .execute(&pool)
            .await
            .unwrap();
    };

    // Used a moment ago -> allowed, not written again.
    assert_eq!(me(app.clone()).await, StatusCode::OK);
    let t0 = last_seen().await;
    assert_eq!(me(app.clone()).await, StatusCode::OK);
    assert_eq!(last_seen().await, t0, "no write within a minute");
    age(10.0).await;
    let t10 = last_seen().await;
    assert_eq!(me(app.clone()).await, StatusCode::OK);
    assert_eq!(last_seen().await, t10, "10 seconds old is not rewritten");
    // 20 min idle -> still allowed, time updated.
    age(20.0 * 60.0).await;
    let t20 = last_seen().await;
    assert_eq!(me(app.clone()).await, StatusCode::OK);
    assert!(last_seen().await > t20 + 19.0 * 60.0, "refreshed");
    // 31 min idle -> session ended.
    age(31.0 * 60.0).await;
    assert_eq!(me(app.clone()).await, StatusCode::UNAUTHORIZED);
    // Idle limit off -> same old session works until expiry.
    assert_eq!(me(app_with(0)).await, StatusCode::OK);

    // Limit changes at runtime (runtime settings).
    let minutes = dhonomos_core::Shared::new(30);
    let app = router(
        store.clone(),
        ApiConfig {
            tenant_id: DEFAULT_TENANT,
            session_idle_minutes: minutes.clone(),
            ..ApiConfig::default()
        },
    );
    age(31.0 * 60.0).await;
    assert_eq!(
        me(app.clone()).await,
        StatusCode::UNAUTHORIZED,
        "31 minutes idle"
    );
    minutes.replace(60);
    assert_eq!(
        me(app.clone()).await,
        StatusCode::OK,
        "within the new limit"
    );
    age(31.0 * 60.0).await;
    minutes.replace(0);
    assert_eq!(me(app.clone()).await, StatusCode::OK, "off");
    age(31.0 * 60.0).await;
    minutes.replace(30);
    assert_eq!(me(app).await, StatusCode::UNAUTHORIZED);
}

/// X-9: SSO login never ends on another site, however the path is spelled.
#[tokio::test]
async fn single_sign_on_returns_only_to_paths_on_this_site() {
    let (_c, store, _, _) = setup(None).await;
    let idp = mock_idp().await;
    let app = router(
        store.clone(),
        ApiConfig {
            tenant_id: DEFAULT_TENANT,
            oidc: Some(dhonomos_api::OidcConfig {
                issuer: idp.issuer.clone(),
                client_id: "dhonomos".into(),
                client_secret: Some("s3".into()),
                redirect_url: "http://dhonomos.test/api/v1/auth/oidc/callback".into(),
                scopes: "openid".into(),
                username_claim: "preferred_username".into(),
                role_claim: "groups".into(),
                admin: vec!["*".into()],
                operator: Vec::new(),
                viewer: Vec::new(),
            }),
            ..ApiConfig::default()
        },
    );
    let exp = time::OffsetDateTime::now_utc().unix_timestamp() + 300;
    let landing = |return_to: &'static str| {
        let (app, claims, challenge, issuer) = (
            app.clone(),
            idp.claims.clone(),
            idp.challenge.clone(),
            idp.issuer.clone(),
        );
        async move {
            let resp = app
                .clone()
                .oneshot(
                    Request::get(format!("/api/v1/auth/oidc/login?return_to={return_to}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::FOUND);
            let cookie = resp.headers()["set-cookie"]
                .to_str()
                .unwrap()
                .split(';')
                .next()
                .unwrap()
                .to_owned();
            let loc = resp.headers()["location"].to_str().unwrap().to_owned();
            let param = |k: &str| {
                loc.split(['?', '&'])
                    .find_map(|kv| kv.strip_prefix(&format!("{k}=")))
                    .unwrap()
                    .to_owned()
            };
            *challenge.lock().unwrap() = param("code_challenge");
            *claims.lock().unwrap() = json!({ "iss": issuer, "aud": "dhonomos", "exp": exp,
                "sub": "u-1", "preferred_username": "kim", "nonce": param("nonce") });
            let resp = app
                .oneshot(
                    Request::get(format!(
                        "/api/v1/auth/oidc/callback?code=good-code&state={}",
                        param("state")
                    ))
                    .header("cookie", cookie)
                    .body(Body::empty())
                    .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::FOUND);
            resp.headers()["location"].to_str().unwrap().to_owned()
        }
    };
    assert_eq!(landing("/jobs").await, "/jobs");
    for bad in [
        "/%09/evil.example",
        "/%0a/evil.example",
        "/%0d/evil.example",
        "//evil.example",
        "/%5Cevil.example",
        "https://evil.example",
    ] {
        assert_eq!(landing(bad).await, "/", "{bad}");
    }
}

/// X-12: all but the UI's own files -> `Cache-Control: no-store`
/// (metrics, exports, OpenAPI document, even plain text).
/// Stored files + cert bundles: checked where they are made.
#[tokio::test]
async fn data_responses_are_not_cached() {
    let admin = "admin-token";
    let (_c, _store, app, _) = setup(Some(admin)).await;
    for uri in [
        "/metrics",
        "/healthz",
        "/api/v1/openapi.json",
        "/api/v1/devices",
        "/api/v1/devices/export.csv",
        "/api/v1/presets/export.yaml",
        "/api/v1/audit",
    ] {
        let resp = app
            .clone()
            .oneshot(
                Request::get(uri)
                    .header("authorization", format!("Bearer {admin}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.headers()
                .get("cache-control")
                .map(|v| v.to_str().unwrap()),
            Some("no-store"),
            "{uri} ({})",
            resp.status()
        );
    }
}

// --- WireGuard management (ADR-110, stage 1) ----------------------------------------------

/// WireGuard test key from `n`: 32 bytes of `n + 1`.
fn wg_key(n: u8) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode([n.wrapping_add(1); 32])
}

async fn wg_hub_and_network(app: &Router, admin: &str) -> (String, String) {
    let (s, hub) = call(
        app,
        "POST",
        "/api/v1/wireguard/hubs",
        Some(json!({ "name": "lab-hub", "endpoint_host": "hub.example.org" })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{hub}");
    let hub = hub["id"].as_str().unwrap().to_owned();
    let (s, net) = call(
        app,
        "POST",
        "/api/v1/wireguard/networks",
        Some(json!({ "hub_id": hub, "name": "branches" })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{net}");
    (hub, net["id"].as_str().unwrap().to_owned())
}

/// Set hub public key, as `dhonomos-wg-hub` reports it at start.
/// Needed for client config files with a server-made key pair.
async fn wg_hub_has_key(store: &Store, hub: &str) -> String {
    let key = wg_key(200);
    store
        .set_wg_hub_public_key(hub.parse().unwrap(), &key)
        .await
        .unwrap()
        .unwrap();
    key
}

async fn wg_login(app: &Router, name: &str) -> String {
    let (s, _, cookie) = call_cookie(
        app,
        "POST",
        "/api/v1/auth/login",
        Some(json!({ "username": name, "password": "correct horse battery" })),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "login {name}");
    cookie.unwrap().split(';').next().unwrap().to_owned()
}

async fn wg_user(app: &Router, admin: &str, name: &str, role: &str, scope: Option<Value>) -> Uuid {
    let (s, v) = call(
        app,
        "POST",
        "/api/v1/users",
        Some(
            json!({ "username": name, "password": "correct horse battery", "role": role,
                     "scope": scope }),
        ),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    v["id"].as_str().unwrap().parse().unwrap()
}

/// Hubs, networks, members, site prefixes via API.
/// Prefixes + addresses handed out in order; client private key shown once, never again.
/// Site prefixes must not collide; every write audited.
#[tokio::test]
async fn wireguard_hubs_networks_members_and_site_prefixes() {
    let admin = "admin-token";
    let (_c, store, app, device) = setup(Some(admin)).await;

    // Read: operators; change hubs + networks: admin.
    let viewer = api_key(&app, admin, "viewer", None).await;
    let operator = api_key(&app, admin, "operator", None).await;
    assert_eq!(
        call(&app, "GET", "/api/v1/wireguard/hubs", None, None)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    let (s, v) = call(&app, "GET", "/api/v1/wireguard/hubs", None, Some(&viewer)).await;
    assert_eq!(
        (s, v["error"].as_str()),
        (StatusCode::FORBIDDEN, Some("this needs the operator role"))
    );
    let (s, v) = call(&app, "GET", "/api/v1/wireguard/hubs", None, Some(&operator)).await;
    assert_eq!(
        (s, v["items"].as_array().map(Vec::len)),
        (StatusCode::OK, Some(0))
    );
    let (s, v) = call(
        &app,
        "POST",
        "/api/v1/wireguard/hubs",
        Some(json!({ "name": "x", "endpoint_host": "h.example.org" })),
        Some(&operator),
    )
    .await;
    assert_eq!(
        (s, v["error"].as_str()),
        (StatusCode::FORBIDDEN, Some("this needs the admin role"))
    );

    // Hubs.
    for (body, why) in [
        (
            json!({ "name": "", "endpoint_host": "h.example.org" }),
            "name",
        ),
        (
            json!({ "name": "x", "endpoint_host": "https://h.example.org" }),
            "endpoint_host",
        ),
        (
            json!({ "name": "x", "endpoint_host": "h.example.org:51820" }),
            "endpoint_host",
        ),
        (json!({ "name": "x" }), "endpoint_host"),
        (
            json!({ "name": "x", "endpoint_host": "h.example.org", "extra": 1 }),
            "extra",
        ),
    ] {
        let (s, v) = call(
            &app,
            "POST",
            "/api/v1/wireguard/hubs",
            Some(body),
            Some(admin),
        )
        .await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
        assert!(v["error"].as_str().unwrap().contains(why), "{v}");
    }
    let (hub, net) = wg_hub_and_network(&app, admin).await;
    let (s, v) = call(
        &app,
        "POST",
        "/api/v1/wireguard/hubs",
        Some(json!({ "name": "lab-hub", "endpoint_host": "h2.example.org" })),
        Some(admin),
    )
    .await;
    assert_eq!(
        (s, v["error"].as_str()),
        (StatusCode::CONFLICT, Some("a hub named \"lab-hub\" exists"))
    );
    let (s, v) = call(
        &app,
        "GET",
        &format!("/api/v1/wireguard/hubs/{hub}"),
        None,
        Some(&operator),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        (
            v["name"].as_str(),
            v["endpoint_host"].as_str(),
            v["public_key"].is_null(),
            v["networks"].as_i64()
        ),
        (Some("lab-hub"), Some("hub.example.org"), true, Some(1))
    );
    let (s, v) = call(
        &app,
        "PATCH",
        &format!("/api/v1/wireguard/hubs/{hub}"),
        Some(json!({ "endpoint_host": "HUB2.Example.org" })),
        Some(admin),
    )
    .await;
    assert_eq!(
        (s, v["endpoint_host"].as_str()),
        (StatusCode::OK, Some("hub2.example.org"))
    );
    let (s, _) = call(
        &app,
        "GET",
        &format!("/api/v1/wireguard/hubs/{}", Uuid::now_v7()),
        None,
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // Networks: 1st pool prefix, then next; hub = 1st host.
    let (s, first) = call(
        &app,
        "GET",
        &format!("/api/v1/wireguard/networks/{net}"),
        None,
        Some(&operator),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{first}");
    assert_eq!(
        (
            first["ipv4_prefix"].as_str(),
            first["hub_address"].as_str(),
            first["listen_port"].as_i64(),
            first["mtu"].as_i64(),
            first["persistent_keepalive"].as_i64(),
            first["hub"]["name"].as_str(),
            first["hub"]["endpoint_host"].as_str(),
        ),
        (
            Some("10.77.0.0/24"),
            Some("10.77.0.1"),
            Some(51820),
            Some(1420),
            Some(25),
            Some("lab-hub"),
            Some("hub2.example.org"),
        )
    );
    assert_eq!(
        first["members"],
        json!({ "device": 0, "client": 0, "revoked": 0 })
    );
    let (s, second) = call(
        &app,
        "POST",
        "/api/v1/wireguard/networks",
        Some(
            json!({ "hub_id": hub, "name": "labs", "prefix_len": 25, "mtu": 1412,
                     "persistent_keepalive": 0 }),
        ),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{second}");
    assert_eq!(
        (
            second["ipv4_prefix"].as_str(),
            second["listen_port"].as_i64(),
            second["mtu"].as_i64()
        ),
        (Some("10.77.1.0/25"), Some(51821), Some(1412))
    );
    for (body, status, why) in [
        (
            json!({ "hub_id": hub, "name": "x", "ipv4_prefix": "10.77.0.0/24" }),
            StatusCode::CONFLICT,
            "overlaps 10.77.0.0/24",
        ),
        (
            json!({ "hub_id": hub, "name": "x", "ipv4_prefix": "10.77.0.0/16" }),
            StatusCode::CONFLICT,
            "overlaps",
        ),
        (
            json!({ "hub_id": hub, "name": "x", "ipv4_prefix": "10.77.5.1/24" }),
            StatusCode::UNPROCESSABLE_ENTITY,
            "host bits",
        ),
        (
            json!({ "hub_id": hub, "name": "x", "ipv4_prefix": "10.77.5.0/30" }),
            StatusCode::UNPROCESSABLE_ENTITY,
            "between 16 and 29",
        ),
        (
            json!({ "hub_id": hub, "name": "x", "ipv4_prefix": "10.77.5.0/24", "prefix_len": 24 }),
            StatusCode::UNPROCESSABLE_ENTITY,
            "not both",
        ),
        (
            json!({ "hub_id": hub, "name": "x", "prefix_len": 30 }),
            StatusCode::UNPROCESSABLE_ENTITY,
            "prefix_len",
        ),
        (
            json!({ "hub_id": hub, "name": "x", "prefix_len": 15 }),
            StatusCode::UNPROCESSABLE_ENTITY,
            "prefix_len",
        ),
        (
            json!({ "hub_id": hub, "name": "x", "mtu": 1000 }),
            StatusCode::UNPROCESSABLE_ENTITY,
            "mtu",
        ),
        (
            json!({ "hub_id": hub, "name": "x", "listen_port": 0 }),
            StatusCode::UNPROCESSABLE_ENTITY,
            "listen_port",
        ),
        (
            json!({ "hub_id": hub, "name": "x", "listen_port": 51820 }),
            StatusCode::CONFLICT,
            "port 51820",
        ),
        (
            json!({ "hub_id": hub, "name": "branches" }),
            StatusCode::CONFLICT,
            "exists",
        ),
        (
            json!({ "hub_id": Uuid::now_v7(), "name": "x" }),
            StatusCode::NOT_FOUND,
            "hub not found",
        ),
    ] {
        let (s, v) = call(
            &app,
            "POST",
            "/api/v1/wireguard/networks",
            Some(body.clone()),
            Some(admin),
        )
        .await;
        assert_eq!(s, status, "{body}: {v}");
        assert!(v["error"].as_str().unwrap().contains(why), "{body}: {v}");
    }
    // Explicit prefix outside the pool -> fine.
    let (s, v) = call(
        &app,
        "POST",
        "/api/v1/wireguard/networks",
        Some(
            json!({ "hub_id": hub, "name": "own", "ipv4_prefix": "192.168.250.0/24",
                     "listen_port": 51900 }),
        ),
        Some(admin),
    )
    .await;
    assert_eq!(
        (s, v["listen_port"].as_i64()),
        (StatusCode::CREATED, Some(51900)),
        "{v}"
    );
    let (_, list) = call(
        &app,
        "GET",
        "/api/v1/wireguard/networks",
        None,
        Some(&operator),
    )
    .await;
    assert_eq!(
        list["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n["name"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["branches", "labs", "own"]
    );

    // Members: device -> 1st host after the hub's, client -> next.
    let (s, dm) = call(
        &app,
        "POST",
        &format!("/api/v1/wireguard/networks/{net}/members"),
        Some(json!({ "kind": "device", "device_id": device,
                     "site_prefixes": [{ "prefix": "192.168.10.0/24", "description": "office" }] })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{dm}");
    assert_eq!(
        (
            dm["address"].as_str(),
            dm["name"].as_str(),
            dm["kind"].as_str(),
            dm["key_mode"].as_str(),
            dm["public_key"].is_null(),
            dm["private_key"].is_null(),
            dm["user_id"].is_null(),
            dm["site_prefixes"][0]["prefix"].as_str(),
            dm["site_prefixes"][0]["description"].as_str(),
        ),
        (
            Some("10.77.0.2"),
            Some("SN1"),
            Some("device"),
            Some("device"),
            true,
            true,
            true,
            Some("192.168.10.0/24"),
            Some("office"),
        ),
        "stage 1 makes no key for a device"
    );
    let dm_id = dm["id"].as_str().unwrap().to_owned();
    // Key pair made here -> comes with config file -> needs the hub key.
    wg_hub_has_key(&store, &hub).await;
    let (s, cm) = call(
        &app,
        "POST",
        &format!("/api/v1/wireguard/networks/{net}/members"),
        Some(json!({ "kind": "client", "name": "ops laptop", "user_id": null })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{cm}");
    assert_eq!(
        (
            cm["address"].as_str(),
            cm["kind"].as_str(),
            cm["user_id"].is_null()
        ),
        (Some("10.77.0.3"), Some("client"), true)
    );
    // Private key returned once = key of the stored public one.
    let private = cm["private_key"].as_str().unwrap().to_owned();
    let public = cm["public_key"].as_str().unwrap().to_owned();
    assert_eq!(private.len(), 44);
    assert_eq!(
        dhonomos_wireguard::public_from_private(&private).unwrap(),
        public
    );
    let cm_id = cm["id"].as_str().unwrap().to_owned();
    // Never shown again: not in member, lists or audit trail.
    let (_, one) = call(
        &app,
        "GET",
        &format!("/api/v1/wireguard/members/{cm_id}"),
        None,
        Some(admin),
    )
    .await;
    assert!(one.get("private_key").is_none(), "{one}");
    assert_eq!(one["public_key"].as_str(), Some(public.as_str()));
    let mut everything = String::new();
    for uri in [
        format!("/api/v1/wireguard/networks/{net}/members"),
        format!("/api/v1/wireguard/networks/{net}"),
        "/api/v1/wireguard/networks".to_owned(),
        "/api/v1/audit?limit=1000".to_owned(),
    ] {
        let (s, v) = call(&app, "GET", &uri, None, Some(admin)).await;
        assert_eq!(s, StatusCode::OK, "{uri}");
        everything.push_str(&v.to_string());
    }
    assert!(!everything.contains(&private), "the private key leaked");
    assert!(everything.contains(&public), "the public key is shown");

    // Client with own key -> none returned; keys unique per network.
    let own_key = wg_key(7);
    let (s, v) = call(
        &app,
        "POST",
        &format!("/api/v1/wireguard/networks/{net}/members"),
        Some(json!({ "kind": "client", "name": "server", "user_id": null, "public_key": own_key })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    assert_eq!(
        (
            v["address"].as_str(),
            v["public_key"].as_str(),
            v["private_key"].is_null()
        ),
        (Some("10.77.0.4"), Some(own_key.as_str()), true)
    );
    for (body, status, why) in [
        (
            json!({ "kind": "client", "name": "dup", "user_id": null, "public_key": own_key }),
            StatusCode::CONFLICT,
            "public key",
        ),
        (
            json!({ "kind": "client", "name": "bad", "user_id": null, "public_key": "short" }),
            StatusCode::UNPROCESSABLE_ENTITY,
            "public_key",
        ),
        (
            json!({ "kind": "client", "user_id": null }),
            StatusCode::UNPROCESSABLE_ENTITY,
            "name is required",
        ),
        (
            json!({ "kind": "client", "name": "x", "user_id": null, "device_id": device }),
            StatusCode::UNPROCESSABLE_ENTITY,
            "device members",
        ),
        (
            json!({ "kind": "client", "name": "x", "user_id": null, "site_prefixes": [] }),
            StatusCode::UNPROCESSABLE_ENTITY,
            "device members",
        ),
        // No --secrets-key -> no pre-shared key can be stored.
        (
            json!({ "kind": "client", "name": "x", "user_id": null, "preshared_key_enabled": true }),
            StatusCode::UNPROCESSABLE_ENTITY,
            "a pre-shared key needs the server's secrets key (--secrets-key)",
        ),
        // api-token has no own account -> says whose client this is.
        (
            json!({ "kind": "client", "name": "x" }),
            StatusCode::UNPROCESSABLE_ENTITY,
            "no account of its own",
        ),
        (
            json!({ "kind": "client", "name": "x", "user_id": Uuid::now_v7() }),
            StatusCode::UNPROCESSABLE_ENTITY,
            "does not name an account",
        ),
        (
            json!({ "kind": "device" }),
            StatusCode::UNPROCESSABLE_ENTITY,
            "device_id is required",
        ),
        (
            json!({ "kind": "device", "device_id": device }),
            StatusCode::CONFLICT,
            "member of this network already",
        ),
        (
            json!({ "kind": "device", "device_id": Uuid::now_v7() }),
            StatusCode::NOT_FOUND,
            "device not found",
        ),
        (
            json!({ "kind": "device", "device_id": device, "key_mode": "cloud" }),
            StatusCode::UNPROCESSABLE_ENTITY,
            "key_mode",
        ),
        (
            json!({ "kind": "device", "device_id": device, "public_key": own_key }),
            StatusCode::UNPROCESSABLE_ENTITY,
            "client members",
        ),
        (
            json!({ "kind": "router" }),
            StatusCode::UNPROCESSABLE_ENTITY,
            "kind",
        ),
    ] {
        let (s, v) = call(
            &app,
            "POST",
            &format!("/api/v1/wireguard/networks/{net}/members"),
            Some(body.clone()),
            Some(admin),
        )
        .await;
        assert_eq!(s, status, "{body}: {v}");
        assert!(v["error"].as_str().unwrap().contains(why), "{body}: {v}");
    }
    let (s, _) = call(
        &app,
        "POST",
        &format!("/api/v1/wireguard/networks/{}/members", Uuid::now_v7()),
        Some(json!({ "kind": "client", "name": "x", "user_id": null })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // Site prefixes must not collide with the network, each other or another member.
    let second_device = {
        store
            .upsert_cwmp_device(
                DEFAULT_TENANT,
                &CwmpIdentity {
                    oui: "001122".into(),
                    product_class: "Box".into(),
                    serial_number: "SN2".into(),
                },
                &InformUpdate::default(),
            )
            .await
            .unwrap()
            .id
    };
    let members_uri = format!("/api/v1/wireguard/networks/{net}/members");
    for (prefixes, status, why) in [
        (
            json!([{ "prefix": "192.168.10.0/24" }]),
            StatusCode::CONFLICT,
            "overlaps 192.168.10.0/24",
        ),
        (
            json!([{ "prefix": "192.168.10.128/25" }]),
            StatusCode::CONFLICT,
            "overlaps 192.168.10.0/24",
        ),
        (
            json!([{ "prefix": "192.168.0.0/16" }]),
            StatusCode::CONFLICT,
            "another member",
        ),
        (
            json!([{ "prefix": "10.77.0.0/16" }]),
            StatusCode::CONFLICT,
            "tunnel prefix",
        ),
        (
            json!([{ "prefix": "10.77.0.64/26" }]),
            StatusCode::CONFLICT,
            "tunnel prefix",
        ),
        (
            json!([{ "prefix": "192.168.20.1/24" }]),
            StatusCode::UNPROCESSABLE_ENTITY,
            "host bits",
        ),
        (
            json!([{ "prefix": "0.0.0.0/0" }]),
            StatusCode::UNPROCESSABLE_ENTITY,
            "default route",
        ),
        (
            json!([{ "prefix": "128.0.0.0/1" }]),
            StatusCode::UNPROCESSABLE_ENTITY,
            "shorter than /8",
        ),
        (
            json!([{ "prefix": "fd00::/64" }]),
            StatusCode::UNPROCESSABLE_ENTITY,
            "not an IPv4 prefix",
        ),
        (
            json!([{ "prefix": "192.168.20.0" }]),
            StatusCode::UNPROCESSABLE_ENTITY,
            "not an IPv4 prefix",
        ),
        (
            json!([{ "prefix": "127.0.0.0/8" }]),
            StatusCode::UNPROCESSABLE_ENTITY,
            "reserved",
        ),
        (
            json!([{ "prefix": "172.20.0.0/16" }, { "prefix": "172.20.1.0/24" }]),
            StatusCode::UNPROCESSABLE_ENTITY,
            "in the list overlap",
        ),
        (
            json!([{ "prefix": "172.20.0.0/16", "description": "x".repeat(201) }]),
            StatusCode::UNPROCESSABLE_ENTITY,
            "description",
        ),
    ] {
        let (s, v) = call(
            &app,
            "POST",
            &members_uri,
            Some(
                json!({ "kind": "device", "device_id": second_device, "site_prefixes": prefixes }),
            ),
            Some(admin),
        )
        .await;
        assert_eq!(s, status, "{prefixes}: {v}");
        assert!(
            v["error"].as_str().unwrap().contains(why),
            "{prefixes}: {v}"
        );
    }
    // No refusal left a member behind.
    let (_, list) = call(&app, "GET", &members_uri, None, Some(admin)).await;
    assert_eq!(list["total"], 3, "{list}");
    let (s, sm) = call(
        &app,
        "POST",
        &members_uri,
        Some(
            json!({ "kind": "device", "device_id": second_device, "name": "branch 2",
                     "key_mode": "server", "preshared_key_enabled": false,
                     "site_prefixes": [{ "prefix": "192.168.20.0/24" }] }),
        ),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{sm}");
    assert_eq!(
        (
            sm["name"].as_str(),
            sm["key_mode"].as_str(),
            sm["preshared_key_enabled"].as_bool(),
            sm["address"].as_str()
        ),
        (
            Some("branch 2"),
            Some("server"),
            Some(false),
            Some("10.77.0.5")
        )
    );
    let sm_id = sm["id"].as_str().unwrap().to_owned();
    // Replace the list of the 1st device: all or nothing.
    let patch = |id: &str, body: Value| {
        let (app, uri) = (app.clone(), format!("/api/v1/wireguard/members/{id}"));
        async move { call(&app, "PATCH", &uri, Some(body), Some(admin)).await }
    };
    let (s, v) = patch(
        &dm_id,
        json!({ "name": "renamed", "site_prefixes": [
        { "prefix": "192.168.11.0/24" }, { "prefix": "192.168.20.0/25" } ] }),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    let (_, v) = call(
        &app,
        "GET",
        &format!("/api/v1/wireguard/members/{dm_id}"),
        None,
        Some(admin),
    )
    .await;
    assert_eq!(
        (
            v["name"].as_str(),
            v["site_prefixes"].as_array().map(Vec::len)
        ),
        (Some("SN1"), Some(1)),
        "a refused change changed nothing"
    );
    let (s, v) = patch(&dm_id, json!({ "name": "renamed", "site_prefixes": [
        { "prefix": "192.168.10.0/24", "description": "still" }, { "prefix": "192.168.11.0/24" } ] })).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        (
            v["name"].as_str(),
            v["site_prefixes"].as_array().map(Vec::len),
            v["site_prefixes"][0]["description"].as_str()
        ),
        (Some("renamed"), Some(2), Some("still"))
    );
    let (s, v) = patch(&dm_id, json!({ "site_prefixes": [] })).await;
    assert_eq!(
        (s, v["site_prefixes"].as_array().map(Vec::len)),
        (StatusCode::OK, Some(0))
    );
    // Client has none; unknown keys refused.
    let (s, v) = patch(
        &cm_id,
        json!({ "site_prefixes": [{ "prefix": "192.168.30.0/24" }] }),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    let (s, v) = patch(&cm_id, json!({ "name": "ops" })).await;
    assert_eq!((s, v["name"].as_str()), (StatusCode::OK, Some("ops")));
    let (s, _) = patch(&cm_id, json!({ "public_key": wg_key(9) })).await;
    assert_eq!(
        s,
        StatusCode::UNPROCESSABLE_ENTITY,
        "keys are not changed here"
    );

    // Paging + network counts.
    let (_, page) = call(
        &app,
        "GET",
        &format!("{members_uri}?limit=2&offset=1"),
        None,
        Some(admin),
    )
    .await;
    assert_eq!(
        (
            page["total"].as_i64(),
            page["limit"].as_i64(),
            page["offset"].as_i64()
        ),
        (Some(4), Some(2), Some(1))
    );
    assert_eq!(
        page["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m["address"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["10.77.0.3", "10.77.0.4"]
    );
    let (_, v) = call(
        &app,
        "GET",
        &format!("/api/v1/wireguard/networks/{net}"),
        None,
        Some(admin),
    )
    .await;
    assert_eq!(
        v["members"],
        json!({ "device": 2, "client": 2, "revoked": 0 })
    );

    // Revoke -> row kept, address rests: next member skips it.
    // Server client = admin's: operator does not even see it.
    let (s, _) = call(
        &app,
        "POST",
        &format!("/api/v1/wireguard/members/{cm_id}/revoke"),
        None,
        Some(&operator),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, v) = call(
        &app,
        "POST",
        &format!("/api/v1/wireguard/members/{cm_id}/revoke"),
        Some(json!({ "reason": "laptop lost" })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["revoked_reason"].as_str(), Some("laptop lost"));
    let first_revoked_at = v["revoked_at"].as_str().unwrap().to_owned();
    // Again, no body -> no change.
    let (s, v) = call(
        &app,
        "POST",
        &format!("/api/v1/wireguard/members/{cm_id}/revoke"),
        None,
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        (v["revoked_reason"].as_str(), v["revoked_at"].as_str()),
        (Some("laptop lost"), Some(first_revoked_at.as_str()))
    );
    let (s, v) = call(
        &app,
        "POST",
        &format!("/api/v1/wireguard/members/{dm_id}/revoke"),
        Some(json!({ "reason": "x".repeat(201) })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    let (s, v) = patch(&cm_id, json!({ "name": "again" })).await;
    assert_eq!(
        (s, v["error"].as_str()),
        (StatusCode::CONFLICT, Some("the member is revoked"))
    );
    let (s, v) = call(
        &app,
        "POST",
        &members_uri,
        Some(json!({ "kind": "client", "name": "next", "user_id": null })),
        Some(admin),
    )
    .await;
    assert_eq!(
        (s, v["address"].as_str()),
        (StatusCode::CREATED, Some("10.77.0.6")),
        "{v}"
    );
    let (_, v) = call(
        &app,
        "GET",
        &format!("{members_uri}?include_revoked=false"),
        None,
        Some(admin),
    )
    .await;
    assert_eq!(v["total"], 4, "{v}");
    let (_, v) = call(&app, "GET", &members_uri, None, Some(admin)).await;
    assert_eq!(v["total"], 5, "{v}");

    // Prefix of a network with live members stays; rest may change.
    let (s, v) = call(
        &app,
        "PATCH",
        &format!("/api/v1/wireguard/networks/{net}"),
        Some(json!({ "ipv4_prefix": "10.88.0.0/24" })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    assert!(v["error"].as_str().unwrap().contains("not revoked"), "{v}");
    let (s, v) = call(
        &app,
        "PATCH",
        &format!("/api/v1/wireguard/networks/{net}"),
        Some(json!({ "mtu": 1380, "persistent_keepalive": 15, "name": "branches-2" })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        (
            v["mtu"].as_i64(),
            v["persistent_keepalive"].as_i64(),
            v["name"].as_str(),
            v["ipv4_prefix"].as_str()
        ),
        (
            Some(1380),
            Some(15),
            Some("branches-2"),
            Some("10.77.0.0/24")
        )
    );
    // Only admin deletes members for good.
    let (s, _) = call(
        &app,
        "DELETE",
        &format!("/api/v1/wireguard/members/{sm_id}"),
        None,
        Some(&operator),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = call(
        &app,
        "DELETE",
        &format!("/api/v1/wireguard/members/{sm_id}"),
        None,
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _) = call(
        &app,
        "GET",
        &format!("/api/v1/wireguard/members/{sm_id}"),
        None,
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // Hub with networks stays; network delete takes its members.
    let (s, v) = call(
        &app,
        "DELETE",
        &format!("/api/v1/wireguard/hubs/{hub}"),
        None,
        Some(admin),
    )
    .await;
    assert_eq!(
        (s, v["error"].as_str()),
        (
            StatusCode::CONFLICT,
            Some("the hub still has networks; delete or move them first")
        )
    );
    let (s, _) = call(
        &app,
        "DELETE",
        &format!("/api/v1/wireguard/networks/{net}"),
        None,
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _) = call(
        &app,
        "GET",
        &format!("/api/v1/wireguard/members/{dm_id}"),
        None,
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND, "its members went with it");
    for name in ["labs", "own"] {
        let (_, list) = call(&app, "GET", "/api/v1/wireguard/networks", None, Some(admin)).await;
        let id = list["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|n| n["name"] == name)
            .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_owned();
        let (s, _) = call(
            &app,
            "DELETE",
            &format!("/api/v1/wireguard/networks/{id}"),
            None,
            Some(admin),
        )
        .await;
        assert_eq!(s, StatusCode::NO_CONTENT);
    }
    let (s, _) = call(
        &app,
        "DELETE",
        &format!("/api/v1/wireguard/hubs/{hub}"),
        None,
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);

    // Every write in audit trail, under `wireguard.`, without keys.
    let (_, audit) = call(
        &app,
        "GET",
        "/api/v1/audit?action=wireguard.&limit=1000",
        None,
        Some(admin),
    )
    .await;
    let actions: Vec<&str> = audit["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["action"].as_str().unwrap())
        .collect();
    for want in [
        "wireguard.hub.create",
        "wireguard.hub.update",
        "wireguard.hub.delete",
        "wireguard.network.create",
        "wireguard.network.update",
        "wireguard.network.delete",
        "wireguard.member.create",
        "wireguard.member.update",
        "wireguard.member.revoke",
        "wireguard.member.delete",
    ] {
        assert!(actions.contains(&want), "{want} missing from {actions:?}");
    }
    assert_eq!(
        actions
            .iter()
            .filter(|a| **a == "wireguard.member.revoke")
            .count(),
        1,
        "the repeated revocation is not recorded again"
    );
    let created = audit["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["action"] == "wireguard.member.create" && a["detail"]["key_pair_made"] == true)
        .unwrap();
    assert_eq!(created["actor"], "api-token");
    assert!(created["detail"].get("private_key").is_none());
    assert!(!audit.to_string().contains(&private));
}

/// 1 CPE speaking CWMP + USP = 2 devices: 2nd record cannot join a network
/// where the 1st is a device member.
#[tokio::test]
async fn wireguard_the_twin_of_a_device_member_cannot_join() {
    let admin = "admin-token";
    let (_c, store, app, device) = setup(Some(admin)).await;
    let (_hub, net) = wg_hub_and_network(&app, admin).await;
    let (s, v) = call(
        &app,
        "POST",
        &format!("/api/v1/wireguard/networks/{net}/members"),
        Some(json!({ "kind": "device", "device_id": device })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    // USP record of the same CPE (same OUI + serial as the CWMP one).
    let twin = store
        .upsert_usp_device(DEFAULT_TENANT, "os::001122-SN1", None)
        .await
        .unwrap()
        .id;
    store
        .update_device_info(
            twin,
            &dhonomos_store::DeviceInfo {
                oui: Some("001122".into()),
                serial_number: Some("SN1".into()),
                ..dhonomos_store::DeviceInfo::default()
            },
        )
        .await
        .unwrap();
    let (s, v) = call(
        &app,
        "POST",
        &format!("/api/v1/wireguard/networks/{net}/members"),
        Some(json!({ "kind": "device", "device_id": twin })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    assert_eq!(
        v["error"],
        "the same device is a member of this network already through its other record (CWMP or USP)"
    );
}

/// Clients belong to accounts (Q6): scoped accounts none; others see + revoke own, admins all.
/// Client revoked when its account is disabled, deleted, demoted below operator or scoped.
/// Device members follow the device scope.
#[tokio::test]
async fn wireguard_clients_follow_their_accounts_and_device_members_the_scope() {
    let admin = "admin-token";
    let (_c, store, app, outside) = setup(Some(admin)).await;
    let inside = store
        .upsert_cwmp_device(
            DEFAULT_TENANT,
            &CwmpIdentity {
                oui: "001122".into(),
                product_class: "Box".into(),
                serial_number: "EAST1".into(),
            },
            &InformUpdate::default(),
        )
        .await
        .unwrap()
        .id;
    let (s, v) = call(
        &app,
        "PATCH",
        &format!("/api/v1/devices/{inside}"),
        Some(json!({ "tags": ["east"] })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (hub, net) = wg_hub_and_network(&app, admin).await;
    wg_hub_has_key(&store, &hub).await;
    let members_uri = format!("/api/v1/wireguard/networks/{net}/members");

    // Static token = no account -> need another admin before demoting one.
    wg_user(&app, admin, "root", "admin", None).await;
    let alice = wg_user(&app, admin, "alice", "operator", None).await;
    let bob = wg_user(
        &app,
        admin,
        "bob",
        "operator",
        Some(json!({ "tags": ["east"] })),
    )
    .await;
    let carol = wg_user(&app, admin, "carol", "viewer", None).await;
    let (alice_s, bob_s, carol_s) = (
        wg_login(&app, "alice").await,
        wg_login(&app, "bob").await,
        wg_login(&app, "carol").await,
    );
    let as_user = |session: &str, method: &'static str, uri: String, body: Option<Value>| {
        let (app, session) = (app.clone(), session.to_owned());
        async move {
            let (s, v, _) = call_cookie(&app, method, &uri, body, Some(&session)).await;
            (s, v)
        }
    };

    // Viewer reads nothing here, creates nothing.
    let (s, _) = as_user(&carol_s, "GET", "/api/v1/wireguard/hubs".into(), None).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = as_user(
        &carol_s,
        "POST",
        members_uri.clone(),
        Some(json!({ "kind": "client", "name": "x" })),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // Scoped operator cannot have a client, however asked.
    for body in [
        json!({ "kind": "client", "name": "bob-pc" }),
        json!({ "kind": "client", "name": "bob-pc", "user_id": bob }),
        json!({ "kind": "client", "name": "bob-pc", "user_id": null }),
    ] {
        let (s, v) = as_user(&bob_s, "POST", members_uri.clone(), Some(body.clone())).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{body}: {v}");
    }
    let (_, v) = as_user(
        &bob_s,
        "POST",
        members_uri.clone(),
        Some(json!({ "kind": "client", "name": "bob-pc" })),
    )
    .await;
    assert_eq!(
        v["error"],
        "accounts with a device scope cannot add client members"
    );
    // Unscoped operator: own client, by default or by naming themself...
    let (s, mine) = as_user(
        &alice_s,
        "POST",
        members_uri.clone(),
        Some(json!({ "kind": "client", "name": "alice-pc" })),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{mine}");
    assert_eq!(mine["user_id"], json!(alice));
    assert_eq!(mine["private_key"].as_str().map(str::len), Some(44));
    let (s, mine2) = as_user(&alice_s, "POST", members_uri.clone(), Some(json!({ "kind": "client", "name": "alice-phone", "user_id": alice, "public_key": wg_key(1) }))).await;
    assert_eq!(s, StatusCode::CREATED, "{mine2}");
    // ...but not for others, no server client.
    for body in [
        json!({ "kind": "client", "name": "x", "user_id": bob }),
        json!({ "kind": "client", "name": "x", "user_id": null }),
    ] {
        let (s, v) = as_user(&alice_s, "POST", members_uri.clone(), Some(body.clone())).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{body}: {v}");
    }
    // Admins can, for accounts allowed to have them.
    for (user, why) in [(bob, "device scope"), (carol, "operator or admin")] {
        let (s, v) = call(
            &app,
            "POST",
            &members_uri,
            Some(json!({ "kind": "client", "name": "x", "user_id": user })),
            Some(admin),
        )
        .await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
        assert!(v["error"].as_str().unwrap().contains(why), "{v}");
    }
    let (s, theirs) = call(
        &app,
        "POST",
        &members_uri,
        Some(json!({ "kind": "client", "name": "alice-ops", "user_id": alice })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{theirs}");
    let (s, server) = call(
        &app,
        "POST",
        &members_uri,
        Some(json!({ "kind": "client", "name": "monitoring", "user_id": null })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{server}");
    assert!(server["user_id"].is_null());

    // Device members: scoped operator -> devices inside scope only; unscoped -> any.
    let (s, v) = as_user(
        &bob_s,
        "POST",
        members_uri.clone(),
        Some(json!({ "kind": "device", "device_id": outside })),
    )
    .await;
    assert_eq!(
        (s, v["error"].as_str()),
        (StatusCode::NOT_FOUND, Some("device not found"))
    );
    let (s, east) = as_user(&bob_s, "POST", members_uri.clone(), Some(json!({ "kind": "device", "device_id": inside, "site_prefixes": [{ "prefix": "192.168.5.0/24" }] }))).await;
    assert_eq!(s, StatusCode::CREATED, "{east}");
    assert_eq!(east["name"], "EAST1");
    let (s, west) = as_user(
        &alice_s,
        "POST",
        members_uri.clone(),
        Some(json!({ "kind": "device", "device_id": outside })),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{west}");

    // Who sees what.
    let ids = |v: &Value| -> Vec<String> {
        v["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m["name"].as_str().unwrap().to_owned())
            .collect()
    };
    let (_, v) = call(&app, "GET", &members_uri, None, Some(admin)).await;
    assert_eq!(ids(&v).len(), 6, "{v}");
    // Alice: every device (no scope) + her clients, whoever made them.
    let (_, v) = as_user(&alice_s, "GET", members_uri.clone(), None).await;
    let mut seen = ids(&v);
    seen.sort();
    assert_eq!(
        seen,
        ["EAST1", "SN1", "alice-ops", "alice-pc", "alice-phone"]
    );
    let (_, v) = as_user(&bob_s, "GET", members_uri.clone(), None).await;
    assert_eq!(
        ids(&v),
        ["EAST1"],
        "the scoped operator sees the device inside its scope only"
    );
    let (_, v) = as_user(
        &bob_s,
        "GET",
        format!("/api/v1/wireguard/networks/{net}"),
        None,
    )
    .await;
    assert_eq!(
        v["members"],
        json!({ "device": 1, "client": 0, "revoked": 0 }),
        "counts follow the same rule"
    );
    let (_, v) = as_user(
        &alice_s,
        "GET",
        format!("/api/v1/wireguard/networks/{net}"),
        None,
    )
    .await;
    assert_eq!(
        v["members"],
        json!({ "device": 2, "client": 3, "revoked": 0 })
    );
    let (_, v) = call(
        &app,
        "GET",
        &format!("/api/v1/wireguard/networks/{net}"),
        None,
        Some(admin),
    )
    .await;
    assert_eq!(
        v["members"],
        json!({ "device": 2, "client": 4, "revoked": 0 })
    );
    // Not visible -> not readable, changeable or revocable: not found.
    let (theirs_id, west_id) = (theirs["id"].as_str().unwrap(), west["id"].as_str().unwrap());
    // (Server client = admin's; device outside scope != scoped operator's;
    // someone else's client neither.)
    for (who, id) in [
        (&alice_s, server["id"].as_str().unwrap()),
        (&bob_s, west_id),
        (&bob_s, mine["id"].as_str().unwrap()),
    ] {
        for (method, suffix, body) in [
            ("GET", "", None),
            ("PATCH", "", Some(json!({ "name": "x" }))),
            ("POST", "/revoke", None),
        ] {
            let (s, v) = as_user(
                who,
                method,
                format!("/api/v1/wireguard/members/{id}{suffix}"),
                body,
            )
            .await;
            assert_eq!(s, StatusCode::NOT_FOUND, "{method} {id}: {v}");
        }
    }
    // Operator may revoke own client + device members they see.
    let (s, v) = as_user(
        &alice_s,
        "POST",
        format!(
            "/api/v1/wireguard/members/{}/revoke",
            mine2["id"].as_str().unwrap()
        ),
        Some(json!({ "reason": "sold the phone" })),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, v) = as_user(
        &bob_s,
        "POST",
        format!(
            "/api/v1/wireguard/members/{}/revoke",
            east["id"].as_str().unwrap()
        ),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(v["revoked_reason"].is_null());
    // Delete: admin only.
    let (s, _) = as_user(
        &alice_s,
        "DELETE",
        format!("/api/v1/wireguard/members/{}", mine["id"].as_str().unwrap()),
        None,
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN);

    // Account disabled -> its clients revoked with reason, in audit trail too.
    let reason_of = |id: &str| {
        let (app, uri) = (app.clone(), format!("/api/v1/wireguard/members/{id}"));
        async move {
            let (_, v) = call(&app, "GET", &uri, None, Some(admin)).await;
            (
                v["revoked_at"].is_string(),
                v["revoked_reason"].as_str().map(str::to_owned),
                v["user_id"].as_str().map(str::to_owned),
            )
        }
    };
    let alice_s_id = alice.to_string();
    assert_eq!(
        reason_of(mine["id"].as_str().unwrap()).await,
        (false, None, Some(alice_s_id.clone()))
    );
    let (s, v) = call(
        &app,
        "PATCH",
        &format!("/api/v1/users/{alice}"),
        Some(json!({ "disabled": true })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    for id in [mine["id"].as_str().unwrap(), theirs_id] {
        assert_eq!(
            reason_of(id).await,
            (true, Some("user disabled".into()), Some(alice_s_id.clone())),
            "{id}"
        );
    }
    assert_eq!(
        reason_of(mine2["id"].as_str().unwrap()).await.1.as_deref(),
        Some("sold the phone"),
        "an earlier revocation keeps its reason"
    );
    assert!(
        !reason_of(server["id"].as_str().unwrap()).await.0,
        "server clients are untouched"
    );
    let (_, audit) = call(
        &app,
        "GET",
        "/api/v1/audit?action=wireguard.member.revoke&limit=100",
        None,
        Some(admin),
    )
    .await;
    let automatic: Vec<&Value> = audit["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|a| a["detail"]["automatic"] == true)
        .collect();
    assert_eq!(automatic.len(), 2, "{audit}");
    assert!(
        automatic
            .iter()
            .all(|a| a["detail"]["reason"] == "user disabled" && a["actor"] == "api-token")
    );
    // Account enabled again -> clients not back.
    let (s, _) = call(
        &app,
        "PATCH",
        &format!("/api/v1/users/{alice}"),
        Some(json!({ "disabled": false })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert!(reason_of(theirs_id).await.0);

    // Demotion below operator, device scope, deletion.
    let dave = wg_user(&app, admin, "dave", "operator", None).await;
    let erin = wg_user(&app, admin, "erin", "operator", None).await;
    let frank = wg_user(&app, admin, "frank", "operator", None).await;
    let gina = wg_user(&app, admin, "gina", "admin", None).await;
    let mut clients = Vec::new();
    for user in [dave, erin, frank, gina] {
        let (s, v) = call(
            &app,
            "POST",
            &members_uri,
            Some(json!({ "kind": "client", "name": format!("pc-{user}"), "user_id": user })),
            Some(admin),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED, "{v}");
        clients.push(v["id"].as_str().unwrap().to_owned());
    }
    let (s, _) = call(
        &app,
        "PATCH",
        &format!("/api/v1/users/{dave}"),
        Some(json!({ "role": "viewer" })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, v) = call(
        &app,
        "PATCH",
        &format!("/api/v1/users/{erin}"),
        Some(json!({ "scope": { "tags": ["east"] } })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, _) = call(
        &app,
        "DELETE",
        &format!("/api/v1/users/{frank}"),
        None,
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    // Admin made operator -> keeps the client.
    let (s, _) = call(
        &app,
        "PATCH",
        &format!("/api/v1/users/{gina}"),
        Some(json!({ "role": "operator" })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        reason_of(&clients[0]).await,
        (true, Some("role changed".into()), Some(dave.to_string()))
    );
    assert_eq!(
        reason_of(&clients[1]).await,
        (true, Some("scope changed".into()), Some(erin.to_string()))
    );
    assert_eq!(
        reason_of(&clients[2]).await,
        (true, Some("user deleted".into()), None),
        "revoked, and the row stays without an owner"
    );
    assert_eq!(
        reason_of(&clients[3]).await,
        (false, None, Some(gina.to_string()))
    );
    // Revoked clients listed in the network with reasons.
    let (_, v) = call(&app, "GET", &members_uri, None, Some(admin)).await;
    let revoked: Vec<&str> = v["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|m| m["revoked_reason"].as_str())
        .collect();
    for reason in [
        "user disabled",
        "role changed",
        "scope changed",
        "user deleted",
        "sold the phone",
    ] {
        assert!(revoked.contains(&reason), "{reason} in {revoked:?}");
    }
}

/// 2 tenants share a DB, nothing else: own hubs, networks (+ pool), members, counts.
#[tokio::test]
async fn wireguard_data_belongs_to_one_tenant() {
    let admin = "admin-token";
    let (_c, store, app, device) = setup(Some(admin)).await;
    let other = Uuid::now_v7();
    sqlx_insert_tenant(&store, other).await;
    let foreign = router(
        store.clone(),
        ApiConfig {
            bearer_token: Some("other-token".into()),
            tenant_id: other,
            ..ApiConfig::default()
        },
    );
    let (hub, net) = wg_hub_and_network(&app, admin).await;
    let (s, member) = call(
        &app,
        "POST",
        &format!("/api/v1/wireguard/networks/{net}/members"),
        Some(json!({ "kind": "device", "device_id": device })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{member}");
    let member = member["id"].as_str().unwrap();

    let theirs = "other-token";
    let (_, v) = call(
        &foreign,
        "GET",
        "/api/v1/wireguard/hubs",
        None,
        Some(theirs),
    )
    .await;
    assert_eq!(v["items"], json!([]));
    let (_, v) = call(
        &foreign,
        "GET",
        "/api/v1/wireguard/networks",
        None,
        Some(theirs),
    )
    .await;
    assert_eq!(v["items"], json!([]));
    for (method, uri, body) in [
        ("GET", format!("/api/v1/wireguard/hubs/{hub}"), None),
        (
            "PATCH",
            format!("/api/v1/wireguard/hubs/{hub}"),
            Some(json!({ "name": "x" })),
        ),
        ("DELETE", format!("/api/v1/wireguard/hubs/{hub}"), None),
        ("GET", format!("/api/v1/wireguard/networks/{net}"), None),
        (
            "PATCH",
            format!("/api/v1/wireguard/networks/{net}"),
            Some(json!({ "name": "x" })),
        ),
        ("DELETE", format!("/api/v1/wireguard/networks/{net}"), None),
        (
            "GET",
            format!("/api/v1/wireguard/networks/{net}/members"),
            None,
        ),
        ("GET", format!("/api/v1/wireguard/members/{member}"), None),
        (
            "PATCH",
            format!("/api/v1/wireguard/members/{member}"),
            Some(json!({ "name": "x" })),
        ),
        (
            "POST",
            format!("/api/v1/wireguard/members/{member}/revoke"),
            None,
        ),
        (
            "DELETE",
            format!("/api/v1/wireguard/members/{member}"),
            None,
        ),
    ] {
        let (s, v) = call(&foreign, method, &uri, body, Some(theirs)).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{method} {uri}: {v}");
    }
    // They cannot build on our hub or use our device.
    let (s, v) = call(
        &foreign,
        "POST",
        "/api/v1/wireguard/networks",
        Some(json!({ "hub_id": hub, "name": "x" })),
        Some(theirs),
    )
    .await;
    assert_eq!(
        (s, v["error"].as_str()),
        (StatusCode::NOT_FOUND, Some("hub not found"))
    );
    // Theirs start at the pool start, with the names ours use.
    let (_, their_net) = wg_hub_and_network(&foreign, theirs).await;
    let (_, v) = call(
        &foreign,
        "GET",
        &format!("/api/v1/wireguard/networks/{their_net}"),
        None,
        Some(theirs),
    )
    .await;
    assert_eq!(v["ipv4_prefix"], "10.77.0.0/24");
    let (s, v) = call(
        &foreign,
        "POST",
        &format!("/api/v1/wireguard/networks/{their_net}/members"),
        Some(json!({ "kind": "device", "device_id": device })),
        Some(theirs),
    )
    .await;
    assert_eq!(
        (s, v["error"].as_str()),
        (StatusCode::NOT_FOUND, Some("device not found"))
    );
    // All of ours unchanged.
    let (_, v) = call(
        &app,
        "GET",
        &format!("/api/v1/wireguard/networks/{net}"),
        None,
        Some(admin),
    )
    .await;
    assert_eq!(v["members"]["device"], 1);
    assert_eq!(v["name"], "branches");
}

/// OpenAPI document describes the WireGuard operations + the one-time private key.
/// Stage 3: client with key pair made here -> wg-quick config + QR code in that response.
/// Config can be fetched again, no private key. Re-key replaces the key at the hub.
/// No secret reaches the audit trail.
#[tokio::test]
async fn wireguard_client_configuration_files_and_rekeying() {
    let admin = "admin-token";
    let (_c, _store, app, device) = setup(Some(admin)).await;
    let (hub, net) = wg_hub_and_network(&app, admin).await;
    let members_uri = format!("/api/v1/wireguard/networks/{net}/members");
    let (_, network) = call(
        &app,
        "GET",
        &format!("/api/v1/wireguard/networks/{net}"),
        None,
        Some(admin),
    )
    .await;
    let tunnel = network["ipv4_prefix"].as_str().unwrap().to_owned();
    let port = network["listen_port"].as_i64().unwrap();
    let count = |app: Router| {
        let uri = members_uri.clone();
        async move {
            let (_, v) = call(&app, "GET", &uri, None, Some(admin)).await;
            v["total"].as_i64().unwrap()
        }
    };

    // Hub key not reported yet -> no config possible -> no key pair either.
    let (s, v) = call(
        &app,
        "POST",
        &members_uri,
        Some(json!({ "kind": "client", "name": "ops laptop", "user_id": null })),
        Some(admin),
    )
    .await;
    assert_eq!(
        (s, v["error"].as_str()),
        (
            StatusCode::CONFLICT,
            Some("the hub has not reported its public key yet: start dhonomos-wg-hub on it first")
        )
    );
    assert_eq!(count(app.clone()).await, 0);
    // Client with own key -> no hub key needed, no config.
    let (s, own) = call(
        &app,
        "POST",
        &members_uri,
        Some(
            json!({ "kind": "client", "name": "own-key", "user_id": null,
                     "public_key": wg_key(1) }),
        ),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{own}");
    for field in ["private_key", "config", "config_filename", "qr_svg"] {
        assert!(own[field].is_null(), "{field}: {own}");
    }
    let own_id = own["id"].as_str().unwrap().to_owned();
    let (s, v) = call(
        &app,
        "GET",
        &format!("/api/v1/wireguard/members/{own_id}/config"),
        None,
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    assert!(v["error"].as_str().unwrap().contains("public key"), "{v}");

    // Hub reports its key; device member brings a site prefix.
    let token = wg_hub_token(&app, admin, &hub).await;
    let hub_key = wg_key(100);
    let (s, _, _, _) = wg_hub_call(
        &app,
        "PUT",
        "/api/v1/wg-hub/public-key",
        Some(json!({ "public_key": hub_key })),
        Some(&token),
        &[],
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, dm) = call(
        &app,
        "POST",
        &members_uri,
        Some(json!({ "kind": "device", "device_id": device,
                     "site_prefixes": [{ "prefix": "192.168.10.0/24" }] })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{dm}");
    let dm_id = dm["id"].as_str().unwrap().to_owned();

    // Created with key pair made here: private key, config with it, QR.
    let (s, cm) = call(
        &app,
        "POST",
        &members_uri,
        Some(json!({ "kind": "client", "name": "ops laptop", "user_id": null })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{cm}");
    let cm_id = cm["id"].as_str().unwrap().to_owned();
    let private = cm["private_key"].as_str().unwrap().to_owned();
    let address = cm["address"].as_str().unwrap().to_owned();
    let config = cm["config"].as_str().unwrap();
    for line in [
        format!("\nPrivateKey = {private}\n"),
        format!("\nAddress = {address}/32\n"),
        format!("\nPublicKey = {hub_key}\n"),
        format!("\nEndpoint = hub.example.org:{port}\n"),
        format!("\nAllowedIPs = {tunnel}, 192.168.10.0/24\n"),
        "\nMTU = 1420\n".to_owned(),
        "\nPersistentKeepalive = 25\n".to_owned(),
    ] {
        assert!(config.contains(&line), "{line:?} in {config}");
    }
    assert_eq!(cm["config_filename"], "branches.conf");
    let qr = cm["qr_svg"].as_str().unwrap();
    assert!(qr.starts_with("<svg") || qr.starts_with("<?xml"), "{qr}");
    let (_, audit) = call(
        &app,
        "GET",
        "/api/v1/audit?action=wireguard.member.create&limit=100",
        None,
        Some(admin),
    )
    .await;
    let record = audit["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["target_id"] == cm_id.as_str())
        .unwrap()
        .clone();
    assert_eq!(record["detail"]["key_pair_made"], true);
    let all = audit.to_string();
    assert!(!all.contains(&private), "{all}");
    assert!(
        !all.contains("PrivateKey") && !all.contains("Interface"),
        "{all}"
    );

    // Config again: no private key, no QR code.
    let config_uri = |id: &str| format!("/api/v1/wireguard/members/{id}/config");
    let (s, again) = call(&app, "GET", &config_uri(&cm_id), None, Some(admin)).await;
    assert_eq!(s, StatusCode::OK, "{again}");
    let text = again["config"].as_str().unwrap();
    assert!(
        text.contains(
            "\n# PrivateKey = (not kept by Dhonomos: put the private key of this member here)\n"
        ),
        "{text}"
    );
    assert!(
        !text.contains("\nPrivateKey") && !text.contains(&private),
        "{text}"
    );
    assert!(text.contains(&format!("\nAllowedIPs = {tunnel}, 192.168.10.0/24\n")));
    assert_eq!(again["config_filename"], "branches.conf");
    assert!(again.get("qr_svg").is_none() && again.get("private_key").is_none());
    let (s, v) = call(&app, "GET", &config_uri(&dm_id), None, Some(admin)).await;
    assert_eq!(
        (s, v["error"].as_str()),
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            Some("device members are configured over TR-181, not with a configuration file")
        )
    );

    // Operators see own clients' config, not another operator's.
    wg_user(&app, admin, "alice", "operator", None).await;
    wg_user(&app, admin, "dave", "operator", None).await;
    let (alice, dave) = (wg_login(&app, "alice").await, wg_login(&app, "dave").await);
    let (s, mine, _) = call_cookie(
        &app,
        "POST",
        &members_uri,
        Some(json!({ "kind": "client", "name": "alice-pc" })),
        Some(&alice),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{mine}");
    assert!(mine["config"].as_str().unwrap().contains("\"alice-pc\""));
    let mine_id = mine["id"].as_str().unwrap().to_owned();
    let mine_key = mine["public_key"].as_str().unwrap().to_owned();
    let (s, _, _) = call_cookie(&app, "GET", &config_uri(&mine_id), None, Some(&alice)).await;
    assert_eq!(s, StatusCode::OK);
    let rekey_uri = |id: &str| format!("/api/v1/wireguard/members/{id}/rekey");
    let (s, _, _) = call_cookie(&app, "GET", &config_uri(&mine_id), None, Some(&dave)).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _, _) = call_cookie(&app, "POST", &rekey_uri(&mine_id), None, Some(&dave)).await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // Re-key without body -> new pair, config with new private key.
    let old_key = cm["public_key"].as_str().unwrap().to_owned();
    let (s, rk) = call(&app, "POST", &rekey_uri(&cm_id), None, Some(admin)).await;
    assert_eq!(s, StatusCode::OK, "{rk}");
    let new_key = rk["public_key"].as_str().unwrap().to_owned();
    let new_private = rk["private_key"].as_str().unwrap().to_owned();
    assert_ne!(new_key, old_key);
    assert_ne!(new_private, private);
    assert_eq!(rk["address"].as_str(), Some(address.as_str()));
    assert!(
        rk["config"]
            .as_str()
            .unwrap()
            .contains(&format!("\nPrivateKey = {new_private}\n"))
    );
    assert_eq!(rk["config_filename"], "branches.conf");
    assert!(rk["qr_svg"].as_str().unwrap().contains("<svg"));
    let (s, _, state, _) =
        wg_hub_call(&app, "GET", "/api/v1/wg-hub/state", None, Some(&token), &[]).await;
    assert_eq!(s, StatusCode::OK);
    let state = state.to_string();
    assert!(
        state.contains(&new_key) && !state.contains(&old_key),
        "{state}"
    );
    let (_, audit) = call(
        &app,
        "GET",
        "/api/v1/audit?action=wireguard.member.rekey",
        None,
        Some(admin),
    )
    .await;
    let records = audit["items"].as_array().unwrap();
    assert_eq!(records.len(), 1, "{audit}");
    assert_eq!(records[0]["target_type"], "wg_member");
    assert_eq!(
        records[0]["detail"],
        json!({ "network": net, "name": "ops laptop", "old_public_key": old_key,
                "public_key": new_key, "key_pair_made": true, "preshared_key": null })
    );
    assert!(!audit.to_string().contains(&new_private));
    // `{}` = no body too.
    let (s, rk2) = call(
        &app,
        "POST",
        &rekey_uri(&cm_id),
        Some(json!({})),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{rk2}");
    assert!(rk2["private_key"].is_string());
    assert_ne!(rk2["public_key"], json!(new_key));
    // Key given -> nothing secret returned.
    let (s, rk3) = call(
        &app,
        "POST",
        &rekey_uri(&cm_id),
        Some(json!({ "public_key": wg_key(7) })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{rk3}");
    assert_eq!(rk3["public_key"], json!(wg_key(7)));
    for field in ["private_key", "config", "config_filename", "qr_svg"] {
        assert!(rk3[field].is_null(), "{field}: {rk3}");
    }
    // Refused: other live member's key, bad key or field, device, revoked member.
    let (s, v) = call(
        &app,
        "POST",
        &rekey_uri(&cm_id),
        Some(json!({ "public_key": mine_key })),
        Some(admin),
    )
    .await;
    assert_eq!(
        (s, v["error"].as_str()),
        (
            StatusCode::CONFLICT,
            Some("another member of this network has this public key")
        )
    );
    for body in [
        json!({ "public_key": "not a key" }),
        json!({ "public_key": wg_key(8), "extra": 1 }),
    ] {
        let (s, v) = call(&app, "POST", &rekey_uri(&cm_id), Some(body), Some(admin)).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    }
    let (s, v) = call(&app, "POST", &rekey_uri(&dm_id), None, Some(admin)).await;
    assert_eq!(
        (s, v["error"].as_str()),
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            Some("device members are configured over TR-181, not with a configuration file")
        )
    );
    let (s, _) = call(
        &app,
        "POST",
        &format!("/api/v1/wireguard/members/{own_id}/revoke"),
        None,
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    for (method, uri) in [("GET", config_uri(&own_id)), ("POST", rekey_uri(&own_id))] {
        let (s, v) = call(&app, method, &uri, None, Some(admin)).await;
        assert_eq!(
            (s, v["error"].as_str()),
            (StatusCode::CONFLICT, Some("the member is revoked")),
            "{method} {uri}"
        );
    }

    // Viewers reach neither.
    let viewer = api_key(&app, admin, "viewer", None).await;
    let (s, _) = call(&app, "GET", &config_uri(&cm_id), None, Some(&viewer)).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = call(&app, "POST", &rekey_uri(&cm_id), None, Some(&viewer)).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn wireguard_is_in_the_openapi_document() {
    let (_c, _store, app, _) = setup(None).await;
    let (_, doc) = call(&app, "GET", "/api/v1/openapi.json", None, None).await;
    for (path, method) in [
        ("/api/v1/wireguard/summary", "get"),
        ("/api/v1/wireguard/hubs", "get"),
        ("/api/v1/wireguard/hubs", "post"),
        ("/api/v1/wireguard/hubs/{id}", "patch"),
        ("/api/v1/wireguard/networks", "post"),
        ("/api/v1/wireguard/networks/{id}", "delete"),
        ("/api/v1/wireguard/networks/{id}/members", "get"),
        ("/api/v1/wireguard/networks/{id}/members", "post"),
        ("/api/v1/wireguard/members/{id}", "get"),
        ("/api/v1/wireguard/members/{id}/revoke", "post"),
        ("/api/v1/wireguard/members/{id}/config", "get"),
        ("/api/v1/wireguard/members/{id}/rekey", "post"),
        ("/api/v1/wireguard/members/{id}", "delete"),
        ("/api/v1/wireguard/hubs/{id}/token", "post"),
        ("/api/v1/wireguard/hubs/{id}/token", "delete"),
        ("/api/v1/wg-hub/state", "get"),
        ("/api/v1/wg-hub/public-key", "put"),
        ("/api/v1/wg-hub/status", "post"),
    ] {
        assert!(doc["paths"][path][method].is_object(), "{method} {path}");
    }
    // Hub routes take the hub token, not a user role.
    let state = &doc["paths"]["/api/v1/wg-hub/state"]["get"];
    assert_eq!(state["tags"], json!(["wireguard-hub"]));
    assert_eq!(state["security"], json!([{ "hub_token": [] }]));
    assert!(!state["description"].as_str().unwrap().contains("role"));
    assert!(doc["components"]["securitySchemes"]["hub_token"].is_object());
    assert!(doc["components"]["schemas"]["WgHubState"].is_object());
    assert!(
        doc["paths"]["/api/v1/wireguard/hubs/{id}/token"]["post"]["description"]
            .as_str()
            .unwrap()
            .contains("`admin` role")
    );
    // Revocation reason optional.
    let revoke = &doc["paths"]["/api/v1/wireguard/members/{id}/revoke"]["post"];
    assert_ne!(revoke["requestBody"]["required"], json!(true), "{revoke}");
    let create = &doc["paths"]["/api/v1/wireguard/networks/{id}/members"]["post"];
    assert!(
        create["description"]
            .as_str()
            .unwrap()
            .contains("private_key")
    );
    let schema = &doc["components"]["schemas"]["WgMemberCreated"];
    assert!(
        schema.to_string().contains("shown only once")
            || schema.to_string().contains("Shown only once"),
        "{schema}"
    );
    for field in ["config", "config_filename", "qr_svg"] {
        assert!(
            schema["properties"][field].is_object() || schema.to_string().contains(field),
            "{field}: {schema}"
        );
    }
    assert!(doc["components"]["schemas"]["WgClientConfig"].is_object());
    // Device members show device-side state; states explained.
    let member = &doc["components"]["schemas"]["WgMember"];
    assert!(
        member["properties"]["device_status"].is_object(),
        "{member}"
    );
    let status = doc["components"]["schemas"]["WgDeviceStatus"].to_string();
    for state in ["pending", "applied", "blocked", "unsupported", "error"] {
        assert!(status.contains(&format!("`{state}`")), "{state}: {status}");
    }
    assert!(!member.to_string().contains("applied_hash"), "{member}");
    // Routes whose changes wake devices -> say so.
    for (path, method) in [
        ("/api/v1/wireguard/hubs/{id}", "patch"),
        ("/api/v1/wg-hub/public-key", "put"),
        ("/api/v1/wireguard/networks/{id}", "patch"),
        ("/api/v1/wireguard/networks/{id}", "delete"),
        ("/api/v1/wireguard/networks/{id}/members", "post"),
        ("/api/v1/wireguard/members/{id}", "patch"),
        ("/api/v1/wireguard/members/{id}/revoke", "post"),
        ("/api/v1/wireguard/members/{id}", "delete"),
    ] {
        let description = doc["paths"][path][method]["description"]
            .as_str()
            .unwrap_or_default();
        assert!(
            description.contains("woken") && description.contains("connection request"),
            "{method} {path}: {description}"
        );
    }
    let rekey = &doc["paths"]["/api/v1/wireguard/members/{id}/rekey"]["post"];
    assert_ne!(rekey["requestBody"]["required"], json!(true), "{rekey}");
    assert!(
        rekey["description"]
            .as_str()
            .unwrap()
            .contains("shown only in this response")
    );
    assert!(
        doc["paths"]["/api/v1/wireguard/members/{id}/config"]["get"]["description"]
            .as_str()
            .unwrap()
            .contains("`operator` role")
    );
    // Read: operator role; hub changes: admin.
    assert!(
        doc["paths"]["/api/v1/wireguard/hubs"]["get"]["description"]
            .as_str()
            .unwrap_or_default()
            .contains("`operator` role")
    );
    assert!(
        doc["paths"]["/api/v1/wireguard/hubs"]["post"]["description"]
            .as_str()
            .unwrap()
            .contains("`admin` role")
    );
}

/// Call of hub routes: hub token, extra headers, client address the server sees.
/// -> status, headers, body (JSON, or null if empty).
async fn wg_hub_call(
    app: &Router,
    method: &str,
    uri: &str,
    body: Option<Value>,
    token: Option<&str>,
    headers: &[(&str, &str)],
) -> (StatusCode, axum::http::HeaderMap, Value, usize) {
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
            [198, 51, 100, 20],
            41000,
        ))));
    if let Some(t) = token {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let req = match body {
        Some(b) => req
            .header("content-type", "application/json")
            .body(Body::from(b.to_string())),
        None => req.body(Body::empty()),
    }
    .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let headers = resp.headers().clone();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        headers,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        bytes.len(),
    )
}

async fn wg_hub_token(app: &Router, admin: &str, hub: &str) -> String {
    let (s, v) = call(
        app,
        "POST",
        &format!("/api/v1/wireguard/hubs/{hub}/token"),
        None,
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    v["token"].as_str().unwrap().to_owned()
}

/// Hub tokens: issued by admins, shown once, replaced + revoked at once, never audited.
#[tokio::test]
async fn wireguard_hub_tokens_are_issued_once_and_replaced() {
    let admin = "admin-token";
    let (_c, _store, app, _) = setup(Some(admin)).await;
    let (hub, _) = wg_hub_and_network(&app, admin).await;
    let operator = api_key(&app, admin, "operator", None).await;
    let path = format!("/api/v1/wireguard/hubs/{hub}/token");

    let (s, _) = call(&app, "POST", &path, None, Some(&operator)).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = call(&app, "DELETE", &path, None, Some(&operator)).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _) = call(
        &app,
        "POST",
        &format!("/api/v1/wireguard/hubs/{}/token", Uuid::now_v7()),
        None,
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    let (s, v) = call(&app, "POST", &path, None, Some(admin)).await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    let first = v["token"].as_str().unwrap().to_owned();
    assert!(first.starts_with("dwh_"), "{first}");
    let prefix = v["token_prefix"].as_str().unwrap();
    assert_eq!(prefix.len(), 12);
    assert!(first.starts_with(prefix));
    assert_eq!(v["hub"]["token_prefix"], prefix);
    assert_eq!(v["hub"]["id"], hub.as_str());

    let (s, shown) = call(
        &app,
        "GET",
        &format!("/api/v1/wireguard/hubs/{hub}"),
        None,
        Some(&operator),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(shown["token_prefix"], prefix);
    assert!(shown["token_created_at"].is_string());
    assert!(!shown.to_string().contains(&first));

    let state = |t: String| {
        let app = app.clone();
        async move {
            wg_hub_call(&app, "GET", "/api/v1/wg-hub/state", None, Some(&t), &[])
                .await
                .0
        }
    };
    assert_eq!(state(first.clone()).await, StatusCode::OK);

    // New token replaces old one at once.
    let second = wg_hub_token(&app, admin, &hub).await;
    assert_ne!(first, second);
    assert_eq!(state(first.clone()).await, StatusCode::UNAUTHORIZED);
    assert_eq!(state(second.clone()).await, StatusCode::OK);

    let (s, _) = call(&app, "DELETE", &path, None, Some(admin)).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(state(second.clone()).await, StatusCode::UNAUTHORIZED);
    // Revoke again -> fine; unknown hub -> not.
    let (s, _) = call(&app, "DELETE", &path, None, Some(admin)).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _) = call(
        &app,
        "DELETE",
        &format!("/api/v1/wireguard/hubs/{}/token", Uuid::now_v7()),
        None,
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (_, shown) = call(
        &app,
        "GET",
        &format!("/api/v1/wireguard/hubs/{hub}"),
        None,
        Some(admin),
    )
    .await;
    assert!(shown["token_prefix"].is_null());

    let (_, audit) = call(&app, "GET", "/api/v1/audit?limit=1000", None, Some(admin)).await;
    let text = audit.to_string();
    assert!(!text.contains(&first) && !text.contains(&second));
    let actions: Vec<(&str, &Value)> = audit["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|a| {
            a["action"]
                .as_str()
                .unwrap()
                .starts_with("wireguard.hub.token")
        })
        .map(|a| (a["action"].as_str().unwrap(), &a["detail"]))
        .collect();
    assert_eq!(actions.len(), 4, "{actions:?}");
    assert!(actions.iter().any(|(a, d)| *a == "wireguard.hub.token"
        && d["replaced"] == json!(true)
        && second.starts_with(d["token_prefix"].as_str().unwrap())));
    assert!(
        actions
            .iter()
            .any(|(a, _)| *a == "wireguard.hub.token_revoke")
    );
}

/// Hub routes take only a hub token.
#[tokio::test]
async fn wireguard_hub_routes_need_a_hub_token() {
    let admin = "admin-token";
    let (_c, _store, app, _) = setup(Some(admin)).await;
    let (hub, _) = wg_hub_and_network(&app, admin).await;
    wg_hub_token(&app, admin, &hub).await;
    let key = api_key(&app, admin, "admin", None).await;
    wg_user(&app, admin, "hubuser", "admin", None).await;
    let cookie = wg_login(&app, "hubuser").await;

    let (s, _, v, _) = wg_hub_call(&app, "GET", "/api/v1/wg-hub/state", None, None, &[]).await;
    assert_eq!(
        (s, v["error"].as_str()),
        (StatusCode::UNAUTHORIZED, Some("a hub token is required"))
    );
    for t in [key.as_str(), admin] {
        let (s, _, v, _) =
            wg_hub_call(&app, "GET", "/api/v1/wg-hub/state", None, Some(t), &[]).await;
        assert_eq!(
            (s, v["error"].as_str()),
            (StatusCode::UNAUTHORIZED, Some("a hub token is required"))
        );
    }
    let (s, _, _, _) = wg_hub_call(
        &app,
        "GET",
        "/api/v1/wg-hub/state",
        None,
        None,
        &[("cookie", cookie.as_str())],
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _, v, _) = wg_hub_call(
        &app,
        "POST",
        "/api/v1/wg-hub/status",
        Some(json!({ "peers": [] })),
        Some("dwh_not-a-token-of-this-server"),
        &[],
    )
    .await;
    assert_eq!(
        (s, v["error"].as_str()),
        (StatusCode::UNAUTHORIZED, Some("invalid hub token"))
    );
    let (s, _, _, _) = wg_hub_call(
        &app,
        "PUT",
        "/api/v1/wg-hub/public-key",
        Some(json!({ "public_key": wg_key(1) })),
        Some("dwh_x"),
        &[],
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

/// `GET /wg-hub/state`: state + its tag, 304 for the tag the hub has,
/// long-poll answers as soon as the state changes.
#[tokio::test]
async fn wireguard_hub_state_long_polls_on_the_revision() {
    let admin = "admin-token";
    let (_c, _store, app, _) = setup(Some(admin)).await;
    let (hub, net) = wg_hub_and_network(&app, admin).await;
    let token = wg_hub_token(&app, admin, &hub).await;

    let (s, h, state, _) =
        wg_hub_call(&app, "GET", "/api/v1/wg-hub/state", None, Some(&token), &[]).await;
    assert_eq!(s, StatusCode::OK, "{state}");
    let revision = state["revision"].as_i64().unwrap();
    let tag = h["etag"].to_str().unwrap().to_owned();
    assert_eq!(tag, format!("\"r{revision}\""));
    assert_eq!(state["hub_id"], hub.as_str());
    let n = &state["networks"][0];
    assert_eq!(n["id"], net.as_str());
    assert_eq!(n["interface"], "dwg51820");
    assert_eq!(n["listen_port"], 51820);
    assert_eq!(n["prefix"], "10.77.0.0/24");
    assert_eq!(n["address"], "10.77.0.1");
    assert_eq!(n["peers"], json!([]));

    let (s, h, _, len) = wg_hub_call(
        &app,
        "GET",
        "/api/v1/wg-hub/state?wait=0",
        None,
        Some(&token),
        &[("if-none-match", tag.as_str())],
    )
    .await;
    assert_eq!((s, len), (StatusCode::NOT_MODIFIED, 0));
    assert_eq!(h["etag"].to_str().unwrap(), tag);
    // Other tag -> gets the state.
    let (s, _, _, _) = wg_hub_call(
        &app,
        "GET",
        "/api/v1/wg-hub/state",
        None,
        Some(&token),
        &[("if-none-match", "\"r0\"")],
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _, v, _) = wg_hub_call(
        &app,
        "GET",
        "/api/v1/wg-hub/state?wait=61",
        None,
        Some(&token),
        &[],
    )
    .await;
    assert_eq!(
        (s, v["error"].as_str()),
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            Some("wait must be between 0 and 60 seconds")
        )
    );

    // No change -> 304 after the wait.
    let started = std::time::Instant::now();
    let (s, _, _, _) = wg_hub_call(
        &app,
        "GET",
        "/api/v1/wg-hub/state?wait=2",
        None,
        Some(&token),
        &[("if-none-match", tag.as_str())],
    )
    .await;
    let took = started.elapsed();
    assert_eq!(s, StatusCode::NOT_MODIFIED);
    assert!(
        took >= std::time::Duration::from_millis(1900) && took < std::time::Duration::from_secs(4),
        "{took:?}"
    );

    // Change -> waiting hub answered at once.
    let poll = {
        let (app, token, tag) = (app.clone(), token.clone(), tag.clone());
        tokio::spawn(async move {
            let started = std::time::Instant::now();
            let out = wg_hub_call(
                &app,
                "GET",
                "/api/v1/wg-hub/state?wait=10",
                None,
                Some(&token),
                &[("if-none-match", tag.as_str())],
            )
            .await;
            (out, started.elapsed())
        })
    };
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let (s, m) = call(
        &app,
        "POST",
        &format!("/api/v1/wireguard/networks/{net}/members"),
        Some(json!({ "kind": "client", "name": "srv", "user_id": null,
                     "public_key": wg_key(1) })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{m}");
    let ((s, h, state, _), took) = poll.await.unwrap();
    assert_eq!(s, StatusCode::OK);
    assert!(took < std::time::Duration::from_secs(5), "{took:?}");
    let newer = state["revision"].as_i64().unwrap();
    assert!(newer > revision);
    assert_eq!(h["etag"].to_str().unwrap(), format!("\"r{newer}\""));
    let peer = &state["networks"][0]["peers"][0];
    assert_eq!(peer["member_id"], m["id"]);
    assert_eq!(peer["kind"], "client");
    assert_eq!(peer["public_key"], wg_key(1));
    assert_eq!(peer["allowed_ips"], json!(["10.77.0.2/32"]));
}

/// Held long-poll -> 304 at once on server shutdown.
#[tokio::test]
async fn wireguard_hub_state_long_poll_ends_at_shutdown() {
    let admin = "admin-token";
    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let (_c, _store, app, _) = setup_with_shutdown(Some(admin), Some(stop_rx)).await;
    let (hub, _net) = wg_hub_and_network(&app, admin).await;
    let token = wg_hub_token(&app, admin, &hub).await;
    let (s, h, _, _) =
        wg_hub_call(&app, "GET", "/api/v1/wg-hub/state", None, Some(&token), &[]).await;
    assert_eq!(s, StatusCode::OK);
    let tag = h["etag"].to_str().unwrap().to_owned();

    let poll = {
        let (app, token, tag) = (app.clone(), token.clone(), tag.clone());
        tokio::spawn(async move {
            let out = wg_hub_call(
                &app,
                "GET",
                "/api/v1/wg-hub/state?wait=30",
                None,
                Some(&token),
                &[("if-none-match", tag.as_str())],
            )
            .await;
            (out, std::time::Instant::now())
        })
    };
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let sent = std::time::Instant::now();
    stop_tx.send(true).unwrap();
    let ((s, h, _, _), answered) = tokio::time::timeout(std::time::Duration::from_secs(5), poll)
        .await
        .expect("the long-poll ends")
        .unwrap();
    assert_eq!(s, StatusCode::NOT_MODIFIED);
    assert_eq!(h["etag"].to_str().unwrap(), tag);
    let took = answered.duration_since(sent);
    assert!(took < std::time::Duration::from_secs(2), "{took:?}");
}

/// Hub reports its public key (audited on change) + peer status (shown on members).
/// Each call records when + from where the hub was seen.
#[tokio::test]
async fn wireguard_hub_reports_its_key_and_peer_status() {
    let admin = "admin-token";
    let (_c, _store, app, _) = setup(Some(admin)).await;
    let (hub, net) = wg_hub_and_network(&app, admin).await;
    let token = wg_hub_token(&app, admin, &hub).await;
    let agent = [("user-agent", "dhonomos-wg-hub/0.1.0")];

    let (s, _, v, _) = wg_hub_call(
        &app,
        "PUT",
        "/api/v1/wg-hub/public-key",
        Some(json!({ "public_key": "not a key" })),
        Some(&token),
        &agent,
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        v["error"].as_str().unwrap().starts_with("public_key: "),
        "{v}"
    );
    let (s, _, _, _) = wg_hub_call(
        &app,
        "PUT",
        "/api/v1/wg-hub/public-key",
        Some(json!({ "key": wg_key(1) })),
        Some(&token),
        &agent,
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);

    let audits = |app: Router| async move {
        let (_, v) = call(
            &app,
            "GET",
            "/api/v1/audit?action=wireguard.hub.public_key",
            None,
            Some(admin),
        )
        .await;
        v["items"].as_array().unwrap().clone()
    };
    for (key, expected) in [(wg_key(1), 1), (wg_key(1), 1), (wg_key(2), 2)] {
        let (s, _, _, _) = wg_hub_call(
            &app,
            "PUT",
            "/api/v1/wg-hub/public-key",
            Some(json!({ "public_key": key })),
            Some(&token),
            &agent,
        )
        .await;
        assert_eq!(s, StatusCode::NO_CONTENT);
        let (_, h) = call(
            &app,
            "GET",
            &format!("/api/v1/wireguard/hubs/{hub}"),
            None,
            Some(admin),
        )
        .await;
        assert_eq!(h["public_key"], key.as_str());
        assert_eq!(audits(app.clone()).await.len(), expected);
    }
    let records = audits(app.clone()).await;
    let latest = &records[0];
    assert_eq!(latest["actor"], "hub:lab-hub");
    assert_eq!(latest["target_type"], "wg_hub");
    assert_eq!(latest["detail"]["old"], wg_key(1));
    assert_eq!(latest["detail"]["new"], wg_key(2));
    assert!(records[1]["detail"]["old"].is_null());

    // Peer status.
    let (s, m) = call(
        &app,
        "POST",
        &format!("/api/v1/wireguard/networks/{net}/members"),
        Some(json!({ "kind": "client", "name": "srv", "user_id": null,
                     "public_key": wg_key(5) })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{m}");
    let member = m["id"].as_str().unwrap();
    assert!(m["hub_status"].is_null());
    let peer = |endpoint: Value, key: String| {
        json!({ "network_id": net, "public_key": key, "endpoint": endpoint,
                "latest_handshake": 1_760_000_000, "rx_bytes": 1234, "tx_bytes": 5678 })
    };
    let (s, _, v, _) = wg_hub_call(
        &app,
        "POST",
        "/api/v1/wg-hub/status",
        Some(
            json!({ "peers": [peer(json!("198.51.100.7:40000"), wg_key(5)),
                               peer(Value::Null, wg_key(6))] }),
        ),
        Some(&token),
        &agent,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v, json!({ "accepted": 1, "ignored": 1 }));
    let (_, got) = call(
        &app,
        "GET",
        &format!("/api/v1/wireguard/members/{member}"),
        None,
        Some(admin),
    )
    .await;
    let st = &got["hub_status"];
    assert_eq!(st["endpoint"], "198.51.100.7:40000");
    assert_eq!(st["rx_bytes"], 1234);
    assert_eq!(st["tx_bytes"], 5678);
    assert_eq!(st["latest_handshake"], "2025-10-09T08:53:20Z");
    assert!(st["reported_at"].is_string());

    for (body, what) in [
        (
            json!({ "peers": [peer(json!("not an address"), wg_key(5))] }),
            "peers[0].endpoint: not an address:port",
        ),
        (
            json!({ "peers": [peer(Value::Null, wg_key(5)), peer(Value::Null, "x".into())] }),
            "peers[1].public_key: ",
        ),
        (
            json!({ "peers": [{ "network_id": net, "public_key": wg_key(5),
                                "endpoint": null, "latest_handshake": null,
                                "rx_bytes": 9_223_372_036_854_775_808u64, "tx_bytes": 0 }] }),
            "peers[0].rx_bytes: ",
        ),
        (json!({ "peers": "none" }), ""),
    ] {
        let (s, _, v, _) = wg_hub_call(
            &app,
            "POST",
            "/api/v1/wg-hub/status",
            Some(body),
            Some(&token),
            &agent,
        )
        .await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
        assert!(v["error"].as_str().unwrap().starts_with(what), "{v}");
    }

    // Hub seen, from the address the server saw, with its version.
    let (_, h) = call(
        &app,
        "GET",
        &format!("/api/v1/wireguard/hubs/{hub}"),
        None,
        Some(admin),
    )
    .await;
    assert!(h["last_seen_at"].is_string(), "{h}");
    assert_eq!(h["last_seen_ip"], "198.51.100.20");
    assert_eq!(h["version"], "0.1.0");
    assert!(h["state_revision"].as_i64().unwrap() > 1);
}

/// What a test CR receiver heard within `wait`: names in the paths (`/cr/<name>`)
/// it was called on; stops early after `expect` names.
async fn wg_woken(
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<String>,
    expect: usize,
    wait: std::time::Duration,
) -> std::collections::BTreeSet<String> {
    let mut heard = std::collections::BTreeSet::new();
    let until = tokio::time::Instant::now() + wait;
    while heard.len() < expect || expect == 0 {
        match tokio::time::timeout_at(until, rx.recv()).await {
            Ok(Some(name)) => {
                heard.insert(name);
            }
            _ => break,
        }
    }
    heard
}

fn names(list: &[&str]) -> std::collections::BTreeSet<String> {
    list.iter().map(|s| (*s).to_owned()).collect()
}

/// Changes to a device member's WireGuard config -> CR wakes the CWMP devices concerned.
/// USP Agents, name changes, clients -> no wake. Device members show device-side state.
#[tokio::test]
async fn wireguard_changes_wake_the_cwmp_devices_concerned() {
    let admin = "admin-token";
    let (_c, store, app, a) = setup(Some(admin)).await;
    let soon = std::time::Duration::from_secs(3);
    let quiet = std::time::Duration::from_secs(1);

    // CR receiver: `/cr/<name>` answers 200 + tells the test.
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let receiver = axum::Router::new().route(
        "/cr/{name}",
        axum::routing::any(
            move |axum::extract::Path(name): axum::extract::Path<String>| {
                let tx = tx.clone();
                async move {
                    tx.send(name).unwrap();
                    StatusCode::OK
                }
            },
        ),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, receiver).await });
    let inform = |serial: &str, name: &str| {
        let store = store.clone();
        let (serial, url) = (serial.to_owned(), format!("http://{addr}/cr/{name}"));
        async move {
            store
                .upsert_cwmp_device(
                    DEFAULT_TENANT,
                    &CwmpIdentity {
                        oui: "001122".into(),
                        product_class: "Box".into(),
                        serial_number: serial,
                    },
                    &InformUpdate {
                        connection_request_url: Some(url),
                        ..InformUpdate::default()
                    },
                )
                .await
                .unwrap()
                .id
        }
    };
    assert_eq!(inform("SN1", "a").await, a);
    let b = inform("SN2", "b").await;
    let usp = store
        .upsert_usp_device(DEFAULT_TENANT, "os::wg-agent", None)
        .await
        .unwrap()
        .id;

    let (hub, net) = wg_hub_and_network(&app, admin).await;
    let members = format!("/api/v1/wireguard/networks/{net}/members");
    let add = |body: Value| {
        let (app, members) = (app.clone(), members.clone());
        async move {
            let (s, v) = call(&app, "POST", &members, Some(body), Some(admin)).await;
            assert_eq!(s, StatusCode::CREATED, "{v}");
            v
        }
    };
    // Device member without site prefixes -> only its own device woken.
    let mb = add(json!({ "kind": "device", "device_id": b })).await;
    assert_eq!(wg_woken(&mut rx, 2, soon).await, names(&["b"]));
    // USP Agent needs no wake; client is no device.
    let mu = add(json!({ "kind": "device", "device_id": usp })).await;
    let client = add(json!({ "kind": "client", "name": "pc", "user_id": null,
                             "public_key": wg_key(1) }))
    .await;
    assert!(wg_woken(&mut rx, 0, quiet).await.is_empty());
    // With site prefixes the others route to them -> whole network.
    let ma = add(json!({ "kind": "device", "device_id": a,
                         "site_prefixes": [{ "prefix": "192.168.10.0/24" }] }))
    .await;
    assert_eq!(wg_woken(&mut rx, 2, soon).await, names(&["a", "b"]));

    // Device state: new device member pending; clients none; hash stays inside.
    let member_uri = |m: &Value| format!("/api/v1/wireguard/members/{}", m["id"].as_str().unwrap());
    let (_, v) = call(&app, "GET", &member_uri(&mb), None, Some(admin)).await;
    assert_eq!(
        v["device_status"],
        json!({ "state": "pending", "detail": null, "checked_at": null }),
        "{v}"
    );
    let (_, v) = call(&app, "GET", &member_uri(&client), None, Some(admin)).await;
    assert!(v["device_status"].is_null(), "{v}");
    assert!(v.as_object().unwrap().contains_key("device_status"), "{v}");
    store
        .set_wg_member_device_state(
            mb["id"].as_str().unwrap().parse().unwrap(),
            "applied",
            None,
            Some("hash"),
        )
        .await
        .unwrap();
    let (_, v) = call(&app, "GET", &member_uri(&mb), None, Some(admin)).await;
    assert_eq!(v["device_status"]["state"], "applied", "{v}");
    assert!(v["device_status"]["detail"].is_null(), "{v}");
    assert!(v["device_status"]["checked_at"].is_string(), "{v}");
    assert!(!v.to_string().contains("hash"), "{v}");
    let (_, v) = call(&app, "GET", &members, None, Some(admin)).await;
    assert!(
        v["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m["device_status"]["state"] == "applied"),
        "{v}"
    );

    // 1. MTU in every device config; USP Agent not woken.
    let net_uri = format!("/api/v1/wireguard/networks/{net}");
    let (s, v) = call(
        &app,
        "PATCH",
        &net_uri,
        Some(json!({ "mtu": 1400 })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(wg_woken(&mut rx, 2, soon).await, names(&["a", "b"]));
    let (_, v) = call(
        &app,
        "GET",
        &format!("/api/v1/devices/{a}"),
        None,
        Some(admin),
    )
    .await;
    assert_eq!(v["last_wake_outcome"], "sent", "{v}");
    let (_, v) = call(
        &app,
        "GET",
        &format!("/api/v1/devices/{usp}"),
        None,
        Some(admin),
    )
    .await;
    assert!(v["last_wake_at"].is_null(), "{v}");
    // Same MTU again -> no change.
    call(
        &app,
        "PATCH",
        &net_uri,
        Some(json!({ "mtu": 1400 })),
        Some(admin),
    )
    .await;
    assert!(wg_woken(&mut rx, 0, quiet).await.is_empty());

    // 2. Name is in no device config.
    let (s, _) = call(
        &app,
        "PATCH",
        &net_uri,
        Some(json!({ "name": "renamed" })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert!(wg_woken(&mut rx, 0, quiet).await.is_empty());

    // 3. New site prefixes -> into the others' AllowedIPs; same ones again do not.
    let prefixes = json!({ "site_prefixes": [{ "prefix": "192.168.20.0/24" }] });
    let (s, v) = call(
        &app,
        "PATCH",
        &member_uri(&ma),
        Some(prefixes.clone()),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(wg_woken(&mut rx, 2, soon).await, names(&["a", "b"]));
    let (s, _) = call(&app, "PATCH", &member_uri(&ma), Some(prefixes), Some(admin)).await;
    assert_eq!(s, StatusCode::OK);
    assert!(wg_woken(&mut rx, 0, quiet).await.is_empty());
    let (s, _) = call(
        &app,
        "PATCH",
        &member_uri(&ma),
        Some(json!({ "name": "cpe-a" })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert!(wg_woken(&mut rx, 0, quiet).await.is_empty());

    // 5. New hub key, reported by hub; same key again -> no wake.
    let token = wg_hub_token(&app, admin, &hub).await;
    for (key, woken) in [(wg_key(7), names(&["a", "b"])), (wg_key(7), names(&[]))] {
        let (s, _, _, _) = wg_hub_call(
            &app,
            "PUT",
            "/api/v1/wg-hub/public-key",
            Some(json!({ "public_key": key })),
            Some(&token),
            &[],
        )
        .await;
        assert_eq!(s, StatusCode::NO_CONTENT);
        let wait = if woken.is_empty() { quiet } else { soon };
        assert_eq!(wg_woken(&mut rx, woken.len(), wait).await, woken);
    }

    // New endpoint; same one again -> no wake.
    let hub_uri = format!("/api/v1/wireguard/hubs/{hub}");
    let endpoint = json!({ "endpoint_host": "hub2.example.org" });
    let (s, _) = call(&app, "PATCH", &hub_uri, Some(endpoint.clone()), Some(admin)).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(wg_woken(&mut rx, 2, soon).await, names(&["a", "b"]));
    call(&app, "PATCH", &hub_uri, Some(endpoint), Some(admin)).await;
    assert!(wg_woken(&mut rx, 0, quiet).await.is_empty());

    // 4. Revoked member: its device drops the network, the others its prefixes;
    // 2nd revocation -> no change.
    let revoke = format!("{}/revoke", member_uri(&mb));
    let (s, _) = call(&app, "POST", &revoke, None, Some(admin)).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(wg_woken(&mut rx, 2, soon).await, names(&["a", "b"]));
    call(&app, "POST", &revoke, None, Some(admin)).await;
    assert!(wg_woken(&mut rx, 0, quiet).await.is_empty());
    // Revoke/delete of a client or USP member -> no own CWMP device woken;
    // client wakes nobody.
    let (s, _) = call(
        &app,
        "POST",
        &format!("{}/revoke", member_uri(&client)),
        None,
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert!(wg_woken(&mut rx, 0, quiet).await.is_empty());
    let (s, _) = call(&app, "DELETE", &member_uri(&mu), None, Some(admin)).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(wg_woken(&mut rx, 1, soon).await, names(&["a"]));
    // Delete device member -> its own device + network woken.
    let (s, _) = call(&app, "DELETE", &member_uri(&mb), None, Some(admin)).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(wg_woken(&mut rx, 2, soon).await, names(&["a", "b"]));
    // Delete network -> devices of its live members woken, read before they go.
    let (s, _) = call(&app, "DELETE", &net_uri, None, Some(admin)).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(wg_woken(&mut rx, 1, soon).await, names(&["a"]));
    assert!(wg_woken(&mut rx, 0, quiet).await.is_empty());
}

/// Key rotation of device members: 1 member (operator, within scope) or whole network
/// (admin). Request audited, shown on the member, wakes the CWMP devices concerned.
#[tokio::test]
async fn wireguard_device_key_rotation_requests() {
    let admin = "admin-token";
    let (_c, store, app, a) = setup(Some(admin)).await;
    let soon = std::time::Duration::from_secs(3);
    let quiet = std::time::Duration::from_secs(1);

    // CR receiver: `/cr/<name>` answers 200 + tells the test.
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let receiver = axum::Router::new().route(
        "/cr/{name}",
        axum::routing::any(
            move |axum::extract::Path(name): axum::extract::Path<String>| {
                let tx = tx.clone();
                async move {
                    tx.send(name).unwrap();
                    StatusCode::OK
                }
            },
        ),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, receiver).await });
    let inform = |serial: &str, name: &str| {
        let store = store.clone();
        let (serial, url) = (serial.to_owned(), format!("http://{addr}/cr/{name}"));
        async move {
            store
                .upsert_cwmp_device(
                    DEFAULT_TENANT,
                    &CwmpIdentity {
                        oui: "001122".into(),
                        product_class: "Box".into(),
                        serial_number: serial,
                    },
                    &InformUpdate {
                        connection_request_url: Some(url),
                        ..InformUpdate::default()
                    },
                )
                .await
                .unwrap()
                .id
        }
    };
    assert_eq!(inform("SN1", "a").await, a);
    let b = inform("SN2", "b").await;

    let (_hub, net) = wg_hub_and_network(&app, admin).await;
    let members = format!("/api/v1/wireguard/networks/{net}/members");
    let add = |body: Value| {
        let (app, members) = (app.clone(), members.clone());
        async move {
            let (s, v) = call(&app, "POST", &members, Some(body), Some(admin)).await;
            assert_eq!(s, StatusCode::CREATED, "{v}");
            v["id"].as_str().unwrap().to_owned()
        }
    };
    let ma = add(json!({ "kind": "device", "device_id": a })).await;
    let mb = add(json!({ "kind": "device", "device_id": b })).await;
    let client = add(json!({ "kind": "client", "name": "pc", "user_id": null,
                             "public_key": wg_key(1) }))
    .await;
    let (s, _) = call(
        &app,
        "POST",
        &format!("/api/v1/wireguard/members/{mb}/revoke"),
        None,
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    wg_woken(&mut rx, 0, quiet).await;

    wg_user(&app, admin, "alice", "operator", None).await;
    wg_user(
        &app,
        admin,
        "bob",
        "operator",
        Some(json!({ "tags": ["east"] })),
    )
    .await;
    wg_user(&app, admin, "carol", "viewer", None).await;
    let (alice, bob, carol) = (
        wg_login(&app, "alice").await,
        wg_login(&app, "bob").await,
        wg_login(&app, "carol").await,
    );
    let rotate = |id: &str| format!("/api/v1/wireguard/members/{id}/rotate-key");

    // Member key: 202 + member, pending, request shown; its device woken.
    let ma_id: Uuid = ma.parse().unwrap();
    store
        .set_wg_device_member_key(ma_id, &wg_key(5))
        .await
        .unwrap()
        .unwrap();
    store
        .set_wg_member_device_state(
            ma_id,
            "blocked",
            Some("the device did not make a new key"),
            Some("h"),
        )
        .await
        .unwrap();
    let (s, v, _) = call_cookie(&app, "POST", &rotate(&ma), None, Some(&alice)).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{v}");
    assert_eq!(v["id"], ma);
    assert!(v["rotate_requested_at"].is_string(), "{v}");
    assert_eq!(
        v["device_status"]["state"], "pending",
        "a blocked member is tried again at once: {v}"
    );
    assert!(v["device_status"]["detail"].is_null(), "{v}");
    assert_eq!(wg_woken(&mut rx, 1, soon).await, names(&["a"]));
    let (_, v) = call(
        &app,
        "GET",
        &format!("/api/v1/wireguard/members/{ma}"),
        None,
        Some(admin),
    )
    .await;
    assert!(v["rotate_requested_at"].is_string(), "{v}");
    let (_, v) = call(
        &app,
        "GET",
        &format!("/api/v1/wireguard/members/{client}"),
        None,
        Some(admin),
    )
    .await;
    assert!(v["rotate_requested_at"].is_null(), "{v}");
    assert!(
        v.as_object().unwrap().contains_key("rotate_requested_at"),
        "{v}"
    );
    let (_, audit) = call(
        &app,
        "GET",
        "/api/v1/audit?action=wireguard.member.rotate_key",
        None,
        Some(admin),
    )
    .await;
    let records = audit["items"].as_array().unwrap();
    assert_eq!(records.len(), 1, "{audit}");
    assert_eq!(records[0]["target_type"], "wg_member");
    assert_eq!(records[0]["target_id"], ma);
    let name = records[0]["detail"]["name"].clone();
    assert!(name.is_string(), "{audit}");
    assert_eq!(
        records[0]["detail"],
        json!({ "network": net, "name": name, "public_key": wg_key(5) })
    );

    // Refusals: client, revoked member, viewer, device outside scope, unknown.
    let (s, v) = call(&app, "POST", &rotate(&client), None, Some(admin)).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert_eq!(
        v["error"],
        "only device members' keys are rotated here; re-key a client instead"
    );
    let (s, v) = call(&app, "POST", &rotate(&mb), None, Some(admin)).await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    let (s, _, _) = call_cookie(&app, "POST", &rotate(&ma), None, Some(&carol)).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _, _) = call_cookie(&app, "POST", &rotate(&ma), None, Some(&bob)).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let (s, _) = call(
        &app,
        "POST",
        &rotate(&Uuid::now_v7().to_string()),
        None,
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert!(wg_woken(&mut rx, 0, quiet).await.is_empty());

    // Whole network: admin only; live device members, not the revoked one or the client.
    let rotate_all = format!("/api/v1/wireguard/networks/{net}/rotate-keys");
    let (s, _, _) = call_cookie(&app, "POST", &rotate_all, None, Some(&alice)).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, v) = call(&app, "POST", &rotate_all, None, Some(admin)).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{v}");
    assert_eq!(v, json!({ "requested": 1 }));
    assert_eq!(wg_woken(&mut rx, 1, soon).await, names(&["a"]));
    let (_, audit) = call(
        &app,
        "GET",
        "/api/v1/audit?action=wireguard.network.rotate_keys",
        None,
        Some(admin),
    )
    .await;
    let records = audit["items"].as_array().unwrap();
    assert_eq!(records.len(), 1, "{audit}");
    assert_eq!(records[0]["target_type"], "wg_network");
    assert_eq!(records[0]["target_id"], net);
    assert_eq!(records[0]["detail"], json!({ "members": 1 }));
    let (s, _) = call(
        &app,
        "POST",
        &format!("/api/v1/wireguard/networks/{}/rotate-keys", Uuid::now_v7()),
        None,
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // Both documented.
    let (_, doc) = call(&app, "GET", "/api/v1/openapi.json", None, None).await;
    for path in [
        "/api/v1/wireguard/members/{id}/rotate-key",
        "/api/v1/wireguard/networks/{id}/rotate-keys",
    ] {
        let op = &doc["paths"][path]["post"];
        let description = op["description"].as_str().unwrap_or_default();
        assert!(
            description.contains("few seconds") && description.contains("connection request"),
            "{path}: {description}"
        );
        assert!(op["responses"]["202"].is_object(), "{path}: {op}");
    }
    assert!(
        doc["components"]["schemas"]["WgMember"]["properties"]["rotate_requested_at"].is_object()
    );
}

/// Tunnel health summary: per state, per network, with thresholds; for operators.
#[tokio::test]
async fn wireguard_summary_counts_tunnel_states() {
    let admin = "admin-token";
    let (_c, store, app, device) = setup(Some(admin)).await;
    let (hub, net) = wg_hub_and_network(&app, admin).await;
    let operator = api_key(&app, admin, "operator", None).await;
    let viewer = api_key(&app, admin, "viewer", None).await;
    let uri = "/api/v1/wireguard/summary";
    assert_eq!(
        call(&app, "GET", uri, None, Some(&viewer)).await.0,
        StatusCode::FORBIDDEN
    );
    let (s, v) = call(
        &app,
        "POST",
        &format!("/api/v1/wireguard/networks/{net}/members"),
        Some(json!({ "kind": "device", "device_id": device, "key_mode": "device" })),
        Some(&operator),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    let member: Uuid = v["id"].as_str().unwrap().parse().unwrap();
    sqlx::query("UPDATE wg_hubs SET last_seen_at = now() WHERE id = $1::uuid")
        .bind(&hub)
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO wg_peer_status (member_id, latest_handshake, rx_bytes, tx_bytes, reported_at) \
         VALUES ($1, now() - interval '20 minutes', 0, 0, now())",
    )
    .bind(member)
    .execute(store.pool())
    .await
    .unwrap();

    let (s, v) = call(&app, "GET", uri, None, Some(&operator)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        v["thresholds"],
        json!({ "connected_secs": 180, "stale_secs": 900, "hub_silent_secs": 300 })
    );
    let stale =
        json!({ "total": 1, "connected": 0, "idle": 0, "stale": 1, "never": 0, "unknown": 0 });
    let none =
        json!({ "total": 0, "connected": 0, "idle": 0, "stale": 0, "never": 0, "unknown": 0 });
    assert_eq!(v["totals"], json!({ "device": stale, "client": none }));
    assert_eq!(
        v["networks"],
        json!([{ "id": net, "name": "branches", "hub_id": hub, "hub_name": "lab-hub",
                 "device": stale, "client": none }])
    );
    // Caller whose scope excludes the device -> counts nothing, sees the network.
    let usp_only = api_key(&app, admin, "operator", Some(json!({ "protocol": "usp" }))).await;
    let (s, v) = call(&app, "GET", uri, None, Some(&usp_only)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["totals"]["device"], none);
    assert_eq!(v["networks"][0]["device"], none);
}

/// Device WireGuard view: own live device members + twin's, with network name, twin,
/// device-reported data; 404 outside the caller's device scope.
#[tokio::test]
async fn device_wireguard_view_lists_own_and_twin_members() {
    let admin = "admin-token";
    let (_c, store, app, device) = setup(Some(admin)).await;
    let (hub, net) = wg_hub_and_network(&app, admin).await;
    let (s, other) = call(
        &app,
        "POST",
        "/api/v1/wireguard/networks",
        Some(json!({ "hub_id": hub, "name": "auxiliary" })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{other}");
    let other = other["id"].as_str().unwrap().to_owned();
    // USP record of the same CPE (setup device = CWMP 001122 / SN1).
    let twin = store
        .upsert_usp_device(DEFAULT_TENANT, "os::001122-SN1", None)
        .await
        .unwrap()
        .id;
    store
        .update_device_info(
            twin,
            &dhonomos_store::DeviceInfo {
                oui: Some("001122".into()),
                serial_number: Some("SN1".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let operator = api_key(&app, admin, "operator", None).await;
    let add = |network: String, device_id: Uuid| {
        let (app, operator) = (app.clone(), operator.clone());
        async move {
            let (s, v) = call(
                &app,
                "POST",
                &format!("/api/v1/wireguard/networks/{network}/members"),
                Some(json!({ "kind": "device", "device_id": device_id, "key_mode": "device" })),
                Some(&operator),
            )
            .await;
            assert_eq!(s, StatusCode::CREATED, "{v}");
            v["id"].as_str().unwrap().to_owned()
        }
    };
    let own = add(net.clone(), device).await;
    let via_twin = add(other.clone(), twin).await;
    // What the CWMP record read of its own tunnel (LS500X names); twin read nothing.
    let alias = dhonomos_wireguard::alias_of(net.parse().unwrap());
    for (path, value) in [
        ("Device.WireGuard.Tunnel.1.Alias", alias.as_str()),
        ("Device.WireGuard.Tunnel.1.Status", "Enabled"),
        ("Device.WireGuard.Tunnel.1.Interface.1.Status", "Up"),
        ("Device.WireGuard.Tunnel.1.Stats.BytesSent", "1000"),
        ("Device.WireGuard.Peer.1.Alias", alias.as_str()),
        ("Device.WireGuard.Peer.1.LastHandshakeTime", "37"),
    ] {
        sqlx::query("INSERT INTO device_params (device_id, path, value) VALUES ($1, $2, $3)")
            .bind(device)
            .bind(path)
            .bind(value)
            .execute(store.pool())
            .await
            .unwrap();
    }

    let uri = format!("/api/v1/devices/{device}/wireguard");
    // Viewer may not read it.
    let viewer = api_key(&app, admin, "viewer", None).await;
    assert_eq!(
        call(&app, "GET", &uri, None, Some(&viewer)).await.0,
        StatusCode::FORBIDDEN
    );
    let (s, v) = call(&app, "GET", &uri, None, Some(&operator)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let items = v["items"].as_array().unwrap();
    assert_eq!(items.len(), 2, "{v}");
    // By network name: auxiliary (twin's) before branches (own).
    assert_eq!(items[0]["id"], via_twin.as_str());
    assert_eq!(items[0]["network_name"], "auxiliary");
    assert_eq!(items[0]["network_id"], other.as_str());
    assert_eq!(
        items[0]["via_twin"],
        json!({ "device_id": twin, "protocol": "usp" })
    );
    assert_eq!(items[1]["id"], own.as_str());
    assert_eq!(items[1]["network_name"], "branches");
    assert_eq!(items[1]["via_twin"], Value::Null);
    assert_eq!(items[1]["device_status"]["state"], "pending");
    assert!(items[1].get("hub_status").is_some());
    let side = &items[1]["device_side"];
    assert_eq!(side["tunnel_status"], "Enabled", "{side}");
    assert_eq!(side["interface_status"], "Up");
    assert_eq!(side["last_handshake_secs"], 37);
    assert_eq!(side["bytes_sent"], 1000);
    assert_eq!(side["bytes_received"], Value::Null);
    assert!(side["read_at"].is_string(), "{side}");
    assert_eq!(side.as_object().unwrap().len(), 6, "{side}");
    // Twin's rows read from the twin, which has none.
    assert_eq!(items[0]["device_side"], Value::Null);

    // Unknown device + device outside caller scope -> 404.
    let (s, v) = call(
        &app,
        "GET",
        &format!("/api/v1/devices/{}/wireguard", Uuid::now_v7()),
        None,
        Some(&operator),
    )
    .await;
    assert_eq!(
        (s, v["error"].as_str()),
        (StatusCode::NOT_FOUND, Some("device not found"))
    );
    let usp_only = api_key(&app, admin, "operator", Some(json!({ "protocol": "usp" }))).await;
    let (s, v) = call(&app, "GET", &uri, None, Some(&usp_only)).await;
    assert_eq!(
        (s, v["error"].as_str()),
        (StatusCode::NOT_FOUND, Some("device not found"))
    );
    // From the twin's side: caller sees twin's member, not the CWMP record's.
    let (s, v) = call(
        &app,
        "GET",
        &format!("/api/v1/devices/{twin}/wireguard"),
        None,
        Some(&usp_only),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        v["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["id"].as_str().unwrap())
            .collect::<Vec<_>>(),
        [via_twin.as_str()]
    );
}

/// Stale-handshake rule -> alarm raised, cleared once a handshake comes in again.
#[tokio::test]
async fn wg_handshake_alarms_raise_and_clear() {
    use dhonomos_core::alarms::{AlarmEngine, AlarmRules, Webhooks};

    let admin = "admin-token";
    let (_c, store, app, device) = setup(Some(admin)).await;
    let (hub, net) = wg_hub_and_network(&app, admin).await;
    let (s, m) = call(
        &app,
        "POST",
        &format!("/api/v1/wireguard/networks/{net}/members"),
        Some(json!({ "kind": "device", "device_id": device })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{m}");
    let member: Uuid = m["id"].as_str().unwrap().parse().unwrap();
    sqlx::query(
        "UPDATE wg_members SET device_state = 'applied', created_at = now() - interval '1 hour' WHERE id = $1",
    )
    .bind(member)
    .execute(store.pool())
    .await
    .unwrap();
    sqlx::query("UPDATE wg_hubs SET last_seen_at = now() WHERE id = $1::uuid")
        .bind(&hub)
        .execute(store.pool())
        .await
        .unwrap();
    let handshake = |ago: &'static str| {
        let store = store.clone();
        async move {
            sqlx::query(
                r#"
                INSERT INTO wg_peer_status (member_id, latest_handshake, rx_bytes, tx_bytes, reported_at)
                VALUES ($1, now() - $2::text::interval, 0, 0, now())
                ON CONFLICT (member_id) DO UPDATE SET latest_handshake = EXCLUDED.latest_handshake
                "#,
            )
            .bind(member)
            .bind(ago)
            .execute(store.pool())
            .await
            .unwrap();
        }
    };
    handshake("20 minutes").await;
    let rules = AlarmRules::from_yaml(
        "alarms: [{ name: wg-handshake, severity: major, when: { wg_handshake_minutes: 10 } }]",
    )
    .unwrap();
    let engine = AlarmEngine::new(store.clone(), DEFAULT_TENANT, rules, Webhooks::default());
    assert_eq!(engine.evaluate().await.unwrap(), (1, 0));
    let alarms = store
        .list_alarms(DEFAULT_TENANT, Some("active"), Some(device), None, 10)
        .await
        .unwrap();
    assert_eq!(alarms.len(), 1);
    assert_eq!(alarms[0].rule, "wg-handshake");
    assert!(
        alarms[0]
            .message
            .starts_with("No WireGuard handshake for 2"),
        "{}",
        alarms[0].message
    );
    handshake("1 minute").await;
    assert_eq!(engine.evaluate().await.unwrap(), (0, 1));
}

/// Tunnel history: hub status report samples device members (1/step, not every report),
/// never clients; samples read as device time series.
#[tokio::test]
async fn wg_status_reports_become_tunnel_history_of_device_members() {
    let admin = "admin-token";
    let (_c, store, _, device) = setup(Some(admin)).await;
    let ingest = dhonomos_core::MetricsIngest::new(store.clone(), 30, 2);
    ingest.maintain().await.unwrap();
    let app = router(
        store.clone(),
        ApiConfig {
            bearer_token: Some(admin.into()),
            tenant_id: DEFAULT_TENANT,
            metrics_ingest: Some(ingest),
            ..ApiConfig::default()
        },
    );
    let (hub, net) = wg_hub_and_network(&app, admin).await;
    let (s, m) = call(
        &app,
        "POST",
        &format!("/api/v1/wireguard/networks/{net}/members"),
        Some(json!({ "kind": "device", "device_id": device })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{m}");
    let member: Uuid = m["id"].as_str().unwrap().parse().unwrap();
    sqlx::query("UPDATE wg_members SET public_key = $2 WHERE id = $1")
        .bind(member)
        .bind(wg_key(1))
        .execute(store.pool())
        .await
        .unwrap();
    let (s, c) = call(
        &app,
        "POST",
        &format!("/api/v1/wireguard/networks/{net}/members"),
        Some(json!({ "kind": "client", "name": "pc", "user_id": null,
                     "public_key": wg_key(2) })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{c}");
    let token = wg_hub_token(&app, admin, &hub).await;

    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let report = |rx: u64, handshake: i64| {
        json!({ "peers": [
            { "network_id": net, "public_key": wg_key(1), "endpoint": null,
              "latest_handshake": handshake, "rx_bytes": rx, "tx_bytes": rx * 2 },
            { "network_id": net, "public_key": wg_key(2), "endpoint": null,
              "latest_handshake": handshake, "rx_bytes": rx, "tx_bytes": rx },
        ] })
    };
    let post = |body: Value| {
        let (app, token) = (app.clone(), token.clone());
        async move {
            let (s, _, v, _) = wg_hub_call(
                &app,
                "POST",
                "/api/v1/wg-hub/status",
                Some(body),
                Some(&token),
                &[],
            )
            .await;
            assert_eq!(s, StatusCode::OK, "{v}");
            assert_eq!(v, json!({ "accepted": 2, "ignored": 0 }));
        }
    };
    let nid = net.replace('-', "");
    let connected = format!("Dhonomos.WireGuard.{nid}.Connected");
    // Connected samples: (count, min, max) over the last day.
    let samples = || {
        let (app, uri) = (
            app.clone(),
            format!("/api/v1/devices/{device}/metrics/series?path={connected}&step=300"),
        );
        async move {
            let (s, v) = call(&app, "GET", &uri, None, Some(admin)).await;
            assert_eq!(s, StatusCode::OK, "{v}");
            let pts = v["points"].as_array().unwrap().clone();
            let count: i64 = pts.iter().map(|p| p["count"].as_i64().unwrap()).sum();
            let min = pts
                .iter()
                .map(|p| p["min"].as_f64().unwrap())
                .fold(f64::MAX, f64::min);
            let max = pts
                .iter()
                .map(|p| p["max"].as_f64().unwrap())
                .fold(f64::MIN, f64::max);
            (count, min, max)
        }
    };
    // Sampling runs after the answer -> wait for it. Resend `body`: report may have come
    // while an earlier sampling task was still running (not sampled).
    let until = |body: Value, count: i64| {
        let (post, samples) = (&post, &samples);
        async move {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            loop {
                post(body.clone()).await;
                let got = samples().await;
                if got.0 >= count {
                    return got;
                }
                assert!(std::time::Instant::now() < deadline, "no samples: {got:?}");
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }
    };

    // 1st report: 1 sample, connected.
    assert_eq!(until(report(1_000, now - 10), 1).await, (1, 1.0, 1.0));
    // Another right after: not due.
    post(report(5_000, now - 10)).await;
    // Rates need >= 1 s since last sample.
    tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;
    // Handshake ages out -> sampled at once, with rates.
    assert_eq!(until(report(6_000, now - 600), 2).await, (2, 0.0, 1.0));

    let (_, v) = call(
        &app,
        "GET",
        &format!("/api/v1/devices/{device}/metrics"),
        None,
        Some(admin),
    )
    .await;
    let mut paths: Vec<&str> = v["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["path"].as_str().unwrap())
        .collect();
    paths.sort_unstable();
    let rx = format!("Dhonomos.WireGuard.{nid}.RxRate");
    let tx = format!("Dhonomos.WireGuard.{nid}.TxRate");
    assert_eq!(paths, [connected.as_str(), rx.as_str(), tx.as_str()], "{v}");
    // Client has no record for samples: the device's 3 are all.
    let total: i64 = sqlx::query_scalar("SELECT count(*) FROM metric_samples")
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(total, 4);
}

/// Pre-shared keys (ADR-110): made + sealed here, shown once (also in client config).
/// Never in a member, a list, the re-fetched config or the audit log.
/// Given to the hub with the peer; replaced by a change or re-key.
/// Nothing works without the secrets key.
#[tokio::test]
async fn wireguard_preshared_keys_are_made_once_and_given_to_the_hub() {
    let admin = "admin-token";
    let (_c, store, plain, device) = setup(Some(admin)).await;
    let app = router(
        store.clone(),
        ApiConfig {
            bearer_token: Some(admin.into()),
            tenant_id: DEFAULT_TENANT,
            secrets: Some(secret_box()),
            ..ApiConfig::default()
        },
    );
    let (hub, net) = wg_hub_and_network(&app, admin).await;
    let hub_key = wg_hub_has_key(&store, &hub).await;
    let members_uri = format!("/api/v1/wireguard/networks/{net}/members");
    let is_key = |v: &Value| {
        v.as_str()
            .is_some_and(|k| k.len() == 44 && k.ends_with('='))
    };
    let mut shown: Vec<String> = Vec::new();

    // No secrets key -> 422 for every kind, nothing made.
    let refused = "a pre-shared key needs the server's secrets key (--secrets-key)";
    for body in [
        json!({ "kind": "device", "device_id": device, "preshared_key_enabled": true }),
        json!({ "kind": "client", "name": "c", "user_id": null, "preshared_key_enabled": true }),
    ] {
        let (s, v) = call(&plain, "POST", &members_uri, Some(body), Some(admin)).await;
        assert_eq!(
            (s, v["error"].as_str()),
            (StatusCode::UNPROCESSABLE_ENTITY, Some(refused))
        );
    }

    // Client with key pair made here: key in the answer + in its config.
    let (s, pc) = call(
        &app,
        "POST",
        &members_uri,
        Some(json!({ "kind": "client", "name": "laptop", "user_id": null,
                     "preshared_key_enabled": true })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{pc}");
    assert!(is_key(&pc["preshared_key"]), "{pc}");
    let psk1 = pc["preshared_key"].as_str().unwrap().to_owned();
    shown.push(psk1.clone());
    assert_eq!(pc["preshared_key_enabled"], true);
    let config = pc["config"].as_str().unwrap();
    assert!(
        config.contains(&format!(
            "[Peer]\nPublicKey = {hub_key}\nPresharedKey = {psk1}\n"
        )),
        "{config}"
    );
    let pc_id = pc["id"].as_str().unwrap().to_owned();
    let member_uri = format!("/api/v1/wireguard/members/{pc_id}");

    // Fetched again: a comment in its place; member never carries it.
    let (s, v) = call(
        &app,
        "GET",
        &format!("{member_uri}/config"),
        None,
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let config = v["config"].as_str().unwrap();
    assert!(
        config.contains(&format!(
            "PublicKey = {hub_key}\n# PresharedKey = (shown once when it was made)\n"
        )),
        "{config}"
    );
    assert!(!config.contains(&psk1));
    let (_, v) = call(&app, "GET", &member_uri, None, Some(admin)).await;
    assert_eq!(v["preshared_key_enabled"], true);
    assert!(v.get("preshared_key").is_none(), "{v}");

    // Client with own public key + device member: key once, no config.
    let (s, own) = call(
        &app,
        "POST",
        &members_uri,
        Some(json!({ "kind": "client", "name": "own", "user_id": null,
                     "public_key": wg_key(7), "preshared_key_enabled": true })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{own}");
    assert!(is_key(&own["preshared_key"]), "{own}");
    assert!(own["config"].is_null() && own["private_key"].is_null());
    shown.push(own["preshared_key"].as_str().unwrap().to_owned());
    let (s, dm) = call(
        &app,
        "POST",
        &members_uri,
        Some(json!({ "kind": "device", "device_id": device, "preshared_key_enabled": true })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{dm}");
    assert!(is_key(&dm["preshared_key"]), "{dm}");
    assert_eq!(dm["preshared_key_enabled"], true);
    shown.push(dm["preshared_key"].as_str().unwrap().to_owned());
    // Not asked -> none.
    let (s, none) = call(
        &app,
        "POST",
        &members_uri,
        Some(json!({ "kind": "client", "name": "none", "user_id": null,
                     "public_key": wg_key(8) })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{none}");
    assert!(none["preshared_key"].is_null());
    assert_eq!(none["preshared_key_enabled"], false);

    // Hub gets each peer's key; peer without one -> no such field.
    let token = wg_hub_token(&app, admin, &hub).await;
    let state_of = async |app: &Router| {
        let (s, h, v, _) =
            wg_hub_call(app, "GET", "/api/v1/wg-hub/state", None, Some(&token), &[]).await;
        (s, h.get("etag").map(|t| t.to_str().unwrap().to_owned()), v)
    };
    let peer_psk = |state: &Value, member: &str| {
        state["networks"][0]["peers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["member_id"] == member)
            .map(|p| p.get("preshared_key").cloned())
    };
    let (s, tag1, state) = state_of(&app).await;
    assert_eq!(s, StatusCode::OK, "{state}");
    assert_eq!(peer_psk(&state, &pc_id), Some(Some(json!(psk1))));
    assert_eq!(
        peer_psk(&state, own["id"].as_str().unwrap()),
        Some(Some(own["preshared_key"].clone()))
    );
    assert_eq!(peer_psk(&state, none["id"].as_str().unwrap()), Some(None));

    // Server without the key cannot open them -> 500, no state.
    let (s, tag, v) = state_of(&plain).await;
    assert_eq!(
        (s, v["error"].as_str(), tag),
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Some("a stored pre-shared key cannot be opened"),
            None
        )
    );
    // Same with another key.
    let other = router(
        store.clone(),
        ApiConfig {
            tenant_id: DEFAULT_TENANT,
            secrets: Some(std::sync::Arc::new(
                dhonomos_core::SecretBox::from_base64(&wg_key(42), "other").unwrap(),
            )),
            ..ApiConfig::default()
        },
    );
    let (s, _, v) = state_of(&other).await;
    assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR, "{v}");

    // On again: new key, shown once; hub state changes with it.
    let (s, v) = call(
        &app,
        "PATCH",
        &member_uri,
        Some(json!({ "preshared_key_enabled": true })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(is_key(&v["preshared_key"]), "{v}");
    let psk2 = v["preshared_key"].as_str().unwrap().to_owned();
    assert_ne!(psk2, psk1);
    shown.push(psk2.clone());
    let (_, tag2, state) = state_of(&app).await;
    assert_ne!(tag2, tag1);
    assert_eq!(peer_psk(&state, &pc_id), Some(Some(json!(psk2))));
    // Re-key -> another one, in answer + config.
    let (s, v) = call(
        &app,
        "POST",
        &format!("{member_uri}/rekey"),
        None,
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let psk3 = v["preshared_key"].as_str().unwrap().to_owned();
    assert!(![&psk1, &psk2].contains(&&psk3));
    assert!(
        v["config"]
            .as_str()
            .unwrap()
            .contains(&format!("PresharedKey = {psk3}\n"))
    );
    shown.push(psk3.clone());
    let (_, tag3, state) = state_of(&app).await;
    assert_ne!(tag3, tag2);
    assert_eq!(peer_psk(&state, &pc_id), Some(Some(json!(psk3))));
    // Re-key of a client without one -> none made.
    let (s, v) = call(
        &app,
        "POST",
        &format!(
            "/api/v1/wireguard/members/{}/rekey",
            none["id"].as_str().unwrap()
        ),
        Some(json!({ "public_key": wg_key(9) })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(v["preshared_key"].is_null());
    // Off -> gone from member + hub.
    let (s, v) = call(
        &app,
        "PATCH",
        &member_uri,
        Some(json!({ "preshared_key_enabled": false })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert!(v["preshared_key"].is_null());
    assert_eq!(v["preshared_key_enabled"], false);
    let (_, tag4, state) = state_of(&app).await;
    assert_ne!(tag4, tag3);
    assert_eq!(peer_psk(&state, &pc_id), Some(None));
    // No secrets key -> cannot turn on; off works.
    let (s, v) = call(
        &plain,
        "PATCH",
        &member_uri,
        Some(json!({ "preshared_key_enabled": true })),
        Some(admin),
    )
    .await;
    assert_eq!(
        (s, v["error"].as_str()),
        (StatusCode::UNPROCESSABLE_ENTITY, Some(refused))
    );
    // Revoked member cannot be changed.
    let (s, _) = call(
        &app,
        "POST",
        &format!("{member_uri}/revoke"),
        None,
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _) = call(
        &app,
        "PATCH",
        &member_uri,
        Some(json!({ "preshared_key_enabled": true })),
        Some(admin),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT);

    // Audited without keys; members + lists never carry them.
    let (_, audit) = call(&app, "GET", "/api/v1/audit?limit=500", None, Some(admin)).await;
    let (_, list) = call(&app, "GET", &members_uri, None, Some(admin)).await;
    for k in &shown {
        assert!(
            !audit.to_string().contains(k.as_str()),
            "the audit log has a key"
        );
        assert!(!list.to_string().contains(k.as_str()), "the list has a key");
    }
    let detail = |action: &str| -> Vec<Value> {
        audit["items"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|a| a["action"] == action && a["target_id"] == pc_id.as_str())
            .map(|a| a["detail"]["preshared_key"].clone())
            .collect()
    };
    assert_eq!(detail("wireguard.member.create"), [json!("made")]);
    let mut updates = detail("wireguard.member.update");
    updates.sort_by_key(ToString::to_string);
    assert_eq!(updates, [json!("cleared"), json!("replaced")]);
    assert_eq!(detail("wireguard.member.rekey"), [json!("replaced")]);
}

/// `GET /settings/server`: the list the server hands over; admins only.
#[tokio::test]
async fn server_settings_are_for_admins() {
    let (_c, store, _, _) = setup(None).await;
    let admin = "admin-token-0123456789";
    let app = router(
        store.clone(),
        ApiConfig {
            bearer_token: Some(admin.into()),
            tenant_id: DEFAULT_TENANT,
            server_settings: std::sync::Arc::new(vec![dhonomos_api::ServerSetting {
                key: "acs_listen".into(),
                flag: "--acs-listen".into(),
                env: "DHONOMOS_ACS_LISTEN".into(),
                group: "listeners_tls".into(),
                category: dhonomos_api::SettingCategory::Bootstrap,
                help: "ACS listen address".into(),
                source: dhonomos_api::SettingSource::Default,
                is_set: true,
                value: Some("[::]:7547".into()),
                kind: dhonomos_api::SettingKind::Text,
                editable: false,
                locked_reason: None,
                web_value: None,
            }]),
            ..ApiConfig::default()
        },
    );
    let (s, v) = call(&app, "GET", "/api/v1/settings/server", None, Some(admin)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        v,
        json!({ "items": [{
            "key": "acs_listen",
            "flag": "--acs-listen",
            "env": "DHONOMOS_ACS_LISTEN",
            "group": "listeners_tls",
            "category": "bootstrap",
            "help": "ACS listen address",
            "source": "default",
            "is_set": true,
            "value": "[::]:7547",
            "kind": "text",
            "editable": false,
            "locked_reason": null,
            "web_value": null,
        }]})
    );
    for role in ["operator", "viewer"] {
        let key = api_key(&app, admin, role, None).await;
        let (s, v) = call(&app, "GET", "/api/v1/settings/server", None, Some(&key)).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{role}: {v}");
    }
}

/// Registry item as the server binary hands it over.
fn setting(
    key: &str,
    category: dhonomos_api::SettingCategory,
    kind: dhonomos_api::SettingKind,
    locked_reason: Option<&str>,
    value: &str,
) -> dhonomos_api::ServerSetting {
    dhonomos_api::ServerSetting {
        key: key.into(),
        flag: format!("--{}", key.replace('_', "-")),
        env: format!("DHONOMOS_{}", key.to_ascii_uppercase()),
        group: "g".into(),
        category,
        help: String::new(),
        source: if locked_reason.is_some() {
            dhonomos_api::SettingSource::Env
        } else {
            dhonomos_api::SettingSource::Default
        },
        is_set: true,
        value: Some(value.into()),
        kind,
        editable: category == dhonomos_api::SettingCategory::Runtime && locked_reason.is_none(),
        locked_reason: locked_reason.map(str::to_owned),
        web_value: None,
    }
}

/// Runtime settings from the web (stages 2-3): stored, checked by server binary hook,
/// applied, audited, with history; errors for options that cannot change.
#[tokio::test]
async fn runtime_settings_are_changed_from_the_web() {
    use dhonomos_api::{SettingCategory as C, SettingKind as K};
    let (_c, store, _, _) = setup(None).await;
    let admin = "admin-token-0123456789";
    let applied = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let hooks = dhonomos_api::SettingsHooks {
        // Server binary parsers, as far as this test needs.
        validate: std::sync::Arc::new(|values| match values.get("session_hours") {
            Some(v) if v.as_str().is_some_and(|h| h.parse::<i64>().is_err()) => Err(format!(
                "error: invalid value '{}' for '--session-hours <SESSION_HOURS>'",
                v.as_str().unwrap_or_default()
            )),
            _ => Ok(()),
        }),
        apply_now: {
            let applied = applied.clone();
            std::sync::Arc::new(move || {
                applied.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            })
        },
        ..Default::default()
    };
    let app = router(
        store.clone(),
        ApiConfig {
            bearer_token: Some(admin.into()),
            tenant_id: DEFAULT_TENANT,
            server_settings: std::sync::Arc::new(vec![
                setting("session_hours", C::Runtime, K::Text, None, "12"),
                setting("webhook_url", C::Runtime, K::List, None, ""),
                setting(
                    "smtp_host",
                    C::Runtime,
                    K::Text,
                    Some("paired with the SMTP password in the server's configuration"),
                    "mail.example",
                ),
                setting("acs_listen", C::Bootstrap, K::Text, None, "[::]:7547"),
            ]),
            settings_hooks: hooks,
            ..ApiConfig::default()
        },
    );
    let a = Some(admin);
    let get = |key: &'static str| {
        let app = app.clone();
        async move {
            let (s, v) = call(&app, "GET", "/api/v1/settings/server", None, a).await;
            assert_eq!(s, StatusCode::OK, "{v}");
            v["items"]
                .as_array()
                .unwrap()
                .iter()
                .find(|i| i["key"] == key)
                .unwrap()
                .clone()
        }
    };
    let i = get("session_hours").await;
    assert_eq!(
        (
            &i["editable"],
            &i["locked_reason"],
            &i["kind"],
            &i["source"],
            &i["web_value"]
        ),
        (
            &json!(true),
            &Value::Null,
            &json!("text"),
            &json!("default"),
            &Value::Null
        )
    );
    let i = get("smtp_host").await;
    assert_eq!(i["editable"], false);
    assert_eq!(
        i["locked_reason"],
        "paired with the SMTP password in the server's configuration"
    );

    // Change: stored, applied, shown as from the web.
    let uri = "/api/v1/settings/server/session_hours";
    let (s, v) = call(&app, "PUT", uri, Some(json!({ "value": "8" })), a).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        (&v["key"], &v["value"], &v["source"], &v["web_value"]),
        (
            &json!("session_hours"),
            &json!("8"),
            &json!("web"),
            &json!("8")
        )
    );
    assert_eq!(applied.load(std::sync::atomic::Ordering::SeqCst), 1);
    let i = get("session_hours").await;
    assert_eq!((&i["value"], &i["source"]), (&json!("8"), &json!("web")));
    let (s, _) = call(&app, "PUT", uri, Some(json!({ "value": "4" })), a).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        store.runtime_settings(DEFAULT_TENANT).await.unwrap()["session_hours"],
        json!("4")
    );

    // Lists = arrays of strings.
    let (s, v) = call(
        &app,
        "PUT",
        "/api/v1/settings/server/webhook_url",
        Some(json!({ "value": ["https://a.example/x", "https://b.example/y"] })),
        a,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["value"], "https://a.example/x,https://b.example/y");

    // Refused change -> nothing stored.
    let refused = [
        (
            "/api/v1/settings/server/nope",
            json!("1"),
            StatusCode::NOT_FOUND,
            "setting not found",
        ),
        (
            "/api/v1/settings/server/acs_listen",
            json!("[::]:1"),
            StatusCode::UNPROCESSABLE_ENTITY,
            "acs_listen cannot be changed from the web",
        ),
        (
            "/api/v1/settings/server/smtp_host",
            json!("other.example"),
            StatusCode::CONFLICT,
            "paired with the SMTP password in the server's configuration",
        ),
        (
            uri,
            json!("soon"),
            StatusCode::UNPROCESSABLE_ENTITY,
            "error: invalid value 'soon' for '--session-hours <SESSION_HOURS>'",
        ),
        (
            uri,
            json!(["8"]),
            StatusCode::UNPROCESSABLE_ENTITY,
            "value must be a string",
        ),
        (
            "/api/v1/settings/server/webhook_url",
            json!("https://a.example"),
            StatusCode::UNPROCESSABLE_ENTITY,
            "value must be an array of strings",
        ),
    ];
    for (uri, value, status, error) in refused {
        let (s, v) = call(&app, "PUT", uri, Some(json!({ "value": value })), a).await;
        assert_eq!((s, v["error"].as_str().unwrap()), (status, error), "{uri}");
    }
    let (s, v) = call(&app, "DELETE", "/api/v1/settings/server/smtp_host", None, a).await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    let (s, _) = call(
        &app,
        "DELETE",
        "/api/v1/settings/server/acs_listen",
        None,
        a,
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(applied.load(std::sync::atomic::Ordering::SeqCst), 3);

    // Audited with old + new values.
    let (_, v) = call(&app, "GET", "/api/v1/audit?action=settings.", None, a).await;
    let entries: Vec<_> = v["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            (
                e["action"].clone(),
                e["target_id"].clone(),
                e["detail"].clone(),
            )
        })
        .collect();
    assert_eq!(
        entries[1],
        (
            json!("settings.update"),
            json!("session_hours"),
            json!({ "key": "session_hours", "old": "8", "new": "4" })
        )
    );
    assert_eq!(
        entries[2].2,
        json!({ "key": "session_hours", "old": null, "new": "8" })
    );

    // Back to default.
    let (s, _) = call(&app, "DELETE", uri, None, a).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let i = get("session_hours").await;
    assert_eq!(
        (&i["value"], &i["source"], &i["web_value"]),
        (&json!("12"), &json!("default"), &Value::Null)
    );
    // Nothing to reset -> no change, no record.
    let (s, _) = call(&app, "DELETE", uri, None, a).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    assert_eq!(applied.load(std::sync::atomic::Ordering::SeqCst), 4);
    let (_, v) = call(&app, "GET", "/api/v1/audit?action=settings.reset", None, a).await;
    assert_eq!(v["items"].as_array().unwrap().len(), 1);
    assert_eq!(
        v["items"][0]["detail"],
        json!({ "key": "session_hours", "old": "4", "new": null })
    );

    // History, newest first.
    let (s, v) = call(&app, "GET", &format!("{uri}/history"), None, a).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let h: Vec<_> = v["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| (c["old"].clone(), c["new"].clone(), c["actor"].clone()))
        .collect();
    assert_eq!(
        h,
        [
            (json!("4"), Value::Null, json!("api-token")),
            (json!("8"), json!("4"), json!("api-token")),
            (Value::Null, json!("8"), json!("api-token")),
        ]
    );
    assert!(v["items"][0]["at"].is_string());
    let (s, _) = call(&app, "GET", "/api/v1/settings/server/nope/history", None, a).await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    // Admins only.
    for role in ["operator", "viewer"] {
        let key = api_key(&app, admin, role, None).await;
        let k = Some(key.as_str());
        let (s, _) = call(&app, "PUT", uri, Some(json!({ "value": "2" })), k).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{role}");
        let (s, _) = call(&app, "DELETE", uri, None, k).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{role}");
        let (s, _) = call(&app, "GET", &format!("{uri}/history"), None, k).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{role}");
    }
}

/// Web value with a token -> never leaves the API unmasked; masked text sent back -> refused.
#[tokio::test]
async fn web_values_are_masked_and_the_mask_is_refused() {
    use dhonomos_api::{SettingCategory as C, SettingKind as K};
    let (_c, store, _, _) = setup(None).await;
    let admin = "admin-token-0123456789";
    let app = router(
        store.clone(),
        ApiConfig {
            bearer_token: Some(admin.into()),
            tenant_id: DEFAULT_TENANT,
            server_settings: std::sync::Arc::new(vec![
                setting("webhook_url", C::Runtime, K::List, None, ""),
                // Locked: stored value still shown, masked.
                setting(
                    "smtp_host",
                    C::Runtime,
                    K::Text,
                    Some("set in the server's configuration (environment or command line)"),
                    "mail.example",
                ),
            ]),
            ..ApiConfig::default()
        },
    );
    let a = Some(admin);
    let token = "tok-secret-4711";
    let uri = "/api/v1/settings/server/webhook_url";
    let (s, v) = call(
        &app,
        "PUT",
        uri,
        Some(json!({ "value": [format!("https://hooks.example/x?token={token}"), "https://u:pw-secret@b.example/"] })),
        a,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    store
        .set_runtime_setting(
            DEFAULT_TENANT,
            "smtp_host",
            &json!(format!("smtp://u:{token}@mail.example")),
            None,
        )
        .await
        .unwrap();
    let mut seen = v.to_string();
    for path in [
        "/api/v1/settings/server".to_owned(),
        format!("{uri}/history"),
        "/api/v1/settings/server/smtp_host/history".to_owned(),
        "/api/v1/audit".to_owned(),
    ] {
        let (s, v) = call(&app, "GET", &path, None, a).await;
        assert_eq!(s, StatusCode::OK, "{path}: {v}");
        seen.push_str(&v.to_string());
    }
    for secret in [token, "pw-secret"] {
        assert!(!seen.contains(secret), "{secret} in {seen}");
    }
    let (_, v) = call(&app, "GET", "/api/v1/settings/server", None, a).await;
    assert_eq!(
        v["items"][0]["web_value"],
        json!([
            "https://hooks.example/x?token=****",
            "https://u:****@b.example/"
        ])
    );
    assert_eq!(
        v["items"][0]["value"],
        "https://hooks.example/x?token=****,https://u:****@b.example/"
    );
    assert_eq!(v["items"][1]["web_value"], "smtp://u:****@mail.example");
    assert_eq!(
        v["items"][1]["source"], "env",
        "a locked value keeps its source"
    );

    // Masked text as the editor shows it, sent back unchanged.
    let (s, v) = call(
        &app,
        "PUT",
        uri,
        Some(json!({ "value": ["https://hooks.example/x?token=****"] })),
        a,
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        v["error"],
        "re-enter the full value; the shown value is masked"
    );
    assert_eq!(
        store.runtime_settings(DEFAULT_TENANT).await.unwrap()["webhook_url"][0],
        json!(format!("https://hooks.example/x?token={token}")),
        "unchanged"
    );
}

/// Alarm rules from the web (stage 4): validated like the file, stored with history,
/// audited, applied via the watcher the API wakes, evaluated without restart; admins only.
#[tokio::test]
async fn alarm_rules_are_edited_from_the_web() {
    use dhonomos_core::alarms::{AlarmEngine, AlarmRules, Webhooks};

    let admin = "admin-token-0123456789";
    let (_c, store, _, device) = setup(None).await;
    let rules = dhonomos_core::Shared::new(AlarmRules::default());
    let wake = std::sync::Arc::new(tokio::sync::Notify::new());
    tokio::spawn(dhonomos_core::alarms::watch_stored(
        store.clone(),
        DEFAULT_TENANT,
        rules.clone(),
        std::time::Duration::from_secs(3600),
        wake.clone(),
        Some(0),
    ));
    let app = router(
        store.clone(),
        ApiConfig {
            bearer_token: Some(admin.into()),
            tenant_id: DEFAULT_TENANT,
            alarm_rules: rules.clone(),
            settings_hooks: dhonomos_api::SettingsHooks {
                apply_alarm_rules: {
                    let wake = wake.clone();
                    std::sync::Arc::new(move || wake.notify_one())
                },
                ..Default::default()
            },
            ..ApiConfig::default()
        },
    );
    let a = Some(admin);
    let uri = "/api/v1/settings/alarm-rules";
    let applied = |name: &'static str, present: bool| {
        let rules = rules.clone();
        async move {
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
            while rules.get().contains(name) != present {
                assert!(tokio::time::Instant::now() < deadline, "{name} not applied");
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        }
    };

    // Nothing stored -> no rules.
    let (s, v) = call(&app, "GET", uri, None, a).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        v,
        json!({
            "source": "none", "path": null, "yaml": null, "editable": true,
            "rules": { "alarms": [], "storm_threshold": 50 },
            "updated_by": null, "updated_at": null,
        })
    );

    // Refused: invalid rules (reason from the file check), too large, no YAML.
    let invalid = "alarms: [{ name: x, severity: fatal, when: { offline_minutes: 5 } }]";
    let (s, v) = call(&app, "PUT", uri, Some(json!({ "yaml": invalid })), a).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        v["error"].as_str(),
        Some(AlarmRules::from_yaml(invalid).unwrap_err().as_str())
    );
    let big = format!("alarms: []\n{}", "#".repeat(256 * 1024));
    let (s, v) = call(&app, "PUT", uri, Some(json!({ "yaml": big })), a).await;
    assert_eq!(
        (s, v["error"].as_str()),
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            Some("the alarm rules must be at most 256 KiB")
        )
    );
    let (s, _) = call(&app, "PUT", uri, Some(json!({ "rules": [] })), a).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        store
            .alarm_rule_set(DEFAULT_TENANT)
            .await
            .unwrap()
            .is_none()
    );

    // Offline rule: stored, applied without restart, raises an alarm.
    sqlx::query("UPDATE devices SET last_contact_at = now() - interval '1 hour' WHERE id = $1")
        .bind(device)
        .execute(store.pool())
        .await
        .unwrap();
    let engine = AlarmEngine::new(
        store.clone(),
        DEFAULT_TENANT,
        rules.clone(),
        Webhooks::default(),
    );
    assert_eq!(engine.evaluate().await.unwrap(), (0, 0));
    let first = "alarms:\n  - name: offline\n    severity: major\n    when: { offline_minutes: 30 }\n  - name: noise\n    severity: minor\n    when: { metric: Device.X.Noise, above: -70 }\n";
    let (s, v) = call(&app, "PUT", uri, Some(json!({ "yaml": first })), a).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        (&v["source"], &v["yaml"], &v["editable"], &v["path"]),
        (&json!("web"), &json!(first), &json!(true), &Value::Null)
    );
    assert_eq!(v["rules"]["alarms"][0]["name"], "offline");
    assert_eq!(
        v["rules"]["alarms"][0]["when"],
        json!({ "offline_minutes": 30 })
    );
    let actor = v["updated_by"].as_str().unwrap().to_owned();
    assert!(v["updated_at"].is_string());
    applied("offline", true).await;
    assert_eq!(engine.evaluate().await.unwrap(), (1, 0));
    let (s, v) = call(&app, "GET", uri, None, a).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!((&v["source"], &v["yaml"]), (&json!("web"), &json!(first)));
    let (_, v) = call(&app, "GET", "/api/v1/alarm-rules", None, a).await;
    assert_eq!(v["items"].as_array().unwrap().len(), 2);

    // Removed -> next evaluation clears its alarm.
    let second = "alarms:\n  - name: noise\n    severity: minor\n    when: { metric: Device.X.Noise, above: -70 }\n  - name: boots\n    severity: warning\n    when: { event: inform, count: 5, within_minutes: 60 }\n";
    let (s, v) = call(&app, "PUT", uri, Some(json!({ "yaml": second })), a).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    applied("offline", false).await;
    assert_eq!(engine.evaluate().await.unwrap(), (0, 1));
    assert!(
        store
            .active_alarm_rules(DEFAULT_TENANT)
            .await
            .unwrap()
            .is_empty()
    );

    // Audited: rule count + names added and removed.
    let (_, v) = call(
        &app,
        "GET",
        "/api/v1/audit?action=settings.alarm_rules",
        None,
        a,
    )
    .await;
    let details: Vec<_> = v["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| (e["target_id"].clone(), e["detail"].clone()))
        .collect();
    assert_eq!(
        details,
        [
            (
                json!("alarm_rules"),
                json!({ "rules_before": 2, "rules_after": 2,
                        "names_added": ["boots"], "names_removed": ["offline"] })
            ),
            (
                json!("alarm_rules"),
                json!({ "rules_before": 0, "rules_after": 2,
                        "names_added": ["offline", "noise"], "names_removed": [] })
            ),
        ]
    );

    // Versions, newest first.
    let (s, v) = call(&app, "GET", "/api/v1/settings/alarm-rules/history", None, a).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let items = v["items"].as_array().unwrap();
    assert_eq!(items.len(), 2);
    assert_eq!(
        (&items[0]["yaml"], &items[0]["actor"]),
        (&json!(second), &json!(actor))
    );
    assert_eq!(items[1]["yaml"], first);
    assert!(items[0]["at"].is_string());

    // Admins only.
    for role in ["operator", "viewer"] {
        let key = api_key(&app, admin, role, None).await;
        for (method, path, body) in [
            ("GET", uri, None),
            ("PUT", uri, Some(json!({ "yaml": "alarms: []" }))),
            ("GET", "/api/v1/settings/alarm-rules/history", None),
        ] {
            let (s, v) = call(&app, method, path, body, Some(&key)).await;
            assert_eq!(s, StatusCode::FORBIDDEN, "{role} {method} {path}: {v}");
        }
        // Rules stay readable.
        let (s, _) = call(&app, "GET", "/api/v1/alarm-rules", None, Some(&key)).await;
        assert_eq!(s, StatusCode::OK);
    }
}

/// `--alarms` file set -> rules shown as in the file, cannot change.
#[tokio::test]
async fn alarm_rules_from_the_file_are_read_only() {
    use dhonomos_core::alarms::AlarmRules;

    let admin = "admin-token-0123456789";
    let (_c, store, _, _) = setup(None).await;
    // Stored rules (from before the file was given) -> not used.
    store
        .set_alarm_rule_set(DEFAULT_TENANT, "alarms: []", Some("alice"))
        .await
        .unwrap();
    let text = "alarms: [{ name: from-file, severity: minor, when: { offline_minutes: 9 } }]\n";
    let app = router(
        store.clone(),
        ApiConfig {
            bearer_token: Some(admin.into()),
            tenant_id: DEFAULT_TENANT,
            alarm_rules: AlarmRules::from_yaml(text).unwrap().into(),
            alarm_rules_file: Some(dhonomos_api::AlarmRulesFile {
                path: "/etc/dhonomos/alarms.yaml".into(),
                yaml: dhonomos_core::Shared::new(text.to_owned()),
            }),
            ..ApiConfig::default()
        },
    );
    let uri = "/api/v1/settings/alarm-rules";
    let (s, v) = call(&app, "GET", uri, None, Some(admin)).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(
        v,
        json!({
            "source": "file", "path": "/etc/dhonomos/alarms.yaml", "yaml": text,
            "editable": false,
            "rules": { "alarms": [{ "name": "from-file", "severity": "minor",
                                    "devices": v["rules"]["alarms"][0]["devices"],
                                    "when": { "offline_minutes": 9 } }],
                       "storm_threshold": 50 },
            "updated_by": null, "updated_at": null,
        })
    );
    let (s, v) = call(
        &app,
        "PUT",
        uri,
        Some(json!({ "yaml": "alarms: []" })),
        Some(admin),
    )
    .await;
    assert_eq!(
        (s, v["error"].as_str()),
        (
            StatusCode::CONFLICT,
            Some("the alarm rules are set by the server's --alarms file")
        )
    );
    assert_eq!(
        store
            .alarm_rule_set_history(DEFAULT_TENANT, 20)
            .await
            .unwrap()
            .len(),
        1
    );
}
