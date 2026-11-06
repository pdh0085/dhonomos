//! Session state machine behaviour (docs/design/03-cwmp-session-fsm.md).
#![allow(clippy::unwrap_used)]

use dhonomos_cwmp_codec::{
    Body, CwmpNamespace, Envelope, Fault, GetParameterValues, GetParameterValuesResponse,
    GetRPCMethods, Header, Inform, Reboot, RebootResponse, Rpc, TransferComplete,
};
use dhonomos_cwmp_session::{
    Outcome, Reply, Session, SessionError, State, Step, negotiate_version,
};

fn env(ns: CwmpNamespace, id: &str, rpc: impl Into<Rpc>) -> Envelope {
    Envelope::rpc(ns, id, rpc)
}

fn inform() -> Envelope {
    env(CwmpNamespace::V1_0, "c1", Inform::default())
}

fn reply_env(r: Reply) -> Envelope {
    match r {
        Reply::Envelope(e) => e,
        Reply::Empty => panic!("expected an envelope"),
    }
}

/// Inform answered -> CPE turn.
fn started() -> Session {
    let mut s = Session::new("s");
    s.receive(Some(inform())).unwrap();
    s.answer(Ok(())).unwrap();
    s
}

#[test]
fn happy_path() {
    let mut s = Session::new("s");
    let Step::CpeRequest(Rpc::Inform(_)) = s.receive(Some(inform())).unwrap() else {
        panic!("expected Inform")
    };
    assert_eq!(s.state(), State::InformPending);
    let resp = reply_env(s.answer(Ok(())).unwrap());
    assert_eq!(resp.header.id.as_deref(), Some("c1"));
    assert!(matches!(resp.body, Body::Rpc(Rpc::InformResponse(ref r)) if r.max_envelopes == 1));
    assert_eq!(resp.header.use_cwmp_version, None);

    assert_eq!(s.receive(None).unwrap(), Step::AcsTurn { completed: None });
    let req = reply_env(
        s.send(Some(
            GetParameterValues {
                parameter_names: vec!["Device.DeviceInfo.".into()],
            }
            .into(),
        ))
        .unwrap(),
    );
    assert_eq!(req.header.id.as_deref(), Some("s-1"));
    assert_eq!(s.state(), State::AwaitResponse);

    let Step::AcsTurn { completed: Some(c) } = s
        .receive(Some(env(
            CwmpNamespace::V1_0,
            "s-1",
            GetParameterValuesResponse::default(),
        )))
        .unwrap()
    else {
        panic!("expected completion")
    };
    assert_eq!(
        (c.request_id.as_str(), c.method.as_str()),
        ("s-1", "GetParameterValues")
    );
    assert!(matches!(
        c.outcome,
        Outcome::Response(Rpc::GetParameterValuesResponse(_))
    ));
    assert!(c.id_matched);

    let req = reply_env(s.send(Some(Reboot::default().into())).unwrap());
    assert_eq!(req.header.id.as_deref(), Some("s-2"));
    s.receive(Some(env(CwmpNamespace::V1_0, "s-2", RebootResponse {})))
        .unwrap();
    assert_eq!(s.send(None).unwrap(), Reply::Empty);
    assert!(s.is_ended());
    assert_eq!(s.receive(None), Err(SessionError::Ended));
}

#[test]
fn inform_fault_ends_session() {
    let mut s = Session::new("s");
    s.receive(Some(inform())).unwrap();
    let r = reply_env(s.answer(Err(Fault::new(8005, "Retry request"))).unwrap());
    assert!(matches!(r.body, Body::Fault(ref f) if f.code == 8005));
    assert!(s.is_ended());
}

#[test]
fn first_message_must_be_inform() {
    let mut s = Session::new("s");
    assert_eq!(
        s.receive(None),
        Err(SessionError::ExpectedInform {
            got: "empty".into()
        })
    );
    assert_eq!(
        s.receive(Some(env(CwmpNamespace::V1_0, "x", GetRPCMethods {}))),
        Err(SessionError::ExpectedInform {
            got: "GetRPCMethods".into()
        })
    );
}

#[test]
fn cpe_requests_in_cpe_turn() {
    let mut s = started();
    let Step::CpeRequest(Rpc::TransferComplete(_)) = s
        .receive(Some(env(
            CwmpNamespace::V1_0,
            "t1",
            TransferComplete::default(),
        )))
        .unwrap()
    else {
        panic!()
    };
    let r = reply_env(s.answer(Ok(())).unwrap());
    assert_eq!(r.header.id.as_deref(), Some("t1"));
    assert!(matches!(
        r.body,
        Body::Rpc(Rpc::TransferCompleteResponse(_))
    ));

    // Retry later (8005) -> session stays in CPE turn.
    s.receive(Some(env(
        CwmpNamespace::V1_0,
        "t2",
        TransferComplete::default(),
    )))
    .unwrap();
    let r = reply_env(s.answer(Err(Fault::new(8005, "Retry request"))).unwrap());
    assert!(matches!(r.body, Body::Fault(ref f) if f.code == 8005));
    assert_eq!(s.state(), State::CpeTurn);

    // GetRPCMethods -> ACS method list.
    s.receive(Some(env(CwmpNamespace::V1_0, "g", GetRPCMethods {})))
        .unwrap();
    let Body::Rpc(Rpc::GetRPCMethodsResponse(m)) = reply_env(s.answer(Ok(())).unwrap()).body else {
        panic!()
    };
    assert!(m.method_list.iter().any(|x| x == "TransferComplete"));
}

#[test]
fn unknown_cpe_method_gets_fault_8000() {
    let mut s = started();
    let Step::Reply(r) = s
        .receive(Some(env(CwmpNamespace::V1_0, "u", Reboot::default())))
        .unwrap()
    else {
        panic!("expected automatic reply")
    };
    assert!(matches!(reply_env(r).body, Body::Fault(ref f) if f.code == 8000));
    assert_eq!(s.state(), State::CpeTurn);
}

#[test]
fn awaiting_response_variants() {
    let mut s = started();
    s.receive(None).unwrap();
    s.send(Some(Reboot::default().into())).unwrap();
    // Fault + mismatched ID -> tolerated + reported.
    let fault = Envelope {
        namespace: CwmpNamespace::V1_0,
        header: Header {
            id: Some("other".into()),
            ..Header::default()
        },
        body: Body::Fault(Fault::new(9001, "Request denied")),
    };
    let Step::AcsTurn { completed: Some(c) } = s.receive(Some(fault)).unwrap() else {
        panic!()
    };
    assert!(matches!(c.outcome, Outcome::Fault(ref f) if f.code == 9001));
    assert!(!c.id_matched);

    s.send(Some(Reboot::default().into())).unwrap();
    let Step::AcsTurn { completed: Some(c) } = s
        .receive(Some(env(
            CwmpNamespace::V1_0,
            "s-2",
            GetParameterValuesResponse::default(),
        )))
        .unwrap()
    else {
        panic!()
    };
    assert!(matches!(c.outcome, Outcome::Mismatch(_)));

    s.send(Some(Reboot::default().into())).unwrap();
    let Step::AcsTurn { completed: Some(c) } = s.receive(None).unwrap() else {
        panic!()
    };
    assert_eq!(c.outcome, Outcome::NoResponse);

    s.send(Some(Reboot::default().into())).unwrap();
    assert_eq!(
        s.receive(Some(env(
            CwmpNamespace::V1_0,
            "x",
            TransferComplete::default()
        ))),
        Err(SessionError::UnexpectedRequest {
            method: "TransferComplete".into()
        })
    );
}

#[test]
fn protocol_errors_in_cpe_turn() {
    let mut s = started();
    assert_eq!(
        s.receive(Some(inform())),
        Err(SessionError::UnexpectedInform)
    );
    assert!(matches!(
        s.receive(Some(env(CwmpNamespace::V1_0, "r", RebootResponse {}))),
        Err(SessionError::UnexpectedResponse { .. })
    ));
}

#[test]
fn api_misuse_is_reported() {
    let mut s = Session::new("s");
    assert!(matches!(s.send(None), Err(SessionError::Misuse { .. })));
    assert!(matches!(s.answer(Ok(())), Err(SessionError::Misuse { .. })));
    s.receive(Some(inform())).unwrap();
    assert!(matches!(s.receive(None), Err(SessionError::Misuse { .. })));
    s.answer(Ok(())).unwrap();
    s.receive(None).unwrap();
    // Response RPC as ACS request -> misuse.
    assert!(matches!(
        s.send(Some(RebootResponse {}.into())),
        Err(SessionError::Misuse { .. })
    ));
}

#[test]
fn namespace_and_version_negotiation() {
    let mut s = Session::new("s");
    let mut e = env(CwmpNamespace::V1_2, "c", Inform::default());
    e.header.supported_cwmp_versions = Some("1.0,1.1,1.2,1.3,1.4,1.5".into());
    s.receive(Some(e)).unwrap();
    let r = reply_env(s.answer(Ok(())).unwrap());
    assert_eq!(r.namespace, CwmpNamespace::V1_2);
    assert_eq!(r.header.use_cwmp_version.as_deref(), Some("1.4"));
    assert_eq!(s.cwmp_version(), Some("1.4"));

    assert_eq!(negotiate_version("1.0, 1.2").as_deref(), Some("1.2"));
    assert_eq!(negotiate_version("2.0,x").as_deref(), None);
}

#[test]
fn replies_round_trip_through_codec() {
    let mut s = started();
    s.receive(None).unwrap();
    let body = s
        .send(Some(Reboot::default().into()))
        .unwrap()
        .to_body()
        .unwrap();
    let decoded = Envelope::decode(body.as_bytes()).unwrap().unwrap();
    assert!(matches!(decoded.body, Body::Rpc(Rpc::Reboot(_))));
    assert_eq!(
        s.send(None).map(|r| r.to_body()),
        Err(SessionError::Misuse {
            state: State::AwaitResponse,
            call: "send"
        })
    );
}
