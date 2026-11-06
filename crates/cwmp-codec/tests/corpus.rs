//! Decode every captured message in `tests/corpus/` + check re-encoding is lossless.
#![allow(clippy::unwrap_used)]

use std::path::Path;

use dhonomos_cwmp_codec::{Body, CwmpNamespace, Envelope, EventCode, Rpc};

fn corpus(dir: &str) -> Vec<(String, Vec<u8>)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/corpus")
        .join(dir);
    let mut files: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "xml"))
        .collect();
    files.sort();
    files
        .into_iter()
        .map(|p| {
            let name = p.file_stem().unwrap().to_string_lossy().into_owned();
            (name, std::fs::read(p).unwrap())
        })
        .collect()
}

fn decode(bytes: &[u8]) -> Envelope {
    Envelope::decode(bytes).unwrap().unwrap()
}

#[test]
fn every_message_decodes_and_round_trips() {
    let files = corpus("genieacs-sim");
    assert_eq!(files.len(), 25);
    for (name, bytes) in files {
        let env = decode(&bytes);
        // File name = "<seq>-<label>"; label = method (ACS-<Method>, Fault-<Method>).
        let label = name.split_once('-').unwrap().1;
        match &env.body {
            Body::Rpc(rpc) => {
                let expected = label.strip_prefix("ACS-").unwrap_or(label);
                let expected = expected.strip_suffix("Fault").unwrap_or(expected);
                assert_eq!(rpc.name(), expected, "{name}");
            }
            Body::Fault(f) => {
                assert!(label.starts_with("Fault-"), "{name}");
                assert_eq!(f.code, 9000, "{name}");
            }
        }
        assert_eq!(env.namespace, CwmpNamespace::V1_0, "{name}");
        let again = decode(env.encode().as_bytes());
        assert_eq!(again, env, "{name}: re-encoding changed the message");
    }
}

#[test]
fn inform_contents() {
    let (_, bytes) = &corpus("genieacs-sim")[0];
    let env = decode(bytes);
    assert_eq!(env.header.id.as_deref(), Some("ug7em4nb"));
    let Body::Rpc(Rpc::Inform(inform)) = env.body else {
        panic!("expected Inform")
    };
    assert_eq!(inform.device_id.oui, "202BC1");
    assert_eq!(inform.device_id.product_class, "BM632w");
    let events: Vec<_> = inform
        .events
        .iter()
        .map(|e| EventCode::parse(&e.event_code))
        .collect();
    assert_eq!(events, [EventCode::Periodic]);
    assert_eq!(inform.max_envelopes, 1);
    // Simulator declares arrayType [16] but sends 7 items -> items counted, not declared size.
    assert_eq!(inform.parameter_list.len(), 7);
    let pv = &inform.parameter_list[3];
    assert_eq!(pv.name, "InternetGatewayDevice.DeviceInfo.ProvisioningCode");
    assert_eq!(
        (pv.value.as_str(), pv.xsd_type.as_deref()),
        ("", Some("string"))
    );
}

#[test]
fn responses() {
    let files = corpus("genieacs-sim");
    let get = |label: &str| {
        let (_, b) = files.iter().find(|(n, _)| n.ends_with(label)).unwrap();
        match decode(b).body {
            Body::Rpc(r) => r,
            Body::Fault(f) => panic!("{label}: unexpected fault {f:?}"),
        }
    };
    let Rpc::GetParameterValuesResponse(gpv) = get("-GetParameterValuesResponse") else {
        panic!()
    };
    assert_eq!(gpv.parameter_list[1].value, "300");
    assert_eq!(
        gpv.parameter_list[1].xsd_type.as_deref(),
        Some("unsignedInt")
    );

    let Rpc::GetParameterNamesResponse(gpn) = get("-GetParameterNamesResponse") else {
        panic!()
    };
    assert_eq!(gpn.parameter_list.len(), 16);
    assert_eq!(gpn.parameter_list.iter().filter(|p| p.writable).count(), 1);

    let Rpc::AddObjectResponse(add) = get("-AddObjectResponse") else {
        panic!()
    };
    assert_eq!((add.instance_number, add.status), (2, 0));

    let Rpc::DownloadResponse(dl) = get("-DownloadResponse") else {
        panic!()
    };
    assert_eq!(
        (dl.status, dl.start_time.as_str()),
        (1, "0001-01-01T00:00:00Z")
    );
}
