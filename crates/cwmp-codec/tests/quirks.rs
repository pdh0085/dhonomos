//! Hand-written variants seen on real CPEs -> lenient decode.
#![allow(clippy::unwrap_used)]

use dhonomos_cwmp_codec::{
    Body, CwmpNamespace, DecodeError, DuOperation, Envelope, Fault, GetParameterValuesResponse,
    Header, ParameterValue, Rpc, SetParameterValues, SetParameterValuesFault,
};

fn decode(xml: &str) -> Envelope {
    Envelope::decode(xml.as_bytes())
        .unwrap_or_else(|e| panic!("{e}"))
        .unwrap()
}

fn rpc(xml: &str) -> Rpc {
    match decode(xml).body {
        Body::Rpc(r) => r,
        Body::Fault(f) => panic!("unexpected fault {f:?}"),
    }
}

#[test]
fn uppercase_prefixes_default_namespace_and_whitespace() {
    let env = decode(
        r#"<?xml version="1.0"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
    xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/">
  <SOAP-ENV:Header>
    <ID xmlns="urn:dslforum-org:cwmp-1-2" SOAP-ENV:mustUnderstand="1"> 7 </ID>
  </SOAP-ENV:Header>
  <SOAP-ENV:Body>
    <Inform xmlns="urn:dslforum-org:cwmp-1-2">
      <DeviceId>
        <Manufacturer>ACME</Manufacturer><OUI>001122</OUI>
        <ProductClass>Box</ProductClass><SerialNumber>SN1</SerialNumber>
      </DeviceId>
      <Event><EventStruct><EventCode>1 BOOT</EventCode><CommandKey></CommandKey></EventStruct></Event>
      <MaxEnvelopes>1</MaxEnvelopes>
      <CurrentTime>2026-10-03T00:00:00Z</CurrentTime>
      <RetryCount>0</RetryCount>
      <ParameterList>
        <ParameterValueStruct>
          <Name>Device.DeviceInfo.SoftwareVersion</Name>
          <Value>  1.0 &amp; more  </Value>
        </ParameterValueStruct>
      </ParameterList>
    </Inform>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>"#,
    );
    assert_eq!(env.namespace, CwmpNamespace::V1_2);
    assert_eq!(env.header.id.as_deref(), Some("7"));
    let Body::Rpc(Rpc::Inform(i)) = env.body else {
        panic!()
    };
    assert_eq!(i.device_id.serial_number, "SN1");
    // Value whitespace kept. No xsi:type -> None.
    assert_eq!(i.parameter_list[0].value, "  1.0 & more  ");
    assert_eq!(i.parameter_list[0].xsd_type, None);
}

#[test]
fn cwmp_1_4_headers_round_trip() {
    let mut env = Envelope::rpc(
        CwmpNamespace::V1_2,
        "1",
        dhonomos_cwmp_codec::InformResponse { max_envelopes: 1 },
    );
    env.header = Header {
        id: Some("1".into()),
        hold_requests: Some(false),
        no_more_requests: None,
        session_timeout: Some(60),
        supported_cwmp_versions: Some("1.0,1.1,1.2,1.3,1.4".into()),
        use_cwmp_version: Some("1.4".into()),
    };
    let xml = env.encode();
    assert!(xml.contains(r#"<cwmp:UseCWMPVersion soap-env:mustUnderstand="1">1.4<"#));
    assert!(xml.contains(r#"<cwmp:SupportedCWMPVersions soap-env:mustUnderstand="0">"#));
    assert_eq!(decode(&xml), env);
}

#[test]
fn booleans_and_missing_fields() {
    let r = rpc(
        r#"<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" xmlns:c="urn:dslforum-org:cwmp-1-0">
<s:Body><c:GetParameterNames><ParameterPath>Device.</ParameterPath><NextLevel>TRUE</NextLevel></c:GetParameterNames></s:Body></s:Envelope>"#,
    );
    let Rpc::GetParameterNames(g) = r else {
        panic!()
    };
    assert!(g.next_level);

    // Missing optional elements -> default. No header -> OK.
    let r = rpc(
        r#"<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" xmlns:c="urn:dslforum-org:cwmp-1-0">
<s:Body><c:AddObjectResponse><InstanceNumber>3</InstanceNumber></c:AddObjectResponse></s:Body></s:Envelope>"#,
    );
    let Rpc::AddObjectResponse(a) = r else {
        panic!()
    };
    assert_eq!((a.instance_number, a.status), (3, 0));
}

#[test]
fn invalid_numbers_are_errors() {
    let err = Envelope::decode(
        br#"<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" xmlns:c="urn:dslforum-org:cwmp-1-0">
<s:Body><c:AddObjectResponse><InstanceNumber>three</InstanceNumber></c:AddObjectResponse></s:Body></s:Envelope>"#,
    );
    assert!(matches!(
        err,
        Err(DecodeError::InvalidValue {
            ty: "unsignedInt",
            ..
        })
    ));
}

#[test]
fn set_parameter_values_fault_round_trip() {
    let fault = Fault {
        set_parameter_values_faults: vec![
            SetParameterValuesFault {
                parameter_name: "Device.A".into(),
                fault_code: 9007,
                fault_string: "Invalid parameter value".into(),
            },
            SetParameterValuesFault {
                parameter_name: "Device.B".into(),
                fault_code: 9008,
                fault_string: "Not writable".into(),
            },
        ],
        ..Fault::new(9003, "Invalid arguments")
    };
    let env = Envelope {
        namespace: CwmpNamespace::V1_0,
        header: Header {
            id: Some("x".into()),
            ..Header::default()
        },
        body: Body::Fault(fault.clone()),
    };
    let decoded = decode(&env.encode());
    assert_eq!(decoded.body, Body::Fault(fault));
}

#[test]
fn du_operations_and_results_variants() {
    // Spec form: repeated <Operations xsi:type=...>.
    let r = rpc(
        r#"<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" xmlns:c="urn:dslforum-org:cwmp-1-2" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
<s:Body><c:ChangeDUState>
  <Operations xsi:type="c:InstallOpStruct"><URL>http://x/a.ipk</URL><UUID>u1</UUID></Operations>
  <Operations xsi:type="c:UninstallOpStruct"><UUID>u2</UUID></Operations>
  <CommandKey>k</CommandKey>
</c:ChangeDUState></s:Body></s:Envelope>"#,
    );
    let Rpc::ChangeDUState(c) = r else { panic!() };
    assert_eq!(c.operations.len(), 2);
    assert!(matches!(&c.operations[0], DuOperation::Install(op) if op.url == "http://x/a.ipk"));
    assert!(matches!(&c.operations[1], DuOperation::Uninstall(op) if op.uuid == "u2"));

    // Common non-spec form: results inside an array element.
    let r = rpc(
        r#"<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" xmlns:c="urn:dslforum-org:cwmp-1-2">
<s:Body><c:DUStateChangeComplete>
  <Results><OpResultStruct><UUID>a</UUID></OpResultStruct><OpResultStruct><UUID>b</UUID></OpResultStruct></Results>
  <CommandKey>k</CommandKey>
</c:DUStateChangeComplete></s:Body></s:Envelope>"#,
    );
    let Rpc::DUStateChangeComplete(d) = r else {
        panic!()
    };
    let uuids: Vec<_> = d.results.iter().map(|r| r.uuid.as_str()).collect();
    assert_eq!(uuids, ["a", "b"]);
}

#[test]
fn unknown_methods_empty_bodies_and_garbage() {
    let r = rpc(
        r#"<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" xmlns:c="urn:dslforum-org:cwmp-1-0">
<s:Body><c:X_ACME_Frobnicate><A>1</A></c:X_ACME_Frobnicate></s:Body></s:Envelope>"#,
    );
    assert_eq!(r.name(), "X_ACME_Frobnicate");
    assert!(matches!(r, Rpc::Unknown { .. }));

    assert!(Envelope::decode(b"").unwrap().is_none());
    assert!(Envelope::decode(b" \r\n").unwrap().is_none());
    assert!(matches!(
        Envelope::decode(b"<html/>"),
        Err(DecodeError::NotAnEnvelope(_))
    ));
    assert!(matches!(
        Envelope::decode(br#"<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"/>"#),
        Err(DecodeError::MissingBody)
    ));
    assert!(matches!(
        Envelope::decode(b"<s:Envelope><s:Body>"),
        Err(DecodeError::Xml { .. })
    ));
}

#[test]
fn encoding_is_strict() {
    let env = Envelope::rpc(
        CwmpNamespace::V1_0,
        "acs-1",
        SetParameterValues {
            parameter_list: vec![ParameterValue::new(
                "Device.ManagementServer.PeriodicInformInterval",
                "600",
                "unsignedInt",
            )],
            parameter_key: "k<1>".into(),
        },
    );
    let xml = env.encode();
    for needle in [
        r#"xmlns:cwmp="urn:dslforum-org:cwmp-1-0""#,
        r#"<cwmp:ID soap-env:mustUnderstand="1">acs-1</cwmp:ID>"#,
        r#"<ParameterList soap-enc:arrayType="cwmp:ParameterValueStruct[1]">"#,
        r#"<Value xsi:type="xsd:unsignedInt">600</Value>"#,
        "<ParameterKey>k&lt;1&gt;</ParameterKey>",
    ] {
        assert!(xml.contains(needle), "missing {needle} in {xml}");
    }
}

/// Fuzz find: invalid element name accepted + re-emitted as is -> malformed XML on encode.
#[test]
fn fuzz_regression_invalid_element_name() {
    let input = br#"<soap-env:Envelope xmlns:soap-env="http:sdance" xmlns:cwmp="urn:dslfor%m-org:cwmp-1-0"><soap-env:Header><cwmp:ID soap-env:mustUnderstand="1">acs-1</cwmp:ID></soap-env:Header><soap-env:Body><cwmp:GetRPCMet(<<//></soap-env:Body></soap-env:Envelope>"#;
    assert!(matches!(
        Envelope::decode(input),
        Err(DecodeError::InvalidName(_))
    ));

    // Hand-built Unknown RPC with bad name -> must still encode to well-formed XML.
    let env = Envelope {
        namespace: CwmpNamespace::V1_0,
        header: Header::default(),
        body: Body::Rpc(Rpc::Unknown {
            name: "Bad<Name".into(),
        }),
    };
    let xml = env.encode();
    assert!(!xml.contains("Bad<Name"));
    assert!(matches!(
        Envelope::decode(xml.as_bytes()),
        Err(DecodeError::MissingBody)
    ));
}

/// Realistic large response -> far below the structural limits.
#[test]
fn large_parameter_responses_decode() {
    for count in [10_000, 50_000] {
        let list: Vec<ParameterValue> = (0..count)
            .map(|i| {
                ParameterValue::new(
                    format!("Device.WiFi.AccessPoint.{i}.AssociatedDevice.1.SignalStrength"),
                    "-61",
                    "int",
                )
            })
            .collect();
        let env = Envelope::rpc(
            CwmpNamespace::V1_2,
            "big",
            GetParameterValuesResponse {
                parameter_list: list,
            },
        );
        let xml = env.encode();
        assert!(xml.len() < 8 << 20, "{} bytes", xml.len());
        assert_eq!(Envelope::decode(xml.as_bytes()).unwrap().unwrap(), env);
    }
}

/// Small on the wire but huge tree -> decode error.
#[test]
fn structural_limits_apply_to_whole_envelopes() {
    let many = format!(
        r#"<Envelope xmlns="{}"><Body>{}</Body></Envelope>"#,
        "N".repeat(20_000),
        "<a/>".repeat(600_000)
    );
    assert!(matches!(
        Envelope::decode(many.as_bytes()),
        Err(DecodeError::TooLarge {
            what: "elements",
            ..
        })
    ));
    let decls: String = (0..300).map(|i| format!(" xmlns:p{i}=\"u\"")).collect();
    let xml = format!("<Envelope{decls}><Body><p0:a/></Body></Envelope>");
    assert!(matches!(
        Envelope::decode(xml.as_bytes()),
        Err(DecodeError::TooLarge { .. })
    ));
}
