//! Property tests: encode -> decode = identity + decode never panics.

use dhonomos_cwmp_codec::{
    CwmpNamespace, DeviceId, Envelope, EventStruct, Inform, ParameterInfo, ParameterValue, Rpc,
    SetParameterValues,
};
use proptest::prelude::*;

/// Text unchanged by the trim of ordinary fields.
fn field() -> impl Strategy<Value = String> {
    "[A-Za-z0-9_.:/<>&\"' -]{0,24}".prop_map(|s| s.trim().to_owned())
}

/// Parameter values kept as is, incl. whitespace + markup chars.
fn value() -> impl Strategy<Value = String> {
    "[\\PC\t\n\r]{0,32}"
}

fn param() -> impl Strategy<Value = ParameterValue> {
    (
        field(),
        value(),
        prop::option::of("(string|unsignedInt|boolean|dateTime)"),
    )
        .prop_map(|(name, value, xsd_type)| ParameterValue {
            name,
            value,
            xsd_type,
        })
}

fn namespace() -> impl Strategy<Value = CwmpNamespace> {
    prop_oneof![
        Just(CwmpNamespace::V1_0),
        Just(CwmpNamespace::V1_1),
        Just(CwmpNamespace::V1_2),
    ]
}

fn rpc() -> impl Strategy<Value = Rpc> {
    let inform = (
        (field(), field(), field(), field()),
        prop::collection::vec((field(), field()), 0..4),
        any::<u32>(),
        prop::collection::vec(param(), 0..6),
    )
        .prop_map(|((m, o, p, s), events, retry, params)| {
            Rpc::Inform(Inform {
                device_id: DeviceId {
                    manufacturer: m,
                    oui: o,
                    product_class: p,
                    serial_number: s,
                },
                events: events
                    .into_iter()
                    .map(|(event_code, command_key)| EventStruct {
                        event_code,
                        command_key,
                    })
                    .collect(),
                max_envelopes: 1,
                current_time: "2026-10-03T00:00:00Z".into(),
                retry_count: retry,
                parameter_list: params,
            })
        });
    let spv = (prop::collection::vec(param(), 0..6), field()).prop_map(|(l, k)| {
        Rpc::SetParameterValues(SetParameterValues {
            parameter_list: l,
            parameter_key: k,
        })
    });
    let gpn = prop::collection::vec((field(), any::<bool>()), 0..6).prop_map(|v| {
        Rpc::GetParameterNamesResponse(dhonomos_cwmp_codec::GetParameterNamesResponse {
            parameter_list: v
                .into_iter()
                .map(|(name, writable)| ParameterInfo { name, writable })
                .collect(),
        })
    });
    prop_oneof![inform, spv, gpn]
}

proptest! {
    #[test]
    fn encode_then_decode_is_identity(ns in namespace(), id in field(), rpc in rpc()) {
        let env = Envelope::rpc(ns, id, rpc);
        let xml = env.encode();
        let back = Envelope::decode(xml.as_bytes())
            .map_err(|e| TestCaseError::fail(format!("{e}\n{xml}")))?;
        // Value without type -> encode writes xsi:type="xsd:string".
        let mut expected = env;
        if let dhonomos_cwmp_codec::Body::Rpc(Rpc::Inform(Inform { parameter_list, .. }))
        | dhonomos_cwmp_codec::Body::Rpc(Rpc::SetParameterValues(SetParameterValues { parameter_list, .. })) =
            &mut expected.body
        {
            for p in parameter_list {
                p.xsd_type.get_or_insert_with(|| "string".into());
            }
        }
        prop_assert_eq!(back, Some(expected));
    }

    #[test]
    fn decode_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        let _ = Envelope::decode(&bytes);
    }

    #[test]
    fn decode_never_panics_on_mangled_envelopes(cut in 0usize..400, junk in "[<>/=\"a-z: ]{0,8}") {
        let base = Envelope::rpc(CwmpNamespace::V1_0, "1", dhonomos_cwmp_codec::Reboot { command_key: "k".into() }).encode();
        let cut = cut.min(base.len());
        let mangled = format!("{}{}{}", &base[..cut], junk, &base[cut..]);
        let _ = Envelope::decode(mangled.as_bytes());
    }
}
