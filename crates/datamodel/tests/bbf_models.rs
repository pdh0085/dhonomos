//! Load vendored BBF `-full` data models + check contents.
//! Expected counts: computed independently with Python ElementTree.
#![allow(clippy::unwrap_used)]

use std::sync::LazyLock;

use dhonomos_datamodel::{
    Access, ActiveNotify, BaseType, DataModel, Item, MaxEntries, Path, Requirement, TypeRef,
    Variant, Version,
};

fn load(file: &str) -> DataModel {
    let path = format!("{}/../../schemas/{file}", env!("CARGO_MANIFEST_DIR"));
    let xml = std::fs::read_to_string(&path).unwrap();
    DataModel::from_xml(&xml).unwrap()
}

static USP: LazyLock<DataModel> = LazyLock::new(|| load("tr-181-2-21-0-usp-full.xml"));
static CWMP: LazyLock<DataModel> = LazyLock::new(|| load("tr-181-2-21-0-cwmp-full.xml"));
static IGD: LazyLock<DataModel> = LazyLock::new(|| load("tr-098-1-8-0-full.xml"));

struct Counts {
    data_types: usize,
    objects: usize,
    multi: usize,
    params: usize,
    commands: usize,
    events: usize,
    profiles: usize,
}

fn counts(dm: &DataModel) -> Counts {
    let o = dm.objects();
    Counts {
        data_types: dm.data_types().count(),
        objects: o.len(),
        multi: o.iter().filter(|o| o.is_multi_instance()).count(),
        params: o.iter().map(|o| o.parameters.len()).sum(),
        commands: o.iter().map(|o| o.commands.len()).sum(),
        events: o.iter().map(|o| o.events.len()).sum(),
        profiles: dm.profiles().len(),
    }
}

#[test]
fn tr181_usp_header_and_counts() {
    let dm = &*USP;
    assert_eq!(dm.variant(), Variant::Usp);
    assert_eq!(dm.root(), "Device");
    assert_eq!(dm.version(), Version::new(2, 21));
    let c = counts(dm);
    assert_eq!(
        (
            c.data_types,
            c.objects,
            c.multi,
            c.params,
            c.commands,
            c.events,
            c.profiles
        ),
        (59, 932, 478, 7529, 212, 59, 273)
    );
}

#[test]
fn tr181_cwmp_and_tr098_counts() {
    let c = counts(&CWMP);
    assert_eq!(CWMP.variant(), Variant::Cwmp);
    assert_eq!(
        (
            c.data_types,
            c.objects,
            c.multi,
            c.params,
            c.commands,
            c.events,
            c.profiles
        ),
        (51, 975, 496, 8105, 0, 0, 245)
    );

    let c = counts(&IGD);
    assert_eq!(IGD.variant(), Variant::Common);
    assert_eq!(IGD.root(), "InternetGatewayDevice");
    assert_eq!(IGD.version(), Version::new(1, 14));
    assert_eq!(
        (
            c.data_types,
            c.objects,
            c.multi,
            c.params,
            c.commands,
            c.events,
            c.profiles
        ),
        (6, 192, 91, 1801, 0, 0, 92)
    );
}

#[test]
fn multi_instance_object() {
    let o = USP.object("Device.WiFi.Radio.{i}.").unwrap();
    assert!(o.is_multi_instance());
    assert_eq!(o.access, Access::ReadOnly);
    assert_eq!((o.min_entries, o.max_entries), (0, MaxEntries::Unbounded));
    assert_eq!(
        o.num_entries_parameter.as_deref(),
        Some("RadioNumberOfEntries")
    );
    assert_eq!(o.version, Some(Version::new(2, 12)));
    let keys: Vec<_> = o.unique_keys.iter().map(|k| k.parameters.clone()).collect();
    assert_eq!(keys, [vec!["Alias".to_owned()], vec!["Name".to_owned()]]);
    assert!(
        !o.unique_keys[0].functional,
        "Alias is a non-functional key"
    );
    assert!(!o.description.is_empty());
}

#[test]
fn parameter_lookup_and_resolution() {
    let (_, p) = USP.parameter("Device.DeviceInfo.SerialNumber").unwrap();
    assert_eq!(p.access, Access::ReadOnly);
    assert_eq!(USP.resolve(&p.syntax).unwrap().base, BaseType::String);

    let (_, p) = USP
        .parameter("Device.Ethernet.Interface.{i}.Stats.BytesSent")
        .unwrap();
    assert_eq!(p.active_notify, ActiveNotify::CanDeny);
    assert_eq!(p.syntax.ty, TypeRef::Named("StatsCounter64".into()));
    let r = USP.resolve(&p.syntax).unwrap();
    assert_eq!(r.base, BaseType::UnsignedLong);
    assert_eq!(r.data_type.as_deref(), Some("StatsCounter64"));
    assert_eq!(r.facets.units.as_deref(), Some("bytes"));

    let (_, p) = USP
        .parameter("Device.WiFi.Radio.{i}.OperatingFrequencyBand")
        .unwrap();
    assert_eq!(p.access, Access::ReadWrite);
    let er = p.syntax.facets.enumeration_ref.as_ref().unwrap();
    assert_eq!(er.target_param, "SupportedFrequencyBands");

    assert!(USP.parameter("Device.DeviceInfo.NoSuchThing").is_none());
    assert!(USP.parameter("Device.DeviceInfo.").is_none());
}

#[test]
fn data_type_chain_merges_facets() {
    // IPv4Address -> IPAddress -> string(size <= 45): size narrowed + patterns added.
    let dt = USP.data_type("IPv4Address").unwrap();
    assert_eq!(dt.base, TypeRef::Named("IPAddress".into()));
    let syntax = dhonomos_datamodel::Syntax {
        ty: TypeRef::Named("IPv4Address".into()),
        list: None,
        facets: Default::default(),
        defaults: vec![],
        secured: false,
        command: false,
    };
    let r = USP.resolve(&syntax).unwrap();
    assert_eq!(r.base, BaseType::String);
    assert_eq!(r.data_type.as_deref(), Some("IPv4Address"));
    assert_eq!(
        r.facets.sizes.iter().map(|s| s.max).collect::<Vec<_>>(),
        [Some(15)]
    );
    assert_eq!(r.facets.patterns.len(), 2);
    assert_eq!(r.facets.patterns[0], "", "empty value is allowed");

    // Base alone -> keeps own facets.
    let base = dhonomos_datamodel::Syntax {
        ty: TypeRef::Named("IPAddress".into()),
        ..syntax
    };
    let r = USP.resolve(&base).unwrap();
    assert_eq!(
        r.facets.sizes.iter().map(|s| s.max).collect::<Vec<_>>(),
        [Some(45)]
    );
    assert!(r.facets.patterns.is_empty());
}

#[test]
fn every_parameter_type_resolves() {
    for dm in [&*USP, &*CWMP, &*IGD] {
        for o in dm.objects() {
            for p in &o.parameters {
                dm.resolve(&p.syntax)
                    .unwrap_or_else(|e| panic!("{}{}: {e}", o.path, p.name));
            }
        }
    }
}

#[test]
fn commands_and_events() {
    let (_, reboot) = USP.command("Device.Reboot()").unwrap();
    assert!(!reboot.is_async);
    assert!(CWMP.command("Device.Reboot()").is_none());

    let (_, ping) = USP.command("Device.IP.Diagnostics.IPPing()").unwrap();
    assert!(ping.is_async);
    let pv = ping
        .input
        .parameters
        .iter()
        .find(|p| p.name == "ProtocolVersion")
        .unwrap();
    assert!(pv.mandatory);
    let values: Vec<_> = pv
        .syntax
        .facets
        .enumerations
        .iter()
        .map(|e| e.value.as_str())
        .collect();
    assert_eq!(values, ["Any", "IPv4", "IPv6"]);
    assert!(!ping.output.parameters.is_empty());

    let (_, boot) = USP.event("Device.Boot!").unwrap();
    let names: Vec<_> = boot
        .arguments
        .parameters
        .iter()
        .map(|p| p.name.as_str())
        .collect();
    assert!(names.starts_with(&["CommandKey", "Cause"]));
    let local_shutdown = boot.arguments.parameters[1]
        .syntax
        .facets
        .enumerations
        .iter()
        .find(|e| e.value == "LocalShutdown")
        .unwrap();
    assert_eq!(local_shutdown.version, Some(Version::new(2, 21)));
}

#[test]
fn profiles() {
    use dhonomos_datamodel::Status;
    let p = USP
        .profiles()
        .iter()
        .find(|p| p.name == "Baseline:1")
        .unwrap();
    assert_eq!(p.extends, ["_Baseline:1"]);
    assert_eq!(p.status, Status::Deleted);
    assert!(p.objects.is_empty());

    let base = USP
        .profiles()
        .iter()
        .find(|p| p.name == "_Baseline:1")
        .unwrap();
    let info = base
        .objects
        .iter()
        .find(|o| o.path == "Device.DeviceInfo.")
        .unwrap();
    assert_eq!(info.requirement, Requirement::Present);
    assert_eq!(info.parameters.len(), 9);
}

#[test]
fn lookup_by_instance_path() {
    let find = |s: &str| USP.lookup(&Path::parse(s).unwrap());
    assert!(matches!(
        find("Device.WiFi.Radio.1.Channel"),
        Some(Item::Parameter(o, p)) if o.path == "Device.WiFi.Radio.{i}." && p.name == "Channel"
    ));
    assert!(matches!(
        find(r#"Device.IP.Interface.[Name=="wan"]."#),
        Some(Item::Object(_))
    ));
    assert!(matches!(
        find("Device.IP.Interface.*.IPv4Address.2."),
        Some(Item::Object(_))
    ));
    assert!(
        matches!(find("Device.IP.Diagnostics.IPPing()"), Some(Item::Command(_, c)) if c.is_async)
    );
    assert!(matches!(find("Device.Boot!"), Some(Item::Event(..))));
    // Instance selector after single-instance object.
    assert_eq!(find("Device.DeviceInfo.1.Manufacturer"), None);
    // Unknown names + reference following.
    assert_eq!(find("Device.WiFi.Radio.1.NoSuch"), None);
    assert_eq!(find("Device.NAT.PortMapping.1.Interface+.Name"), None);
    // CWMP model: no commands.
    assert_eq!(CWMP.lookup(&Path::parse("Device.Reboot()").unwrap()), None);
}

#[test]
fn check_parameter_values() {
    use dhonomos_datamodel::{Checked, ValueError};
    let check = |p: &str, v: &str| USP.check_parameter(&Path::parse(p).unwrap(), v);

    assert_eq!(
        check("Device.WiFi.Radio.1.Enable", "1"),
        Ok(Checked::Valid("true".into()))
    );
    assert_eq!(
        check(
            "Device.Ethernet.Interface.1.MACAddress",
            "00:11:22:33:44:55"
        ),
        Ok(Checked::Valid("00:11:22:33:44:55".into()))
    );
    assert!(matches!(
        check(
            "Device.Ethernet.Interface.1.MACAddress",
            "00-11-22-33-44-55"
        ),
        Err(ValueError::NotAllowed { .. })
    ));
    assert!(matches!(
        check(
            "Device.IP.Interface.1.IPv4Address.1.IPAddress",
            "192.168.1.256"
        ),
        Err(ValueError::NotAllowed { .. })
    ));
    // ManagementServer: CWMP-only.
    let interval = Path::parse("Device.ManagementServer.PeriodicInformInterval").unwrap();
    assert!(matches!(
        CWMP.check_parameter(&interval, "0"),
        Err(ValueError::Range { .. })
    ));
    assert_eq!(
        CWMP.check_parameter(&interval, "86400"),
        Ok(Checked::Valid("86400".into()))
    );
    assert_eq!(
        check("Device.X_00D09E_Foo.Bar", "x"),
        Ok(Checked::NotInModel {
            vendor_extension: true
        })
    );
    assert_eq!(
        check("Device.WiFi.Radio.1.NewIn2_22", "x"),
        Ok(Checked::NotInModel {
            vendor_extension: false
        })
    );
}

#[test]
fn list_defaults_are_in_wire_format() {
    let (_, p) = USP
        .parameter("Device.Bridging.Bridge.{i}.Port.{i}.PriorityRegeneration")
        .unwrap();
    assert_eq!(p.syntax.defaults[0].value, "0,1,2,3,4,5,6,7");
}

#[test]
fn all_patterns_compile() {
    for dm in [&*USP, &*CWMP, &*IGD] {
        assert_eq!(dm.unsupported_patterns().count(), 0);
    }
}

#[test]
fn every_default_value_validates() {
    use dhonomos_datamodel::DefaultKind;
    let mut failures = Vec::new();
    for dm in [&*USP, &*CWMP, &*IGD] {
        for o in dm.objects() {
            for p in &o.parameters {
                for d in &p.syntax.defaults {
                    // TR-098 predates "unknown time" convention -> "" for dateTime.
                    let legacy_empty_datetime = dm.root() == "InternetGatewayDevice"
                        && d.value.is_empty()
                        && dm.resolve(&p.syntax).unwrap().base == BaseType::DateTime;
                    if d.kind != DefaultKind::Implementation
                        && !legacy_empty_datetime
                        && let Err(e) = dm.check_value(&p.syntax, &d.value)
                    {
                        failures.push(format!("{}{} = {:?}: {e}", o.path, p.name, d.value));
                    }
                }
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn version_matrix() {
    let path = |s: &str| Path::parse(s).unwrap();
    // Description: added in 2.21; Enable: 2.12; Manufacturer: inherits 2.12 of DeviceInfo.
    let desc = path("Device.WiFi.Radio.1.Description");
    assert_eq!(
        USP.introduced_in(USP.lookup(&desc).unwrap()),
        Some(Version::new(2, 21))
    );
    assert!(USP.lookup_in_version(&desc, Version::new(2, 20)).is_none());
    assert!(USP.lookup_in_version(&desc, Version::new(2, 21)).is_some());
    let mfr = USP.lookup(&path("Device.DeviceInfo.Manufacturer")).unwrap();
    assert_eq!(USP.introduced_in(mfr), Some(Version::new(2, 12)));
    // TR-098: no version attributes -> everything available.
    let igd = path("InternetGatewayDevice.DeviceInfo.Manufacturer");
    assert!(IGD.lookup_in_version(&igd, Version::new(1, 0)).is_some());
}
