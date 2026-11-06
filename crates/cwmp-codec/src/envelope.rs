//! SOAP envelope: header, body (RPC or fault), namespaces.

use crate::error::{DecodeError, Result};
use crate::field::Field;
use crate::rpc::Rpc;
use crate::xml::{self, Element, NS_SOAP_ENC, NS_SOAP_ENV, NS_XSD, NS_XSI, Writer};

/// CWMP SOAP namespace. CWMP 1.3 + 1.4 reuse `cwmp-1-2`.
/// Version -> `SupportedCWMPVersions` / `UseCWMPVersion` headers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CwmpNamespace {
    /// `urn:dslforum-org:cwmp-1-0`
    #[default]
    V1_0,
    /// `urn:dslforum-org:cwmp-1-1`
    V1_1,
    /// `urn:dslforum-org:cwmp-1-2` (CWMP 1.2 to 1.4)
    V1_2,
}

impl CwmpNamespace {
    pub fn uri(self) -> &'static str {
        match self {
            Self::V1_0 => "urn:dslforum-org:cwmp-1-0",
            Self::V1_1 => "urn:dslforum-org:cwmp-1-1",
            Self::V1_2 => "urn:dslforum-org:cwmp-1-2",
        }
    }

    /// Parse a namespace URI. Unknown minor (`cwmp-1-3`) -> newest known ([`Self::V1_2`]).
    pub fn from_uri(uri: &str) -> Option<Self> {
        let rest = uri.strip_prefix("urn:dslforum-org:cwmp-1-")?;
        Some(match rest.parse::<u32>().ok()? {
            0 => Self::V1_0,
            1 => Self::V1_1,
            _ => Self::V1_2,
        })
    }
}

/// CWMP SOAP header fields.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Header {
    /// `cwmp:ID`: links request + response.
    pub id: Option<String>,
    /// `cwmp:HoldRequests` (ACS -> CPE): CPE must not send requests.
    pub hold_requests: Option<bool>,
    /// `cwmp:NoMoreRequests` (deprecated since 1.1).
    pub no_more_requests: Option<bool>,
    /// `cwmp:SessionTimeout`, seconds (CWMP 1.3+).
    pub session_timeout: Option<u32>,
    /// `cwmp:SupportedCWMPVersions` (CPE, CWMP 1.4), e.g. `1.0,1.1,1.2,1.3,1.4`.
    pub supported_cwmp_versions: Option<String>,
    /// `cwmp:UseCWMPVersion` (ACS, CWMP 1.4).
    pub use_cwmp_version: Option<String>,
}

/// One failed parameter of an SPV fault.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SetParameterValuesFault {
    /// Parameter path.
    pub parameter_name: String,
    pub fault_code: u32,
    /// Description.
    pub fault_string: String,
}

/// CWMP fault in a SOAP Fault.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Fault {
    /// SOAP `faultcode`: `Client` (sender at fault) or `Server`.
    pub soap_fault_code: String,
    /// CWMP fault code: 9000-9899 CPE, 8000-8899 ACS.
    pub code: u32,
    /// Description.
    pub string: String,
    /// Per-parameter faults (9003 on SPV).
    pub set_parameter_values_faults: Vec<SetParameterValuesFault>,
}

impl Fault {
    /// SOAP faultcode from CWMP code: 8002/9002 -> `Server`, else `Client`.
    pub fn new(code: u32, string: impl Into<String>) -> Self {
        Self {
            soap_fault_code: if matches!(code, 8002 | 9002) {
                "Server".into()
            } else {
                "Client".into()
            },
            code,
            string: string.into(),
            set_parameter_values_faults: Vec::new(),
        }
    }
}

/// SOAP Body content.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum Body {
    /// RPC request or response.
    Rpc(Rpc),
    /// Fault response.
    Fault(Fault),
}

/// CWMP SOAP envelope (decoded or to encode).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// CWMP namespace (received or to send).
    pub namespace: CwmpNamespace,
    pub header: Header,
    pub body: Body,
}

impl Envelope {
    /// Envelope with this ID + RPC, default header.
    pub fn rpc(namespace: CwmpNamespace, id: impl Into<String>, rpc: impl Into<Rpc>) -> Self {
        Self {
            namespace,
            header: Header {
                id: Some(id.into()),
                ..Header::default()
            },
            body: Body::Rpc(rpc.into()),
        }
    }

    /// Decode one envelope. Empty or whitespace-only HTTP body -> `Ok(None)`.
    /// CWMP: empty body = nothing more to send.
    pub fn decode(input: &[u8]) -> Result<Option<Self>> {
        if input.iter().all(u8::is_ascii_whitespace) {
            return Ok(None);
        }
        let root = xml::parse(input)?;
        if !root.name.eq_ignore_ascii_case("Envelope") {
            return Err(DecodeError::NotAnEnvelope(root.name));
        }
        let header = root.child("Header");
        let body = root.child("Body").ok_or(DecodeError::MissingBody)?;
        let content = body.children.first().ok_or(DecodeError::MissingBody)?;

        // Namespace: body element, else any header element, else 1.0.
        let namespace = std::iter::once(content)
            .chain(header.into_iter().flat_map(|h| h.children.iter()))
            .find_map(|e| e.ns.as_deref().and_then(CwmpNamespace::from_uri))
            .unwrap_or_default();

        let body = if content.name.eq_ignore_ascii_case("Fault")
            && content.ns.as_deref() != Some(namespace.uri())
        {
            Body::Fault(decode_fault(content)?)
        } else {
            Body::Rpc(Rpc::decode(content)?)
        };
        Ok(Some(Self {
            namespace,
            header: header.map(decode_header).transpose()?.unwrap_or_default(),
            body,
        }))
    }

    /// Encode as compact XML, standard prefixes (`soap-env`, `soap-enc`, `xsd`, `xsi`, `cwmp`).
    pub fn encode(&self) -> String {
        let mut w = Writer::default();
        w.out.push_str(r#"<?xml version="1.0" encoding="UTF-8"?>"#);
        w.open(
            "soap-env:Envelope",
            &[
                ("xmlns:soap-env", NS_SOAP_ENV),
                ("xmlns:soap-enc", NS_SOAP_ENC),
                ("xmlns:xsd", NS_XSD),
                ("xmlns:xsi", NS_XSI),
                ("xmlns:cwmp", self.namespace.uri()),
            ],
        );
        encode_header(&self.header, &mut w);
        w.open("soap-env:Body", &[]);
        match &self.body {
            Body::Rpc(rpc) => rpc.encode(&mut w),
            Body::Fault(f) => encode_fault(f, &mut w),
        }
        w.close("soap-env:Body");
        w.close("soap-env:Envelope");
        w.out
    }
}

fn decode_header(h: &Element) -> Result<Header> {
    let text = |name: &str| h.child(name).map(|e| e.text.trim().to_owned());
    Ok(Header {
        id: text("ID"),
        hold_requests: h
            .child("HoldRequests")
            .map(|e| bool::read(Some(e)))
            .transpose()?,
        no_more_requests: h
            .child("NoMoreRequests")
            .map(|e| bool::read(Some(e)))
            .transpose()?,
        session_timeout: h
            .child("SessionTimeout")
            .map(|e| u32::read(Some(e)))
            .transpose()?,
        supported_cwmp_versions: text("SupportedCWMPVersions"),
        use_cwmp_version: text("UseCWMPVersion"),
    })
}

fn encode_header(h: &Header, w: &mut Writer) {
    let mut items: Vec<(&str, &str, String)> = Vec::new();
    if let Some(v) = &h.id {
        items.push(("cwmp:ID", "1", v.clone()));
    }
    if let Some(v) = h.hold_requests {
        items.push(("cwmp:HoldRequests", "1", if v { "1" } else { "0" }.into()));
    }
    if let Some(v) = h.no_more_requests {
        items.push(("cwmp:NoMoreRequests", "0", if v { "1" } else { "0" }.into()));
    }
    if let Some(v) = h.session_timeout {
        items.push(("cwmp:SessionTimeout", "0", v.to_string()));
    }
    if let Some(v) = &h.supported_cwmp_versions {
        items.push(("cwmp:SupportedCWMPVersions", "0", v.clone()));
    }
    if let Some(v) = &h.use_cwmp_version {
        items.push(("cwmp:UseCWMPVersion", "1", v.clone()));
    }
    if items.is_empty() {
        return;
    }
    w.open("soap-env:Header", &[]);
    for (name, must, value) in items {
        w.leaf(name, &[("soap-env:mustUnderstand", must)], &value);
    }
    w.close("soap-env:Header");
}

fn decode_fault(el: &Element) -> Result<Fault> {
    let cwmp = el.child("detail").and_then(|d| d.child("Fault"));
    let mut fault = Fault {
        soap_fault_code: String::read(el.child("faultcode"))?,
        ..Fault::default()
    };
    if let Some(c) = cwmp {
        fault.code = u32::read(c.child("FaultCode"))?;
        fault.string = String::read(c.child("FaultString"))?;
        for spv in c.children_named("SetParameterValuesFault") {
            fault
                .set_parameter_values_faults
                .push(SetParameterValuesFault {
                    parameter_name: String::read(spv.child("ParameterName"))?,
                    fault_code: u32::read(spv.child("FaultCode"))?,
                    fault_string: String::read(spv.child("FaultString"))?,
                });
        }
    } else {
        // Non-CWMP SOAP fault -> keep SOAP faultstring.
        fault.string = String::read(el.child("faultstring"))?;
    }
    Ok(fault)
}

fn encode_fault(f: &Fault, w: &mut Writer) {
    w.open("soap-env:Fault", &[]);
    w.leaf("faultcode", &[], &f.soap_fault_code);
    w.leaf("faultstring", &[], "CWMP fault");
    w.open("detail", &[]);
    w.open("cwmp:Fault", &[]);
    w.leaf("FaultCode", &[], &f.code.to_string());
    w.leaf("FaultString", &[], &f.string);
    for spv in &f.set_parameter_values_faults {
        w.open("SetParameterValuesFault", &[]);
        w.leaf("ParameterName", &[], &spv.parameter_name);
        w.leaf("FaultCode", &[], &spv.fault_code.to_string());
        w.leaf("FaultString", &[], &spv.fault_string);
        w.close("SetParameterValuesFault");
    }
    w.close("cwmp:Fault");
    w.close("detail");
    w.close("soap-env:Fault");
}
