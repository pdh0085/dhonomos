//! Sans-IO CWMP session state machine (CW-11).
//!
//! Design: `docs/design/03-cwmp-session-fsm.md`.
//! Host: each decoded HTTP request body -> [`Session::receive`] -> act on [`Step`]:
//!
//! - [`Step::CpeRequest`]: store CPE data -> [`Session::answer`].
//! - [`Step::AcsTurn`]: handle previous result (if any) -> [`Session::send`]
//!   with next queued RPC, `None` = session end.
//! - [`Step::Reply`]: send reply as is.
//!
//! ```
//! use dhonomos_cwmp_codec::{CwmpNamespace, Envelope, Inform, Reboot};
//! use dhonomos_cwmp_session::{Reply, Session, Step};
//!
//! let mut s = Session::new("s1");
//! let inform = Envelope::rpc(CwmpNamespace::V1_0, "c1", Inform::default());
//! assert!(matches!(s.receive(Some(inform)).unwrap(), Step::CpeRequest(_)));
//! let Reply::Envelope(resp) = s.answer(Ok(())).unwrap() else { unreachable!() };
//! assert_eq!(resp.header.id.as_deref(), Some("c1"));
//! assert!(matches!(s.receive(None).unwrap(), Step::AcsTurn { completed: None }));
//! s.send(Some(Reboot::default().into())).unwrap();
//! ```

use dhonomos_cwmp_codec::{
    AutonomousDUStateChangeCompleteResponse, AutonomousTransferCompleteResponse, Body,
    CwmpNamespace, DUStateChangeCompleteResponse, Envelope, Fault, FaultCode,
    GetRPCMethodsResponse, Header, InformResponse, KickedResponse, RequestDownloadResponse, Rpc,
    TransferCompleteResponse,
};

/// ACS methods -> answer to GetRPCMethods from a CPE.
pub const ACS_METHODS: &[&str] = &[
    "Inform",
    "GetRPCMethods",
    "TransferComplete",
    "AutonomousTransferComplete",
    "DUStateChangeComplete",
    "AutonomousDUStateChangeComplete",
    "RequestDownload",
    "Kicked",
];

/// Highest CWMP version of this ACS.
pub const MAX_CWMP_VERSION: (u32, u32) = (1, 4);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Wait for opening Inform.
    AwaitInform,
    /// Inform received -> host must [`Session::answer`].
    InformPending,
    /// CPE may send requests or empty POST.
    CpeTurn,
    /// CPE request waits for [`Session::answer`].
    CpeRequestPending,
    /// Host must [`Session::send`] next RPC or end session.
    AcsTurn,
    /// Wait for CPE response to an ACS request.
    AwaitResponse,
    Ended,
}

/// Host action after [`Session::receive`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// CPE request (Inform first). Handle it -> [`Session::answer`].
    CpeRequest(Rpc),
    /// ACS turn -> [`Session::send`].
    AcsTurn {
        /// Result of previous ACS request, if any.
        completed: Option<Completed>,
    },
    /// Send this reply, no host decision (e.g. fault 8000 for unknown method).
    Reply(Reply),
}

/// HTTP response content.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum Reply {
    /// HTTP 200 + this SOAP envelope.
    Envelope(Envelope),
    /// HTTP 204 No Content -> nothing more from ACS, session end.
    Empty,
}

impl Reply {
    /// HTTP body. `None` for 204.
    pub fn to_body(&self) -> Option<String> {
        match self {
            Self::Envelope(e) => Some(e.encode()),
            Self::Empty => None,
        }
    }
}

/// Result of an ACS request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Completed {
    /// `cwmp:ID` used by the ACS.
    pub request_id: String,
    /// Sent method, e.g. `GetParameterValues`.
    pub method: String,
    pub outcome: Outcome,
    /// Response has same `cwmp:ID`. Mismatch tolerated.
    pub id_matched: bool,
}

/// CPE answer to an ACS request.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum Outcome {
    /// Matching `...Response`.
    Response(Rpc),
    Fault(Fault),
    /// Response for a different method.
    Mismatch(Rpc),
    /// Empty POST instead of a response.
    NoResponse,
}

/// CPE protocol violation or host API misuse.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SessionError {
    /// 1st message != Inform -> host: HTTP 400, drop session.
    #[error("expected Inform, got {got}")]
    ExpectedInform {
        /// Method name, `empty` for empty POST.
        got: String,
    },
    /// Inform inside a session -> host: start new session with it.
    #[error("Inform received in an established session")]
    UnexpectedInform,
    /// Response with no ACS request outstanding.
    #[error("unexpected response {method}")]
    UnexpectedResponse {
        /// Method name.
        method: String,
    },
    /// CPE request while an ACS request is outstanding.
    #[error("unexpected request {method} while awaiting a response")]
    UnexpectedRequest {
        /// Method name.
        method: String,
    },
    /// Host call not valid in current state.
    #[error("{call} is not valid in state {state:?}")]
    Misuse {
        state: State,
        /// Host method name.
        call: &'static str,
    },
    #[error("session has ended")]
    Ended,
}

/// One CWMP session with one CPE.
#[derive(Debug, Clone)]
pub struct Session {
    state: State,
    namespace: CwmpNamespace,
    cwmp_version: Option<String>,
    id_prefix: String,
    seq: u64,
    pending_cpe: Option<(Option<String>, Rpc)>,
    outstanding: Option<(String, String)>,
}

impl Session {
    /// `id_prefix` -> ACS request IDs unique across sessions.
    pub fn new(id_prefix: impl Into<String>) -> Self {
        Self {
            state: State::AwaitInform,
            namespace: CwmpNamespace::default(),
            cwmp_version: None,
            id_prefix: id_prefix.into(),
            seq: 0,
            pending_cpe: None,
            outstanding: None,
        }
    }

    pub fn state(&self) -> State {
        self.state
    }

    /// CPE namespace. Replies use the same.
    pub fn namespace(&self) -> CwmpNamespace {
        self.namespace
    }

    /// CWMP version from `SupportedCWMPVersions`, if CPE sent it.
    pub fn cwmp_version(&self) -> Option<&str> {
        self.cwmp_version.as_deref()
    }

    pub fn is_ended(&self) -> bool {
        self.state == State::Ended
    }

    /// One HTTP request body in. `None` = empty POST.
    pub fn receive(&mut self, input: Option<Envelope>) -> Result<Step, SessionError> {
        match self.state {
            State::AwaitInform => self.receive_inform(input),
            State::CpeTurn => self.receive_cpe_turn(input),
            State::AwaitResponse => self.receive_response(input),
            State::Ended => Err(SessionError::Ended),
            state => Err(SessionError::Misuse {
                state,
                call: "receive",
            }),
        }
    }

    fn receive_inform(&mut self, input: Option<Envelope>) -> Result<Step, SessionError> {
        let Some(env) = input else {
            return Err(SessionError::ExpectedInform {
                got: "empty".into(),
            });
        };
        let Body::Rpc(rpc @ Rpc::Inform(_)) = env.body else {
            let got = match &env.body {
                Body::Rpc(r) => r.name().to_owned(),
                Body::Fault(_) => "Fault".into(),
            };
            return Err(SessionError::ExpectedInform { got });
        };
        self.namespace = env.namespace;
        self.cwmp_version = env
            .header
            .supported_cwmp_versions
            .as_deref()
            .and_then(negotiate_version);
        self.pending_cpe = Some((env.header.id, rpc.clone()));
        self.state = State::InformPending;
        Ok(Step::CpeRequest(rpc))
    }

    fn receive_cpe_turn(&mut self, input: Option<Envelope>) -> Result<Step, SessionError> {
        let Some(env) = input else {
            self.state = State::AcsTurn;
            return Ok(Step::AcsTurn { completed: None });
        };
        let rpc = match env.body {
            Body::Fault(_) => {
                return Err(SessionError::UnexpectedResponse {
                    method: "Fault".into(),
                });
            }
            Body::Rpc(Rpc::Inform(_)) => return Err(SessionError::UnexpectedInform),
            Body::Rpc(r) if r.is_response() => {
                return Err(SessionError::UnexpectedResponse {
                    method: r.name().to_owned(),
                });
            }
            Body::Rpc(r) => r,
        };
        if !ACS_METHODS.contains(&rpc.name()) {
            let fault = Fault::new(
                FaultCode::ACS_METHOD_NOT_SUPPORTED.0,
                FaultCode::ACS_METHOD_NOT_SUPPORTED.description(),
            );
            return Ok(Step::Reply(
                self.envelope(env.header.id, Body::Fault(fault)),
            ));
        }
        self.pending_cpe = Some((env.header.id, rpc.clone()));
        self.state = State::CpeRequestPending;
        Ok(Step::CpeRequest(rpc))
    }

    fn receive_response(&mut self, input: Option<Envelope>) -> Result<Step, SessionError> {
        let (request_id, method) = self.outstanding.clone().ok_or(SessionError::Misuse {
            state: self.state,
            call: "receive",
        })?;
        let (outcome, id_matched) = match input {
            None => (Outcome::NoResponse, false),
            Some(env) => {
                let id_matched = env.header.id.as_deref() == Some(request_id.as_str());
                let outcome = match env.body {
                    Body::Fault(f) => Outcome::Fault(f),
                    Body::Rpc(Rpc::Inform(_)) => return Err(SessionError::UnexpectedInform),
                    Body::Rpc(r) if !r.is_response() => {
                        return Err(SessionError::UnexpectedRequest {
                            method: r.name().to_owned(),
                        });
                    }
                    Body::Rpc(r) if r.name().strip_suffix("Response") == Some(method.as_str()) => {
                        Outcome::Response(r)
                    }
                    Body::Rpc(r) => Outcome::Mismatch(r),
                };
                (outcome, id_matched)
            }
        };
        self.outstanding = None;
        self.state = State::AcsTurn;
        Ok(Step::AcsTurn {
            completed: Some(Completed {
                request_id,
                method,
                outcome,
                id_matched,
            }),
        })
    }

    /// Answer pending CPE request. `Ok` -> standard response, `Err(fault)` -> fault.
    /// Fault 8005 -> CPE retries later.
    /// Faulted Inform -> session end.
    pub fn answer(&mut self, outcome: Result<(), Fault>) -> Result<Reply, SessionError> {
        let response = match outcome {
            Err(fault) => return self.finish_answer(Body::Fault(fault)),
            Ok(()) => match self.pending_cpe.as_ref().map(|(_, r)| r) {
                Some(rpc) => default_response(rpc),
                None => {
                    return Err(SessionError::Misuse {
                        state: self.state,
                        call: "answer",
                    });
                }
            },
        };
        self.finish_answer(Body::Rpc(response))
    }

    /// Answer pending CPE request with own response (e.g. KickedResponse + URL).
    pub fn answer_with(&mut self, response: Rpc) -> Result<Reply, SessionError> {
        self.finish_answer(Body::Rpc(response))
    }

    fn finish_answer(&mut self, body: Body) -> Result<Reply, SessionError> {
        if !matches!(self.state, State::InformPending | State::CpeRequestPending) {
            return Err(SessionError::Misuse {
                state: self.state,
                call: "answer",
            });
        }
        let (id, _) = self.pending_cpe.take().ok_or(SessionError::Misuse {
            state: self.state,
            call: "answer",
        })?;
        let was_inform = self.state == State::InformPending;
        let is_fault = matches!(body, Body::Fault(_));
        let mut reply = self.envelope(id, body);
        if was_inform
            && !is_fault
            && let (Reply::Envelope(env), Some(v)) = (&mut reply, &self.cwmp_version)
        {
            env.header.use_cwmp_version = Some(v.clone());
        }
        self.state = if was_inform && is_fault {
            State::Ended
        } else {
            State::CpeTurn
        };
        Ok(reply)
    }

    /// ACS turn: send next request. `None` -> session end (HTTP 204).
    pub fn send(&mut self, rpc: Option<Rpc>) -> Result<Reply, SessionError> {
        if self.state != State::AcsTurn {
            return Err(SessionError::Misuse {
                state: self.state,
                call: "send",
            });
        }
        let Some(rpc) = rpc else {
            self.state = State::Ended;
            return Ok(Reply::Empty);
        };
        if rpc.is_response() || matches!(rpc, Rpc::Unknown { .. }) {
            return Err(SessionError::Misuse {
                state: self.state,
                call: "send (not a request)",
            });
        }
        self.seq += 1;
        let id = format!("{}-{}", self.id_prefix, self.seq);
        self.outstanding = Some((id.clone(), rpc.name().to_owned()));
        self.state = State::AwaitResponse;
        Ok(self.envelope(Some(id), Body::Rpc(rpc)))
    }

    fn envelope(&self, id: Option<String>, body: Body) -> Reply {
        Reply::Envelope(Envelope {
            namespace: self.namespace,
            header: Header {
                id,
                ..Header::default()
            },
            body,
        })
    }
}

/// Standard response to a CPE request.
fn default_response(rpc: &Rpc) -> Rpc {
    match rpc {
        Rpc::Inform(_) => InformResponse { max_envelopes: 1 }.into(),
        Rpc::GetRPCMethods(_) => GetRPCMethodsResponse {
            method_list: ACS_METHODS.iter().map(|m| (*m).to_owned()).collect(),
        }
        .into(),
        Rpc::TransferComplete(_) => TransferCompleteResponse {}.into(),
        Rpc::AutonomousTransferComplete(_) => AutonomousTransferCompleteResponse {}.into(),
        Rpc::DUStateChangeComplete(_) => DUStateChangeCompleteResponse {}.into(),
        Rpc::AutonomousDUStateChangeComplete(_) => {
            AutonomousDUStateChangeCompleteResponse {}.into()
        }
        Rpc::RequestDownload(_) => RequestDownloadResponse {}.into(),
        _ => KickedResponse::default().into(),
    }
}

/// Highest version in a `SupportedCWMPVersions` list that this ACS supports.
pub fn negotiate_version(supported: &str) -> Option<String> {
    supported
        .split(',')
        .filter_map(|v| {
            let (major, minor) = v.trim().split_once('.')?;
            Some((major.parse::<u32>().ok()?, minor.parse::<u32>().ok()?))
        })
        .filter(|&v| v <= MAX_CWMP_VERSION)
        .max()
        .map(|(major, minor)| format!("{major}.{minor}"))
}
