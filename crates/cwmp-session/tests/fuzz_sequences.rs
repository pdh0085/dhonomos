//! Random inputs + host calls -> never panic; ended session stays ended.

use dhonomos_cwmp_codec::{
    CwmpNamespace, Envelope, Fault, GetRPCMethods, Inform, Reboot, RebootResponse, TransferComplete,
};
use dhonomos_cwmp_session::{Session, State};
use proptest::prelude::*;

#[derive(Debug, Clone)]
enum Op {
    Receive(u8),
    AnswerOk,
    AnswerFault,
    Send(bool),
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        (0u8..6).prop_map(Op::Receive),
        Just(Op::AnswerOk),
        Just(Op::AnswerFault),
        any::<bool>().prop_map(Op::Send),
    ]
}

fn input(k: u8) -> Option<Envelope> {
    let ns = CwmpNamespace::V1_0;
    match k {
        0 => None,
        1 => Some(Envelope::rpc(ns, "i", Inform::default())),
        2 => Some(Envelope::rpc(ns, "t", TransferComplete::default())),
        3 => Some(Envelope::rpc(ns, "s-1", RebootResponse {})),
        4 => Some(Envelope::rpc(ns, "g", GetRPCMethods {})),
        _ => Some(Envelope::rpc(ns, "r", Reboot::default())),
    }
}

proptest! {
    #[test]
    fn never_panics(ops in prop::collection::vec(op(), 0..40)) {
        let mut s = Session::new("p");
        let mut ended = false;
        for op in ops {
            let _ = match op {
                Op::Receive(k) => s.receive(input(k)).map(|_| ()),
                Op::AnswerOk => s.answer(Ok(())).map(|_| ()),
                Op::AnswerFault => s.answer(Err(Fault::new(8005, "Retry request"))).map(|_| ()),
                Op::Send(some) => s.send(some.then(|| Reboot::default().into())).map(|_| ()),
            };
            if ended {
                prop_assert_eq!(s.state(), State::Ended);
            }
            ended = s.is_ended();
        }
    }
}
