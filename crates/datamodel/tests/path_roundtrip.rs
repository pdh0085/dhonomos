//! Property test: any path AST -> Display -> parse -> same AST.
#![allow(clippy::unwrap_used)]

use dhonomos_datamodel::{Expr, Op, Path, RefIndex, RelStep, Segment, Target};
use proptest::prelude::*;

fn name() -> impl Strategy<Value = String> {
    "[A-Za-z_][A-Za-z0-9_-]{0,12}"
}

fn plain_step() -> impl Strategy<Value = RelStep> {
    name().prop_map(|name| RelStep {
        name,
        index: None,
        deref: false,
    })
}

fn ref_step() -> impl Strategy<Value = RelStep> {
    (
        name(),
        prop_oneof![
            Just(None),
            (1u32..100).prop_map(|n| Some(RefIndex::Item(n))),
            Just(Some(RefIndex::All)),
        ],
        any::<bool>(),
    )
        .prop_map(|(name, index, deref)| RelStep {
            name,
            deref: deref || index.is_some(),
            index,
        })
}

fn expr() -> impl Strategy<Value = Expr> {
    let op = prop_oneof![
        Just(Op::Eq),
        Just(Op::Ne),
        Just(Op::Lt),
        Just(Op::Gt),
        Just(Op::Le),
        Just(Op::Ge),
    ];
    let value = prop_oneof![
        ".{0,16}".prop_map(|v| (v, true)),
        "[A-Za-z0-9.:_-]{1,16}".prop_map(|v| (v, false)),
    ];
    (prop::collection::vec(ref_step(), 1..3), op, value).prop_map(|(path, op, (value, quoted))| {
        Expr {
            path,
            op,
            value,
            quoted,
        }
    })
}

fn selector() -> impl Strategy<Value = Segment> {
    prop_oneof![
        (1u32..10_000).prop_map(Segment::Instance),
        Just(Segment::Placeholder),
        Just(Segment::Wildcard),
        "[A-Za-z][A-Za-z0-9_-]{0,10}".prop_map(Segment::Alias),
        prop::collection::vec(expr(), 1..3).prop_map(Segment::Search),
    ]
}

fn path() -> impl Strategy<Value = Path> {
    // (name + optional selector) x1..5; target != Object -> one more name at the end.
    let body = prop::collection::vec((plain_step(), prop::option::of(selector())), 1..6);
    let target = prop_oneof![
        Just(Target::Object),
        Just(Target::Parameter),
        Just(Target::Command),
        Just(Target::Event),
    ];
    (body, target, plain_step()).prop_map(|(body, target, last)| {
        let mut segments = Vec::new();
        for (step, sel) in body {
            segments.push(Segment::Name(step));
            segments.extend(sel);
        }
        if target != Target::Object {
            segments.push(Segment::Name(last));
        }
        Path { segments, target }
    })
}

proptest! {
    #[test]
    fn display_then_parse_is_identity(p in path()) {
        let text = p.to_string();
        let parsed = Path::parse(&text).map_err(|e| TestCaseError::fail(e.to_string()))?;
        prop_assert_eq!(parsed, p, "text: {}", text);
    }

    #[test]
    fn parser_never_panics(s in "[A-Za-z0-9.\\[\\]{}*=!<>&#+\"()_-]{0,40}") {
        let _ = Path::parse(&s);
    }
}
