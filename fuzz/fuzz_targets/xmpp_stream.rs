//! Built-in XMPP server stream parser: never panic on any bytes, bounded buffer.
//! Same events for any read cuts: whole input vs small pieces -> same events if it parses,
//! error both ways if not (pieces may hit a size limit before the bad byte).
//!
//! 1st input byte -> stanza limit + piece size.
//! `starttls` or `auth` element -> stream restart (as the server after STARTTLS, SASL).
#![no_main]

use dhonomos_xmpp::{Condition, Event, MAX_STANZA, MAX_STANZA_PRE_AUTH, Parser};
use libfuzzer_sys::fuzz_target;

/// All parser output for `data`, fed `chunk` bytes at a time.
fn parse(data: &[u8], max: usize, chunk: usize) -> (Vec<Event>, Option<Condition>) {
    let mut p = Parser::new();
    p.set_max_stanza(max);
    let mut events = Vec::new();
    for piece in data.chunks(chunk) {
        p.feed(piece);
        loop {
            match p.next_event() {
                Ok(Some(event)) => {
                    if let Event::Stanza(el) = &event
                        && matches!(el.name.as_str(), "starttls" | "auth")
                    {
                        p.restart();
                    }
                    events.push(event);
                }
                Ok(None) => break,
                Err(c) => {
                    // Error = final.
                    assert_eq!(p.next_event(), Err(c));
                    return (events, Some(c));
                }
            }
        }
        // Waiting for more -> max 1 token of a stanza held back.
        assert!(p.buffered() <= max.max(4096), "{} bytes buffered", p.buffered());
    }
    (events, None)
}

fuzz_target!(|data: &[u8]| {
    let Some((&config, input)) = data.split_first() else {
        return;
    };
    let max = [64, 512, MAX_STANZA_PRE_AUTH, MAX_STANZA][usize::from(config & 3)];
    let chunk = 1 + usize::from(config >> 2);
    let (whole, whole_end) = parse(input, max, input.len().max(1));
    let (pieces, pieces_end) = parse(input, max, chunk);
    match whole_end {
        None => {
            assert_eq!(pieces_end, None);
            assert_eq!(pieces, whole);
        }
        Some(_) => {
            assert!(pieces_end.is_some(), "the pieces must reach the error too");
            assert!(pieces.len() <= whole.len());
            assert_eq!(pieces[..], whole[..pieces.len()]);
        }
    }
});
