//! Path parse: never panic. Parsed path -> Display -> parse = same path.
#![no_main]

use libfuzzer_sys::fuzz_target;
use dhonomos_datamodel::Path;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    if let Ok(p) = Path::parse(s) {
        let text = p.to_string();
        let again = Path::parse(&text).expect("displayed path must parse");
        assert_eq!(again, p, "{s:?} -> {text:?}");
        let _ = p.template();
    }
});
