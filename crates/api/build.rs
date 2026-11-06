//! Rerun on UI bundle change: rust-embed reads `ui/build` at compile time of this crate.
//! `ui/build` may be a link to a work dir (see scripts/build-ui.sh).
fn main() {
    println!("cargo:rerun-if-changed=../../ui/build");
}
