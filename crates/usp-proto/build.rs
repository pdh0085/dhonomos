//! Rust types from the vendored BBF USP protobuf schemas.
//! `protox` (pure Rust) -> no `protoc` binary needed.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../proto");
    let files = ["usp-msg-1-5.proto", "usp-record-1-5.proto"];
    for f in files {
        println!("cargo:rerun-if-changed={proto_dir}/{f}");
    }
    let fds = protox::compile(files, [proto_dir])?;
    prost_build::Config::new().compile_fds(fds)?;
    Ok(())
}
