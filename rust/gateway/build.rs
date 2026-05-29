//! Build-time codegen do contrato gRPC (ADR-0091).
//!
//! Usa `protoc-bin-vendored` para fornecer o `protoc` sem depender de
//! instalação no sistema — o CI (`crate_release_audit.yml`) não instala
//! protoc, e `cargo clippy --workspace --all-targets` roda este build.rs.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    std::env::set_var("PROTOC", protoc);
    println!("cargo:rerun-if-changed=proto/audit_exposer.proto");
    tonic_build::compile_protos("proto/audit_exposer.proto")?;
    Ok(())
}
