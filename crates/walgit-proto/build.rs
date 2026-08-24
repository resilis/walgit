#[path = "src/descriptor_lint.rs"]
mod descriptor_lint;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/walgit/v1/wal.proto");
    println!("cargo:rerun-if-changed=proto/walgit/v2/options.proto");
    println!("cargo:rerun-if-changed=proto/walgit/v2/control.proto");
    let mut cfg = prost_build::Config::new();
    cfg.bytes(["."]);
    cfg.boxed(".walgit.v2.WalTailEntry.ref_representation.ref_delta_catalog");
    cfg.boxed(".walgit.v2.RepoControl.pack_representation.pack_catalog");
    cfg.boxed(".walgit.v2.RepoControl.grant_representation.grant_catalog");
    let descriptor_path =
        std::path::PathBuf::from(std::env::var("OUT_DIR")?).join("walgit-descriptor.bin");
    cfg.file_descriptor_set_path(&descriptor_path);
    let protos = [
        "proto/walgit/v1/wal.proto",
        "proto/walgit/v2/options.proto",
        "proto/walgit/v2/control.proto",
    ];
    let descriptors = cfg.load_fds(&protos, &["proto"])?;
    // Decode the raw descriptor bytes so custom options remain available. The
    // prost-types intermediate intentionally drops unknown extension fields.
    let descriptor_bytes = std::fs::read(&descriptor_path)?;
    let pool = prost_reflect::DescriptorPool::decode(descriptor_bytes.as_slice())?;
    descriptor_lint::lint_v2_descriptors(&pool).map_err(std::io::Error::other)?;
    cfg.compile_fds(descriptors)?;
    Ok(())
}
