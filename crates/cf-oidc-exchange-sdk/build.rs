//! Generates the `oidc.exchange.v1` API from `openapi/oidc/exchange/v1/exchangev1.yaml`
//! into `OUT_DIR`, which `src/lib.rs` mounts as `v1`.
//!
//! The crate's features pick what is generated: the model types always, the
//! axum server with `server`, the reqwest client with `client`. Nothing
//! generated is checked in, so the spec is the only thing to edit.

use std::{env, error::Error, fs, path::PathBuf};

use openapi_to_rust::{
    CodeGenerator, GeneratorConfig, SchemaAnalyzer, TypeMapper,
    config::{ServerSection, ServerValidationSection},
    spec_source::{parse_spec, validate_oas_document},
};

const SPEC: &str = "openapi/oidc/exchange/v1/exchangev1.yaml";

/// The largest request body the server buffers. A token exchange carries one
/// OIDC token, a few KB at most.
const MAX_BODY_BYTES: usize = 16 * 1024;

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={SPEC}");

    let out_dir = PathBuf::from(env::var("OUT_DIR")?).join("exchangev1");
    let server = env::var_os("CARGO_FEATURE_SERVER").is_some();
    let client = env::var_os("CARGO_FEATURE_CLIENT").is_some();

    let config = GeneratorConfig {
        spec_path: SPEC.into(),
        output_dir: out_dir.clone(),
        module_name: "exchangev1".to_string(),
        enable_async_client: client,
        tracing_enabled: false,
        server: server.then(|| ServerSection {
            framework: "axum".to_string(),
            operations: vec!["tag:ExchangeService".to_string()],
            prune_models: false,
            validation: ServerValidationSection {
                max_body_bytes: MAX_BODY_BYTES,
                ..Default::default()
            },
        }),
        ..Default::default()
    };

    let spec = parse_spec(&fs::read_to_string(SPEC)?, SPEC)?;
    if let Some(warning) = validate_oas_document(&spec)? {
        println!("cargo:warning={warning}");
    }

    let mapper = TypeMapper::new(config.types.clone());
    let mut analysis = SchemaAnalyzer::with_type_mapper(spec, mapper)?.analyze()?;
    let generator = CodeGenerator::new(config).with_source_provenance(SPEC);
    let mut result = generator.generate_all(&mut analysis)?;

    // `include!` takes no inner attributes or inner doc comments, and the
    // generated module root opens with both. src/lib.rs says what they did.
    result.mod_file.content = result
        .mod_file
        .content
        .lines()
        .filter(|line| !line.starts_with("//!") && !line.starts_with("#!["))
        .collect::<Vec<_>>()
        .join("\n");

    // A file from a feature since turned off would otherwise linger. Nothing
    // includes it, but it's stale all the same.
    if out_dir.exists() {
        fs::remove_dir_all(&out_dir)?;
    }
    generator.write_files(&result)?;
    Ok(())
}
