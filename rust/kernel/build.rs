//! build.rs — SkillRegistry codegen (PROP-031 / ADR-031b)
//!
//! Le skill_registry.yaml e skill_revocation.yaml em build-time.
//! Gera OUT_DIR/skill_registry_generated.rs com arrays de hashes compilados.
//! Zero heap no runtime: dados estaticos no binario (nao lidos em disco).
//!
//! Principio de Jonas: registry vazio -> warn, nao falha build.
//! Falha de parse do YAML -> falha o build (fail-secure).

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    let manifest_dir = PathBuf::from(
        env::var("CARGO_MANIFEST_DIR")
            .unwrap_or_else(|_| panic!("build.rs: CARGO_MANIFEST_DIR nao definido — ambiente Cargo corrompido")),
    );
    // Caminho relativo ao workspace root (dois niveis acima de rust/kernel/)
    let data_dir = manifest_dir.join("..").join("..").join("data").join("policies");

    let registry_path   = data_dir.join("skill_registry.yaml");
    let revocation_path = data_dir.join("skill_revocation.yaml");

    // Rerun-if-changed: rebuild apenas quando YAMLs mudam
    println!("cargo:rerun-if-changed={}", registry_path.display());
    println!("cargo:rerun-if-changed={}", revocation_path.display());

    let allowed  = load_hashes(&registry_path,   "skills");
    let revoked  = load_hashes(&revocation_path, "revoked");

    if allowed.is_empty() {
        println!("cargo:warning=SkillRegistry: allowed list vazia — fail-open ativo (dev mode)");
    }

    let out_dir = PathBuf::from(
        env::var("OUT_DIR")
            .unwrap_or_else(|_| panic!("build.rs: OUT_DIR nao definido — ambiente Cargo corrompido")),
    );
    let out_file  = out_dir.join("skill_registry_generated.rs");

    let content = format!(
        "// GERADO AUTOMATICAMENTE por build.rs — nao editar\n\
         pub static ALLOWED_SKILL_HASHES: &[[u8; 32]] = &[{}];\n\
         pub static REVOKED_SKILL_HASHES: &[[u8; 32]] = &[{}];\n",
        hashes_to_rust(&allowed),
        hashes_to_rust(&revoked),
    );

    fs::write(&out_file, content)
        .unwrap_or_else(|e| panic!("build.rs: falha ao escrever {}: {}", out_file.display(), e));
}

fn load_hashes(path: &Path, key: &str) -> Vec<[u8; 32]> {
    if !path.exists() {
        println!("cargo:warning=SkillRegistry: {} nao encontrado — usando lista vazia", path.display());
        return vec![];
    }

    let content = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("build.rs: falha ao ler {}: {}", path.display(), e));

    // Parser YAML minimo — evita dependencia serde_yaml no build script
    // Aceita: "  - <hex64>" por linha sob a chave especificada
    let mut in_section = false;
    let mut hashes = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with(&format!("{}:", key)) {
            in_section = true;
            continue;
        }
        if in_section {
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if let Some(stripped) = trimmed.strip_prefix("- ") {
                let hex = stripped.trim();
                if hex == "[]" { break; }
                hashes.push(parse_blake3_hex(hex, path));
            } else if !trimmed.starts_with(' ') && !trimmed.starts_with('-') {
                break; // nova chave YAML — sai da secao
            }
        }
    }

    hashes
}

fn parse_blake3_hex(hex: &str, source: &Path) -> [u8; 32] {
    if hex.len() != 64 {
        panic!(
            "build.rs: hash invalido em {} — esperado 64 chars hex BLAKE3, obtido {} chars: '{}'",
            source.display(), hex.len(), hex
        );
    }
    let mut bytes = [0u8; 32];
    for i in 0..32 {
        bytes[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .unwrap_or_else(|_| panic!(
                "build.rs: hex invalido '{}' em {}", &hex[i*2..i*2+2], source.display()
            ));
    }
    bytes
}

fn hashes_to_rust(hashes: &[[u8; 32]]) -> String {
    hashes
        .iter()
        .map(|h| {
            let inner: Vec<String> = h.iter().map(|b| format!("0x{:02x}", b)).collect();
            format!("[{}]", inner.join(", "))
        })
        .collect::<Vec<_>>()
        .join(", ")
}
