//! Packs the programs to install (the folder $RETIFS_SETUP_FILES) into one
//! zstd stream the installer carries: per file, u16 name length, name,
//! u64 length, bytes.
use std::io::Write;

fn main() {
    println!("cargo:rerun-if-env-changed=RETIFS_SETUP_FILES");
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("payload.zst");
    let mut packed = Vec::new();
    if let Ok(dir) = std::env::var("RETIFS_SETUP_FILES") {
        let mut entries: Vec<_> = std::fs::read_dir(&dir).expect("RETIFS_SETUP_FILES").flatten().filter(|e| e.path().is_file()).collect();
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            println!("cargo:rerun-if-changed={}", e.path().display());
            let name = e.file_name().to_string_lossy().into_owned();
            let data = std::fs::read(e.path()).unwrap();
            packed.extend_from_slice(&(name.len() as u16).to_le_bytes());
            packed.extend_from_slice(name.as_bytes());
            packed.extend_from_slice(&(data.len() as u64).to_le_bytes());
            packed.extend_from_slice(&data);
        }
    }
    let mut enc = zstd::Encoder::new(std::fs::File::create(&out).unwrap(), 19).unwrap();
    enc.write_all(&packed).unwrap();
    enc.finish().unwrap();
}
