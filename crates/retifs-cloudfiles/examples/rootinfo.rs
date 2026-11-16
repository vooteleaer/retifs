//! `cargo run -p retifs-cloudfiles --example rootinfo -- FOLDER`: the sync
//! root a folder is in, as Windows has it registered.

#[cfg(windows)]
fn main() {
    let dir = std::env::args().nth(1).expect("FOLDER");
    let id = cloud_filter::root::SyncRootId::from_path(std::path::Path::new(&dir)).expect("not in a sync root");
    let info = id.info().expect("its registration");
    println!("path {:?}", info.path());
    println!("population {:?}", info.population_type());
    println!("hydration {:?}", info.hydration_type());
}

#[cfg(not(windows))]
fn main() {}
