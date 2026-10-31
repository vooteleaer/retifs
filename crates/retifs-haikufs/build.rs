// On Haiku the module links against userlandfs's emulation of the kernel's
// file system calls (publish_vnode, get_vnode, ...). Elsewhere it builds empty.
fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("haiku") {
        println!("cargo:rustc-link-lib=dylib=userlandfs_haiku_kernel");
    }
}
