//! Haiku's file system module interface (`<drivers/fs_interface.h>`,
//! `<drivers/module.h>`, `<fs_info.h>`), as userlandfs's `haiku_kernel`
//! interface loads it. Only what this module uses is typed; the other
//! operations are left empty (`None`), which the VFS treats as unsupported.

#![allow(non_camel_case_types, dead_code)]

use std::ffi::{c_char, c_int, c_void};

pub type status_t = i32;
pub type dev_t = i32;
pub type ino_t = i64;
pub type off_t = i64;
pub type partition_id = i32;
pub type port_id = i32;

pub const B_OK: status_t = 0;
pub const B_MODULE_INIT: i32 = 1;
pub const B_MODULE_UNINIT: i32 = 2;
/// `open_query` flags (`<fs_query.h>`).
pub const B_LIVE_QUERY: u32 = 1 << 0;

pub const B_FS_IS_READONLY: u32 = 0x0000_0001;
pub const B_FS_IS_PERSISTENT: u32 = 0x0000_0004;
pub const B_FS_IS_SHARED: u32 = 0x0000_0008;
pub const B_FS_HAS_MIME: u32 = 0x0001_0000;
pub const B_FS_HAS_ATTR: u32 = 0x0002_0000;
pub const B_FS_HAS_QUERY: u32 = 0x0004_0000;


pub const B_DEV_NAME_LENGTH: usize = 128;
pub const B_FILE_NAME_LENGTH: usize = 256;
pub const B_OS_NAME_LENGTH: usize = 32;

#[repr(C)]
pub struct module_info {
    pub name: *const c_char,
    pub flags: u32,
    /// Declared variadic in C (`status_t (*)(int32, ...)`); every caller
    /// passes the operation only, and on x86_64 a callee reading just the
    /// first integer argument is call-compatible.
    pub std_ops: Option<unsafe extern "C" fn(op: i32) -> status_t>,
}

#[repr(C)]
pub struct fs_info {
    pub dev: dev_t,
    pub root: ino_t,
    pub flags: u32,
    pub block_size: off_t,
    pub io_size: off_t,
    pub total_blocks: off_t,
    pub free_blocks: off_t,
    pub total_nodes: off_t,
    pub free_nodes: off_t,
    pub device_name: [c_char; B_DEV_NAME_LENGTH],
    pub volume_name: [c_char; B_FILE_NAME_LENGTH],
    pub fsh_name: [c_char; B_OS_NAME_LENGTH],
}

#[repr(C)]
pub struct fs_volume {
    pub id: dev_t,
    pub partition: partition_id,
    pub layer: i32,
    pub private_volume: *mut c_void,
    pub ops: *mut fs_volume_ops,
    pub sub_volume: *mut fs_volume,
    pub super_volume: *mut fs_volume,
    pub file_system: *mut file_system_module_info,
    pub file_system_name: *mut c_char,
}

#[repr(C)]
pub struct fs_vnode {
    pub private_node: *mut c_void,
    pub ops: *mut fs_vnode_ops,
}

/// An operation this module doesn't provide: pointer-sized, always `None`.
pub type Unused = Option<unsafe extern "C" fn()>;

type Vol = *mut fs_volume;
type Node = *mut fs_vnode;
type Cookie = *mut c_void;
type Dirent = *mut libc::dirent;
type Stat = *mut libc::stat;

#[repr(C)]
pub struct fs_volume_ops {
    pub unmount: Option<unsafe extern "C" fn(Vol) -> status_t>,
    pub read_fs_info: Option<unsafe extern "C" fn(Vol, *mut fs_info) -> status_t>,
    pub write_fs_info: Unused,
    pub sync: Option<unsafe extern "C" fn(Vol) -> status_t>,
    pub get_vnode: Option<unsafe extern "C" fn(Vol, ino_t, Node, *mut c_int, *mut u32, bool) -> status_t>,

    pub open_index_dir: Option<unsafe extern "C" fn(Vol, *mut Cookie) -> status_t>,
    pub close_index_dir: Option<unsafe extern "C" fn(Vol, Cookie) -> status_t>,
    pub free_index_dir_cookie: Option<unsafe extern "C" fn(Vol, Cookie) -> status_t>,
    pub read_index_dir: Option<unsafe extern "C" fn(Vol, Cookie, Dirent, usize, *mut u32) -> status_t>,
    pub rewind_index_dir: Option<unsafe extern "C" fn(Vol, Cookie) -> status_t>,
    pub create_index: Unused,
    pub remove_index: Unused,
    pub read_index_stat: Option<unsafe extern "C" fn(Vol, *const c_char, Stat) -> status_t>,

    pub open_query: Option<unsafe extern "C" fn(Vol, *const c_char, u32, port_id, u32, *mut Cookie) -> status_t>,
    pub close_query: Option<unsafe extern "C" fn(Vol, Cookie) -> status_t>,
    pub free_query_cookie: Option<unsafe extern "C" fn(Vol, Cookie) -> status_t>,
    pub read_query: Option<unsafe extern "C" fn(Vol, Cookie, Dirent, usize, *mut u32) -> status_t>,
    pub rewind_query: Option<unsafe extern "C" fn(Vol, Cookie) -> status_t>,

    pub all_layers_mounted: Unused,
    pub create_sub_vnode: Unused,
    pub delete_sub_vnode: Unused,
}

#[repr(C)]
pub struct fs_vnode_ops {
    pub lookup: Option<unsafe extern "C" fn(Vol, Node, *const c_char, *mut ino_t) -> status_t>,
    pub get_vnode_name: Option<unsafe extern "C" fn(Vol, Node, *mut c_char, usize) -> status_t>,
    pub put_vnode: Option<unsafe extern "C" fn(Vol, Node, bool) -> status_t>,
    pub remove_vnode: Unused,

    pub can_page: Unused,
    pub read_pages: Unused,
    pub write_pages: Unused,
    pub io: Unused,
    pub cancel_io: Unused,
    pub get_file_map: Unused,

    pub ioctl: Unused,
    pub set_flags: Unused,
    pub select: Unused,
    pub deselect: Unused,
    pub fsync: Option<unsafe extern "C" fn(Vol, Node, bool) -> status_t>,

    pub read_symlink: Unused,
    pub create_symlink: Unused,
    pub link: Unused,
    pub unlink: Unused,
    pub rename: Unused,

    pub access: Option<unsafe extern "C" fn(Vol, Node, c_int) -> status_t>,
    pub read_stat: Option<unsafe extern "C" fn(Vol, Node, Stat) -> status_t>,
    pub write_stat: Unused,
    pub preallocate: Unused,

    pub create: Unused,
    pub open: Option<unsafe extern "C" fn(Vol, Node, c_int, *mut Cookie) -> status_t>,
    pub close: Option<unsafe extern "C" fn(Vol, Node, Cookie) -> status_t>,
    pub free_cookie: Option<unsafe extern "C" fn(Vol, Node, Cookie) -> status_t>,
    pub read: Option<unsafe extern "C" fn(Vol, Node, Cookie, off_t, *mut c_void, *mut usize) -> status_t>,
    pub write: Unused,

    pub create_dir: Unused,
    pub remove_dir: Unused,
    pub open_dir: Option<unsafe extern "C" fn(Vol, Node, *mut Cookie) -> status_t>,
    pub close_dir: Option<unsafe extern "C" fn(Vol, Node, Cookie) -> status_t>,
    pub free_dir_cookie: Option<unsafe extern "C" fn(Vol, Node, Cookie) -> status_t>,
    pub read_dir: Option<unsafe extern "C" fn(Vol, Node, Cookie, Dirent, usize, *mut u32) -> status_t>,
    pub rewind_dir: Option<unsafe extern "C" fn(Vol, Node, Cookie) -> status_t>,

    pub open_attr_dir: Option<unsafe extern "C" fn(Vol, Node, *mut Cookie) -> status_t>,
    pub close_attr_dir: Option<unsafe extern "C" fn(Vol, Node, Cookie) -> status_t>,
    pub free_attr_dir_cookie: Option<unsafe extern "C" fn(Vol, Node, Cookie) -> status_t>,
    pub read_attr_dir: Option<unsafe extern "C" fn(Vol, Node, Cookie, Dirent, usize, *mut u32) -> status_t>,
    pub rewind_attr_dir: Option<unsafe extern "C" fn(Vol, Node, Cookie) -> status_t>,

    pub create_attr: Unused,
    pub open_attr: Option<unsafe extern "C" fn(Vol, Node, *const c_char, c_int, *mut Cookie) -> status_t>,
    pub close_attr: Option<unsafe extern "C" fn(Vol, Node, Cookie) -> status_t>,
    pub free_attr_cookie: Option<unsafe extern "C" fn(Vol, Node, Cookie) -> status_t>,
    pub read_attr: Option<unsafe extern "C" fn(Vol, Node, Cookie, off_t, *mut c_void, *mut usize) -> status_t>,
    pub write_attr: Unused,
    pub read_attr_stat: Option<unsafe extern "C" fn(Vol, Node, Cookie, Stat) -> status_t>,
    pub write_attr_stat: Unused,
    pub rename_attr: Unused,
    pub remove_attr: Unused,

    pub create_special_node: Unused,
    pub get_super_vnode: Unused,

    pub test_lock: Unused,
    pub acquire_lock: Unused,
    pub release_lock: Unused,
}

#[repr(C)]
pub struct file_system_module_info {
    pub info: module_info,
    pub short_name: *const c_char,
    pub pretty_name: *const c_char,
    pub flags: u32,

    pub identify_partition: Unused,
    pub scan_partition: Unused,
    pub free_identify_partition_cookie: Unused,
    pub free_partition_content_cookie: Unused,

    pub mount: Option<unsafe extern "C" fn(Vol, *const c_char, u32, *const c_char, *mut ino_t) -> status_t>,

    pub get_supported_operations: Unused,
    pub validate_resize: Unused,
    pub validate_move: Unused,
    pub validate_set_content_name: Unused,
    pub validate_set_content_parameters: Unused,
    pub validate_initialize: Unused,
    pub shadow_changed: Unused,
    pub defragment: Unused,
    pub repair: Unused,
    pub resize: Unused,
    pub move_: Unused,
    pub set_content_name: Unused,
    pub set_content_parameters: Unused,
    pub initialize: Unused,
    pub uninitialize: Unused,
}

// Provided to the module by userlandfs's libuserlandfs_haiku_kernel, as the
// kernel provides them to kernel file systems.
unsafe extern "C" {
    pub fn publish_vnode(volume: Vol, id: ino_t, private_node: *mut c_void, ops: *mut fs_vnode_ops, mode: c_int, flags: u32) -> status_t;
    pub fn get_vnode(volume: Vol, id: ino_t, private_node: *mut *mut c_void) -> status_t;
    pub fn put_vnode(volume: Vol, id: ino_t) -> status_t;
    pub fn notify_query_entry_created(port: port_id, token: i32, device: dev_t, directory: ino_t, name: *const c_char, node: ino_t) -> status_t;
    pub fn notify_query_entry_removed(port: port_id, token: i32, device: dev_t, directory: ino_t, name: *const c_char, node: ino_t) -> status_t;
}
