//! retifs-setup.exe: installs retifs for the current user, no administrator
//! needed, and uninstalls it (`--uninstall`, from Apps & features).
//!
//! - The programs go to `%LOCALAPPDATA%\Programs\retifs`: retifsd, the
//!   retifs command, the Cloud Files provider, prnsd (Reticulum, bundled)
//!   and retifs-desktop, the utility in the notification area.
//! - retifs-desktop starts at login (`--autostart`) and starts Reticulum
//!   where none runs yet, then retifsd; nothing runs as a service.
//! - The folder is put on the user's PATH (for `retifs`), a Start menu
//!   shortcut is made, and Apps & features lists it.
//! - Uninstalling removes all that and leaves the user's data: the store in
//!   `%LOCALAPPDATA%\retifs` and Reticulum's `%USERPROFILE%\.reticulum`.
#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(windows)]
mod setup;

#[cfg(windows)]
fn main() {
    setup::run();
}

#[cfg(not(windows))]
fn main() {
    eprintln!("retifs-setup is the Windows installer");
}
