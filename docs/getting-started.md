# Getting started: two devices and the apps

This walks you through trying retifs on two of your own devices, then the apps on top of it. It takes about half an hour. Everything here is a **test release**: use copies of your photos and documents, not the only ones.

You'll need two devices: a computer (Windows or Linux) and a phone (Android), or two computers. Haiku works too.

## 1. Reticulum first

retifs runs on [Reticulum](https://reticulum.network) and joins the device's Reticulum *shared instance*; it never brings its own. Start one on each device:

- **Debian, Ubuntu, Raspberry Pi OS:** `sudo apt install ./prns_*.deb` from the [Prns packages for retifs](https://github.com/vooteleaer/Prns/releases) (a fork's build of upstream Prns, until Prns publishes packages): it starts `prnsd` in your session.
- **Windows, macOS:** Prns's own `prnsd` from the [Prns 0.3.8 release](https://github.com/KenAKAFrosty/Prns/releases/tag/v0.3.8): unpack it and run `prnsd`. On first start it writes a configuration with the automatic interfaces on; on a desktop it sits in the tray. Python's `rnsd` (`pip install rns`) works anywhere too.
- **Android:** install `personal-hopspot-*.apk` from the [Prns packages for retifs](https://github.com/vooteleaer/Prns/releases): Prns's Android app (a development build). Open it and start the node. Sideband or Columba may also work as the phone's shared instance, but haven't been tried.
- **Haiku:** install the `prns` package from the release; it starts `prnsd` at login.

The two devices must reach each other over Reticulum: on the same network they find each other by themselves (AutoInterface); otherwise give both the same TCP interface to a hub in their Reticulum config.

## 2. Install retifs

From the [release](https://github.com/vooteleaer/retifs/releases):

- **Windows 10/11:** run `retifs-setup-*.exe`. It installs for you only (no administrator) and puts the retifs utility in the notification area.
- **Debian, Ubuntu, Raspberry Pi OS:** `sudo apt install ./retifs_*.deb ./retifs-desktop_*.deb` (the second is the utility, a GTK app).
- **Android:** install `retifs-android-*.apk` (allow installing from your browser or file manager). Open it once: it starts retifs and stays running.
- **Haiku:** `pkgman install` the `prns` and `retifs` packages (or open them in Tracker), then restart.

Every install also joins the library **retifs-installers** by itself (nothing of it is fetched until you open it): new versions of retifs and the apps arrive there, through retifs. Leave it if you don't want it; it isn't joined again.

Open the utility (the tray icon, or the retifs app). It should say retifs is running and show this device. If it waits for Reticulum, check step 1.

## 3. Your first library

A **library** is where records live: "photos", "family", "work". Each has its own key.

1. In the utility: **New library**, name it `test`.
2. On Windows, it appears in Explorer under `C:\Users\<you>\retifs\test`. On Linux, mount it: `retifs mount test` (then `~/retifs/test`). On Haiku it's a volume in `~/retifs`.
3. Copy a few files in. They're now records, encrypted, with three copies kept as soon as other nodes are around.

## 4. The second device

1. On the first device, open the library's menu: **Invite…**, choose **Read and write**, **Make invitation**. Copy the link (or show the QR code).
2. On the second device: **Join a library** → **Join with link**, paste it.
3. In a moment the library is there too, with the same files. Change something on either side: the other follows. Turn one off, change things on both, turn it back on: both changes are kept.

Things to try:
- **Members…** shows who reads and writes. Removing someone rotates the library's key: they keep what they had, not what comes next.
- **Copy link** gives a read-only link for anyone you trust with everything in the library.
- **Leave library…** removes it from one device; **Delete everywhere…** (for those who may invite) removes it from every member's device.

## 5. The apps

The apps read the same libraries; none of them owns its data. They're demos of what retifs makes possible, and their code is in their own repositories: [Photos](https://github.com/vooteleaer/retifs-photos), [Map](https://github.com/vooteleaer/retifs-map), [Contacts](https://github.com/vooteleaer/retifs-contacts), [Calendar](https://github.com/vooteleaer/retifs-calendar), and the utility itself, [retifs-desktop](https://github.com/vooteleaer/retifs-desktop).

On Android, an app asks retifs before it may use any library: open it, tap **Choose libraries…**, and allow it in retifs (which libraries, and whether it may add to them).

### Photos

- **Android:** install `retifs-photos-android-*.apk`. It backs up the phone's camera pictures into a library you choose (Backup tab), each with its thumbnails, so every device shows them at once. Long-press to select: star (favourite), **+** to put them in albums. Optionally, what's backed up leaves the phone (to its trash) and the library is where your photos are.
- **Windows, Linux, Haiku:** the photos are in the library's folder like any files, and albums under `Albums/<album>/`. On Linux and Haiku there's also the Photos app (`retifs-photos` package).
- An album can be moved to another library with all its photos: open it and tap the library's name at the top.

### Map

Install `retifs-map-android-*.apk` (or the `retifs-map` package on Linux and Haiku). It shows everything that says where it is: your photos, contacts' addresses, events. The map itself comes from retifs libraries, not the internet: in the retifs app, **Announces** lists public libraries heard on the network (a map of Estonia and its places, for example); join one and the map has tiles and search.

### Contacts and Calendar

On Linux (`retifs-contacts`, `retifs-calendar` packages): an address book in your own library `me`, and calendars, one per library holding events. A family's calendar is a library shared with the family. On Haiku, contacts are People files in the `me` volume, and Calendar is the `retifs_calendar` package.

## When something goes wrong

- Logs: Windows `%LOCALAPPDATA%\retifs\logs\`; Linux `journalctl --user -u retifsd`; Android `adb logcat | grep -i retifs`.
- `retifs nodes` shows the other nodes this one knows; `retifs ns info <library>` what a library has and who's in it.
- Please report issues at <https://github.com/vooteleaer/retifs/issues>, with what you did, what you expected and what happened.
