# Versions

One version for retifs and its apps (retifs-desktop, retifs-photos, retifs-map, retifs-contacts, retifs-calendar): a release of them all is `v0.MINOR.PATCH`, the same number in every repo.

- **A release** raises MINOR (`0.1.0`, `0.2.0`, …); a release that only fixes raises PATCH (`0.2.1`). Each repo's commit for it is tagged `v0.MINOR.PATCH`. Until 1.0 they're pre-releases on GitHub: formats may still change.
- **The version** is in each repo's `Cargo.toml` (`[workspace.package]` in the apps, each crate's `[package]` in retifs). Right after a release it's raised to the next one, so builds between releases are builds *towards* it.
- **A build between releases** is the next release's number, `dev` and the repo's commit count (`git rev-list --count HEAD`), which only grows, so newer builds always sort above older ones (a commit hash doesn't):

| | release `0.2.0` | build between releases |
|---|---|---|
| .deb | `0.2.0` | `0.2.0~dev.1234.5d4de2a` (`~` sorts below `0.2.0`) |
| Flatpak bundle | `org.retifs.Photos-0.2.0.flatpak` | `org.retifs.Photos-0.2.0-dev.1234.flatpak` |
| Haiku package | `retifs-0.2.0-1234` | `retifs-0.2.0-1234` (the revision is the commit count either way) |
| Android | `versionName 0.2.0`, `versionCode 1234` | `versionName 0.2.0-dev.1234`, `versionCode 1234` |
| Windows setup | `retifs-setup-0.2.0.exe` | `retifs-setup-0.2.0-dev.1234.exe` |

A build is the release's when its commit carries the tag `v` + the version; the build scripts look for it. Haiku packages are built from a copy of the sources without `.git`: their revision comes in as `REVISION` (the commit count), counted where the sources are copied from.

Every build made goes into the library retifs-installers too, and every release also to GitHub.
