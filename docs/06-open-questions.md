# Open questions

- **Project name.** `retifs` is a working title.
- **Names:** petnames, community namespaces (`community/…`), or both? Zooko's triangle.
- **Discovery:** Bloom filters in announces vs a DHT (the rnfs experience) vs a hybrid.
- **Scaling:** regional limiting of announces, hierarchy, path requests on demand.
- **Relationship with Prns:** upstream contributions vs fork policy, given one dominant maintainer.
- **Pinning economics:** reciprocity vs an exchange mechanism.
- **Spam:** LXMF stamps on announces, pinning requests, attributes.
- **App identity on Linux:** how to bind a per-app capability to a process reliably without a sandbox (Flatpak/portal identity, executable hash, user prompt?).
- **Removal race:** which of a member's writes count when they were made offline, concurrently with that member's removal? Causal rule needed.
- **Padding overhead:** power-of-two classes plus the current chunker cost about 49 % extra storage. Align the chunker to the classes, or use finer classes? (ADR-0008)
- **Conflict UX:** how to show two heads to the user.
- **Range/geo queries with a blind index** over the network.
- **YubiKey PIV vs OpenPGP**: depends on the firmware.
- **Haiku hardware, YubiKey and Rust support.**
- **How to relate to rnfs.** Contact the author?
