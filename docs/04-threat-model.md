# Threat model (draft)

Every crypto decision is checked against this.

## Adversaries

| Adversary | Sees / gets | Must not get |
|---|---|---|
| **Pinning node** | encrypted chunks, their (padded) size, request timing | content, structure (which chunks belong together), attributes, who the owner is |
| **Foreign machine** (thin client) | what the session capability allows, during the session | root or device key; any rights after the session ends |
| **Network observer** | RNS traffic patterns | content, CIDs (the Link is encrypted) |
| **Malicious co-author** (in a group) | everything they were granted | un-narrowed rights, forging others' signatures, rewriting history |
| **Former member** | what they already received | new content after key rotation |
| **Sybil / spammer** | cheap identities | unlimited storage, announces, attributes (stamps, quotas) |
| **Lost/stolen YubiKey or stick** | nothing (a stick without the key is noise) | the identity; the device key is revoked by the root |

## Known leaks
- Chunk count and size class, request timing.
- Public content under a convergent key: anyone can check whether someone has a known file. This is accepted, since the content is public.
- Lease renewal timing (mitigation: delegated renewal).

## Open
- Compromised bootstrap (needs Secure Boot / measured boot).
- Metadata timing analysis of live queries.
- Sybil attacks on the DHT/discovery (rnfs uses node age).
