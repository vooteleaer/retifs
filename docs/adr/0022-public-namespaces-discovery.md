# ADR-0022: Public namespaces and discovery over standard announces

- **Status:** proposed (draft)
- **Date:** 2026-10-21
- **Irreversible:** partly. The announce's aspect and app_data format are read by other nodes and tools; once public namespaces announce with them, changing them needs a version field (included below).

## Context
A *public* namespace is one whose address (writer and read key) its owner chooses to publish: anyone may read it, the way anyone may read a NomadNet page. Today an address has to be passed by hand. People should be able to find public namespaces near them and further away, from the desktop utility's Find, without a central directory (vision: no central server, no global names).

Reticulum already has a discovery mechanism: the announce. NomadNet nodes, LXMF peers and relay-chat hubs all use it, each with its own aspect and a few hundred bytes of app_data, and clients build their lists from what they hear. Transport nodes forward announces, keep the path table, rate-limit them to a share of each interface's bandwidth (2 % by default) and hold back floods (ingress control). Using it means every RNS tool and transport node handles retifs discovery like any other application's.

## Principles
- "Works over any medium" and "needs no infrastructure": discovery rides on Reticulum itself.
- No global namespace: names in announces are claims; the user names what they keep (petnames, [ADR-0020](0020-sharing-names-invitations.md)).
- No new crypto: announces are signed by Reticulum; the address in them is published on purpose.

## Decision

### Public namespaces announce themselves
- Each public namespace has its own RNS destination, aspect `retifs.public`, and announces with the standard mechanism. Its app_data is canonical msgpack:
  ```text
  { "v": 1, "name": str, "about": str (short), "tags": [str], "addr": bin 64 (writer ‖ read key) }
  ```
  It must fit an announce: about 300 bytes in total, so `about` and `tags` are short. A longer description lives in the namespace itself (a record `type=retifs.about`).
- Announced at start, on change, and a few times a day, like NomadNet nodes; never more often, so it costs the network what a NomadNet node costs.
- Making a namespace public is an explicit act (`retifs ns publish NS`); stopping it stops the announces. Copies already announced and mirrored stay readable, as for any address given out.

### Finding them
- **Near:** every node keeps the `retifs.public` announces it hears (name, about, tags, hops, when). That list is Find's "public" scope, the way NomadNet's network list is built.
- **Further:** directory channels (signed lists of public namespaces someone curates, followed like any channel, [ADR-0015](0015-signed-channels.md)) and public search nodes that follow public namespaces and index them (openly: their read keys are public), answering the whole query language.
- **Following** a public namespace mirrors it like a channel; a saved query may span public namespaces.

### Members find each other's nodes in the namespace, not in announces
- Announcing "this node belongs to namespace X" would tell the whole network who shares what. Instead, each member writes its node address into the namespace next to the identity it already publishes there ([ADR-0017](0017-multi-writer-namespaces.md)). Other members read it (it's encrypted like everything in the namespace) and sync with every member's node, not just the one they joined through. Nodes themselves are found by their ordinary `retifs.node` announces.
- This makes sync independent of one hub: in the soak test of 2026-10-21, a member whose only peer lost its path stopped syncing although two other members had everything.

### Prns
Prns 0.3.8 passes app_data with each heard announce (`Diagnostic::AnnounceHeard`), which is enough to keep a list of heard public namespaces. 0.3.7, which retifs used until 2026-10-21, left it out. Prns also keeps each destination's app_data (`DestinationIdentity::app_data`, as Python RNS's `Identity.recall_app_data`), but its snapshot (`DestinationIdentitySnapshot`) doesn't expose it, so app_data heard before retifs started listening can't be recalled. Exposing that is a small upstream change (asked for in [Prns#306](https://github.com/KenAKAFrosty/Prns/issues/306), see [recon](../recon/prns-issue-app-data.md)); until then app_data can't be read on Prns nodes (retifs recognises its storage nodes by identity for the same reason).

## Impact on the threat model
- **Who reads a public namespace** isn't visible to its owner (fetching is anonymous by default); its existence and its announce are visible to everyone, by design.
- **Searching** a public search node shows it the query, over an unidentified link: what's searched, not who searches; timing remains visible.
- **Spam:** anyone can announce anything. Transport rate limits bound the cost to the network; a proof-of-work stamp on the announce (as LXMF uses) can be required later; clients show hops and age and let the user hide sources.
- **Member node addresses** are visible to members only.

## Open
- A stamp on `retifs.public` announces, and how much.
- Tags: free words, or a small convention (type, language, region).
- Whether a node with many public namespaces announces each, or one summary destination with the list fetched over a link.
