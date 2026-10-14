//! The transport seam (ADR-0003): retifs talks to Reticulum only through this
//! trait, so Prns can be swapped or forked, and fetch logic can be tested with
//! an in-memory network.
//!
//! Only the client side is abstracted so far; serving `/retifs/get` is still
//! written against Prns request endpoints in `retifsd`.

use std::{future::Future, time::Duration};

use personal_rns::prelude::*;
use personal_rns::routing::links::LinkId;

pub trait Transport: Clone + Send + 'static {
    /// A remote node's address.
    type Peer: Copy + Send + Sync + 'static;
    /// An established, encrypted session with a peer.
    type Link: Copy + Send + Sync + 'static;

    /// Finds a path to `peer` and opens a link.
    fn connect(&self, peer: Self::Peer) -> impl Future<Output = Result<Self::Link, String>> + Send;

    /// A value both ends of `link` know and no other link shares (the RNS link
    /// ID). Proofs of access are bound to it so they can't be replayed elsewhere.
    fn link_nonce(&self, link: Self::Link) -> Vec<u8>;

    /// Sends a request to `endpoint` on `link` and waits for the response.
    fn request(
        &self,
        link: Self::Link,
        endpoint: &'static str,
        body: Vec<u8>,
    ) -> impl Future<Output = Result<Vec<u8>, String>> + Send;
}

/// Reticulum via a Prns node attached to the local shared instance.
#[derive(Clone)]
pub struct PrnsTransport {
    pub handle: PrnsNodeHandle,
    pub path_timeout: Duration,
}

impl PrnsTransport {
    pub fn new(handle: PrnsNodeHandle) -> Self {
        PrnsTransport { handle, path_timeout: Duration::from_secs(60) }
    }

    /// Requests a path, retrying: a single Prns path request can time out even
    /// when the destination is reachable (seen between two local clients of one prnsd).
    pub async fn ensure_path(&self, peer: DestinationHash) -> Result<(), String> {
        let deadline = tokio::time::Instant::now() + self.path_timeout;
        let mut last = String::from("no attempt");
        while tokio::time::Instant::now() < deadline {
            let left = deadline - tokio::time::Instant::now();
            match tokio::time::timeout(left, self.handle.request_path(peer)).await {
                Ok(Ok(_found)) => return Ok(()),
                Ok(Err(e)) => last = format!("{e:?}"),
                Err(_) => last = "timed out".into(),
            }
        }
        Err(format!("no path within {:?} (last: {last})", self.path_timeout))
    }

    /// Opens a link to a peer whose path is already known.
    pub async fn link(&self, peer: DestinationHash) -> Result<LinkId, String> {
        self.handle.establish_link(peer).await.map_err(|e| format!("link failed: {e:?}"))
    }
}

impl Transport for PrnsTransport {
    type Peer = DestinationHash;
    type Link = LinkId;

    fn link_nonce(&self, link: LinkId) -> Vec<u8> {
        link.as_bytes().to_vec()
    }

    fn connect(&self, peer: DestinationHash) -> impl Future<Output = Result<LinkId, String>> + Send {
        let this = self.clone();
        async move {
            this.ensure_path(peer).await?;
            this.link(peer).await
        }
    }

    fn request(
        &self,
        link: LinkId,
        endpoint: &'static str,
        body: Vec<u8>,
    ) -> impl Future<Output = Result<Vec<u8>, String>> + Send {
        let handle = self.handle.clone();
        async move {
            let (response, _rtt) = handle
                .request(link, RequestEndpointId::of(endpoint), &body)
                .await
                .map_err(|e| format!("{e:?}"))?;
            Ok(response.as_slice().to_vec())
        }
    }
}
