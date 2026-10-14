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
}

impl Transport for PrnsTransport {
    type Peer = DestinationHash;
    type Link = LinkId;

    fn connect(&self, peer: DestinationHash) -> impl Future<Output = Result<LinkId, String>> + Send {
        let handle = self.handle.clone();
        let timeout = self.path_timeout;
        async move {
            tokio::time::timeout(timeout, handle.request_path(peer))
                .await
                .map_err(|_| format!("no path within {timeout:?}"))?
                .map_err(|e| format!("path request failed: {e:?}"))?;
            handle.establish_link(peer).await.map_err(|e| format!("link failed: {e:?}"))
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
