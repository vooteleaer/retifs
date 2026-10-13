#!/usr/bin/env python3
"""Throwaway recon benchmark: fetching many small chunks over RNS.

Measures how retifs-style chunk fetching behaves on a real RNS path:
  A  new Link per chunk
  B  one Link, one request per chunk
  C  one Link, batched requests (/get [id1..idN])

Chunks are deterministic (shake_256 of the chunk id), so the client verifies
every byte without the server sending hashes.

  server:  chunk_bench.py server [--config DIR]
  client:  chunk_bench.py client DEST_HASH [--config DIR] [--n 64] [--size 32768]

Attach to the node's running daemon (prnsd or rnsd) with a minimal config dir
that has no [interfaces], so a failed attach can't grab radios or ports:

  [reticulum]
    enable_transport = No
    share_instance = Yes
    rpc_key = <hex>        # needed when the daemon checks RPC auth
    # shared_instance_type = tcp / shared_instance_port = 37428 if the daemon uses TCP

The rpc_key is full_hash(transport identity private key) of the daemon. Without
it, shared-instance RPC fails ("digest sent was rejected"), and so do Links,
because the client can't get the first-hop timeout.
"""
import argparse
import hashlib
import statistics
import sys
import time

import RNS

APP, ASPECT = "retifsbench", "chunks"


def chunk(i: int, size: int) -> bytes:
    return hashlib.shake_256(f"retifs-bench-{i}".encode()).digest(size)


# ---------------------------------------------------------------- server

def run_server(args):
    RNS.Reticulum(args.config)
    ident = RNS.Identity()
    dest = RNS.Destination(ident, RNS.Destination.IN, RNS.Destination.SINGLE, APP, ASPECT)

    def get(path, data, request_id, link_id, remote_identity, requested_at):
        ids, size = data
        return [chunk(i, size) for i in ids]

    dest.register_request_handler("/get", response_generator=get, allow=RNS.Destination.ALLOW_ALL)
    print(f"server destination: {RNS.hexrep(dest.hash, delimit=False)}", flush=True)
    while True:
        dest.announce()
        time.sleep(30)


# ---------------------------------------------------------------- client

class Client:
    def __init__(self, dest_hash: bytes, timeout: float):
        self.dest_hash = dest_hash
        self.timeout = timeout
        if not RNS.Transport.has_path(dest_hash):
            RNS.Transport.request_path(dest_hash)
            t0 = time.time()
            while not RNS.Transport.has_path(dest_hash):
                if time.time() - t0 > timeout:
                    sys.exit("no path to server")
                time.sleep(0.1)
        self.ident = RNS.Identity.recall(dest_hash)
        self.hops = RNS.Transport.hops_to(dest_hash)

    def link(self) -> RNS.Link:
        out = RNS.Destination(self.ident, RNS.Destination.OUT, RNS.Destination.SINGLE, APP, ASPECT)
        link = RNS.Link(out)
        t0 = time.time()
        while link.status != RNS.Link.ACTIVE:
            if link.status == RNS.Link.CLOSED or time.time() - t0 > self.timeout:
                raise RuntimeError("link failed")
            time.sleep(0.01)
        return link

    def get(self, link: RNS.Link, ids, size):
        receipt = link.request("/get", [list(ids), size], timeout=self.timeout)
        while receipt.get_status() in (RNS.RequestReceipt.SENT, RNS.RequestReceipt.DELIVERED,
                                       RNS.RequestReceipt.RECEIVING):
            time.sleep(0.005)
        if receipt.get_status() != RNS.RequestReceipt.READY:
            raise RuntimeError(f"request failed (status {receipt.get_status()})")
        chunks = receipt.get_response()
        for i, c in zip(ids, chunks):
            if c != chunk(i, size):
                raise RuntimeError(f"chunk {i} corrupt")
        return len(chunks)


def report(name, n, size, seconds, extra=""):
    mbps = n * size * 8 / seconds / 1e6
    print(f"{name:<34} {n:>4} x {size // 1024:>2} KiB  {seconds:7.2f} s  "
          f"{seconds / n * 1000:7.1f} ms/chunk  {mbps:6.2f} Mbps  {extra}", flush=True)


def run_client(args):
    RNS.Reticulum(args.config)
    c = Client(bytes.fromhex(args.dest), args.timeout)
    n, size = args.n, args.size
    print(f"server is {c.hops} hop(s) away; {n} chunks of {size} bytes per pattern", flush=True)

    # A: new link per chunk
    setups = []
    t0 = time.time()
    for i in range(n):
        s = time.time()
        link = c.link()
        setups.append(time.time() - s)
        c.get(link, [i], size)
        link.teardown()
    report("A  new Link per chunk", n, size, time.time() - t0,
          f"(link setup median {statistics.median(setups) * 1000:.0f} ms)")

    # B: one link, one request per chunk
    link = c.link()
    t0 = time.time()
    for i in range(n):
        c.get(link, [i], size)
    report("B  one Link, request per chunk", n, size, time.time() - t0)

    # C: one link, batched
    for batch in args.batches:
        t0 = time.time()
        for start in range(0, n, batch):
            c.get(link, range(start, min(start + batch, n)), size)
        report(f"C  one Link, batch of {batch}", n, size, time.time() - t0)
    link.teardown()
    print("all chunks verified", flush=True)


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="mode", required=True)
    s = sub.add_parser("server")
    s.add_argument("--config")
    cl = sub.add_parser("client")
    cl.add_argument("dest")
    cl.add_argument("--config")
    cl.add_argument("--n", type=int, default=64)
    cl.add_argument("--size", type=int, default=32768)
    cl.add_argument("--batches", type=int, nargs="+", default=[8, 32, 64])
    cl.add_argument("--timeout", type=float, default=60)
    args = ap.parse_args()
    run_server(args) if args.mode == "server" else run_client(args)


if __name__ == "__main__":
    main()
