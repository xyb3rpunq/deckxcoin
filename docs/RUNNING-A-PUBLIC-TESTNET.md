# Running a public testnet

This is the honest version of "make the network live": real nodes, on real
machines, reachable from the internet, that strangers can join.

It does **not** make DECKX worth money, and nothing in this document is aimed
at that. See [COMPLIANCE.md](COMPLIANCE.md) for why, and the section at the
bottom of this file for what "value" would actually require.

---

## What "live" means here

A live network is four things:

1. **Reachable nodes.** At least two, on separate machines, with inbound P2P
   ports open. One node is not a network.
2. **A way for newcomers to find them.** DNS seeds, or published
   `host:port#identity` strings.
3. **Blocks being produced.** Someone has to mine, or the chain sits still.
4. **Something to look at.** An explorer backed by a live node, so the network
   is observable without running one.

Everything below is achievable with the code in this repository. None of it is
implemented as hosted infrastructure, because that needs servers somebody pays
for and a domain somebody owns.

---

## 0. The short version

```bash
curl -fsSL https://raw.githubusercontent.com/xyb3rpunq/deckxcoin/main/chain/scripts/deploy.sh \
  | sudo bash -s -- --network testnet --gateway --faucet --mine dxc1q…
```

`chain/scripts/deploy.sh` installs Node if the system has something older,
creates an unprivileged `deckxd` user, writes a hardened systemd unit, opens
the P2P and gateway ports — and only those — starts the service, checks the
genesis hash, and prints the `host:port#identity` string to publish.

Run it with `--dry-run` first: it prints the plan and the exact unit file
without touching the machine.

`--uninstall` removes the service and leaves the datadir alone, because
deleting somebody's identity key and faucet wallet is not a decision a script
gets to make.

The rest of this document is what that script does, and why.

### Testing it without a server

You do not need a VPS to find out whether it works.

```bash
./chain/scripts/test-deploy-docker.sh
```

runs the whole thing in a container booted with systemd as PID 1 — install,
service active and *not restart-looping*, unprivileged user, 0700 datadir, the
gateway refusing all seven dangerous methods, an idempotent second run, and an
uninstall that keeps the keys. Two minutes, locally, and the container is thrown
away afterwards.

The same checks run on every change to the script in
[`.github/workflows/deploy-test.yml`](../.github/workflows/deploy-test.yml),
because a GitHub Actions runner is also a real Ubuntu machine with systemd —
free for public repositories, and destroyed after each run, which makes it the
one place it is safe to let a script create system users and start services as
root.

Its first run found that `deploy.sh` rejected `--faucet-reserve`, and the first
Docker run found that a Windows checkout gives the script CRLF endings that fail
on Linux with an error pointing at bash options. Neither was reachable from a
laptop without one of these.

---

## 1. Seed nodes

Two small VPS instances are enough. Each needs an open TCP port and a datadir
that survives restarts.

```bash
# On each host
git clone https://github.com/xyb3rpunq/deckxcoin.git
cd deckxcoin/chain && npm install

node src/deckxd.ts \
  --network testnet \
  --datadir /var/lib/deckxd \
  --host 0.0.0.0 \
  --port 19333 \
  --rpcport 19332
```

`--host 0.0.0.0` is the part that makes it public. The default is loopback,
deliberately: a node should not become reachable because somebody forgot a
flag.

On first start the node generates a long-term identity and prints it. Publish
it alongside the address:

```
seed1.example.org:19333#a3f1…            ← the identity is the important half
```

A newcomer pins it:

```bash
node src/deckxd.ts --network testnet --datadir ./data \
     --connect seed1.example.org:19333#a3f1…
```

**Publish the identity, not just the host.** Without it, a newcomer's first
connection is trust-on-first-use, and an attacker positioned on their path at
that moment is not detected. With it, they are.

### systemd

```ini
[Unit]
Description=DeckxCoin node
After=network-online.target

[Service]
Type=simple
User=deckxd
WorkingDirectory=/opt/deckxcoin/chain
ExecStart=/usr/bin/node src/deckxd.ts --network testnet --datadir /var/lib/deckxd --host 0.0.0.0
Restart=always
RestartSec=5
# The datadir holds the identity key and the chain. Nothing else needs it.
UMask=0077
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/deckxd

[Install]
WantedBy=multi-user.target
```

`SIGTERM` closes the database cleanly, so `systemctl stop` is safe. Killing a
node mid-write is the one reliable way to corrupt a datadir.

---

## 2. Peer discovery

Gossip fills a mesh once a node has *one* peer, so discovery only has to solve
the first connection.

**DNS seeds** are how Bitcoin does it: a hostname with several A records, each
pointing at a node.

```
seed.deckxcoin.example.  300  IN  A  203.0.113.10
seed.deckxcoin.example.  300  IN  A  198.51.100.22
```

`NetworkParams.seeds` in `src/params.ts` is where these go. It is empty today
because there are no public nodes to list, and listing hosts that do not exist
would be worse than listing none.

> DNS seeding trades one problem for another: whoever controls the DNS controls
> which peers a new node meets first. That is why the identity pin matters, and
> why a node maintains its own outbound connections from its own address book
> rather than trusting whatever dialled it.

---

## 3. Mining

Without a miner, a live network is a live network at height zero.

```bash
node src/deckxd.ts --network testnet --datadir /var/lib/deckxd \
     --host 0.0.0.0 --mine dxc1q… --mine-interval 30
```

Testnet difficulty (`0x1e00ffff`) is set so a single machine keeps the chain
moving. That also means a single machine can reorganise it — testnet security
is not a goal, and pretending otherwise would be dishonest.

Generate the mining address from a wallet you keep:

```bash
node scripts/create-funded-wallet.ts --amount 0 --out ./miner.txt
```

---

## 4. A faucet

A testnet nobody can get coins on is a testnet nobody uses.

```bash
node src/deckxd.ts --network testnet --datadir /var/lib/deckxd \
     --host 0.0.0.0 --gateway --faucet --faucet-amount 10
```

On first start it generates a wallet at `<datadir>/faucet.key` (mode 0600) and
prints its address. Mine to that address, or send it coins, and it starts
serving.

`src/node/faucet.ts` has four limits, each closing a hole the previous one
leaves open: per address (addresses are free, so this stops only double-clicks),
per IP or IPv6 /64 (catches a script generating fresh addresses), a rolling
24-hour cap (catches the proxy pool), and a reserve so a drained faucet says
"empty" rather than erroring at everybody until an operator notices.

Two failure modes it is built not to have:

- **Concurrent sends double-spending each other.** Requests arriving together
  read the same UTXO set and select the same coin. Sends are serialised, and
  `test/faucet.test.ts` fires five at once and asserts all five land.
- **Check-then-send.** The grant is recorded *before* the broadcast and rolled
  back if it fails, so two requests that pass the check together cannot both
  be paid.

The ledger is persisted next to the key file, because a faucet that forgets its
grants on restart is one you drain by crashing it.

---

## 5. A live explorer

The site in `web/` ships with a **static** `chain.json` generated by
`scripts/export-web-data.ts`. That snapshot is what makes the numbers on the
page reproducible, and it is what renders when no node is running.

`web/live.js` adds the other half. Point it at a gateway:

```json
{
  "gateways": ["https://seed1.example.org"],
  "expectedGenesis": "0000001f4c1c57f8…",
  "pollMs": 15000
}
```

in `web/data/network.json` — or append `?node=https://host&genesis=<hash>` to
the URL to try one without editing anything.

Three things this gets right, each of which is a way to be wrong:

- **The page never claims to be live when it is not.** The banner states
  `LIVE`, `SNAPSHOT`, `NODE UNREACHABLE` or `WRONG CHAIN`, and a failed refresh
  downgrades it rather than leaving stale numbers up as though they were still
  arriving. A snapshot silently presented as current invites somebody to make a
  decision on data that stopped moving weeks ago.
- **The genesis is checked before any live data is shown.** A node that answers
  is not necessarily a node on *your* chain — anyone running a local regtest
  will hit this. Set `expectedGenesis` to the network you actually run; the
  fallback is the snapshot's genesis, which is a mainnet-parameter scenario
  chain and will therefore refuse a testnet gateway.
- **The node's RPC is never what the browser talks to.** `--gateway` starts a
  separate read-only front end (`src/node/gateway.ts`) with a positive
  allowlist, a response cache keyed by method *and* parameters, and a token
  bucket per client. `generate`, `addnode`, `submitblock`, `sync`,
  `getpeerinfo` and `listbanned` are unreachable through it, and a test asserts
  they stay that way.

The allowlist is a list of what is *allowed*, not what is blocked. The
difference decides what happens the day somebody adds a method to the node: with
a denylist it is public the moment it exists.

---

## 6. What this costs

| Item | Rough cost |
|---|---|
| 2 × small VPS | $10–20 / month |
| Domain | $10–15 / year |
| TLS | free (Let's Encrypt) |
| Explorer hosting | free (static) + the proxy on an existing VPS |

---

## What "value" would actually require, stated plainly

This section exists because the question always comes, and answering it once
honestly is better than leaving it to be discovered the expensive way.

**A live network does not give a coin a price.** Running nodes proves the
software works. It does not create demand, and demand is the only thing that
creates price.

**Listing sites index chains, not ambitions.** DexScreener and similar tools
index decentralised-exchange pairs on chains they already support. A sovereign
L1 like DeckxCoin cannot appear on them at all — there is no pair, no DEX, and
no indexer. The only route is to abandon the L1, deploy a token contract on a
chain those tools *do* index, and create a liquidity pool.

**And that is where the arithmetic gets uncomfortable.** If you pair your token
with $500 of some real asset in a pool, the site will display a price and a
market capitalisation. Both are derived from your $500. Nothing was created.
Any amount above that has to come from someone else buying — and with no
product, no users and no revenue, one holder's gain is exactly another
holder's loss. That is not a market. It is a queue.

**This project is deliberately built so it cannot become that.** Contracts hold
no balance, there is no minting primitive, no pooling, no treasury, no address
that accrues protocol revenue, and no premine. Those are not oversights; they
are the design, and they are documented in
[COMPLIANCE.md](COMPLIANCE.md).

The genesis block carries the line *"Every exit liquidity was once someone
conviction."* A token with a small pool and no users is how that sentence
happens to somebody.

**What is actually worth something here** is the code: a chain with 398 tests,
BIP-340 verified against the official vectors, a working man-in-the-middle test,
reorganisation with undo records, and a wallet whose recovery test throws the
wallet away and rebuilds it from the words. That is a portfolio. A token with a
$500 pool is the opposite of one — it is the first thing an experienced
engineer looks for and the first reason they stop reading.
