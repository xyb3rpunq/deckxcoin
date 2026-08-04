# Design notes

Why each decision was made, including the ones that look wrong at first glance.
Read alongside the source — every section names the file it applies to.

---

## 1. Why UTXO, not accounts

`src/tx.ts`, `src/state.ts`

Two reasons, in order of how much they actually drove the choice:

**Payment channels.** Volt needs a funding output that two parties jointly own and can spend into
competing commitment transactions, only one of which is ever broadcast. That is natural in a UTXO
model — the funding output is a specific coin with a specific 2-of-2 condition — and awkward in an
account model, where "the same balance spent two different ways" has no representation.

**Parallel validation.** Inputs name their own history, so signature checking fans out across cores
without a scheduler. Ethereum is spending EIP-7928 (block-level access lists, targeted for
Glamsterdam in H2 2026) to *recover* this property by declaring up front which state a block
touches. A UTXO chain never gave it up.

The cost is real: a UTXO chain has no natural place to put "a contract's balance", which is exactly
why §3 below exists.

---

## 2. Why proof-of-work

`src/block.ts`

The whitepaper's argument in §4 is that one-CPU-one-vote is the only way to establish an ordering
without a trusted identity registry. Staking reintroduces exactly the "who is allowed to vote"
question that PoW dissolves — the stake set is an identity registry with extra steps.

Nothing since 2008 has invalidated that argument. The serious objections to PoW are about energy,
which is a different axis and not one this project is positioned to resolve.

Genesis difficulty is `0x1f00ffff` (≈ 2⁻¹⁶, about 65 536 expected attempts) rather than Bitcoin's
`0x1d00ffff`. That is a deliberate choice: **a genesis block nobody can reproduce is a genesis block
nobody can audit.** Anyone can re-mine this one on a laptop in under a second and confirm the hash
matches. Mainnet parameters would raise it.

---

## 3. Why contracts hold no balance

`src/state.ts`, `src/chain.ts`

This is the central design decision, so it gets the longest justification.

The obvious way to add contracts to a UTXO chain is to give contract accounts a balance field and
let them receive and send. That reproduces Ethereum's failure mode: a contract becomes a pot, and a
bug in the contract drains everyone's deposit at once. Every large Ethereum exploit — The DAO,
Parity, and most of the DeFi incident list since — has that shape.

DeckxCoin instead makes a contract an **authoriser, never a custodian**:

- `ContractAccount` has `code`, `storage`, `deployedAt`, `deployer`. No `balance`.
- Value sent to a contract address stays an ordinary UTXO in the UTXO set.
- `balanceOf()` sums UTXOs like it does for any other address.
- Spending a contract-locked UTXO requires the contract to approve *that specific transaction*.

A bug in a vault contract affects that vault's own outputs and nothing else. There is no shared pot.

**The covenant rule** (`src/chain.ts`, `applyTransaction`):

1. spending transaction must be `kind === 'call'`;
2. `contract.target` must equal the locking address;
3. the contract must execute successfully and return a non-zero first word;
4. if a second word is returned, some output must pay that address.

Rule 4 is the non-obvious one. Without it an approval is a bearer token: anyone observing a valid
approved call can rebroadcast it with the outputs pointing at themselves. Tested in
`test/covenant.test.ts` → *"an approval cannot be redirected to a different recipient"*.

---

## 4. Why there is no CALL opcode

`src/vm.ts`

Cross-contract reentrancy is the single largest source of value lost on Ethereum. The usual
mitigation is a discipline — checks-effects-interactions, or a mutex — which relies on every
developer remembering it every time.

DeckxCoin contracts are **leaves**. They can read chain context and their own storage. They cannot
call another contract. That removes reentrancy as a bug class rather than mitigating it.

The cost is composability: no contract can build on another. For a chain whose contract use-case is
*spending conditions on outputs*, that is a price worth paying. A chain aiming at DeFi would have to
pay differently.

Also removed, and why:

- **SELFDESTRUCT** — state that can vanish underneath a pending transaction, with no remaining
  legitimate use.
- **Unbounded BALANCE** — a contract may read only its own balance. Probing arbitrary accounts is a
  privacy leak with no use case here.

---

## 5. Why SHA-256 everywhere instead of Keccak

`src/crypto.ts`

One hash family means one set of domain-separation rules to get right. `taggedHash(tag, ...)` uses
the BIP-340 construction — `SHA256(SHA256(tag) ‖ SHA256(tag) ‖ data)` — so a digest computed for one
purpose is never valid for another. Two different structures cannot produce the same preimage.

Adding Keccak would buy Ethereum tooling compatibility and cost a second primitive plus a second set
of domain tags. Since the DVM is not EVM-bytecode-compatible anyway, the compatibility was never
available to buy.

---

## 6. Why the state trie is binary, not hexary Merkle-Patricia

`src/merkle.ts`

Ethereum's MPT gives a canonical root over the world state and O(log n) inclusion proofs.
`SparseMerkleTrie` gives both, using a sorted binary tree with domain-tagged leaves and branches — no
node types, no RLP, no path compression.

It is roughly a tenth of the code, which is a tenth of the surface area for a **state-root
divergence bug**, the hardest class of consensus failure to debug. The tradeoff is proof size and
update cost, neither of which binds at this scale.

One deliberate difference from the transaction tree: an odd node is **promoted**, not duplicated, so
there is no CVE-2012-2459 analogue in the state trie.

---

## 7. CVE-2012-2459, kept visible

`src/merkle.ts`

Bitcoin's transaction Merkle tree duplicates the last element on odd levels. That allowed an
attacker to construct two distinct blocks with the same Merkle root, one of which was invalid —
letting them poison a node's view. Bitcoin Core patched it by marking such blocks invalid.

DeckxCoin keeps the duplication rule for whitepaper fidelity (§7) and **rejects the construction at
build time** with a named error. It is easier to reason about a rule you can see fail than a rule
that silently never triggers.

---

## 8. Why txids exclude witness data

`src/tx.ts`

`serializeTx(tx, { withSignatures: false })` omits `pubkey`, `signature`, `cosign` and `preimage`.
Two consequences:

- **Non-malleability from genesis.** Nobody can change a transaction's id by re-encoding its
  signature. Bitcoin only achieved this with segwit in 2017; here it is the day-one behaviour, which
  is what makes a Volt commitment safe to reference before it is broadcast.
- **Signing is well-defined.** The digest cannot depend on a field that only exists after the digest
  has been signed. (This was an actual bug during development — the first version included `pubkey`
  in the txid preimage and every signature failed verification.)

`wtxid()` commits to witness data for the cases that need it.

---

## 9. Why the sighash commits to the prevout

`src/tx.ts`, `sighash()`

BIP-143's fix. Each input signs a digest covering the whole transaction *plus* the value and address
of the output being spent. Without that, a wallet can be tricked into signing away a larger UTXO
than it was shown, because the signature does not commit to what it is spending.

The quadratic-hashing problem of Bitcoin's original SIGHASH is also not reproduced — the transaction
body is serialised once, not once per input.

---

## 10. Why Volt revocation keys need elliptic curve arithmetic

`src/volt/secrets.ts`

The requirement: a public key that **both** parties can compute (so the owner can commit to it in
its own `to_local` output), whose **private** key only the counterparty can ever compute, and only
after being handed the per-commitment secret.

A hash construction cannot do this. Whoever can hash the inputs can produce the secret — and the
owner knows its own per-commitment secret from the moment it generates it. So BOLT-03's construction
is used unmodified:

```
h₁ = H(revocationBasepoint ‖ perCommitmentPoint)
h₂ = H(perCommitmentPoint ‖ revocationBasepoint)

revocationPubkey = revocationBasepoint·h₁ + perCommitmentPoint·h₂
revocationSecret = revocationBaseSecret·h₁ + perCommitmentSecret·h₂
```

The group homomorphism is load-bearing. `test/primitives.test.ts` asserts
`pointCombine(...) == pointFromSecret(scalarCombine(...))` — the identity the whole scheme rests on.

Per-commitment secrets use a hash chain of depth 4096: `secret(i) = H^(N-i)(seed)`. Revealing
secret *i* lets the counterparty derive every earlier secret by hashing forward, so storage is O(1)
rather than O(commitments). BOLT-03 uses a 48-bit indexed tree for the same property; the chain is
the same idea with a smaller index space.

---

## 11. Why the onion is exactly one size

`src/volt/onion.ts`

A one-hop route and a twenty-hop route produce byte-identical packets. Position in a route must not
be inferable from size.

The mechanism is BOLT-04's filler. Each hop shifts the routing block left and appends `HOP_SIZE`
bytes of keystream to the tail. Without a matching filler pre-computed by the sender, that tail
would decrypt to zeroes at the last hop — instantly revealing how many hops remain. The filler makes
the tail indistinguishable from ciphertext at every position.

**One substitution from the spec:** the stream cipher is SHA-256 in counter mode rather than
ChaCha20, to keep the dependency surface at one hash family. Both are PRFs keyed by the per-hop
shared secret; the security argument is unchanged.

`test/onion.test.ts` asserts the set of observed packet sizes across routes of 1, 2, 5, 12 and 20
hops has exactly one element.

---

## 12. Why pathfinding runs backwards

`src/volt/router.ts`

Each hop charges `base + amount · ppm`, so the amount hop *i* forwards depends on everything
downstream of it. Searching forward from the sender means the fee at each step is unknown.

Running Dijkstra **backwards from the destination** fixes this: at every step the amount is already
known, because it is the amount the previously-considered hop must receive.

Two subtleties that were bugs during development:

- **The sender pays no fee on its own outgoing channel.** A channel's fee is charged by the node
  forwarding *out* over it; the sender forwards nothing.
- **`totalCltv` is the first hop's incoming expiry, not the source's.** A channel's `cltv_delta` is a
  requirement its owner places on its own incoming HTLC. The sender has no incoming HTLC, so the
  delta on its outgoing channel does not apply to it.

The cost function is `fee + amount · riskFactor · cltvDelta`. The second term prices the opportunity
cost of locked funds — a cheap route that locks your money for a week is not cheap.

Because balances are private (capacity is public, the split is not), `findRoutes()` returns ranked
alternatives and the sender is expected to retry. `payInvoice()` does exactly that, excluding the
channel that failed.

---

## 13. The onion payload off-by-one

`src/volt/network.ts`

Payload *i* is read by `hops[i].to` and describes what **that node must send onward** — the
parameters of hop *i+1*, not hop *i*.

This is the classic Lightning implementation bug. Get it wrong and every hop believes it is entitled
to the fee of the hop before it; the route fails at the second node with a cryptic "fee
insufficient". It was a real bug here, caught by
`test/volt.test.ts` → *"END TO END: Alice pays Carol through Bob, atomically"*.

---

## 14. Gas accounting, and where it is simplified

`src/vm.ts`, `src/chain.ts`

Kept from Ethereum:

- charged **before** each opcode, so out-of-gas can never leave a half-applied write;
- out-of-gas consumes the full limit — that is what makes spam expensive;
- SSTORE costs 20 000 for zero→non-zero, 2 900 to overwrite, with a 4 800 refund on clear;
- refunds capped at 20 % of gas used (EIP-3529), so they cannot be farmed into gas tokens;
- 24 576-byte code limit (EIP-170), bounding worst-case validation.

**Simplified:** there is no refund output. `checkTx` requires the fee to cover
`gasLimit × gasPrice` as an upfront reservation; `applyTransaction` requires it to cover
`gasUsed × gasPrice` as the settlement. Unused reservation stays with the miner as a tip.

Adding a true refund means either mutating an output's value after execution (breaking the sighash)
or a protocol-level change output (a new transaction shape). Both are v0.2 problems.

---

## 15. Determinism, stated precisely

`src/vm.ts`

Execution is a pure function of `(code, calldata, context, storage)`. The context carries only
`blockNumber`, `blockTime`, `caller`, `callValue` and a balance lookup — all fixed once the block is
fixed. No clock, no randomness, no I/O.

Two nodes replaying the same block always reach the same state root.

The corollary worth stating out loud: **there is no on-chain randomness.** A contract needing it must
take it from calldata and live with the fact that the caller chose it.

---

## 16. What the block header commits to

`src/block.ts`

```
version ‖ prevHash ‖ merkleRoot ‖ stateRoot ‖ time ‖ bits ‖ height ‖ nonce ‖ extraNonce
```

Bitcoin's header plus `stateRoot`. Bitcoin commits to transactions only; Ethereum commits to
transactions *and* the resulting world state, which is what lets a light client be told a contract's
storage value and verify it. DeckxCoin carries both commitments in one header.

`extraNonce` extends the search space once the 32-bit `nonce` is exhausted, so the miner never has to
touch the transaction set to keep searching.

---

## 17. Fork choice is work, not length

`src/chain.ts`

Most-accumulated-work, summing `2²⁵⁶ / (target + 1)` per header. The distinction from
longest-chain matters the instant difficulty varies: without it, a cheap low-difficulty branch with
more blocks can reorganise the honest chain.

`blocks.length` is still the height, and `chainWork` is still tracked — but only `chainWork` decides.

---

## Open questions

Things that are genuinely undecided rather than merely unimplemented:

- **Should covenant approvals be cacheable?** Re-running the contract for every spend is simple and
  obviously correct, but it means every full node re-executes. A commitment to the approval decision
  would let nodes skip it — at the cost of a new consensus object.
- **PTLCs vs HTLCs as the default.** The adaptor point is already carried on every channel. Switching
  settlement is a flag flip in the channel state machine, but it changes what a failed payment leaks.
- **Whether `extraNonce` belongs in the header at all.** Bitcoin puts it in the coinbase, which keeps
  the header at 80 bytes. Putting it in the header is simpler but breaks the "header is 80 bytes"
  convention that a lot of tooling assumes.
