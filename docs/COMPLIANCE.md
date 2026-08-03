# Regulatory positioning

**This is not legal advice.** It is a description of design choices made so that the project stays
inside the boundaries that separate open-source protocol research from regulated financial activity.
Anyone deploying this, or anything derived from it, must take their own advice in their own
jurisdiction.

---

## 1. What this project is

An MIT-licensed reference implementation published for research and education. Concretely:

- **No live network.** There is no mainnet, no public node, no peer-to-peer layer at all. The chain
  runs in-process for tests and demonstrations.
- **No token exists.** DECKX is a unit of account inside a test program. No instrument has been
  issued, transferred to anyone, or made available for acquisition.
- **No sale, ever.** No ICO, no IEO, no presale, no private round, no airdrop, no allocation, no
  vesting schedule for founders or contributors. There is nothing to buy.
- **No treasury, premine, or founder allocation.** The genesis coinbase pays a key derived from the
  publicly documented seed phrase `deckxcoin/genesis/rekt`. Anyone reading the source can derive
  that key. It controls no value because the network does not exist.
- **No custody.** The project holds nothing on anyone's behalf. There is no wallet service, no
  exchange, no bridge, no order book, and no counterparty.
- **No returns are promised or implied.** Nothing in this repository or on the website states or
  suggests that anything here will appreciate, generate yield, or produce profit.

The name — *Decky Decentralized Coin Exchange* — describes the protocol's ability to express atomic
swaps between parties. It does not describe an operated exchange, and none exists.

---

## 2. Why the Howey factors are not met

The US test asks whether there is (1) an investment of money, (2) in a common enterprise, (3) with an
expectation of profit, (4) derived from the efforts of others. The design deliberately fails all
four:

| Factor | Status here |
|---|---|
| Investment of money | Nothing is sold or solicited. No consideration is accepted from anyone, in any form. |
| Common enterprise | There is no pooling. Each covenant guards individual outputs belonging to individual parties — this is the structural point of the whole design (see §3). |
| Expectation of profit | No performance, yield, appreciation, or return is described anywhere. The README and website both open with a "not audited, no live network, no value" warning. |
| Efforts of others | No team is promised to build value. The repository is a finished artefact with documented limitations, not a roadmap toward a product. |

The equivalent tests elsewhere — the EU's MiCA definitions of asset-referenced and e-money tokens,
the UK FCA's specified-investment perimeter, Singapore's PSA, and Indonesia's Bappebti/OJK regime for
crypto assets — all key on issuance, offering, custody, or operation of a trading venue. This project
does none of those things.

---

## 3. The architecture is the compliance argument

This is the part worth reading, because it is a design decision rather than a disclaimer.

**Contracts here cannot custody value.** `ContractAccount` has no `balance` field. Value sent to a
contract address remains an ordinary UTXO owned by whoever the contract will authorise. The contract
answers one question — *may this specific transaction spend this specific output?* — and nothing
else.

The consequences:

- **No pooling.** There is no shared pot for multiple parties to contribute to, which is the
  structural feature that turns a smart contract into a common enterprise.
- **No issuance primitive.** There is no `mint`, no token standard, no fungible-claim abstraction.
  The library ships five covenants — TimeVault, Escrow, Vesting, MultiSig, AtomicSwap — and every
  one is a *spending condition*, not an instrument.
- **No operator.** A covenant, once deployed, has no admin key, no upgrade path, no pause switch,
  and no privileged address. Nobody can be compelled to act because nobody has the power to.
- **No cross-contract calls.** Without `CALL`/`DELEGATECALL`, contracts cannot compose into the
  lending, pooling, and yield structures that attract securities and lending regulation.

A protocol that structurally cannot pool third-party funds is a very different object from one that
merely promises not to.

---

## 4. Deliberate omissions

Things a "DeFi launch" would include, left out on purpose:

- token issuance / minting primitives
- liquidity pools, AMMs, or order books
- staking, lending, borrowing, or yield mechanisms
- governance tokens or on-chain voting over a treasury
- wrapped or bridged representations of external assets
- fee capture to any project-controlled address
- a foundation, a DAO, or any entity with a claim on protocol revenue

The block subsidy pays whoever mines the block. There is no protocol fee, and no address that
accrues value by virtue of the design.

---

## 5. AML/CFT posture

Because the project neither operates a network nor provides any service, it is not a virtual asset
service provider under FATF's definition, and no KYC obligation attaches to publishing source code.

That said, a real deployment would inherit obligations the code does not address today:

- **Travel rule** — no originator/beneficiary data flows exist in the transaction format.
- **Sanctions screening** — no address screening hooks exist, and adding them at the consensus layer
  would be a censorship mechanism, which is its own problem.
- **The AtomicSwap covenant** is dual-use. Atomic swaps are how trustless cross-chain trading works;
  they are also a technique for avoiding intermediaries who would otherwise perform screening.
  Anyone operating a service around it should assume it is in scope for money-transmission rules.

These are stated because pretending otherwise would be worse than the gap itself.

---

## 6. Privacy and data protection

- **No personal data is collected.** The website is static HTML served by GitHub Pages, with no
  analytics, no cookies, no trackers, no fonts or scripts from third-party hosts, and no
  network requests other than fetching its own `chain.json`. There is nothing to consent to.
- **The chain stores no personal data.** Addresses are hashes of public keys. The 80-byte `memo`
  field is free-form and could carry personal data if someone put it there — but nothing in the
  protocol writes it, and immutable ledgers are in tension with erasure rights, which is why the
  field is capped and documented rather than expanded.

---

## 7. If you fork this

Publishing code is generally protected. Operating a network, issuing an asset, taking custody,
running a venue, or marketing an investment is not. Adding any of the following moves the project
across that line and you should get advice **before** shipping, not after:

- a public network with a token that can be acquired for value
- a sale, distribution, or airdrop of any kind
- a treasury, foundation allocation, or protocol fee
- custody of anyone's keys or funds
- an order book, matching engine, or swap interface you operate
- marketing that mentions price, returns, yield, or appreciation

---

## 8. Standing warning

> **DeckxCoin is not audited. There is no live network. DECKX is not available for purchase and has
> no price. Nothing here is financial, investment, tax, or legal advice. Do not place value in this
> software.**

This warning appears in the README, on the website, and in the whitepaper, in the same words.
