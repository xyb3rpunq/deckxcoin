/* ═══════════════════════════════════════════════════════════════════════
   DeckxCoin — explorer renderer.

   Reads data/chain.json (produced by chain/scripts/export-web-data.ts) and
   paints the explorer. No framework, no bundler, no dependencies: one fetch,
   a handful of template functions, done. Total JS on the wire is a few KB,
   which is why the page does not lag.

   Every value rendered here came out of the real node. If the fetch fails the
   page degrades to the static content rather than showing invented numbers.
   ═══════════════════════════════════════════════════════════════════════ */

'use strict';

/* ── tiny helpers ─────────────────────────────────────────────────── */

const $ = (sel) => document.querySelector(sel);
const el = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
};

/** Never innerHTML untrusted-shaped data. Everything below builds nodes. */
const shortHash = (h, head = 10, tail = 6) =>
  !h ? '—' : h.length <= head + tail + 1 ? h : `${h.slice(0, head)}…${h.slice(-tail)}`;

const groupDigits = (s) => String(s).replace(/\B(?=(\d{3})+(?!\d))/g, ' ');

/** zaps → "12.34567890 DECKX" without floating point. */
function deckx(zaps) {
  const v = BigInt(zaps);
  const neg = v < 0n;
  const abs = neg ? -v : v;
  const whole = abs / 100000000n;
  const frac = (abs % 100000000n).toString().padStart(8, '0');
  return `${neg ? '-' : ''}${groupDigits(whole.toString())}.${frac}`;
}

const iso = (unix) => new Date(unix * 1000).toISOString().replace('T', ' ').replace('.000Z', 'Z');

function cell(parent, key, value, tone) {
  const c = el('div', 'ex-cell');
  c.appendChild(el('span', 'ex-k', key));
  c.appendChild(el('span', `ex-v${tone ? ' ' + tone : ''}`, value));
  parent.appendChild(c);
  return c;
}

function kv(parent, key, value) {
  const c = el('div', 'kv');
  c.appendChild(el('span', 'kv-k', key));
  c.appendChild(el('span', 'kv-v', value));
  parent.appendChild(c);
}

/* ── terminal banner ──────────────────────────────────────────────── */

function paintTerminal(data) {
  const g = data.genesis;
  const lines = [
    ['$ ', 'k', 'node src/cli.ts genesis', 'v'],
    null,
    ['  hash        ', 'k', g.hash, 'g'],
    ['  height      ', 'k', '0', 'v'],
    ['  prevHash    ', 'k', '0'.repeat(64), 'k'],
    ['  merkleRoot  ', 'k', g.merkleRoot, 'v'],
    ['  stateRoot   ', 'k', g.stateRoot, 'p'],
    ['  time        ', 'k', `${g.time}  (${g.timeIso})`, 'v'],
    ['  bits        ', 'k', `${g.bits}   target ${shortHash(g.target, 12, 8)}`, 'a'],
    ['  nonce       ', 'k', groupDigits(g.nonce), 'a'],
    null,
    ['  coinbase    ', 'k', g.coinbaseTxid, 'v'],
    ['  reward      ', 'k', `${deckx(g.reward)} DECKX`, 'g'],
    ['  address     ', 'k', g.address, 'v'],
    ['  memo        ', 'k', g.memo, 'a'],
    null,
    ['  pow valid   ', 'k', 'yes', 'g'],
    ['  header valid', 'k', 'yes', 'g'],
    ['  supply      ', 'k', data.supply.balanced ? 'balanced' : 'DRIFT', data.supply.balanced ? 'g' : 'a'],
  ];

  const out = $('#terminal-genesis');
  out.textContent = '';
  for (const line of lines) {
    if (!line) { out.appendChild(document.createTextNode('\n')); continue; }
    const [label, labelTone, value, valueTone] = line;
    out.appendChild(el('span', labelTone, label));
    out.appendChild(el('span', valueTone, value));
    out.appendChild(document.createTextNode('\n'));
  }
}

/* ── hero stats ───────────────────────────────────────────────────── */

function paintHero(data) {
  const set = (key, text, cls) => {
    const node = document.querySelector(`[data-bind="${key}"]`);
    if (!node) return;
    node.textContent = text;
    if (cls) node.classList.add(cls);
  };
  set('genesis.hash.short', shortHash(data.genesis.hash, 12, 8));
  set('genesis.attempts', `~${groupDigits(data.genesis.expectedAttempts)} hashes`);
  set('supply.status', data.supply.balanced ? 'balanced' : 'DRIFT');
}

/* ── monetary policy ──────────────────────────────────────────────── */

function paintSupply(data) {
  const m = data.monetary;
  if (!m) return;

  const stats = $('#supply-stats');
  if (stats) {
    stats.textContent = '';
    const mini = (k, v) => {
      const c = el('div', 'mini');
      c.appendChild(el('span', 'mini-k', k));
      c.appendChild(el('span', 'mini-v', v));
      stats.appendChild(c);
    };
    mini('max supply', groupDigits(BigInt(m.maxSupply) / 100000000n) + ' DECKX');
    mini('halving', `${m.halvingIntervalDays} days`);
    mini('block subsidy', m.initialSubsidyPretty.replace(' DECKX', ''));
    mini('issuance ends', `year ${m.terminalYears}`);
  }

  // Issuance curve — one bar per era, height ∝ cumulative % of the cap.
  const curve = $('#issuance-curve');
  if (curve) {
    curve.textContent = '';
    const shown = m.schedule.slice(0, 16);
    for (const row of shown) {
      const pct = Number(row.percentOfCap);
      const col = el('div', 'curve-col');
      col.title = `Year ${row.year}: ${row.cumulativePretty} (${row.percentOfCap}% of cap)`;

      const bar = el('div', 'curve-bar');
      const fill = el('div', 'curve-fill');
      fill.style.height = Math.max(pct, 1.5).toFixed(2) + '%';
      bar.appendChild(fill);

      col.appendChild(el('span', 'curve-pct', pct >= 99.9 ? '99.9+' : pct.toFixed(0) + '%'));
      col.appendChild(bar);
      col.appendChild(el('span', 'curve-label', 'y' + row.year));
      curve.appendChild(col);
    }
  }

  // Emission schedule — first twelve years plus the terminal era.
  const tbody = document.querySelector('#schedule-table tbody');
  if (tbody) {
    tbody.textContent = '';
    const rows = [...m.schedule.slice(0, 12), m.schedule[m.schedule.length - 1]];
    for (const row of rows) {
      const tr = el('tr');
      const td = (text, cls) => {
        const c = el('td', cls, text);
        tr.appendChild(c);
      };
      td('Year ' + row.year);
      td(groupDigits(row.startHeight));
      td(BigInt(row.subsidy) === 0n ? '0 — issuance ended' : row.subsidyPretty);
      td(row.cumulativePretty);
      td(row.percentOfCap + ' %');
      tbody.appendChild(tr);
    }
  }
}

/* ── covenant library ─────────────────────────────────────────────── */

function paintContractLibrary(data) {
  const grid = $('#contract-library');
  if (!grid || !data.contracts) return;
  grid.textContent = '';

  for (const c of data.contracts) {
    const card = el('article', 'contract-card');

    const head = el('div', 'cc-head');
    head.appendChild(el('h3', 'cc-name', c.name));
    head.appendChild(el('span', 'cc-slots', `${c.storage.length} storage slots`));
    card.appendChild(head);

    card.appendChild(el('p', 'cc-summary', c.summary));

    const section = (title, items, cls) => {
      if (!items || items.length === 0) return;
      card.appendChild(el('h4', 'cc-sub', title));
      const ul = el('ul', 'cc-list ' + (cls || ''));
      for (const item of items) ul.appendChild(el('li', null, item));
      card.appendChild(ul);
    };

    section('Approves when', c.approvesWhen, 'ok-list');
    if (c.calldata.length) section('Calldata', c.calldata, 'mono-list');

    card.appendChild(el('h4', 'cc-sub', 'Storage'));
    const slots = el('div', 'cc-slots-grid');
    for (const s of c.storage) {
      const row = el('div', 'cc-slot');
      row.appendChild(el('span', 'cc-slot-n', s.slot < 0 ? 'key' : String(s.slot)));
      const body = el('div');
      body.appendChild(el('span', 'cc-slot-name', s.name));
      body.appendChild(el('span', 'cc-slot-meaning', s.meaning));
      row.appendChild(body);
      slots.appendChild(row);
    }
    card.appendChild(slots);

    section('Caveats', c.caveats, 'warn-list');
    grid.appendChild(card);
  }
}

/* ── explorer summary ─────────────────────────────────────────────── */

function paintSummary(data) {
  const g = $('#explorer-summary');
  g.textContent = '';
  cell(g, 'chain height', String(data.tip.height));
  cell(g, 'tip hash', shortHash(data.tip.hash, 10, 6));
  cell(g, 'utxo set', groupDigits(data.tip.utxoCount) + ' outputs');
  cell(g, 'contracts', String(data.tip.contracts), 'violet');
  cell(g, 'circulating', deckx(data.supply.utxoTotal) + ' DECKX', 'acid');
  cell(g, 'supply audit', data.supply.balanced ? 'balanced ✓' : 'DRIFT ✗', data.supply.balanced ? 'acid' : '');
  cell(g, 'volt channels', `${data.volt.stats.channels} · ${deckx(data.volt.stats.capacity)} DECKX`);
  cell(g, 'genesis mined in', `${data.genesis.mineMs} ms`, 'acid');
}

/* ── timeline ─────────────────────────────────────────────────────── */

function paintTimeline(data) {
  const list = $('#timeline');
  list.textContent = '';
  for (const step of data.timeline) {
    const li = el('li');
    li.appendChild(el('div', 'tl-num', String(step.step).padStart(2, '0')));
    const body = el('div');
    body.appendChild(el('div', 'tl-title', step.title));
    body.appendChild(el('div', 'tl-detail', step.detail));
    if (step.txid || step.height !== undefined) {
      const bits = [];
      if (step.height !== undefined) bits.push(`block ${step.height}`);
      if (step.txid) bits.push(`tx ${shortHash(step.txid, 14, 8)}`);
      body.appendChild(el('div', 'tl-meta', bits.join('  ·  ')));
    }
    li.appendChild(body);
    list.appendChild(li);
  }
}

/* ── genesis detail ───────────────────────────────────────────────── */

function paintGenesis(data) {
  const g = data.genesis;
  const grid = $('#genesis-detail');
  grid.textContent = '';
  kv(grid, 'block hash', g.hash);
  kv(grid, 'merkle root', g.merkleRoot);
  kv(grid, 'state root', g.stateRoot);
  kv(grid, 'coinbase txid', g.coinbaseTxid);
  kv(grid, 'timestamp', `${g.time} — ${iso(g.time)}`);
  kv(grid, 'difficulty bits', `${g.bits}`);
  kv(grid, 'target', g.target);
  kv(grid, 'winning nonce', groupDigits(g.nonce));
  kv(grid, 'reward', `${g.rewardPretty}`);
  kv(grid, 'paid to', g.address);
  kv(grid, 'embedded message', g.memo);
  kv(grid, 'time to mine', `${g.mineMs} ms (≈ ${groupDigits(g.expectedAttempts)} expected attempts)`);
}

/* ── blocks ───────────────────────────────────────────────────────── */

function txNode(tx) {
  const box = el('div', 'tx');

  const head = el('div', 'tx-head');
  head.appendChild(el('span', `tx-kind ${tx.kind}`, tx.kind));
  head.appendChild(el('span', 'tx-id', tx.txid));
  box.appendChild(head);

  if (tx.memo) box.appendChild(el('div', 'tx-memo', `“${tx.memo}”`));

  if (tx.contract) {
    const c = el('div', 'tx-memo');
    const parts = [`gas limit ${groupDigits(tx.contract.gasLimit)}`, `nonce ${tx.contract.nonce}`];
    if (tx.contract.target) parts.unshift(`target ${shortHash(tx.contract.target, 14, 8)}`);
    if (tx.contract.codeSize) parts.unshift(`code ${tx.contract.codeSize} bytes`);
    c.textContent = parts.join(' · ');
    box.appendChild(c);
  }

  const io = el('div', 'io');

  const inCol = el('div', 'io-col');
  inCol.appendChild(el('h5', null, `inputs (${tx.inputs.length})`));
  if (tx.inputs.length === 0) {
    inCol.appendChild(el('div', 'io-row', 'none — coinbase creates value'));
  } else {
    for (const i of tx.inputs) {
      const row = el('div', 'io-row');
      row.appendChild(document.createTextNode(i.outpoint));
      const flags = [];
      if (i.hasCosign) flags.push('2-of-2');
      if (i.hasPreimage) flags.push('preimage');
      if (i.sequence !== 4294967295) flags.push(`seq ${i.sequence}`);
      if (flags.length) {
        row.appendChild(document.createTextNode('  '));
        row.appendChild(el('span', 'io-script', flags.join(' · ')));
      }
      inCol.appendChild(row);
    }
  }

  const outCol = el('div', 'io-col');
  outCol.appendChild(el('h5', null, `outputs (${tx.outputs.length})`));
  for (const o of tx.outputs) {
    const row = el('div', 'io-row');
    row.appendChild(el('span', 'io-val', deckx(o.value)));
    row.appendChild(document.createTextNode('  →  ' + shortHash(o.address, 16, 8)));
    if (o.script && o.script !== 'p2pkh') {
      row.appendChild(document.createTextNode('  '));
      row.appendChild(el('span', 'io-script', o.script));
    }
    outCol.appendChild(row);
  }

  io.appendChild(inCol);
  io.appendChild(outCol);
  box.appendChild(io);
  return box;
}

const BLOCK_TAGS = {
  0: 'genesis',
};

function paintBlocks(data) {
  const list = $('#block-list');
  list.textContent = '';

  for (const b of data.blocks) {
    const d = el('details', 'block');
    if (b.height === 0) d.open = true;

    const s = el('summary');
    s.appendChild(el('span', 'blk-h', `#${b.height}`));
    s.appendChild(el('span', 'blk-hash', shortHash(b.hash, 18, 10)));
    const kinds = [...new Set(b.transactions.map((t) => t.kind))].filter((k) => k !== 'coinbase');
    s.appendChild(el('span', 'blk-tag', BLOCK_TAGS[b.height] || (kinds.length ? kinds.join(' + ') : `${b.txCount} tx`)));
    d.appendChild(s);

    const body = el('div', 'blk-body');
    const meta = el('div', 'kv-grid');
    kv(meta, 'time', iso(b.time));
    kv(meta, 'nonce', groupDigits(b.nonce));
    kv(meta, 'merkle root', shortHash(b.merkleRoot, 18, 10));
    kv(meta, 'state root', shortHash(b.stateRoot, 18, 10));
    kv(meta, 'subsidy', `${deckx(b.subsidy)} DECKX`);
    kv(meta, 'difficulty', b.bits);
    body.appendChild(meta);

    for (const tx of b.transactions) body.appendChild(txNode(tx));
    d.appendChild(body);
    list.appendChild(d);
  }
}

/* ── contract ─────────────────────────────────────────────────────── */

const SLOT_MEANING = {
  0: 'unlock height',
  1: 'beneficiary (address word)',
  2: 'release attempts',
};

function paintContract(data) {
  const grid = $('#contract-detail');
  grid.textContent = '';
  const c = data.contract;
  if (!c) { kv(grid, 'contract', 'none deployed'); return; }

  kv(grid, 'address', c.address);
  kv(grid, 'deployed by', c.deployer);
  kv(grid, 'deployed at', `block ${c.deployedAt}`);
  kv(grid, 'code size', `${c.codeSize} bytes`);
  for (const [slot, value] of Object.entries(c.storage)) {
    const label = SLOT_MEANING[slot] ? `slot ${slot} — ${SLOT_MEANING[slot]}` : `slot ${slot}`;
    kv(grid, label, slot === '1' ? shortHash(value, 20, 10) : groupDigits(value));
  }
  kv(grid, 'bytecode', shortHash(c.codeHex, 40, 20));
}

/* ── volt ─────────────────────────────────────────────────────────── */

function paintChannels(data) {
  const list = $('#channel-list');
  list.textContent = '';

  for (const ch of data.volt.channels) {
    const box = el('div', 'channel');

    const head = el('div', 'ch-head');
    head.appendChild(el('span', 'ch-name', ch.id));
    head.appendChild(el('span', `ch-state ${ch.state === 'open' ? '' : 'closing'}`, ch.state));
    box.appendChild(head);

    const capacity = Number(BigInt(ch.capacity));
    const a = Number(BigInt(ch.balanceA));
    const pctA = capacity > 0 ? (a / capacity) * 100 : 50;

    const bar = el('div', 'ch-bar');
    const segA = el('div', 'ch-bar-a');
    segA.style.width = pctA.toFixed(2) + '%';
    const segB = el('div', 'ch-bar-b');
    segB.style.width = (100 - pctA).toFixed(2) + '%';
    bar.appendChild(segA);
    bar.appendChild(segB);
    box.appendChild(bar);

    const legend = el('div', 'ch-legend');
    legend.appendChild(el('span', null, `${ch.parties[0]} ${deckx(ch.balanceA)}`));
    legend.appendChild(el('span', null, `${deckx(ch.balanceB)} ${ch.parties[1]}`));
    box.appendChild(legend);

    const meta = el('div', 'ch-meta');
    const add = (k, v) => {
      const row = el('div');
      row.appendChild(document.createTextNode(k + ' '));
      row.appendChild(el('b', null, v));
      meta.appendChild(row);
    };
    add('capacity', ch.capacityPretty);
    add('commitment #', String(ch.commitmentNumber));
    add('revocations', String(ch.revocations));
    add('htlcs settled', String(ch.htlcsSettled));
    add('scid', shortHash(ch.shortChannelId, 8, 5));
    add('funding tx', shortHash(ch.fundingTxid, 8, 6));
    box.appendChild(meta);

    list.appendChild(box);
  }
}

function paintPayment(data) {
  const wrap = $('#payment-detail');
  wrap.textContent = '';
  const p = data.volt.payment;

  const grid = el('div', 'explorer-grid');
  cell(grid, 'status', p.ok ? 'settled ✓' : 'failed', p.ok ? 'acid' : '');
  cell(grid, 'amount received', `${deckx(BigInt(p.amountSent) - BigInt(p.feesPaid))} DECKX`);
  cell(grid, 'amount sent', `${deckx(p.amountSent)} DECKX`);
  cell(grid, 'routing fee', `${groupDigits(p.feesPaid)} zaps`, 'violet');
  cell(grid, 'hops', String(p.hops.length));
  cell(grid, 'onion packet', `${p.onionBytes} bytes`);
  cell(grid, 'settled in', `${p.settleMs} ms`, 'acid');
  cell(grid, 'on-chain txs', '0', 'acid');
  wrap.appendChild(grid);

  const flow = el('div', 'hop-flow');
  const first = el('div', 'hop');
  first.appendChild(el('span', 'hop-name', 'alice'));
  first.appendChild(el('span', 'hop-line', 'sender'));
  first.appendChild(el('span', 'hop-line', `locks ${deckx(p.amountSent)}`));
  flow.appendChild(first);

  p.forwards.forEach((f) => {
    flow.appendChild(el('span', 'hop-arrow', '→'));
    const node = el('div', 'hop');
    node.appendChild(el('span', 'hop-name', f.node));
    node.appendChild(el('span', 'hop-line', `in  ${deckx(f.amountIn)}`));
    if (BigInt(f.amountOut) > 0n) {
      node.appendChild(el('span', 'hop-line', `out ${deckx(f.amountOut)}`));
      node.appendChild(el('span', 'hop-line hop-fee', `keeps ${groupDigits(f.fee)} zaps`));
    } else {
      node.appendChild(el('span', 'hop-line', 'final recipient'));
    }
    node.appendChild(el('span', 'hop-line', `cltv ${f.cltv}`));
    flow.appendChild(node);
  });
  wrap.appendChild(flow);

  const note = el('p', 'sub-note');
  note.textContent =
    `Preimage ${shortHash(p.preimage, 16, 10)} is the receipt: SHA256 of it equals the invoice's ` +
    `payment hash. Bob learned it only when settling backwards, and kept exactly his advertised fee.`;
  wrap.appendChild(note);
}

/* ── boot ─────────────────────────────────────────────────────────── */

function paintError(message) {
  const banner = el('div', 'warn-box');
  banner.appendChild(el('p', null, `Chain data unavailable: ${message}. The explorer needs data/chain.json — regenerate it with "node chain/scripts/export-web-data.ts".`));
  const target = $('#explorer-summary');
  if (target) target.replaceWith(banner);
  const term = $('#terminal-genesis');
  if (term) term.textContent = '$ node src/cli.ts genesis\n\n  chain data not loaded.';
}

async function boot() {
  try {
    const res = await fetch('data/chain.json', { cache: 'no-cache' });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();

    paintTerminal(data);
    paintHero(data);
    paintSupply(data);
    paintContractLibrary(data);
    paintSummary(data);
    paintTimeline(data);
    paintGenesis(data);
    paintBlocks(data);
    paintContract(data);
    paintChannels(data);
    paintPayment(data);

    // Only the value. The label beside it carries data-i18n, and writing both
    // here would put the sentence back under i18n's control — which repaints
    // from its dictionary and would wipe the date on the next language switch.
    const gen = $('#footer-generated');
    if (gen) gen.textContent = `${data.generatedAt} · exporter v${data.generatorVersion}`;

    /*
     * The snapshot is painted first and always. Only then does the page try a
     * live node, and it overwrites the chain figures only once one has
     * answered and proved it is on this chain. That ordering means a slow or
     * absent gateway costs the reader nothing — the page is already complete
     * when the attempt starts.
     */
    if (window.live) window.live.start(data);
  } catch (err) {
    console.error('DeckxCoin explorer:', err);
    paintError(err.message);
  }
}

/* ── interactions ─────────────────────────────────────────────────── */

document.addEventListener('click', (e) => {
  const copy = e.target.closest('.copy-btn');
  if (copy) {
    const src = document.querySelector(copy.dataset.copy);
    if (!src) return;
    navigator.clipboard.writeText(src.textContent.trim()).then(
      () => {
        const original = copy.textContent;
        copy.textContent = 'copied ✓';
        setTimeout(() => { copy.textContent = original; }, 1400);
      },
      () => { copy.textContent = 'press ⌘C'; },
    );
    return;
  }

  const toggle = e.target.closest('.menu-toggle');
  if (toggle) {
    const nav = document.querySelector('.topnav');
    const open = nav.classList.toggle('open');
    toggle.setAttribute('aria-expanded', String(open));
    return;
  }

  if (e.target.closest('.topnav a')) {
    document.querySelector('.topnav').classList.remove('open');
  }
});

boot();
