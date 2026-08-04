/*
 * Live chain data.
 *
 * The page ships with a snapshot in `data/chain.json` — a real chain, really
 * mined, exported by `chain/scripts/export-web-data.ts`. That snapshot is what
 * makes the numbers on this page reproducible, and it is what renders when
 * nobody is running a node.
 *
 * This module adds the other half: when a public gateway is configured and
 * reachable, the explorer switches to reading it, and says so.
 *
 * ── The rule this file is built around ───────────────────────────────────
 * **The page must never claim to be live when it is not.** A snapshot silently
 * presented as current is worse than an obviously static page: it invites
 * someone to make a decision on data that stopped moving weeks ago. So the
 * banner always states which of the two you are looking at, the snapshot's
 * export date is shown when it is the source, and a failed refresh downgrades
 * the banner rather than leaving the last good numbers up as though they were
 * still arriving.
 *
 * ── Genesis is checked, not assumed ──────────────────────────────────────
 * A node that answers is not necessarily a node on *this* chain. Before any
 * live data is displayed, the gateway's genesis hash is compared with the one
 * in the snapshot. A mismatch means the two disagree about what chain they are
 * on, and the explorer refuses the connection loudly rather than mixing blocks
 * from a different network into a page about this one.
 */

(function () {
  'use strict';

  const CONFIG_URL = 'data/network.json';
  const DEFAULT_POLL_MS = 15000;
  const TIMEOUT_MS = 6000;
  const RECENT_BLOCKS = 8;

  const STATUS = {
    SNAPSHOT: 'snapshot',
    CONNECTING: 'connecting',
    LIVE: 'live',
    UNREACHABLE: 'unreachable',
    MISMATCH: 'mismatch',
  };

  const t = (key, fallback) => (window.i18n ? window.i18n.t(key, fallback) : fallback);

  const state = {
    status: STATUS.SNAPSHOT,
    gateway: null,
    snapshot: null,
    chain: null,
    blocks: [],
    faucet: null,
    lastUpdate: 0,
    error: null,
  };

  let timer = null;

  /* ── transport ───────────────────────────────────────────────────────── */

  /**
   * One gateway call, with a timeout.
   *
   * A gateway that accepts the connection and then never answers is the failure
   * that hangs a page forever; `fetch` alone has no timeout, so an AbortSignal
   * is the whole reason this wrapper exists.
   */
  async function call(base, method, params) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);
    try {
      const res = await fetch(base, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ method, params: params || {} }),
        signal: controller.signal,
      });
      if (!res.ok) throw new Error('HTTP ' + res.status);
      const body = await res.json();
      if (body.error) throw new Error(body.error.message || 'gateway error');
      return body.result;
    } finally {
      clearTimeout(timeout);
    }
  }

  async function loadConfig() {
    const query = new URLSearchParams(location.search);

    // A gateway named in the URL wins over the committed list, so anyone can
    // point this page at their own node without editing a file.
    const override = query.get('node');
    if (override) {
      return {
        gateways: [override],
        pollMs: DEFAULT_POLL_MS,
        expectedGenesis: query.get('genesis') || null,
      };
    }

    try {
      const res = await fetch(CONFIG_URL, { cache: 'no-cache' });
      if (!res.ok) throw new Error('HTTP ' + res.status);
      const config = await res.json();
      return {
        gateways: Array.isArray(config.gateways) ? config.gateways : [],
        pollMs: Number(config.pollMs) > 0 ? Number(config.pollMs) : DEFAULT_POLL_MS,
        expectedGenesis: config.expectedGenesis || null,
      };
    } catch {
      return { gateways: [], pollMs: DEFAULT_POLL_MS, expectedGenesis: null };
    }
  }

  /* ── connecting ──────────────────────────────────────────────────────── */

  /**
   * Which genesis a gateway must report to be accepted.
   *
   * The bundled snapshot is a mainnet-parameter scenario chain, while a public
   * deployment is a testnet with its own genesis — so checking against the
   * snapshot alone would reject every real gateway this page is meant to talk
   * to. The operator therefore declares the genesis in `network.json` next to
   * the gateway list, and the snapshot's is only the fallback for the case
   * where the two are the same chain.
   */
  function expectedGenesis(config) {
    if (config && config.expectedGenesis) return config.expectedGenesis;
    return (state.snapshot && state.snapshot.genesis && state.snapshot.genesis.hash) || null;
  }

  async function connect(gateways, config) {
    const expected = expectedGenesis(config);

    for (const base of gateways) {
      try {
        const info = await call(base, 'getblockchaininfo');

        // Same software, different chain, is a real and confusing outcome —
        // anyone running a private regtest will hit it. Say so instead of
        // rendering their blocks under this page's headings.
        if (expected && info.genesis && info.genesis !== expected) {
          state.status = STATUS.MISMATCH;
          state.error = `${base} is on a different chain (genesis ${short(info.genesis)}, expected ${short(expected)})`;
          return null;
        }

        state.gateway = base;
        state.chain = info;
        return base;
      } catch (err) {
        state.error = err.message;
      }
    }
    return null;
  }

  /* ── polling ─────────────────────────────────────────────────────────── */

  async function refresh() {
    if (!state.gateway) return;
    try {
      const info = await call(state.gateway, 'getblockchaininfo');
      const blocks = await recentBlocks(state.gateway, info.height);
      let mempool = null;
      try {
        mempool = await call(state.gateway, 'getmempoolinfo');
      } catch {
        /* a gateway may not expose it; the rest of the view still works */
      }

      state.chain = info;
      state.blocks = blocks;
      state.mempool = mempool;
      state.lastUpdate = Date.now();
      state.status = STATUS.LIVE;
      state.error = null;
    } catch (err) {
      // Downgraded, not silently left showing the last good numbers.
      state.status = STATUS.UNREACHABLE;
      state.error = err.message;
    }
    render();
  }

  async function recentBlocks(base, height) {
    const wanted = [];
    for (let h = height; h > height - RECENT_BLOCKS && h >= 0; h--) wanted.push(h);

    const results = await Promise.all(
      wanted.map(async (h) => {
        try {
          const hash = await call(base, 'getblockhash', { height: h });
          const block = await call(base, 'getblock', { hash });
          return { height: h, hash, txids: block.txids || [], header: block.header || {} };
        } catch {
          return null;
        }
      }),
    );
    return results.filter(Boolean);
  }

  /* ── faucet ──────────────────────────────────────────────────────────── */

  async function loadFaucet(base) {
    try {
      const url = base.replace(/\/+$/, '') + '/faucet';
      const res = await fetch(url, { signal: AbortSignal.timeout(TIMEOUT_MS) });
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  }

  /**
   * Turn a refusal into something the reader's language can express.
   *
   * The faucet's prose reason is written by the node and is always English.
   * Its `verdict` field, though, is a stable machine-readable code — so the
   * client translates that and keeps the server's sentence only when it has no
   * mapping, which is better than showing English to a reader who chose
   * Indonesian.
   */
  function refusalText(answer) {
    const codes = {
      'invalid-address': ['live.refuseAddress', 'That is not a valid DeckxCoin address.'],
      'address-cooldown': ['live.refuseCooldown', 'This address was funded recently. Try again later.'],
      'ip-cooldown': ['live.refuseIp', 'This network was served recently. A new address does not reset it.'],
      'daily-cap': ['live.refuseCap', 'The faucet has hit its daily limit. Try again tomorrow.'],
      reserve: ['live.refuseReserve', 'The faucet is nearly empty and needs refilling.'],
      empty: ['live.refuseEmpty', 'The faucet is empty.'],
    };
    const mapped = codes[answer.verdict];
    if (!mapped) return answer.reason || t('live.refuseUnknown', 'The faucet refused the request.');

    let text = t(mapped[0], mapped[1]);
    if (answer.retryAfterMs > 0) {
      const minutes = Math.ceil(answer.retryAfterMs / 60000);
      text += ` (${minutes} ${t('live.minutes', 'min')})`;
    }
    return text;
  }

  async function requestCoins(address) {
    const url = state.gateway.replace(/\/+$/, '') + '/faucet';
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ address }),
    });
    return await res.json();
  }

  /* ── rendering ───────────────────────────────────────────────────────── */

  const short = (h, head = 10, tail = 6) =>
    !h ? '—' : h.length <= head + tail + 1 ? h : `${h.slice(0, head)}…${h.slice(-tail)}`;

  const el = (tag, cls, text) => {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text !== undefined) node.textContent = text;
    return node;
  };

  function banner() {
    let node = document.querySelector('#live-banner');
    if (!node) {
      node = el('div', 'live-banner');
      node.id = 'live-banner';
      const section = document.querySelector('#explorer .section-head');
      if (!section) return null;
      section.appendChild(node);
    }
    return node;
  }

  function render() {
    const node = banner();
    if (!node) return;
    node.textContent = '';
    node.dataset.status = state.status;

    const dot = el('span', 'live-dot');
    node.appendChild(dot);

    const label = el('span', 'live-label');
    const detail = el('span', 'live-detail');

    if (state.status === STATUS.LIVE) {
      label.textContent = t('live.live', 'LIVE');
      const age = Math.round((Date.now() - state.lastUpdate) / 1000);
      detail.textContent =
        `${hostOf(state.gateway)} · ${t('live.height', 'height')} ${state.chain.height} · ` +
        `${t('live.updated', 'updated')} ${age}s ${t('live.ago', 'ago')}`;
    } else if (state.status === STATUS.CONNECTING) {
      label.textContent = t('live.connecting', 'CONNECTING');
      detail.textContent = t('live.searching', 'looking for a public node…');
    } else if (state.status === STATUS.MISMATCH) {
      label.textContent = t('live.mismatch', 'WRONG CHAIN');
      detail.textContent = state.error || '';
    } else if (state.status === STATUS.UNREACHABLE) {
      label.textContent = t('live.offline', 'NODE UNREACHABLE');
      detail.textContent =
        (state.error ? state.error + ' — ' : '') +
        t('live.fellBack', 'showing the bundled snapshot');
    } else {
      label.textContent = t('live.snapshot', 'SNAPSHOT');
      detail.textContent =
        t('live.noNode', 'no public node configured — showing chain data exported on') +
        ' ' +
        (state.snapshot ? state.snapshot.generatedAt : '—');
    }

    node.appendChild(label);
    node.appendChild(detail);

    if (state.status === STATUS.LIVE) renderLive();
  }

  const hostOf = (url) => {
    try {
      return new URL(url).host;
    } catch {
      return url;
    }
  };

  /** Overwrite the snapshot-derived chain figures with the node's own. */
  function renderLive() {
    const grid = document.querySelector('#explorer-summary');
    if (!grid || !state.chain) return;
    grid.textContent = '';

    const cell = (key, value, tone) => {
      const box = el('div', 'ex-cell');
      box.appendChild(el('span', 'ex-key', key));
      box.appendChild(el('span', 'ex-val mono' + (tone ? ' ' + tone : ''), value));
      grid.appendChild(box);
    };

    const c = state.chain;
    cell(t('live.height', 'chain height'), String(c.height));
    cell(t('live.tip', 'tip hash'), short(c.tip));
    cell(t('live.issued', 'issued'), (c.issuedPretty || '—').replace(' DECKX', '') + ' DECKX', 'acid');
    cell(t('live.subsidy', 'block subsidy'), c.subsidyPretty || '—');
    cell(
      t('live.audit', 'supply audit'),
      c.supplyBalanced ? t('live.balanced', 'balanced ✓') : t('live.drift', 'DRIFT ✗'),
      c.supplyBalanced ? 'acid' : '',
    );
    cell(t('live.capPct', '% of cap'), (c.percentOfCap || '0') + ' %');
    if (state.mempool) {
      cell(t('live.mempool', 'mempool'), `${state.mempool.count ?? 0} tx`);
    }
    cell(t('live.network', 'network'), c.network || '—', 'violet');

    renderBlocks();
  }

  function renderBlocks() {
    const list = document.querySelector('#block-list');
    if (!list || state.blocks.length === 0) return;
    list.textContent = '';

    for (const block of state.blocks) {
      const row = el('article', 'block');
      const head = el('header', 'block-head');
      head.appendChild(el('span', 'block-h', '#' + block.height));
      head.appendChild(el('span', 'block-hash mono', short(block.hash, 14, 8)));
      const count = block.txids.length;
      head.appendChild(
        el('span', 'block-tag', `${count} ${count === 1 ? t('live.tx', 'tx') : t('live.txs', 'txs')}`),
      );
      if (block.header && block.header.time) {
        head.appendChild(
          el('span', 'block-time dim', new Date(block.header.time * 1000).toISOString().slice(0, 19).replace('T', ' ')),
        );
      }
      row.appendChild(head);
      list.appendChild(row);
    }
  }

  /* ── faucet panel ────────────────────────────────────────────────────── */

  /** Nodes whose text has to follow a language switch. */
  let faucetNodes = null;

  /**
   * Re-label the faucet panel after a language switch.
   *
   * Rebuilding the panel would be simpler and would also discard whatever the
   * visitor had typed and the result they were reading — so the labels are
   * updated in place and the input and the last result are left alone.
   */
  function retranslateFaucet() {
    if (!faucetNodes || !state.faucet) return;
    faucetNodes.title.textContent = t('live.faucetTitle', 'Testnet faucet');
    faucetNodes.sub.textContent =
      `${t('live.faucetGives', 'Gives')} ${state.faucet.amountPretty} ${t('live.faucetPer', 'per request.')} ` +
      `${t('live.faucetBalance', 'Balance')} ${state.faucet.balancePretty}.`;
    faucetNodes.button.textContent = t('live.faucetSend', 'Send me coins');
    faucetNodes.input.setAttribute('aria-label', t('live.faucetAddress', 'Your DeckxCoin address'));
  }

  function renderFaucet() {
    if (!state.faucet || !state.gateway) return;
    const section = document.querySelector('#explorer');
    if (!section || document.querySelector('#faucet-panel')) return;

    const panel = el('div', 'faucet-panel');
    panel.id = 'faucet-panel';

    const title = el('h3', null, t('live.faucetTitle', 'Testnet faucet'));
    const sub = el('p', 'faucet-sub');
    panel.appendChild(title);
    panel.appendChild(sub);

    const row = el('div', 'faucet-row');
    const input = el('input', 'faucet-input');
    input.type = 'text';
    input.placeholder = 'dxc1q…';
    input.spellcheck = false;

    const button = el('button', 'btn primary faucet-btn');
    const result = el('p', 'faucet-result');

    faucetNodes = { title, sub, button, input };
    retranslateFaucet();

    button.addEventListener('click', async () => {
      const address = input.value.trim();
      if (!address) {
        result.textContent = t('live.faucetNeedAddress', 'Enter an address first.');
        result.dataset.tone = 'bad';
        return;
      }
      button.disabled = true;
      result.dataset.tone = '';
      result.textContent = t('live.faucetSending', 'asking the faucet…');
      try {
        const answer = await requestCoins(address);
        result.dataset.tone = answer.allowed ? 'good' : 'bad';
        result.textContent = answer.allowed
          ? `${t('live.faucetSent', 'Sent')} ${answer.amountPretty} — tx ${short(answer.txid, 12, 8)}`
          : refusalText(answer);
      } catch (err) {
        result.dataset.tone = 'bad';
        result.textContent = err.message;
      } finally {
        button.disabled = false;
      }
    });

    row.appendChild(input);
    row.appendChild(button);
    panel.appendChild(row);
    panel.appendChild(result);

    const summary = document.querySelector('#explorer-summary');
    if (summary && summary.parentNode) summary.parentNode.insertBefore(panel, summary.nextSibling);
  }

  /* ── boot ────────────────────────────────────────────────────────────── */

  async function start(snapshot) {
    state.snapshot = snapshot;
    const config = await loadConfig();

    if (config.gateways.length === 0) {
      state.status = STATUS.SNAPSHOT;
      render();
      return;
    }

    state.status = STATUS.CONNECTING;
    render();

    const base = await connect(config.gateways, config);
    if (!base) {
      if (state.status !== STATUS.MISMATCH) state.status = STATUS.UNREACHABLE;
      render();
      return;
    }

    state.faucet = await loadFaucet(base);
    await refresh();
    renderFaucet();

    if (timer) clearInterval(timer);
    timer = setInterval(refresh, config.pollMs);
  }

  // Re-render on a language switch so the banner, the live cells and the
  // faucet labels all follow. i18n only repaints elements carrying data-i18n,
  // and everything this module creates is built in JavaScript instead.
  if (window.i18n) {
    window.i18n.onChange(() => {
      render();
      retranslateFaucet();
    });
  }

  window.live = { start, refresh, get state() { return state; }, STATUS };
})();
