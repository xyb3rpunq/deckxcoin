/*
 * Bilingual switching, without a build step.
 *
 * ── Why English lives in the HTML ─────────────────────────────────────────
 * The page ships with English inline and fetches Indonesian only when it is
 * asked for. That ordering is deliberate:
 *
 *   - the page is readable with JavaScript disabled or still loading
 *   - a search engine indexes real prose, not empty <p> tags waiting on fetch
 *   - a failed fetch degrades to "the page is in English", not "the page is
 *     blank", which is the failure mode of every translate-on-load design
 *
 * ── The one thing that is easy to get wrong ───────────────────────────────
 * Switching to Indonesian overwrites the English in the DOM. If the original
 * is not captured first, switching *back* has nothing to restore and the
 * toggle becomes one-way. Originals are therefore snapshotted the first time
 * an element is touched, and English is served from that snapshot rather than
 * from a second dictionary that could drift out of sync with the markup.
 */

(function () {
  'use strict';

  const LANGS = { en: 'EN', id: 'ID' };
  const DEFAULT = 'en';
  const STORAGE_KEY = 'deckx.lang';

  /** key → the English innerHTML as authored, captured before any swap. */
  const originals = new Map();
  /** key → Indonesian innerHTML. Empty until the dictionary is fetched. */
  let dict = null;
  let loading = null;

  let current = DEFAULT;
  const listeners = new Set();

  /* ── preference ──────────────────────────────────────────────────────── */

  function stored() {
    try {
      const value = localStorage.getItem(STORAGE_KEY);
      return value && Object.hasOwn(LANGS, value) ? value : null;
    } catch {
      // Private browsing throws on access rather than returning null.
      return null;
    }
  }

  function remember(lang) {
    try {
      localStorage.setItem(STORAGE_KEY, lang);
    } catch {
      /* the choice still applies for this page view */
    }
  }

  /**
   * First visit: follow the browser. `navigator.languages` is ordered by the
   * user's own preference, so the first Indonesian or English entry to appear
   * is the answer — checking only `navigator.language` would ignore a reader
   * whose primary locale is neither.
   */
  function preferred() {
    const saved = stored();
    if (saved) return saved;
    for (const tag of navigator.languages || [navigator.language || '']) {
      const code = String(tag).toLowerCase();
      if (code.startsWith('id') || code.startsWith('in-id')) return 'id';
      if (code.startsWith('en')) return 'en';
    }
    return DEFAULT;
  }

  /* ── dictionary ──────────────────────────────────────────────────────── */

  function load() {
    if (dict) return Promise.resolve(dict);
    if (loading) return loading;
    loading = fetch('i18n/id.json', { cache: 'no-cache' })
      .then((res) => {
        if (!res.ok) throw new Error('HTTP ' + res.status);
        return res.json();
      })
      .then((json) => {
        dict = json;
        return dict;
      })
      .catch((err) => {
        loading = null;
        throw err;
      });
    return loading;
  }

  /* ── applying ────────────────────────────────────────────────────────── */

  function capture(el, key) {
    if (!originals.has(key)) originals.set(key, el.innerHTML);
  }

  /**
   * Translate everything under `root`. Called on load, on every switch, and by
   * app.js after it paints explorer content — nodes created after the last
   * switch would otherwise be left in English.
   */
  function apply(root) {
    const scope = root || document;
    const nodes = scope.querySelectorAll('[data-i18n]');

    for (const el of nodes) {
      /*
       * An element whose content is written by app.js must not also be
       * translated: apply() would overwrite the chain data with dictionary
       * text, and the reader would watch live numbers turn back into
       * placeholders every time they switched language. Such elements are
       * split into a translatable label and a separate value node; this guard
       * is the backstop for anyone who forgets.
       */
      if (el.hasAttribute('data-i18n-dynamic')) continue;

      const key = el.getAttribute('data-i18n');
      capture(el, key);

      if (current === 'en') {
        el.innerHTML = originals.get(key);
      } else if (dict && Object.hasOwn(dict, key)) {
        el.innerHTML = dict[key];
      }
      // A key missing from the dictionary keeps its English. A half-translated
      // page is usable; a page with holes in it is not.
    }

    if (scope === document) {
      document.documentElement.lang = current;
      applyMeta();
    }
  }

  /**
   * The title and description are not elements carrying data-i18n, so they are
   * snapshotted here by hand. Without the snapshot, switching to Indonesian
   * overwrites the title and switching back has nothing to restore — the page
   * ends up English with an Indonesian tab label and an Indonesian description
   * in every link preview.
   */
  function captureMeta() {
    if (!originals.has('meta.title')) originals.set('meta.title', document.title);
    const meta = document.querySelector('meta[name="description"]');
    if (meta && !originals.has('meta.description')) {
      originals.set('meta.description', meta.getAttribute('content') || '');
    }
  }

  function applyMeta() {
    captureMeta();
    const title = current === 'en' ? originals.get('meta.title') : dict && dict['meta.title'];
    const description =
      current === 'en' ? originals.get('meta.description') : dict && dict['meta.description'];

    if (title) document.title = title;
    const meta = document.querySelector('meta[name="description"]');
    if (meta && description) meta.setAttribute('content', description);
  }

  /**
   * Translate one string by key.
   *
   * Used by app.js for labels it generates. `fallback` is what English says,
   * so a key that has not been translated yet still renders as real words.
   */
  function t(key, fallback) {
    if (current !== 'en' && dict && Object.hasOwn(dict, key)) return dict[key];
    if (fallback !== undefined) return fallback;
    return originals.get(key) ?? key;
  }

  /* ── switching ───────────────────────────────────────────────────────── */

  function setLanguage(lang, opts) {
    if (!Object.hasOwn(LANGS, lang)) return Promise.resolve();
    const persist = !opts || opts.persist !== false;

    // English needs no fetch: it is already in the DOM, or in `originals`.
    if (lang === 'en') {
      current = 'en';
      if (persist) remember('en');
      apply();
      paintToggle();
      announce();
      return Promise.resolve();
    }

    paintToggle('loading');
    return load()
      .then(() => {
        current = lang;
        if (persist) remember(lang);
        apply();
        paintToggle();
        announce();
      })
      .catch(() => {
        // Stay on English and say so, rather than leaving a dead button.
        paintToggle('error');
      });
  }

  function announce() {
    for (const cb of listeners) {
      try {
        cb(current);
      } catch (err) {
        console.error('i18n listener failed', err);
      }
    }
  }

  /* ── the switch itself ───────────────────────────────────────────────── */

  function buildToggle() {
    const nav = document.querySelector('.topbar');
    if (!nav || document.querySelector('.lang-switch')) return;

    const wrap = document.createElement('div');
    wrap.className = 'lang-switch';
    wrap.setAttribute('role', 'group');
    wrap.setAttribute('aria-label', 'Language / Bahasa');

    for (const [code, label] of Object.entries(LANGS)) {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'lang-btn';
      button.dataset.lang = code;
      button.textContent = label;
      // The full name is what a screen reader should say; the button shows the
      // two-letter code because the header has no room for more.
      button.setAttribute('aria-label', code === 'id' ? 'Bahasa Indonesia' : 'English');
      button.addEventListener('click', () => setLanguage(code));
      wrap.appendChild(button);
    }

    const menu = nav.querySelector('.menu-toggle');
    nav.insertBefore(wrap, menu || null);
    paintToggle();
  }

  function paintToggle(state) {
    const wrap = document.querySelector('.lang-switch');
    if (!wrap) return;
    wrap.dataset.state = state || 'ready';
    for (const button of wrap.querySelectorAll('.lang-btn')) {
      const active = button.dataset.lang === current;
      button.classList.toggle('active', active);
      button.setAttribute('aria-pressed', String(active));
      button.disabled = state === 'loading';
    }
    if (state === 'error') {
      wrap.title = 'Could not load the Indonesian text — staying in English';
    } else {
      wrap.removeAttribute('title');
    }
  }

  /* ── boot ────────────────────────────────────────────────────────────── */

  function boot() {
    buildToggle();
    // Snapshot the English before anything can overwrite it.
    captureMeta();
    apply();
    const want = preferred();
    if (want !== current) setLanguage(want, { persist: false });
  }

  window.i18n = {
    get lang() {
      return current;
    },
    t,
    apply,
    setLanguage,
    onChange(cb) {
      listeners.add(cb);
      return () => listeners.delete(cb);
    },
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
})();
