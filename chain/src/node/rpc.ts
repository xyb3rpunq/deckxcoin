/**
 * JSON-RPC over HTTP.
 *
 * The node's control surface: what a wallet, a block explorer, or an operator
 * uses to see and change state. Deliberately small — every method here is one
 * a real user needs, and nothing is exposed just because it was easy.
 *
 * ── Security posture ──────────────────────────────────────────────────────
 * Binds to loopback by default. There is no authentication, because adding a
 * password would imply this is safe to expose, and it is not: a node with an
 * open RPC port is a node anyone can stop. Reachable RPC belongs behind a
 * reverse proxy that terminates TLS and authenticates, and that is stated here
 * rather than papered over with a token field.
 *
 * Request:   { "id": 1, "method": "getinfo", "params": {} }
 * Response:  { "id": 1, "result": {...} }  or  { "id": 1, "error": {...} }
 */

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';

import type { DeckxNode } from './node.ts';
import { ACCEPT } from './chainstate.ts';
import { formatDeckx, txid, type Transaction } from '../tx.ts';
import { blockHash, blockSubsidy, cumulativeIssuance, type Block } from '../block.ts';
import { isValidAddress, normaliseAddress, type Hex } from '../crypto.ts';
import { isHash } from '../net/wire.ts';

export interface RpcOptions {
  readonly node: DeckxNode;
  readonly port: number;
  /** Loopback by default. Changing this exposes an unauthenticated control port. */
  readonly host?: string;
  /** Largest request body accepted, bytes. */
  readonly maxBodyBytes?: number;
}

interface RpcRequest {
  readonly id?: string | number;
  readonly method?: string;
  readonly params?: Record<string, unknown>;
}

const RPC_ERROR = {
  PARSE: -32700,
  INVALID_REQUEST: -32600,
  METHOD_NOT_FOUND: -32601,
  INVALID_PARAMS: -32602,
  INTERNAL: -32603,
} as const;

class RpcFailure extends Error {
  readonly code: number;
  // Node runs these files with type stripping only, so parameter properties
  // (`constructor(readonly code: number)`) are not available — they emit code
  // rather than just erasing types. Assigning explicitly is the portable form.
  constructor(code: number, message: string) {
    super(message);
    this.code = code;
  }
}

const invalid = (message: string) => new RpcFailure(RPC_ERROR.INVALID_PARAMS, message);

export class RpcServer {
  readonly node: DeckxNode;
  readonly port: number;
  readonly host: string;
  readonly maxBodyBytes: number;
  #server?: Server;

  constructor(opts: RpcOptions) {
    this.node = opts.node;
    this.port = opts.port;
    this.host = opts.host ?? '127.0.0.1';
    this.maxBodyBytes = opts.maxBodyBytes ?? 4 * 1024 * 1024;
  }

  start(): Promise<void> {
    return new Promise((resolve, reject) => {
      const server = createServer((req, res) => void this.#handle(req, res));
      server.on('error', reject);
      server.listen(this.port, this.host, () => {
        this.#server = server;
        resolve();
      });
      server.unref?.();
    });
  }

  stop(): Promise<void> {
    return new Promise((resolve) => {
      if (!this.#server) return resolve();
      this.#server.close(() => resolve());
      this.#server = undefined;
    });
  }

  async #handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (req.method !== 'POST') {
      this.#respond(res, 405, { error: { code: RPC_ERROR.INVALID_REQUEST, message: 'use POST' } });
      return;
    }

    let body = '';
    let size = 0;
    for await (const chunk of req) {
      size += (chunk as Buffer).length;
      if (size > this.maxBodyBytes) {
        this.#respond(res, 413, { error: { code: RPC_ERROR.INVALID_REQUEST, message: 'body too large' } });
        req.destroy();
        return;
      }
      body += (chunk as Buffer).toString('utf8');
    }

    let request: RpcRequest;
    try {
      request = JSON.parse(body || '{}');
    } catch {
      this.#respond(res, 400, { error: { code: RPC_ERROR.PARSE, message: 'malformed JSON' } });
      return;
    }

    const id = request.id ?? null;
    const method = request.method;
    if (typeof method !== 'string') {
      this.#respond(res, 400, { id, error: { code: RPC_ERROR.INVALID_REQUEST, message: 'method is required' } });
      return;
    }

    try {
      const result = this.call(method, request.params ?? {});
      this.#respond(res, 200, { id, result });
    } catch (err) {
      const failure = err instanceof RpcFailure ? err : new RpcFailure(RPC_ERROR.INTERNAL, (err as Error).message);
      this.#respond(res, 200, { id, error: { code: failure.code, message: failure.message } });
    }
  }

  #respond(res: ServerResponse, status: number, body: unknown): void {
    const payload = JSON.stringify(body, (_k, v) => (typeof v === 'bigint' ? v.toString() : v));
    res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) });
    res.end(payload);
  }

  /* ───────────────────────────────────────────────────────── methods ── */

  /** Dispatch a method by name. Exposed so tests can call without HTTP. */
  call(method: string, params: Record<string, unknown>): unknown {
    const { node } = this;
    const chain = node.chain;

    switch (method) {
      case 'getinfo':
        return node.info();

      case 'getblockchaininfo': {
        const audit = chain.auditSupply();
        return {
          network: chain.params.name,
          height: chain.height,
          tip: chain.tipHash,
          chainWork: chain.chainWork.toString(),
          genesis: chain.headerAt(0)!.hash,
          subsidy: blockSubsidy(chain.height).toString(),
          subsidyPretty: formatDeckx(blockSubsidy(chain.height)),
          issued: cumulativeIssuance(chain.height).toString(),
          issuedPretty: formatDeckx(cumulativeIssuance(chain.height)),
          supplyBalanced: audit.balanced,
          percentOfCap: audit.percentOfCap,
        };
      }

      case 'getbestblockhash':
        return chain.tipHash;

      case 'getblockhash': {
        const height = Number(params.height);
        if (!Number.isInteger(height) || height < 0) throw invalid('height must be a non-negative integer');
        const header = chain.headerAt(height);
        if (!header) throw invalid(`no active block at height ${height}`);
        return header.hash;
      }

      case 'getblock': {
        const hash = this.#hashParam(params, 'hash');
        const block = chain.getBlock(hash);
        if (!block) throw invalid(`unknown block ${hash}`);
        const header = chain.getHeader(hash)!;
        return {
          hash,
          height: header.height,
          active: header.active,
          chainWork: header.chainWork.toString(),
          confirmations: header.active ? chain.height - header.height + 1 : 0,
          header: block.header,
          txids: block.transactions.map(txid),
          transactions: params.verbose ? block.transactions : undefined,
        };
      }

      case 'getblockheader': {
        const hash = this.#hashParam(params, 'hash');
        const header = chain.getHeader(hash);
        if (!header) throw invalid(`unknown block ${hash}`);
        return { ...header, chainWork: header.chainWork.toString() };
      }

      case 'gettransaction': {
        const id = this.#hashParam(params, 'txid');
        const pooled = node.mempool.get(id);
        if (pooled) return { txid: id, confirmations: 0, inMempool: true, transaction: pooled };
        const found = this.node.store.findTransaction(id);
        if (!found) throw invalid(`unknown transaction ${id}`);
        return {
          txid: id,
          confirmations: chain.height - found.height + 1,
          inMempool: false,
          height: found.height,
          blockHash: found.blockHash,
          transaction: found.tx,
        };
      }

      case 'getbalance': {
        const address = normaliseAddress(String(params.address ?? ''));
        if (!isValidAddress(address)) throw invalid(`'${address}' is not a valid DeckxCoin address`);
        const balance = chain.state.balanceOf(address);
        return {
          address,
          balance: balance.toString(),
          pretty: formatDeckx(balance),
          utxos: chain.state.utxosFor(address).length,
        };
      }

      case 'listunspent': {
        const address = normaliseAddress(String(params.address ?? ''));
        if (!isValidAddress(address)) throw invalid(`'${address}' is not a valid DeckxCoin address`);
        return chain.state.utxosFor(address).map((u) => ({
          txid: u.txid,
          vout: u.vout,
          value: u.value.toString(),
          pretty: formatDeckx(u.value),
          height: u.height,
          confirmations: chain.height - u.height + 1,
          coinbase: u.coinbase,
          script: u.script?.type ?? 'p2pkh',
        }));
      }

      case 'getcontract': {
        const address = String(params.address ?? '');
        const account = chain.state.getContract(address);
        if (!account) throw invalid(`no contract at ${address}`);
        return {
          ...account,
          balance: chain.state.balanceOf(address).toString(),
          utxos: chain.state.utxosFor(address).length,
        };
      }

      case 'sendrawtransaction': {
        const tx = params.transaction as Transaction | undefined;
        if (!tx || typeof tx !== 'object') throw invalid('transaction is required');
        const result = node.submitTransaction(tx);
        if (!result.ok) throw invalid(result.error ?? 'transaction rejected');
        const id = txid(tx);
        if (!result.duplicate) node.relayTransaction(tx);
        return { txid: id, accepted: true, duplicate: result.duplicate ?? false };
      }

      case 'submitblock': {
        const block = params.block as Block | undefined;
        if (!block?.header) throw invalid('block is required');
        const result = node.submitBlock(block);
        return {
          status: result.status,
          hash: result.hash,
          height: result.height,
          error: result.error,
          accepted: result.status === ACCEPT.CONNECTED,
        };
      }

      case 'generate': {
        const count = Number(params.count ?? 1);
        // Normalised before mining: a coinbase paying a non-canonical address
        // is rejected by consensus, so mining to one would fail every block
        // with an error pointing at the block rather than at the typo.
        const address = normaliseAddress(String(params.address ?? ''));
        if (!Number.isInteger(count) || count < 1 || count > 1000) {
          throw invalid('count must be an integer between 1 and 1000');
        }
        if (!isValidAddress(address)) throw invalid(`'${address}' is not a valid DeckxCoin address`);

        const hashes: Hex[] = [];
        for (let i = 0; i < count; i++) {
          const res = node.mineOne(address);
          if (res.accepted.status !== ACCEPT.CONNECTED) {
            throw new RpcFailure(RPC_ERROR.INTERNAL, `mining failed: ${res.accepted.error}`);
          }
          hashes.push(blockHash(res.block.header));
        }
        return { blocks: hashes, height: chain.height };
      }

      case 'getrawmempool':
        return params.verbose
          ? node.mempool.entries().map((e) => ({
              txid: e.txid,
              fee: e.fee.toString(),
              size: e.size,
              feeRate: e.feeRate,
              addedAtHeight: e.addedAtHeight,
            }))
          : node.mempool.ids();

      case 'getmempoolinfo':
        return node.mempool.stats();

      case 'getpeerinfo':
        return node.net.info();

      case 'addnode': {
        const host = String(params.host ?? '');
        const port = Number(params.port ?? chain.params.defaultPort);
        if (!host) throw invalid('host is required');
        if (!Number.isInteger(port) || port <= 0 || port > 65535) throw invalid('port is out of range');
        void node.net.connect(host, port);
        return { dialling: `${host}:${port}` };
      }

      case 'listbanned':
        return node.net.bans();

      case 'sync':
        return { requested: node.syncFromBest() };

      case 'auditsupply': {
        const audit = chain.auditSupply();
        return {
          ...audit,
          utxoTotal: audit.utxoTotal.toString(),
          expectedSubsidy: audit.expectedSubsidy.toString(),
          pretty: formatDeckx(audit.utxoTotal),
        };
      }

      case 'help':
        return RPC_METHODS;

      default:
        throw new RpcFailure(RPC_ERROR.METHOD_NOT_FOUND, `unknown method '${method}'`);
    }
  }

  #hashParam(params: Record<string, unknown>, name: string): Hex {
    const value = params[name];
    if (!isHash(value)) throw invalid(`${name} must be a 64-character hex hash`);
    return value;
  }
}

export const RPC_METHODS = [
  'getinfo — node, chain, peer and mempool summary',
  'getblockchaininfo — height, tip, issuance and supply audit',
  'getbestblockhash — hash of the active tip',
  'getblockhash { height } — hash of the active block at a height',
  'getblock { hash, verbose? } — a block, optionally with full transactions',
  'getblockheader { hash } — header and chainwork, active or not',
  'gettransaction { txid } — a transaction from the chain or the mempool',
  'getbalance { address } — confirmed balance',
  'listunspent { address } — unspent outputs',
  'getcontract { address } — contract code, storage and guarded value',
  'sendrawtransaction { transaction } — validate, pool and relay',
  'submitblock { block } — submit an externally mined block',
  'generate { count, address } — mine blocks locally (regtest and testnet)',
  'getrawmempool { verbose? } — pooled transaction ids',
  'getmempoolinfo — pool size, bytes and fee range',
  'getpeerinfo — connected peers',
  'addnode { host, port } — dial a peer',
  'listbanned — currently banned hosts',
  'sync — request headers from the best-known peer',
  'auditsupply — verify the UTXO total against cumulative issuance',
  'help — this list',
];

/** Minimal client, so scripts and tests need no HTTP boilerplate. */
export async function rpcCall(
  url: string,
  method: string,
  params: Record<string, unknown> = {},
): Promise<unknown> {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ id: Date.now(), method, params }),
  });
  const body = (await res.json()) as { result?: unknown; error?: { message: string } };
  if (body.error) throw new Error(`${method}: ${body.error.message}`);
  return body.result;
}
