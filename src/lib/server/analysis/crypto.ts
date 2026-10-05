// ============================================
// CRYPTO WALLET ANALYSIS - every source runs in parallel as its own task
// ============================================
import type { AnalysisResult, Indicator } from '@/types';
import {
  checkBitcoinWallet,
  checkEthereumWallet,
  checkChainAbuse,
  checkBTCBlackDNSBL,
  checkRansomwareAddresses,
  checkGitHubScamLists,
  checkChainalysisSanctions,
  type ChainAbuseResult,
  type CryptoResult,
  type CryptoScamDBResult,
} from '@/lib/osint-apis';
import type { AnalysisContext } from './context';
import { TaskRunner } from './tasks';
import { buildResult } from './scoring';
import { withFacts } from './facts';

export async function analyzeCrypto(address: string, ctx: AnalysisContext): Promise<AnalysisResult> {
  const isBitcoin = address.startsWith('1') || address.startsWith('3') || address.startsWith('bc1');
  const isEthereum = address.startsWith('0x') && address.length === 42;
  const runner = new TaskRunner(ctx);

  runner.add<Indicator[]>({
    id: 'format',
    label: 'Address format',
    source: 'Rules',
    sources: 0,
    run: async () => [
      {
        id: 'wallet-format',
        name: 'Address format',
        status: isBitcoin || isEthereum ? 'pass' : 'fail',
        description: isBitcoin ? 'Valid Bitcoin address.' : isEthereum ? 'Valid Ethereum address.' : 'Unknown wallet format.',
        severity: isBitcoin || isEthereum ? 'low' : 'high',
        source: 'Format rules',
      },
    ],
    build: (found, out) => out.indicators.push(...found),
  });

  if (isBitcoin || isEthereum) {
    const explorer = isBitcoin ? 'Blockchain.info' : 'Etherscan';
    runner.add<CryptoResult>({
      id: 'wallet',
      label: 'Wallet activity',
      source: explorer,
      run: () => (isBitcoin ? checkBitcoinWallet(address) : checkEthereumWallet(address)),
      build: (w, out) => {
        out.indicators.push({
          id: 'wallet-activity',
          name: 'Wallet activity',
          status: w.txCount > 0 ? 'pass' : 'warning',
          description:
            w.txCount > 0
              ? `${w.txCount.toLocaleString('en-US')} transaction(s), balance ${w.balance}.`
              : 'No transaction history. Fresh wallets are often created for a single scam.',
          severity: w.txCount > 0 ? 'low' : 'medium',
          source: explorer,
        });
        out.details.blockchain = {
          title: explorer,
          data: { network: w.network, balance: w.balance, transactions: w.txCount, received: w.totalReceived, sent: w.totalSent },
          status: 'pass',
        };
      },
    });
  }

  runner.add<ChainAbuseResult>({
    id: 'chainabuse',
    label: 'Scam reports',
    source: 'ChainAbuse',
    run: () => checkChainAbuse(address),
    build: (c, out) => {
      out.indicators.push({
        id: 'chainabuse',
        name: 'Scam reports',
        status: c.found ? 'fail' : 'pass',
        description: c.found
          ? `${c.reports} report(s)${c.categories.length ? `: ${c.categories.join(', ')}` : ''}.`
          : 'No community scam reports.',
        severity: c.found ? 'critical' : 'low',
        source: 'ChainAbuse',
      });
    },
  });

  if (isBitcoin) {
    runner.add<{ listed: boolean; reason?: string }>({
      id: 'btc-black',
      label: 'BTC Black',
      source: 'BTC Black',
      run: () => checkBTCBlackDNSBL(address),
      build: (b, out) => {
        out.indicators.push({
          id: 'btc-black',
          name: 'BTC Black',
          status: b.listed ? 'fail' : 'pass',
          description: b.listed ? 'Listed on the BTC Black blocklist.' : 'Not listed.',
          severity: b.listed ? 'critical' : 'low',
          source: 'BTC Black',
        });
      },
    });
  }

  runner.add<CryptoScamDBResult>({
    id: 'sanctions',
    label: 'Ransomware and sanctions',
    source: 'OpenSanctions',
    run: () => checkRansomwareAddresses(address),
    build: (r, out) => {
      out.indicators.push({
        id: 'ransomware-db',
        name: 'Ransomware and sanctions',
        status: r.isScam ? 'fail' : 'pass',
        description: r.isScam ? `${r.description}.` : 'Not a known ransomware or sanctioned address.',
        severity: r.isScam ? 'critical' : 'low',
        source: r.source,
      });
    },
  });

  runner.add<CryptoScamDBResult>({
    id: 'github-lists',
    label: 'Known scam wallets',
    source: 'GitHub lists',
    run: () => checkGitHubScamLists(address),
    build: (r, out) => {
      out.indicators.push({
        id: 'github-scam-lists',
        name: 'Known scam wallets',
        status: r.isScam ? 'fail' : 'pass',
        description: r.isScam ? `${r.description}.` : 'Not on the community scam-wallet lists.',
        severity: r.isScam ? 'high' : 'low',
        source: 'GitHub lists',
      });
    },
  });

  runner.add<{ sanctioned: boolean; programs?: string[]; entity?: string }>({
    id: 'chainalysis',
    label: 'OFAC sanctions',
    source: 'Chainalysis',
    serverKeyEnv: 'CHAINALYSIS_API_KEY',
    run: () => checkChainalysisSanctions(address),
    build: (c, out) => {
      out.indicators.push({
        id: 'chainalysis',
        name: 'OFAC sanctions',
        status: c.sanctioned ? 'fail' : 'pass',
        description: c.sanctioned
          ? `OFAC sanctioned address${c.programs?.length ? ` (${c.programs.join(', ')})` : ''}.`
          : 'Not on the OFAC sanctions list.',
        severity: c.sanctioned ? 'critical' : 'low',
        source: 'Chainalysis',
      });
    },
  });

  await runner.run(address, 'crypto');
  const { indicators, details } = runner.collect();
  return withFacts(buildResult('crypto', address, indicators, details, ctx), {
    abuseScore: null,
    vtDetections: null,
    proxyType: null,
    country: null,
  });
}
