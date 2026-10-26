# Proposal: look-alike (typosquatting / impersonation) detection that generalises

Status: **approved 2026-10-23, implemented on `feature/lookalike`** (see section 8 for what changed in the build).

## 1. What is wrong today

`checkTyposquatting()` in `src/lib/osint-apis.ts` has a bug and a design flaw.

**The bug: a brand matches itself.** For each brand it builds digit swaps such as
`brand.replace(/i/g, '1')`. When the brand contains no `i`, as "google" doesn't, the
"swap" is just `google`, and `'google'.includes('google')` is true. "microsoft" matches
itself through its missing `e` and `a`. That is why google.com and microsoft.com are
reported as imitations of themselves.

**The design flaw.**
- It knows 52 hand-picked brand names and nothing else.
- It takes the first label (`split('.')[0]`) instead of the registrable domain. That breaks
  on `co.uk` and `com.au`, and ignores subdomains completely, so it misses
  `google.com.verify-account.ru`.
- It uses substring matching.
- Nothing asks "is this the genuine domain?" before asking "does it look like a brand?".

**Scoring makes it worse.** Any match is a **critical Fail**, which is 60 points alone.
That pushes microsoft.com to High risk; one stray VirusTotal flag added to it took
google.com to Critical.

## 2. How others do it

Every mature system **removes the genuine article before measuring similarity**.

**Chrome** is the best documented reference, and its rules are public in Chromium source [1][2][3]:
- **Reference data:** a top-domain list built from Chrome UX Report data (about 8.5k entries) and
  compiled into a trie of skeletons [4][5].
- **The genuine article goes first:** checks return early when the visited site is itself a top
  domain or one the user engages with [6]. It also throws away matches that differ only in the
  suffix, such as `google.com.mx` vs `google.com` [2].
- **Tiers:**
  - **Full-page block:** a skeleton (Unicode confusable) match against the top 500, or a
    non-tail target embedding (`google.com.evil.net`).
  - **Milder Safety Tip:** a skeleton match in the top 5k.
  - **Logged only:** edit distance against top sites. The source calls edit distance "too
    noisy" for a warning on its own [2].
- **False-positive filters:**
  - Edit distance only for names of 5+ characters (`kMinLengthForEditDistance = 5`) [7].
  - Discard pairs that differ only in the first character ("hank/tank"), only in trailing
    digits, or only by an inserted hyphen [2].
  - Embedding and combosquat checks only for brand names longer than 4 characters.
  - Common words are exempt from embedding [2].
- **Public Suffix List:** ICANN section only (`EXCLUDE_PRIVATE_REGISTRIES`). So
  `alice.github.io` is compared as `github.io` [2][7].

**dnstwist, URLCrazy and ail-typo-squatting** work the other way round [8][9][10]. They
*generate* permutations of one known domain: omission, transposition, homoglyph, bitsquat,
hyphenation, dictionary/combosquat, TLD swap and so on. They then resolve the permutations to
see which exist. That suits monitoring your own brand, not scoring arbitrary domains. dnstwist
labels the input `*original` and leaves the verdict to the analyst [8][11].

**Phishing Catcher and openSquat** score arbitrary new domains, from CT logs or a
newly-registered-domain feed [12][13]:
- **Phishing Catcher:** removes confusables, then adds points for keywords (`login`=25,
  `verify`=25), suspicious TLDs (+20), entropy, edit distance 1 to a high-value keyword (+70),
  and many hyphens or dots. It alerts at ≥65/80/90 [12][14].
- **openSquat:** Levenshtein distance ≤2 to a keyword list [13].

**Commercial tools** (Cloudflare Brand Protection, DomainTools, Proofpoint, ZeroFox, Microsoft
Defender) never rely on string similarity alone. They add registration age, MX records,
certificates, hosting and page or logo similarity [15][16][17][18][19]:
- Cloudflare allows edit distance 0–3, but **only 0 for strings under 5 characters** [15].
- DomainTools only applies its ML models to domains under 28 months old [16].

**Research on how often string similarity alone is wrong:**
- Szurdi et al.: only about **half** of lexically generated typo candidates are real typo
  domains, and **95%** of typo domains target the long tail, not the top 10k [20].
- Tian et al. (IMC 2018): of 657,663 squatting domains for 702 brands, only **0.18%** were
  confirmed phishing [21].
- Kintis et al. (CCS 2017): combosquatting is about **100×** more common than typosquatting, and
  most of it is trademark abuse rather than phishing [22].
- Agten et al. (NDSS 2015): only 156 of the Alexa top 500 brands had *any* defensive
  registrations [23]. So a look-alike usually is **not** owned by the brand, but it also usually
  isn't phishing.

**What follows:** similarity is a strong signal only in specific forms (confusables, target
embedding, brand plus a credential keyword). Plain edit distance and TLD swaps deserve a
warning, not a verdict.

## 3. Recommended approach: popularity-anchored detection (Chrome's model, generalised)

The brand list comes **from a downloaded popularity ranking**, so it covers every popular
brand automatically. The same list provides the "this is the genuine article" exemption.

### Data

| Data | What we use | Size | Licence | Refresh |
|---|---|---|---|---|
| **Tranco top 1M** [24][25] | Top **100k** registrable domains: the "known legitimate" set and the brand targets | 9.7 MB zip download; we keep about 1.8 MB (100k rows) | **Not stated by Tranco** (see licence note) | Daily, 30-day averaged, so under 0.6% churn a day [26] |
| **Public Suffix List** via `tldts` [27][28] | Registrable domain (eTLD+1), ICANN section | About 130 KB minified, 47 KB gzipped, in the npm package | PSL is MPL-2.0; tldts is MIT | Weekly tldts releases; Dependabot keeps it current |
| **Unicode confusables** (UTS #39 v18) [29][30] | Skeleton function | About 6.7k mappings; about 60 KB generated table, vendored | Unicode License v3 | Per Unicode release (yearly); regenerate the table |

Tranco ranks **registrable domains** by default (`filterPLD`) [25]. That is what we compare.
Umbrella and CrUX lists rank hostnames and would need reducing [31].

**Licence note (needs your decision).** Tranco states no licence for the list itself. Its
current inputs include Cloudflare Radar, which is CC BY-NC 4.0, non-commercial [25][32].
- **Non-commercial project:** fine as is.
- **Commercial use:** build a custom Tranco list without Radar (Tranco supports custom source
  selection), or switch to the **Majestic Million** (CC BY 3.0, commercial use allowed, daily).
  Majestic is backlink-based and easier to game [26][33].

### Algorithm

Everything runs in memory against indexes built once per daily refresh. There are **no
per-domain network calls**, so bulk jobs of hundreds of domains cost milliseconds.

1. **Normalise.** Lower-case, strip the trailing dot, and get both the ASCII (punycode) and
   Unicode forms with Node's `url.domainToASCII` and `domainToUnicode`.
2. **Split with the PSL, ICANN section.**
   - Registrable domain: `example.co.uk`.
   - Brand label: the registrable domain minus its suffix, here `example`.
   - Subdomain labels: everything left of the registrable domain.

   Private suffixes such as `github.io` and `blogspot.com` count as ordinary domains, as in
   Chrome. So `alice.github.io` is compared as `github.io`.
3. **Genuine-article exemption (first, always).** If the registrable domain is in the Tranco top
   100k, there is **no look-alike finding**. A Pass row says "Known popular domain (Tranco rank
   N)". This alone fixes google.com, microsoft.com, google.co.uk, amazon.de, googleapis.com and
   microsoftonline.com.
4. **Target embedding → Fail, critical.** Look at the subdomain labels, also split on hyphens. If
   they contain a top-10k registrable domain other than the domain's own, it is embedding. Example:
   `google.com` inside `google.com.verify-account.ru`, or `paypal.com` inside
   `paypal.com-login.info`.
   - Exemptions, from Chrome: the embedded brand label must be longer than 4 characters; the
     domain may embed itself; common English words don't count.
5. **Confusable / homoglyph → Fail, critical.** Compute the skeleton of the brand label. If it
   equals the skeleton of a top-10k brand label while the raw labels differ, it is a confusable.
   This catches `g00gle`, `paypa1`, `rnicrosoft`, and Cyrillic `аpple` (`xn--pple-43d`).
   - Skeleton: UTS #39 algorithm, then lower-case, plus a small supplementary table for
     look-alike digits TR39 doesn't fold (`0→o`, `1→l`, `3→e`, `5→s`).
   - Exemption (TR39, Chrome): a label written entirely in one non-Latin script under a TLD for
     that script, such as Cyrillic under `.ru`/`.рф`, is not a spoof of a Latin brand [3][29].
6. **Brand plus a credential keyword (combosquatting) → Fail, critical.** Split the brand label
   and subdomain labels into tokens: on hyphens, plus a greedy match against the brand index for
   unhyphenated names. Flag when one token is a top-10k brand label (length ≥5) and another is a
   **credential keyword**. Examples: `microsoft-support.co`, `secure-apple-login.net`,
   `amaz0n-billing.com`.
   - The keyword list is about 30 generic words, not brands, taken from Chrome, dnstwist and
     phishing_catcher: login, signin, secure, security, verify, verification, account, update,
     support, billing, payment, wallet, password, recovery, unlock, confirm, webscr and so on
     [2][34][14].
   - Brand plus any **other** word, such as `amazon-deals.com`, is **Warn, low**. Kintis
     shows most of those are trademark abuse, not phishing [22].
7. **Edit distance 1 → Warn, high.** Damerau-Levenshtein distance 1 between the brand label and a
   top-1k brand label of length ≥5. Chrome's false-positive filters apply (only the first letter
   differs, only trailing digits, only a hyphen). Example: `microsofft.com`. Distance-1
   neighbours are found with a deletion-neighbourhood index (SymSpell style), which is O(length)
   per domain.
8. **TLD swap → Warn, medium.** Same brand label as a top-10k domain, different suffix, and not
   itself in the top 100k. Example: `paypal.zip`. Brands often own variants that don't rank, so
   this is a warning only. Chrome treats same-name, different-suffix matches as legitimate [2].
9. **Corroboration.** The **domain-age finding** from the RDAP work (PR #1) already scores
   "registered < 30 days" separately, so a fresh edit-distance or TLD-swap domain scores
   higher without any special-casing.

### Scoring change

| Finding | Today | Proposed | Points |
|---|---|---|---|
| Any brand match, including itself | Fail, critical | removed | — |
| Known popular domain | — | Pass | 0 |
| Target embedding | (missed) | Fail, critical | 60 |
| Confusable / homoglyph of a top-10k brand | Fail, critical | Fail, critical | 60 |
| Brand + credential keyword | Fail, critical | Fail, critical | 60 |
| Edit distance 1 to a top-1k brand | Fail, critical | **Warn, high** | 25 |
| TLD swap | (missed) | **Warn, medium** | 15 |
| Brand + other word | Fail, critical (for 52 brands) | **Warn, low** | 5 |

The four high-confidence classes keep today's weight, so **detection of real squats is not
weakened**. Only the noisy classes, which the research says are wrong about half the time, drop
to warnings. Brand-new registration (+25) or a feed hit then pushes them into High or Critical.

## 4. Alternatives considered and rejected

1. **Permutation generation (dnstwist model) for every brand.** Generating variants for 10k brands
   gives tens of millions of strings. It still misses combosquats and embedding, and needs the
   same brand list. It's the right tool for watching *one* brand, not for scoring arbitrary
   domains. **Rejected:** heavy, and no better at recognising the genuine article.
2. **Wikidata "official website" (P856) as the brand-to-domain map.** It's CC0 and records actual
   ownership: about 2.47M statements, with former sites marked by end-time qualifiers [35][36].
   But bulk use means a weekly dump of about 130 GiB, or SPARQL limited to 60 s a query and 5 in
   parallel per IP, and coverage of smaller brands is uneven [36][37]. **Rejected as the
   primary source; worth adding later** to tell whether a brand owns a TLD variant
   (`amazon.de` → Amazon).
3. **Keeping a hand allowlist of brand domains.** **Rejected** by your constraint; it only covers
   brands someone thought of.
4. **An ML classifier on registration-time features (PREDATOR-style [38]).** Good results, about
   70% detection at 0.35% false positives. But it needs labelled training data and registration
   features we don't have in bulk. **Rejected for now.**
5. **Certificate Transparency.** It shows which names got certificates and when, but proves
   nothing about who owns a name [39][40]. It's useful for *finding* new squats proactively, not
   for scoring one domain. **Out of scope.**

## 5. Expected behaviour

**False positives (legitimate domains flagged):**
- **Small legitimate sites one letter off a top-1k brand:** Warn only, never Fail, with wording
  like "One letter off microsoft.com. If you meant microsoft.com, check the spelling" (Chrome's
  "Did you mean"). Popularity-ratio rules aren't documented anywhere I could verify, so I don't
  propose one.
- **Brand-owned variants outside the top 100k:** TLD-swap Warn. Adding Wikidata later would clear
  many of these.
- **Legitimate non-Latin IDNs:** exempt under the whole-script rule. Mixed-script labels are still
  checked.
- **Brand names that are dictionary words** (apple, target, booking) **next to a credential
  keyword:** would Fail. That combination is rarely benign.

**False negatives (squats missed):**
- **Squats of brands outside the top 10k:** most typo domains target the long tail [20]. We only
  protect brands the ranking knows.
- **A squat popular enough to enter the Tranco top 100k:** it would be exempt. Tranco's 30-day
  averaging makes that hard to game [26], and phishing feeds still catch it.
- **Edit distance 2+, and brands under 5 characters:** confusable and embedding checks still apply
  to short brands; edit distance doesn't.
- **Combosquats with non-credential words:** Warn low only.

**Measuring it during implementation:**
- **False-positive rate:** run the Tranco top 100k (should give 0 findings because of the
  exemption) and a random sample of ranks 100k–1M; the latter measures the warning rate.
- **Recall:** use the OpenPhish feed we already download.
- Report both in the PR.

## 6. Test set

**Must not be flagged** (no look-alike finding; a popular domain gets the Pass row):

| Domain | Why it's a trap |
|---|---|
| google.com, microsoft.com, apple.com, paypal.com | the genuine article (today's bug) |
| google.co.uk, amazon.de, amazon.co.jp | brand on a ccTLD, multi-part suffix |
| googleapis.com, microsoftonline.com, paypalobjects.com | brand plus a word, owned by the brand |
| bbc.co.uk, abc.net.au, gov.uk | naive splitting breaks on co.uk / net.au |
| alice.github.io, myshop.blogspot.com | private PSL suffix, compared as github.io / blogspot.com |
| applebees.com | contains "apple" but isn't apple + keyword |
| booking.com, target.com | dictionary-word brands |
| x.com, box.com, zoom.us | short names (edit distance disabled under 5 characters) |
| king.com (vs bing.com) | edit distance 1 but both popular, and only the first letter differs |
| президент.рф (`xn--d1abbgf6aiiy.xn--p1ai`) | whole-script Cyrillic under a Cyrillic TLD |

**Must be flagged, Fail:**

| Domain | Rule |
|---|---|
| g00gle.com | confusable (0→o) of google.com |
| paypa1.com | confusable (1→l) of paypal.com |
| rnicrosoft.com | confusable (rn→m) of microsoft.com |
| аpple.com (`xn--pple-43d.com`, Cyrillic а) | IDN homoglyph of apple.com |
| gооgle.com (Cyrillic о о) | IDN homoglyph of google.com |
| microsoft-support.co | brand + credential keyword |
| secure-apple-login.net | brand + credential keywords |
| amaz0n-billing.com | confusable brand + credential keyword |
| google.com.verify-account.ru | target embedding (and keyword) |
| paypal.com-login.info | target embedding through a hyphen |
| login.microsoftonline.com.example-auth.net | target embedding deeper in the subdomain |

**Should warn, not fail** (string similarity alone):

| Domain | Expected |
|---|---|
| microsofft.com | Warn, high: edit distance 1 |
| paypal.zip | Warn, medium: TLD swap |
| amazon-deals-today.com | Warn, low: brand + non-credential word |

## 7. Work involved (for the go-ahead)

- **Dependency:** `tldts`.
- **Generated confusables table:** a script plus the vendored output, about 60 KB.
- **Tranco download:** added to the existing daily feed cache, keeping the top 100k. That's
  about 1.8 MB on disk and a few MB in memory.
- **Rewritten detector:** `src/lib/lookalike.ts`, with no per-domain I/O.
- **Unit tests:** the test set above becomes Vitest cases (Vitest arrives with PR #1).
- **Scoring rows:** the new rows as in section 3.
- **Docs:** the docs page and the "How this score works" panel.
- **Measurement:** the false-positive and recall runs from section 5, reported in the PR.

## References

1. Chromium, Lookalike domains: https://chromium.googlesource.com/chromium/src/+/main/docs/security/lookalikes/lookalike-domains.md
2. Chromium, `lookalike_url_util.cc`: https://chromium.googlesource.com/chromium/src/+/main/components/lookalikes/core/lookalike_url_util.cc
3. Chromium, IDN display policy: https://chromium.googlesource.com/chromium/src/+/main/docs/idn.md
4. Chromium, top domains README: https://chromium.googlesource.com/chromium/src/+/main/components/url_formatter/spoof_checks/top_domains/README.md
5. Chromium, `domains.list`: https://chromium.googlesource.com/chromium/src/+/main/components/url_formatter/spoof_checks/top_domains/domains.list (count about 8.5k per The Register: https://www.theregister.com/a/5302383; not confirmed from a primary source)
6. Chromium, `lookalike_url_service.cc`: https://chromium.googlesource.com/chromium/src/+/main/chrome/browser/lookalikes/lookalike_url_service.cc
7. Chromium, `top_domain_util.cc`: https://chromium.googlesource.com/chromium/src/+/main/components/url_formatter/spoof_checks/top_domains/top_domain_util.cc
8. dnstwist: https://github.com/elceef/dnstwist and https://github.com/elceef/dnstwist/blob/master/dnstwist.py
9. URLCrazy: https://github.com/urbanadventurer/urlcrazy
10. ail-typo-squatting: https://github.com/ail-project/ail-typo-squatting
11. dnstwist man page: https://www.mankier.com/1/dnstwist
12. phishing_catcher: https://github.com/x0rz/phishing_catcher (and `catch_phishing.py`)
13. openSquat: https://github.com/atenreiro/opensquat (and `squatting_detector.py`)
14. phishing_catcher keywords: https://raw.githubusercontent.com/x0rz/phishing_catcher/master/suspicious.yaml
15. Cloudflare Brand Protection: https://developers.cloudflare.com/security-center/brand-protection/
16. DomainTools Risk Score: https://docs.domaintools.com/riskscore/userguide
17. Proofpoint Domain Discover: https://www.proofpoint.com/sites/default/files/pfpt-us-ds-domain-discover_0.pdf
18. ZeroFox domain monitoring: https://www.zerofox.com/products/domain-monitoring-tools/
19. Microsoft Defender anti-phishing policies: https://learn.microsoft.com/en-us/defender-office-365/anti-phishing-policies-about
20. Szurdi et al., "The Long 'Taile' of Typosquatting Domain Names", USENIX Security 2014: https://www.usenix.org/conference/usenixsecurity14/technical-sessions/presentation/szurdi
21. Tian et al., "Needle in a Haystack: Tracking Down Elite Phishing Domains in the Wild", IMC 2018: https://par.nsf.gov/servlets/purl/10092810
22. Kintis et al., "Hiding in Plain Sight: A Longitudinal Study of Combosquatting Abuse", CCS 2017: https://arxiv.org/abs/1708.08519
23. Agten et al., "Seven Months' Worth of Mistakes", NDSS 2015: https://www.ndss-symposium.org/ndss2015/seven-months-worth-mistakes-longitudinal-study-typosquatting-abuse
24. Tranco: https://tranco-list.eu/ (and the repo: https://github.com/DistriNet/tranco-list)
25. Tranco latest list configuration: https://tranco-list.eu/api/lists/date/latest ; methodology: https://tranco-list.eu/methodology
26. Le Pochat et al., "Tranco", NDSS 2019: https://lepoch.at/files/tranco-ndss19.pdf
27. Public Suffix List: https://publicsuffix.org/list/ and https://github.com/publicsuffix/list/wiki/Format
28. tldts: https://github.com/remusao/tldts
29. Unicode TR39 (UTS #39): https://www.unicode.org/reports/tr39/
30. confusables.txt: https://www.unicode.org/Public/security/latest/confusables.txt ; licence: https://www.unicode.org/terms_of_use.html
31. CrUX top lists: https://github.com/zakird/crux-top-lists ; Umbrella: https://s3-us-west-1.amazonaws.com/umbrella-static/index.html
32. Cloudflare Radar licence: https://developers.cloudflare.com/radar/ ; rankings: https://developers.cloudflare.com/radar/investigate/domain-ranking-datasets/
33. Majestic Million: https://majestic.com/reports/majestic-million
34. dnstwist dictionary: https://raw.githubusercontent.com/elceef/dnstwist/master/dictionaries/english.dict
35. Wikidata P856: https://www.wikidata.org/wiki/Property:P856
36. Wikidata dumps: https://www.wikidata.org/wiki/Wikidata:Database_download
37. Wikidata Query Service limits: https://www.mediawiki.org/wiki/Wikidata_Query_Service/User_Manual
38. Hao et al., PREDATOR (CCS 2016): https://collaborate.princeton.edu/en/publications/predator-proactive-recognition-and-elimination-of-domain-abuse-at/
39. How CT works: https://certificate.transparency.dev/howctworks/
40. Chrome CT policy: https://googlechrome.github.io/CertificateTransparency/ct_policy.html

**Not verified from a primary source:** Tranco's own licence, the exact size of Chrome's
`domains.list`, and any explicit "popularity ratio" rule in a production system.

## 8. Implementation notes (2026-10-23)

Built as approved, with the four additions:
1. **Licence.** A custom Tranco list using CrUX, Farsight, Majestic and Umbrella, with Cloudflare Radar left out.
   - The bundled list's permanent ID is `BUNDLED_TRANCO_LIST_ID` in `src/lib/lookalike/tranco-list.ts`. The docs page shows it too.
   - Every result names the list it used.
2. **Fail safe.** The check is skipped, with a reason, in three cases: no list exists, the newest list's data is more than 7 days old, or a list includes Radar data.
3. **Corroboration cap.** See `UNCORROBORATED_CAP` in `src/lib/scoring-rules.ts`.
4. **Punycode.** `xn--` labels are decoded before comparison. A label that mixes scripts gets its own Warn row, showing the decoded form and code points.

The test set and a run against real data turned up false positives the proposal didn't anticipate. These changes fix them:

| Change | Why |
|---|---|
| Sites on hosting platforms (PSL private section: vercel.app, github.io, pages.dev) are judged by their own name, not exempted by the platform's rank | 192 of 286 hosts in the OpenPhish feed (2026-10-23) were tenants of such platforms. Chrome's ICANN-only rule would have exempted every one of them. |
| Brands whose name is in Chromium's list of 10k common English words (apple, cloud, media, service) are protected only in the top 1k. Typos, run-together names and "brand + word" are only checked for the top 100. | "simplelogin", "secureworld" and "mediaportal" were matching brands that are just words. |
| A confusable match needs the substitution in the checked name (a non-ASCII letter, a digit the brand lacks, or "rn" for "m"), and a brand name of 4+ characters | Without this, "info.com" was flagged as a fake of "inf0.net" and "tom.be" as a fake of "torn.com". |
| Embedding must cross a dot and end before the public suffix | Stops "hm-treasury.gov.uk" matching treasury.gov and "gac-toyota.com.cn" matching toyota.com. Hyphen-only cases such as "apple-com.ru" become brand + word. |
| A suffix swap onto a country-code TLD is Warn, low | Most are owned by the brand: capitalone.ca, philips.co.in. |
| A one-letter typo of a brand next to a credential word counts | Catches "login-mircosoft.com" from the OpenPhish feed. |
| "portal" removed from the credential words | It matched government and company portals. |
| A failed refresh keeps a list that is still under 7 days old | A brief Tranco outage shouldn't switch the check off. A list older than 7 days is never used. |
| The server generates a new list every 3 days, not daily | That's polite to a free service and still well within the 7-day limit. |

**Measured** with a local copy of Tranco's public list from 2026-10-22 (development only; it includes Radar):
- **Index:** builds in about 190 ms; each domain takes about 24 µs.
- **Domains ranked 100k–1M (900k, mostly legitimate):**

  | Finding | Domains | Share |
  |---|---|---|
  | Fail tier (embedding, confusable, brand + credential word) | 138 | 0.015% |
  | Warn high (edit distance) | 1,229 | 0.14% |
  | Warn medium (gTLD swap) | 2,027 | 0.23% |
  | Warn low (ccTLD swap) | 4,452 | 0.49% |
  | Warn low (brand + word) | 3,000 | 0.33% |

  With the cap, none of these reaches High without an independent source.
- **OpenPhish (286 hosts):**
  - 22 get a look-alike finding.
  - 248 imitate no brand by name. These are random or brand-free names, and the phishing feeds catch them.
  - 16 sit on a domain that is itself in the top 100k.
