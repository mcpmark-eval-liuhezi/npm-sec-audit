# Advisory Triage — lodash & express (npm)

Per advisory returned by GitHub's advisory database for `lodash` and `express` (ecosystem: npm, all severities): the ID, the package, the severity, and a sentence on what it means for our service.

**GHSA-jf85-cpcp-j695 — lodash — critical**
Prototype pollution via `defaultsDeep` (CVE-2019-10744) can let an attacker modify `Object.prototype` when untrusted objects are deep-merged, corrupting every object in our process; fixed in 4.17.12, so we must pin lodash at or above that.

**GHSA-35jh-r3h4-6jhm — lodash — high**
Command injection via the `_.template` function (CVE-2021-23337) executes attacker code when a template string originates from untrusted input; we should never build templates from request data, and upgrade to 4.17.21.

**GHSA-p6mc-m468-83gw — lodash — high**
Prototype pollution via `pick`, `set`, `setWith`, `update`, `updateWith`, and `zipObjectDeep` (CVE-2020-8203) when property identifiers come from users, potentially causing DoS or code execution; upgrade to 4.17.19 and never pass user-controlled keys or paths to these functions.

**GHSA-r5fr-rjxr-66jc — lodash — high**
Code injection via `_.template` `options.imports` key names (CVE-2026-4800) — the fix for CVE-2021-23337 missed this path into the same `Function()` sink, so any codebase still passing untrusted import keys (or running on a polluted `Object.prototype`) is exposed; upgrade to 4.18.0.

**GHSA-4xc9-xhrj-v574 — lodash — high**
Prototype pollution via `merge`, `mergeWith`, and `defaultsDeep` (CVE-2018-16487) through `{constructor: {prototype: {...}}}` payloads; fixed in 4.17.11, so the same merge-with-untrusted-data caution applies and the floor for our lodash version is raised.

**GHSA-f23m-r3pf-42rh — lodash — medium**
Prototype pollution via array path bypass in `_.unset` and `_.omit` (CVE-2026-2950) — array-wrapped path segments dodge the CVE-2025-13465 guard and can delete methods from built-in prototypes; upgrade to 4.18.0, there is no workaround.

**GHSA-xxjr-mmjv-4gpg — lodash — medium**
Prototype pollution via crafted paths in `_.unset` and `_.omit` (CVE-2025-13465) deletes properties from global prototypes without overwriting behavior; fixed in 4.17.23, so it only bites if we run an older lodash or call these functions on user-supplied paths.

**GHSA-29mw-wpgm-hmr9 — lodash — medium**
ReDoS via `toNumber`, `trim`, and `trimEnd` (CVE-2020-28500) lets a crafted long string burn CPU and deny service; upgrade to 4.17.21 and validate/limit string lengths before passing them to these helpers.

**GHSA-x5rq-j2xg-h7qm — lodash — medium**
ReDoS in the date handler regex (CVE-2019-1010266) triggered by very long attacker-supplied strings; upgrade to 4.17.11 so request-length limits plus a patched lodash close this off.

**GHSA-fvqr-27wr-82fm — lodash — medium**
Prototype pollution via `__proto__` in `defaultsDeep`, `merge`, and `mergeWith` (CVE-2018-3721); fixed in 4.17.5, reinforcing that we must never merge untrusted payloads into objects without sanitization.

**GHSA-8p5q-j9m2-g8wr — lodash — low**
Withdrawn/disputed arbitrary code execution via the template function (CVE-2021-41720) — GitHub published it as withdrawn because it is the developer's responsibility not to evaluate untrusted input; recorded for audit completeness, no action beyond good template hygiene.

**GHSA-rv95-896h-c2vc — express — medium**
Open redirect via malformed URLs in `res.location()`/`res.redirect()` (CVE-2024-29041) that can bypass even properly implemented allow lists; upgrade to 4.19.2 (or 5.0.0-beta.3+) and pre-parse redirect targets before passing them to Express.

**GHSA-cm5g-3pgc-8rg4 — express — medium**
Resource injection in `res.links()` Link header values (CVE-2024-10491) lets unsanitized data preload malicious resources; only affects express <= 3.21.4, so confirm we are on 4.x/5.x and sanitize anything placed in Link headers.

**GHSA-gpvr-g6gh-9mc2 — express — medium**
XSS via missing charset in the Content-Type header on 4xx responses (CVE-2014-6393) enables non-standard-encoding attacks such as UTF-7; fixed in 3.11/4.5, which is ancient, so this only matters if we somehow pin an ancient express.

**GHSA-qw6h-vgh9-j6wx — express — low**
XSS via `response.redirect()` with untrusted input (CVE-2024-43796) — even sanitized input can execute untrusted code if an attacker controls the redirect target; upgrade to 4.20.0 and validate redirect URLs against an explicit allowlist.

**GHSA-jj78-5fmv-mv28 — express — low**
Open redirect in Express 3.4.5 through pre-4.0.0-rc1 (CVE-2024-9266) affecting the Response object; not applicable if we run 4.x/5.x, but worth confirming our locked version range excludes 3.x.

**GHSA-pj86-cfqh-vqx6 — express — low**
Withdrawn advisory: the extended query parser's `request.query` prototype behavior (CVE-2024-51999) was judged a correctness bug rather than a vulnerability; recorded for completeness, though upgrading to 4.22.0/5.2.0 makes `request.query` a plain object and removes any residual concern.
