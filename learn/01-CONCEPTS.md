# 01 — Concepts

## What an HTTP response header actually is

When your browser asks a server for a page, the server sends back two
things: the page content itself, and a block of metadata called *response
headers* — plain `Name: value` lines that arrive before the body. Most
headers are mundane (`Content-Type: text/html`, `Date: ...`). A handful of
them are instructions to the browser about how to *behave* — and those are
the ones this tool checks.

A header that isn't sent isn't a neutral "no comment" — for every header in
this rubric, "missing" means the browser falls back to its most permissive
default, which is usually the least safe option. That's why "the site
didn't say anything" is treated as a finding, not silence.

## The seven headers, and the real attack each one stops

### `Strict-Transport-Security` (HSTS) — high severity

**The attack:** you're on public wifi. You type `example.com` into the
address bar with no scheme. Your browser tries `http://` first. An attacker
on the same network intercepts that plaintext request and serves you their
own page instead of redirecting you to the real `https://example.com` —
this is SSL stripping, and it works because your very first request was
never encrypted in the first place.

**The fix:** `Strict-Transport-Security: max-age=31536000; includeSubDomains`
tells the browser "for the next year, never try plain HTTP for this domain
again, even if a link or bookmark points at `http://`." Once a browser has
seen this header once, the stripping attack above stops working for that
user — which is also why it can't protect a user's *very first* visit ever
(that's what browser HSTS preload lists exist to close).

**Why `max-age=0` is worse than missing:** a server can send this exact
header with the value `max-age=0`, which tells browsers "forget HSTS for
this domain immediately." That's not a missing header, it's an
*active downgrade instruction* — which is why this tool's HSTS rule
requires the max-age number to be positive, not just present.

### `Content-Security-Policy` (CSP) — high severity

**The attack:** a comment form on a page doesn't sanitize input, and an
attacker submits a comment containing `<script>steal(document.cookie)</script>`.
Every visitor who views that comment now runs the attacker's JavaScript in
their own logged-in session — classic stored XSS.

**The fix:** a CSP like `Content-Security-Policy: default-src 'self'`
tells the browser "only run scripts that were served from this exact
origin." The injected `<script>` tag above still gets embedded in the page,
but the browser refuses to execute it, because it didn't come from an
allowed source.

**Why `unsafe-inline` defeats most of the point:** a CSP containing
`script-src 'unsafe-inline'` explicitly re-allows exactly the kind of
inline script the header exists to block. It's an extremely common
real-world compromise (some legacy code depends on inline `onclick=`
handlers) — see the GitHub example in [DEMO.md](../DEMO.md), which has this
exact gap. This tool grades that `weak`, not `ok`, because the protection
that matters most is the one being waived.

### `X-Content-Type-Options` — medium severity

**The attack:** a site lets users upload a profile picture. An attacker
uploads a file named `avatar.png` that's actually HTML with embedded
JavaScript. Some older browsers, given an ambiguous or wrong `Content-Type`,
try to be "helpful" and sniff the actual bytes, decide "this looks like
HTML," and render it as a page — running the attacker's script.

**The fix:** `X-Content-Type-Options: nosniff` tells the browser "trust the
`Content-Type` header exactly as sent, don't second-guess it." One header,
one exact required value — there's no partial credit version of this fix.

### `X-Frame-Options` — medium severity

**The attack:** an attacker builds a page with your bank's "Transfer Funds"
page loaded in an invisible iframe, positioned exactly under a big
"You won a prize, click here!" button on their own page. You click what you
think is the prize button; you actually clicked the real transfer button
underneath it. This is clickjacking.

**The fix:** `X-Frame-Options: DENY` tells the browser "never let any page
embed me in a frame, full stop." `SAMEORIGIN` is the softer version (only
this site may frame itself). The deprecated `ALLOW-FROM <url>` value is no
longer honored by current browsers at all — a site relying on it believes
it's protected and isn't, which is why this tool flags it `weak`.

### `Cross-Origin-Opener-Policy` (COOP) — medium severity

**The attack class:** when your page opens another origin in a new tab
(`window.open`), by default that new tab keeps a live JavaScript reference
back to your page's `window` object. Timing and behavior differences
observable through that reference have been used in real side-channel and
information-leak attacks (the family of issues behind Spectre-adjacent
cross-window leaks).

**The fix:** `Cross-Origin-Opener-Policy: same-origin` severs that
cross-origin window reference, isolating your page's browsing context from
anything it opens or is opened by, unless it explicitly opts back in.

### `Referrer-Policy` — low severity

**The attack:** a logged-in user is on
`https://yourapp.com/reset-password?token=abc123` and clicks an outbound
link to an ad network or analytics script embedded on that page. By
default, browsers send the *full* previous URL — token included — as the
`Referer` header on that outbound request. The ad network (or anyone
inspecting its logs) now has a live password-reset token.

**The fix:** `Referrer-Policy: strict-origin-when-cross-origin` sends only
the origin (`https://yourapp.com`), not the full path and query string,
to other origins — while still sending the full URL for same-origin
navigation, where it's harmless.

### `Permissions-Policy` — low severity

**The attack:** a page embeds a third-party ad or widget script. That
third party gets compromised (a real, repeated category of supply-chain
incident). By default, an embedded script running in the page's context can
attempt to access the camera, microphone, or geolocation APIs your page
never intended to expose.

**The fix:** `Permissions-Policy: camera=(), microphone=(), geolocation=()`
explicitly disables browser features the page doesn't use, for every
script running on it, embedded or not.

## The eighth check: information disclosure

`Server: Apache/2.4.41` or `X-Powered-By: Express/4.17.1` doesn't let an
attacker do anything by itself — but it hands them a specific version
number, which is exactly what they'd feed into a CVE database to build a
shortlist of known exploits for your exact stack. `Server: nginx` with no
version attached is normal operational information and isn't penalized;
`Server: nginx/1.18.0` is a fingerprint, and this tool treats the two
differently on purpose (see [02-ARCHITECTURE.md](02-ARCHITECTURE.md) for why
it's scored as a separate penalty rather than folded into the main rubric).

## What this tool deliberately does not do

- It does not crawl a site — only the single URL you give it
- It does not parse full CSP grammar — it looks for a small set of
  known-bad tokens (`unsafe-inline`, `unsafe-eval`), not full policy
  correctness
- It does not attempt to actually trigger XSS, clickjacking, or any other
  exploit — it reasons about what the *headers* would allow, nothing more

That's the honest boundary of a foundations-tier tool. [Mozilla Observatory](https://observatory.mozilla.org/)
and [securityheaders.com](https://securityheaders.com) do the deeper
version of this same idea — once this file makes sense, their output does
too.
