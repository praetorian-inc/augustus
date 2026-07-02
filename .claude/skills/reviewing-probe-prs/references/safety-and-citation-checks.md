# Safety, Citation, and Scrubbing Checks

Mechanical checks that are easy to skip and embarrassing to miss.

## Prompt-safety scan (live destinations in attack prompts)

Attack prompts must never contain live, third-party-owned destinations. If a target ever runs with a real fetch/tool/execution harness, a successful attack could exfiltrate to a host someone else controls.

**1. Enumerate every host/IP/email in the prompt data:**

```bash
grep -rEoh '([a-z0-9-]+\.)+[a-z]{2,}|[0-9]{1,3}(\.[0-9]{1,3}){3}' \
  internal/probes/<dir>/data/*.yaml | sort -u
grep -rEoh '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+' internal/probes/<dir>/data/*.yaml | sort -u
```

**2. Classify each.** Reserved (safe) vs registrable (must change):
- **Reserved / safe (RFC 2606 / 6761):** `example.com|org|net`, `.test`, `.invalid`, `.localhost`, `*.example`, non-routable IPs (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `127.0.0.0/8`).
- **Everything else is registrable** and must be treated as third-party-owned. `company.com`, `attacker.com`, `internal.corp`, etc. are NOT reserved.

**3. Verify "live" before claiming it in the review** (don't assert from memory):

```bash
dig +short A <domain>          # resolves? to what?
dig +short NS <domain>         # delegated?
whois <domain> | grep -iE 'Registrar:|Creation Date|Registry Expiry'
```

Quote the resolved IP / registrar / creation date in the finding — it makes the safety point airtight. A subdomain of a registered base (`api.external.attacker.com`) may resolve via wildcard *right now*; check it specifically.

**4. Recommendation:** replace with reserved values that keep the prompt realistic in shape but route nowhere (`api.external.attacker.com` → `api.external.attacker.invalid`; `ops@company.com` → `ops@example.com`).

## Citation accuracy

- Resolve **every** arXiv ID / reference (WebFetch `https://arxiv.org/abs/<id>`). Confirm it is the cited paper, not an unrelated ID. (Real example: SpAIware cited as an arXiv ID when it is Rehberger's *embracethered* blog post — there is no such paper.)
- A named technique with no real paper (blog/advisory only) should be cited as such, not dressed up as `arXiv:...`.

## Scope / title honesty

- Does the title advertise attacks that are out of scope or unimplemented in the body/code? (e.g. title lists four named attacks; body says one is "out of scope" and the other three aren't actually reproduced.)
- Recommend retitling to the **delivered** scope.

## Scrubbing local/internal references {#scrubbing}

Before saving or posting, remove anything meaningful only to you — it confuses the PR author and leaks internal context:

- **Personal test targets**: local ports/hosts you used (`localhost:9080`, a personal stack URL).
- **Cross-repo paths**: files in another repo the author can't open. Cite an **in-repo** equivalent instead (e.g. point at `internal/generators/rest/rest_test.go` for an `httptest` stub pattern, not a Guard-side `*_e2e_test.go`).
- **Ticket-only context**: internal IDs the public PR can't reference.

Quick self-check: grep your draft for your known local artifacts before posting.

```bash
grep -nE ':9080|localhost|/Guard/|/guard/|LAB-[0-9]|personal-stack' Reviews/pr<N>-review.md
```
