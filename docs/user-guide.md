# User guide: the web UI

A page-by-page tour of the admin web UI, what each verdict means and what to do about it. The UI is a
server-rendered site with no accounts other than the ones you create. It listens on `admin_listen`
(default `127.0.0.1:8081`, reach it through an SSH tunnel, a VPN or a proxy; see
[installation.md](installation.md#tls)).

Contents: [Logging in](#logging-in) - [Dashboard](#dashboard) - [Hosts](#hosts) - [Host detail](#host-detail) -
[Findings](#findings) - [Finding detail](#finding-detail) - [Verdicts](#verdicts-and-what-to-do) -
[Triage tiers](#triage-tiers) - [Rules](#rules) - [Settings](#settings) - [A daily routine](#a-daily-routine)

## Logging in

Open the UI and sign in. The first user is `admin`, created at first start from
`HOLEALIGN_ADMIN_PASSWORD` ([installation.md](installation.md#first-admin-user)). Sessions end after one
hour idle or 12 hours in total. Actions that change something (approve or reject a rule, edit a rule,
create or revoke a token, add or delete a user, change a password, save Matrix routes) ask for **your
current password** again. Login limits and what to do behind a proxy:
[troubleshooting.md](troubleshooting.md#web-login). The top bar has Dashboard, Hosts, Findings, Rules
(with a count of drafts waiting for review), Settings and Log out.

## Dashboard

The overview, and the page to open each morning.

- **Banners** (red) appear only when something is wrong: *Vulnerability feed stale*, *Rules feed
  stale*, *Alert delivery problems* (Matrix, with status codes) and *Pipeline errors* (a host's
  matching failed, a target was skipped, or a limit was hit). Causes and fixes:
  [troubleshooting.md](troubleshooting.md).
- **Cards**, each a link to the matching list: *Exploitable*, *Needs attention*, *Background*, *Not
  exploitable* and *Hosts*. Counts are per CVE per host: sibling packages of one source
  (`openssl` and `libssl3`) count once.
- **Needs attention**: the top entries, worst first.
- **Hosts not checked in recently**: hosts that have not checked in for more than 30 minutes (fixed in
  the UI; the Matrix silence alert uses `alerts.agent_silent_after`).
- **Vulnerability feed**: when the Grype DB was last checked, last updated and the last error.
- **Rules feed** (only when `rules.feed.enabled`): installed bundle number, last update, last check,
  last error.

## Hosts

One row per host: hostname (with a "local (built-in)" badge for the server's own host in agentless
mode), labels, OS, agent version, last check-in, and counts of exploitable, needs-attention and
background findings. Empty list: no host has enrolled yet; create a token under Settings.

## Host detail

- Identity: host ID, labels, OS and kernel, agent version, last check-in (with a *stale* badge after 30 minutes).
- **Findings** for this host in the same list as the Findings page. "Show N resolved" reveals findings
  that disappeared.
- **Targets**: what was scanned: the `host` itself and each container image (with the containers using
  it). A missing target means no inventory arrived for it.
- **Facts**: the configuration facts the server holds for the host, as JSON. When a verdict is
  `conditions_unknown` because a fact is missing, compare with this list (and with
  `holealign-agent -print-facts` on the host). Secrets in `file.match` values are masked before they
  leave the host.

Hosts cannot be deleted in the UI; use `holealign-server host delete`
([operations.md](operations.md#cli-reference)).

## Findings

All findings across hosts, 50 per page, **grouped by CVE per host** with the packages listed inside.
Filters: verdict (default: all open, which excludes resolved), label, host, KEV (yes or no),
vulnerability ID, tier (needs attention by default; `all` and `background` are one click away) and
"include resolved". The view switch changes between grouped by CVE and one row per package. Columns:
verdict (with a KEV badge for CISA Known Exploited Vulnerabilities), vulnerability, packages with the
fixed version, host, severity, CVSS, EPSS, fix state. Clicking a CVE opens the vulnerability page: the
same CVE on every host, with links to NVD and OSV.

## Finding detail

One package, one vulnerability, one host.

- **Verdict**: the verdict badge and a one-line **reason** naming the facts that decided it, for
  example `os.libc=glibc, sshd.config.logingracetime=120`. The rule that decided is linked with its
  status (`reviewed` or `draft`). "No rule covers this vulnerability yet" explains an unknown verdict.
- **Vulnerability**: ID and aliases, severity, CVSS, EPSS, KEV, references.
- **Package**: host, target, package and version, type, PURL, **fixed in**, fix state (`fixed`,
  `not-fixed`, `wont-fix`, `unknown`), first and last seen.
- **Fix command**: a package-manager command derived for the host's OS, when a fixed version exists.
  Review it before you run it; it is a suggestion built from validated names, not executed by
  Holealign.
- **Rule**: for reviewed rules the title, explanation, the conditions (*Exploitable if*, *Not affected
  if*), the facts read, upgrade and mitigation advice, references. For a draft rule it shows only the
  LLM-written text, shortened and labelled *unreviewed*, with a link to review it. Never follow
  instructions found in that text.

## Verdicts and what to do

| Verdict | Meaning | What to do |
|---|---|---|
| `exploitable` | The package is vulnerable and the rule's conditions hold on this host. Alerts Matrix. | Fix first: upgrade to the fixed version, or apply the rule's mitigation. Open the finding for the reason and the fix command. |
| `affected_not_exploitable` | Vulnerable package, but the conditions are not met or are mitigated (for example `LoginGraceTime 0`). Silent. | Plan the upgrade normally. Re-check if the configuration may change: the verdict follows the host's facts and flips when they do. |
| `conditions_unknown` | No rule covers this CVE, a fact the rule needs is missing, or evaluating failed. **Not** a statement that it is safe. | Check the reason. Missing fact: see [troubleshooting.md](troubleshooting.md#collector-and-facts). No rule: use the triage tier (below), and write or approve a rule for CVEs you care about. |
| `not_affected` | A rule says the package is not affected at all (for example a different build or feature). | Nothing, unless you doubt the rule: open it from the finding. |
| `resolved` | The finding disappeared: the package was upgraded or removed. | Nothing. Resolved findings are deleted after `retention.resolved_findings` (30 days). |

A **draft** (LLM-written, unreviewed) rule can never lower a verdict: anything it does not call
exploitable shows as `conditions_unknown`. An `exploitable` result from a draft is kept only when the
rule is grounded in host facts. Details: [rules.md](rules.md#how-verdicts-are-decided).

## Triage tiers

Most findings on a fresh host are `conditions_unknown`, because there is no rule for them. The UI sorts
open findings into two tiers:

- **Needs attention**: `exploitable`; or `conditions_unknown` and the CVE is in CISA KEV, or its EPSS is
  at least `triage.epss_threshold` (default 10 %), or it is Critical or High severity with a fix available.
- **Background**: everything else open.

The tier only changes what the UI emphasises; alerts follow the verdict rules
([notifications.md](notifications.md)). Work the attention list from the top; to shrink it for good,
cover recurring CVEs with rules. Full definition: [rules.md](rules.md#reading-the-dashboard-attention-vs-background).

## Rules

**Rules** lists every rule with status tabs (All, Draft, Reviewed, Rejected), title, **source**
(`built-in`, `feed #<seq>` or `local`) and the CVEs it covers. Statuses: `reviewed` rules are in force;
`draft` rules (written by the LLM) are inert until approved; `rejected` rules are never applied. Layers
and precedence: [rules-feed.md](rules-feed.md#layers-and-precedence).

A rule page shows the explanation, the actions (Approve, Reject, each with a password field), the YAML
editor ("Validate and save") and the findings the rule affects. Saving stores a **local** rule with the
same ID: that overrides a built-in or feed rule on this server only, reloads the engine and
re-evaluates all hosts. Feed rules are read-only; the override is the way to change one.

### Reviewing a draft before you approve it

Approving turns LLM-written text into logic that decides alerts and can make agents read files. The
page shows a *Before you approve* panel; check each item:

1. **Files read.** If the rule has `fact_requests`, the panel lists each fact, collector, path glob and
   regular expression. Approving makes **every agent where the rule applies read those files as root**,
   subject to the allowlist and masking ([rules.md](rules.md#filematch-policy)). Ask: is each path
   needed, and could the pattern capture anything sensitive? If the panel says "requests no extra
   files", nothing new is collected.
2. **Conditions.** Read `exploitable_if` against what you know of the vulnerability (advisory,
   vendor text, the linked references). A condition that is too broad alerts on hosts that are not at
   risk; too narrow hides real risk as `affected_not_exploitable`. Check that it reads the facts it
   should, and the right values.
3. **`not_affected_if`.** When present, a warning is shown: this condition can mark hosts not
   affected, which lowers their verdict. Be strict with it. Prefer rules with only `exploitable_if`.
4. **Scope.** The CVEs and packages the rule covers. A rule for the wrong package name never fires.
5. **Look at real findings.** The page lists the findings the rule affects; open one and check that
   the reason matches the facts on that host.

Then approve with your password. Reject if unsure: a rejected rule stays visible but is never applied.
The text of a draft (title, explanation, advice) is untrusted output from a model; it is shown
shortened and as plain text. Approve and reject are recorded in the audit log
([operations.md](operations.md#monitoring-and-logs)). LLM setup and limits: [llm.md](llm.md).

## Settings

- **Matrix routes**: one line per label, `label = !room:server, !other:server`. A host is alerted in
  the rooms of all its labels; with no matching route it uses `matrix.default_rooms`. Routes from
  `server.yaml`, default rooms and ops rooms are shown read-only below. Saving needs your password.
  See [notifications.md](notifications.md#routing).
- **Enrollment tokens**: list with created, last used, hosts used and maximum, expiry, labels and
  status (`active`, `revoked`, `expired`, `exhausted`); a form to create one (name, max hosts, expiry
  such as `72h` or `7d`, labels) and a Revoke button. A new token is shown **once**, with a ready-made
  `agent.yaml` snippet. Labels on a token are authoritative for the hosts that enroll with it.
- **Users**: add users (password 12 or more characters), change a password, delete a user (not
  yourself). There are no roles: every user can do everything.
- **LLM rule drafting**: read-only provider, model and daily limit. The API key is never shown.

The vulnerability and rules feed status is on the Dashboard, not in Settings. Everything else
(listeners, retention, limits) is in `server.yaml` ([configuration.md](configuration.md)).

## A daily routine

1. Open the Dashboard. Fix banners first (stale feed, delivery problems).
2. Look at **Exploitable**. Upgrade or mitigate; the Matrix alert already told you.
3. Skim **Needs attention**. For each KEV or high-EPSS CVE with no rule, decide: upgrade, or write or
   approve a rule so the verdict becomes a fact.
4. Check **Hosts not checked in recently**.
5. Review drafts in **Rules** when the count in the top bar is not zero.
