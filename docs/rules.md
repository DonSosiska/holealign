# Rules and verdicts

A Grype match says a package version is vulnerable. A **rule** says under which host conditions that
vulnerability can actually be exploited, written as a CEL expression over facts the agents collect.
This page explains how verdicts are decided, how to write and test a rule, the fact catalog, the
strict `file.match` policy, the eight shipped rules, and how LLM-drafted rules are reviewed. The
normative text is [contracts.md section 4](contracts.md#4-rules).

Contents: [How verdicts work](#how-verdicts-work) - [Writing a rule](#writing-a-rule) -
[CEL environment](#cel-environment) - [Fact catalog](#fact-catalog) -
[file.match policy](#filematch-policy) - [Testing a rule locally](#testing-a-rule-locally) -
[Reading the dashboard](#reading-the-dashboard-attention-vs-background) - [Shipped rules](#shipped-rules) - [Review workflow for LLM drafts](#review-workflow-for-llm-drafts)

## How verdicts work

For every finding (host, target, package, vulnerability) the server picks the applicable rule and
evaluates it against the host's facts.

| Verdict | Meaning |
|---|---|
| `exploitable` | Package is vulnerable and the conditions hold. Alerts. |
| `affected_not_exploitable` | Vulnerable, but the conditions are not met or are mitigated. Silent. |
| `conditions_unknown` | No rule, a required fact is absent, or the expression failed. |
| `not_affected` | A rule says the package is not affected at all. |
| `resolved` | The finding is gone (package upgraded or removed). |

Rules come from three layers (built-in < signed rules feed < local DB); see
[rules-feed.md](rules-feed.md#layers-and-precedence). The UI shows each rule's source as `built-in`,
`feed #<seq>` or `local`.

Algorithm, per finding:

1. Find the applicable rule. None: `conditions_unknown`, reason "no rule".
2. Any fact the rule lists in `facts` (or any requested `file.match:*` fact) is absent:
   `conditions_unknown`, and the reason lists the missing facts. **Absent means unknown, never false.**
3. `not_affected_if` is set and true: `affected_not_exploitable`.
4. `exploitable_if` true: `exploitable`; false: `affected_not_exploitable`.
5. An expression error: `conditions_unknown`, and the reason contains the error.
6. **Draft guard** (rules with `status: draft` only). A draft never lowers a verdict. Any result other
   than `exploitable` becomes `conditions_unknown`. An `exploitable` result is kept only when the
   rule is grounded in host facts; a rule whose result does not depend on any fact becomes
   `conditions_unknown`. Reviewed rules are never affected.

The reason is short and names the deciding facts, for example
`os.libc=glibc, sshd.config.logingracetime=120`. It never contains `file.match` values.

Which rule applies: a rule matches a finding when the finding's vulnerability ID or one of its
aliases is in the rule's `vulns` and a `packages` selector matches (`name` is a `path.Match` glob such
as `nginx*` or `linux-image-*`; `type` is equal, or empty for any). Rules with `status: rejected` are
ignored. If several apply (for example separate rules for nginx and Apache), the winner is chosen by
status (`reviewed` over `draft`), then database over file, then the first ID.

Sources of rules: YAML files in `rules_dir` (the shipped ones, read at start) and rules in the
database (LLM drafts and edits made in the web UI). A database rule with the same `id` as a file rule
overrides it, except that a database draft never replaces a file rule.

## Writing a rule

A rule is a YAML file (strict: unknown keys are errors). Put it in `rules_dir` and restart the
server, or create and edit it in the web UI. Required: `id`, `vulns`, `packages`, `exploitable_if`,
`title`, `explanation`, `status`, `source`.

```yaml
id: CVE-2024-6387                        # ^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$
vulns: [CVE-2024-6387]                   # CVE/GHSA IDs this rule covers
title: "OpenSSH regreSSHion: unauthenticated RCE via SIGALRM race"
packages:                                # at most 50 selectors; name is a glob
  - {name: openssh-server, type: deb}
  - {name: openssh-server, type: rpm}
facts: [os.libc, sshd.config]            # every fact the expressions read; any absent -> conditions_unknown
exploitable_if: >                        # CEL, must return bool
  pkg.name.startsWith("openssh-server") &&
  facts["os.libc"] == "glibc" &&
  facts["sshd.config"][?"logingracetime"].orValue("120") != "0"
not_affected_if: ""                      # optional CEL bool; true -> affected_not_exploitable
explanation: "Exploitable only on glibc systems while LoginGraceTime is non-zero."
fix:
  upgrade: "Upgrade OpenSSH to the distribution's patched package and restart sshd."
  mitigation: "Set 'LoginGraceTime 0' in /etc/ssh/sshd_config and reload sshd."
fact_requests: []                        # optional file.match requests, see below (at most 5)
status: reviewed                         # reviewed | draft | rejected
source: user                             # builtin | user | llm:<model>
references: [https://www.qualys.com/2024/07/01/cve-2024-6387/regresshion.txt]
```

Rules for a good rule:

- List in `facts` exactly the facts that must be known to decide. A fact you read with an
  `orValue` default and whose absence should not block the verdict can be left out of the list, but
  every fact read in an expression must be a catalog fact (unknown names are rejected), and a
  catalog fact that is read must be listed.
- Version ranges are already handled by Grype. Do not repeat them unless the advisory has a
  configuration-dependent version rule.
- Express reachability with facts (`services.active`, `sockets.ports`, `nginx.directives`), not with
  `true`.
- `exploitable_if: 'false'` is legitimate when there is no realistic attack path (see
  CVE-2024-4577). Say why in `explanation`.
- A rule is limited to 32 KiB as JSON. Expression cost limit is 10 000 and evaluation has a 50 ms
  timeout; keep expressions simple.

## CEL environment

Expressions are [CEL](https://cel.dev/) and must return a bool.

| Name | Type | Contents |
|---|---|---|
| `facts` | `map(string, dyn)` | Host facts. Read as `facts["literal"]` (the name must be a string literal). |
| `pkg` | `map(string, dyn)` | `name`, `version`, `type`, `purl`, `fixed_versions` (list), `target`, `target_kind` |
| `host` | `map(string, dyn)` | `hostname`, `labels` (list), `os_id`, `os_version_id`, `kernel`, `arch` |

Functions:

| Function | Meaning |
|---|---|
| `version_lt(a, b)` / `version_ge(a, b)` | Loose version comparison: numeric segments compared numerically (`"6.1.10" < "6.10.0"`). |
| `has_module(list, name)` | Sugar for `name in list`. |

Optional types are enabled. Use the optional index for map keys that may be missing:

```
facts["kernel.sysctl"][?"user.max_user_namespaces"].orValue("1") != "0"
has_module(facts["nginx.modules"], "http_v2_module")
version_lt(pkg["version"], "2.4.58")
```

A plain `m["key"]` on a missing key is an evaluation error and gives `conditions_unknown`. The
legacy spelling `m.?["k"]` is rejected by validation. Values of `sshd.config`, `kernel.sysctl` and
`php.ini` are strings; ports in `sockets.listening` are ints; `sockets.ports` is `list<int>`.

## Fact catalog

Facts are a flat map. Built-in facts are collected on every check-in; `file.match:<id>` only when
requested. **Absent means unknown** (the collector is not applicable, the binary is missing, or a
command failed). When a collector determines the software is not installed it sets
`<x>.installed = false` and omits the other `<x>.*` facts. Commands run with a fixed argv (no
shell), a 10 s timeout and stdout capped at 4 MiB. The authoritative table is
[contracts.md section 3](contracts.md#3-fact-catalog); the list of names is in
`internal/server/rules/catalog.go`.

| Fact | Type | Source |
|---|---|---|
| `os.id`, `os.version_id` | string | `/etc/os-release` |
| `os.libc` | string (`glibc` or `musl`) | `ldd --version`, `/lib/ld-musl-*` |
| `os.libc_version` | string | `ldd --version` |
| `kernel.release` | string | `uname -r` |
| `kernel.modules` | list<string> | `/proc/modules` (names) |
| `kernel.sysctl` | map<string,string> | `/proc/sys`, allowlist: `kernel.unprivileged_userns_clone`, `user.max_user_namespaces`, `kernel.unprivileged_bpf_disabled`, `kernel.kptr_restrict`, `kernel.yama.ptrace_scope`, `kernel.dmesg_restrict`, `net.ipv4.ip_forward`, `net.ipv6.conf.all.disable_ipv6`, `fs.protected_symlinks`, `fs.protected_hardlinks`, `vm.unprivileged_userfaultfd`, `kernel.io_uring_disabled`, `kernel.apparmor_restrict_unprivileged_userns` |
| `services.active` | list<string> | `systemctl list-units --type=service --state=running` (names without `.service`); fallback to `/proc/<pid>/comm` mapped through a table of well-known daemons |
| `services.source` | string (`systemd` or `proc`) | origin of `services.active` |
| `sockets.listening` | list<map{proto,addr,port,process}> | `/proc/net/{tcp,tcp6,udp,udp6}` plus `/proc/*/fd` inode mapping (collector reads `/proc/1/net/*`) |
| `sockets.ports` | list<int> | distinct listening ports |
| `sshd.installed` | bool | `sshd` binary exists |
| `sshd.version` | string | `sshd -V` / `ssh -V` |
| `sshd.config` | map<string,string> | `sshd -T` (keys lowercased, first value) |
| `nginx.installed`, `nginx.version` | bool, string | `nginx -v` |
| `nginx.modules` | list<string> | `nginx -V` configure args (`--with-*` names, e.g. `http_v2_module`) |
| `nginx.directives` | map<string,list<string>> | `nginx -T`: directive name to all values (comments stripped, secret-looking values masked as `***`, values capped at 256 bytes) |
| `nginx.http2` | bool | `http2 on` directive or `listen ... http2` |
| `apache.installed`, `apache.version` | bool, string | `apachectl -v` / `httpd -v` |
| `apache.modules` | list<string> | `apachectl -M` (e.g. `proxy_module`) |
| `apache.http2` | bool | `http2_module` loaded and `Protocols` contains `h2` or `h2c` |
| `php.installed`, `php.version` | bool, string | `php -v` |
| `php.sapi` | list<string> | php-fpm, apache2handler, cli present |
| `php.ini` | map<string,string> | `php -i` for `allow_url_include`, `allow_url_fopen`, `disable_functions`, `expose_php`, `open_basedir`, `cgi.fix_pathinfo` |
| `openssl.version` | string | `openssl version` |
| `docker.installed`, `docker.version` | bool, string | Docker API `/version` |
| `docker.containers` | list<map{name,image,image_id,ports,privileged}> | Docker API `/containers/json` plus inspect |
| `runc.version` | string | `runc --version` |
| `sudo.version` | string | `sudo -V` |
| `agent.inventory_error` | string | last inventory scan error (200 chars); absent when the last scan succeeded |
| `agent.collector_error` | string | last error the root collector answered with (200 chars) |
| `agent.skipped` | list<string> | tools not run because their config tree is not trustworthy, e.g. `nginx: /etc/nginx/conf.d writable by gid 33` |
| `file.match:<id>` | list<string> | parametrised, see below |

`agent.skipped`: before `nginx`, `php`, `sshd`, `apachectl`/`httpd` and `sudo` are run, the
collector checks that their configuration trees and every ancestor directory are root-owned and not
group- or world-writable. Otherwise the tool is skipped and its facts are omitted (so rules that
need them give `conditions_unknown`); the reason is listed in `agent.skipped`. See
[operations.md](operations.md#troubleshooting).

## file.match policy

`file.match` lets a reviewed rule ask agents for matching lines of a configuration file, when no
built-in fact covers what it needs. It is the only thing a server can ask an agent to collect, and the
policy is deliberately strict because the collector runs as root and the server (or an LLM) writes
the request. A request is a rule `fact_requests` entry:

```yaml
# illustrative
facts: [file.match:cve-2024-0000.proxy]
fact_requests:
  - name: file.match:cve-2024-0000.proxy        # file.match:<rule id lowercased>.<id>
    collector: file.match
    params:
      path: /etc/apache2/mods-enabled/proxy*.load
      pattern: 'ProxyPass\s'
```

**Server-side validation** (when a rule is saved or loaded):

- At most 5 requests per rule. Name `file.match:<rule ID sanitized>.<id>` with `[a-z0-9._-]`.
- `path`: absolute, clean, under `/etc/`, `/opt/<app>/conf/`, `/opt/<app>/etc/` or `/usr/local/etc/`,
  without `[`, `]` or `\`. Wildcards (`*`, `?`) only in the final component, which needs a literal
  prefix or suffix of at least 3 characters. Directory components are literal.
- A denylist for names and locations: `shadow`, `passwd`, `sudoers`, `*.key`, `*.pem`, `*.p12`,
  `*.pfx`, `*.jks`, `.env`, `.htpasswd`, anything containing `secret`, `token`, `credential`,
  `key`, plus credential-bearing directories such as `/etc/kubernetes`, `/etc/ssl`, `/etc/pki`,
  `/etc/letsencrypt`, `/etc/default`, `/etc/sysconfig`, `/etc/docker`, `/etc/mysql`,
  `/etc/postgresql`, `/etc/redis`, `/etc/cron*`, `/etc/ldap`. The full list is in
  `internal/server/rules/filematch.go` and [contracts.md](contracts.md#4-rules).
- `pattern`: RE2, at most 256 characters, repeat counts at most 100. It must contain a **mandatory
  literal** of at least 4 characters, must not match the empty string, and must match at most 3 of
  about 45 diverse probe lines. So `.*` or a pattern that dumps whole files is rejected.
- Only **reviewed** rules' requests are sent to agents. Drafts are inert.

**Agent-side enforcement** (the collector re-checks everything and does not rely on the server):

- Allowed roots again, symlinks resolved first; a stricter-or-equal denylist on the physical path.
- Only regular, world-readable files, opened with `O_NOFOLLOW` (`openat2` with `RESOLVE_NO_SYMLINKS`
  where available) and every ancestor directory must be traversable by others. Files with a NUL
  byte or a `-----BEGIN ` line are skipped; crypt-hash lines are dropped.
- Secrets are masked **before** the pattern is matched, so a pattern cannot probe secret values
  character by character. Values after keys containing `key`, `secret`, `token`, `pass`, `pw`,
  `psk`, `credential`, `auth` or `community` become `***`; `Bearer ...`, URL user info and long
  random-looking tokens are masked.
- Budgets per check-in: 20 requests, 2 MiB read, 500 lines in total (200 per request), 5 s.

Why so strict: a rule is data from an LLM or an administrator, executed with root's read access on
every host. The allowlist and the masking make the worst case "a non-secret config line leaves the
host", and the review step puts a human in front of every path.

## Testing a rule locally

There is no separate "dry run" command. Practical workflow:

1. **See the facts.** On a host (or any Linux machine with the agent binary) run
   `panoptes-agent -print-facts`. It prints exactly the JSON the server will see, so you can check
   the keys and types your expression reads (for example the lowercase keys of `sshd.config`).
2. **Check syntax and fact names.** Put the YAML in `rules_dir` and restart the server. An invalid
   rule is skipped and logged as `invalid rule skipped` with the reason (`journalctl -u
   panoptes-server | grep 'invalid rule'`). In the web UI, **Rules**, open the rule, edit the YAML
   and press "Validate and save": the same validation runs and every problem is listed.
3. **See the verdict.** After saving or reloading, all hosts are re-evaluated. Open the finding in
   the UI: the verdict reason names the deciding facts and values. A rule that produces
   `conditions_unknown` usually has a fact missing from the host (compare with `-print-facts`) or an
   expression error (the reason shows it).
4. **Rule tests.** Every shipped rule has a test file `rules-tests/<rule-id>.yaml`: a list of cases
   `{name, finding, facts, host, want}` evaluated by the real engine, see
   [rules-feed.md](rules-feed.md#rule-tests). `go test ./internal/server/rules/` runs them. Add cases
   there when you contribute a rule; a rule published through the feed must have at least one
   `exploitable` and one non-exploitable case. The older per-rule Go tests are in
   `internal/server/rules/engine_test.go`; see [development.md](development.md).

Do not test on production alert routes: a new `exploitable` verdict sends a Matrix message to the
rooms of the host's labels.

## Reading the dashboard: attention vs background

Most findings of a fresh host are `conditions_unknown`: there is no rule for them yet. Hundreds of
them are not equally urgent, so the web UI sorts every open finding into a **tier** (computed on
the fly from stored columns, nothing extra is stored):

- **attention**: verdict `exploitable`; or `conditions_unknown` and (the CVE is in CISA KEV, or its
  EPSS is at least `triage.epss_threshold` (default 10%), or its severity is Critical/High and a fix
  is available, `fix_state = fixed`).
- **background**: every other open finding: `conditions_unknown` without any of those signals (no fix,
  or low severity), `affected_not_exploitable`, `not_affected`.

Counts and lists are per **CVE per host**: sibling packages of one source (`openssl` + `libssl3`,
three `openssh-*` packages) are one entry with the packages listed inside. The dashboard cards are
Exploitable, Needs attention (unknown in the attention tier), Background (other unknown),
Not exploitable and Hosts. The Findings and host pages show "needs attention" by default; "show all"
(`tier=all`) and the per-package view (`view=package`) are one click away. An explicit `q`, `verdict`,
`resolved` or `host` filter switches the default to all, so links such as `/findings?q=CVE-...`
keep working. A group is "worst verdict wins" (exploitable, then conditions_unknown, then not
exploitable, then not affected) with the maximum severity, CVSS and EPSS of its packages.

The tier only changes what the UI emphasises. Matrix alerts follow the verdict rules in
[notifications.md](notifications.md), and the way to move a CVE out of "unknown" is to write or
approve a rule for it.

## Shipped rules

All eight have `status: reviewed`, live in [rules/](../rules/) (embedded in the server binary) and have
tests in [rules-tests/](../rules-tests/).

| Rule | What it decides |
|---|---|
| [CVE-2024-6387](../rules/CVE-2024-6387.yaml) | regreSSHion. Exploitable only for `openssh-server` on glibc with `LoginGraceTime` not `0`. |
| [CVE-2023-48795](../rules/CVE-2023-48795.yaml) | Terrapin. Exploitable when sshd allows ChaCha20-Poly1305, or a CBC cipher with an EtM MAC. |
| [CVE-2023-44487-nginx](../rules/CVE-2023-44487-nginx.yaml) | HTTP/2 Rapid Reset on nginx. Exploitable only when `nginx.http2` is true. |
| [CVE-2023-44487-apache](../rules/CVE-2023-44487-apache.yaml) | HTTP/2 Rapid Reset on Apache. Exploitable only when `apache.http2` is true. |
| [CVE-2024-1086](../rules/CVE-2024-1086.yaml) | nf_tables kernel privilege escalation. Exploitable unless unprivileged user namespaces are disabled or restricted by sysctl. |
| [CVE-2024-21626](../rules/CVE-2024-21626.yaml) | runc "Leaky Vessels" container escape. Exploitable when a container runtime (docker, containerd, kubelet, podman, crio) is running. |
| [CVE-2024-3094](../rules/CVE-2024-3094.yaml) | xz backdoor. Exploitable on amd64 glibc hosts with sshd running. |
| [CVE-2024-4577](../rules/CVE-2024-4577.yaml) | PHP-CGI argument injection. Windows-only; `exploitable_if: 'false'`, so never exploitable on Linux. |

## Review workflow for LLM drafts

When a High, Critical or KEV finding has no rule and an LLM is configured ([llm.md](llm.md)), the
drafter writes a rule with `status: draft` and `source: llm:<model>`. It is validated like any
rule, stored, and applied under the draft guard, then waits for a human.

What a draft can and cannot do before review:

- It **never lowers a verdict**: anything other than `exploitable` becomes `conditions_unknown`,
  and `exploitable` is only kept if the expression truly depends on host facts.
- Its `fact_requests` are **not sent to agents**.
- Matrix alerts for it show a warning and a server-generated fix command, not the LLM's text.
- With an LLM configured, `unknown_critical` alerts are held back for 2 hours after the finding first
  appeared, so a draft can arrive first.

Review in the web UI, **Rules**:

1. Open the draft. The LLM's title, explanation and fix text are shown shortened, as plain text,
   in a box labelled unreviewed (do not follow instructions in it).
2. Read "Before you approve": the `file.match` paths and patterns that every affected agent will
   read as root, the vulnerabilities and the package selectors.
3. Edit the YAML if needed ("Validate and save"). Saving stores a user rule and re-evaluates all
   hosts; it does not change the status.
4. **Approve** or **Reject**. Both ask for **your current password again**; too many wrong
   passwords end the session. Each form carries a rule version: if the rule changed after you opened
   it (a redraft, another admin), the action fails with 409 and you must reload and look again.
   Approve sets `status: reviewed`; Reject keeps the rule as `rejected` so the LLM does not
   regenerate it, and it is never applied.

Approvals, rejections, edits and settings changes are written to the server log as audit entries
with the actor and client IP (see [operations.md](operations.md#monitoring-and-logs)).
