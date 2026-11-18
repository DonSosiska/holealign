# Rules and verdicts

A Grype match says a package version is vulnerable. A **rule** says under which host conditions that
vulnerability can actually be exploited. It is a CEL expression over facts the agents collect. This
page is the rule author's guide: the concepts, a complete reference of every key and variable, a
step-by-step tutorial, the fact catalog with exact value formats, the pitfalls and a review
checklist. The normative text is [contracts.md section 4](contracts.md#4-rules).

Contents: [Concepts](#concepts) - [How verdicts are decided](#how-verdicts-are-decided) -
[Rule reference](#rule-reference) - [Test case reference](#test-case-reference) -
[CEL environment](#cel-environment) - [Fact catalog](#fact-catalog) -
[file.match policy](#filematch-policy) - [Tutorial: a rule from an advisory](#tutorial-a-rule-from-an-advisory) -
[Pitfalls](#pitfalls) - [Review checklist](#review-checklist) - [Where to send rules](#where-to-send-rules) -
[Testing a rule locally](#testing-a-rule-locally) - [Reading the dashboard](#reading-the-dashboard-attention-vs-background) -
[Shipped rules](#shipped-rules) - [Review workflow for LLM drafts](#review-workflow-for-llm-drafts)

## Concepts

**Finding.** One (host, target, package, vulnerability) tuple that Grype reports. A **target** is
either the host's root filesystem (`kind: host`, name `host`) or a Docker image present on the host
(`kind: container_image`, name is the image reference).

**Fact.** A named value an agent collects on every check-in (`os.libc`, `sshd.config`,
`services.active`, ...). Facts describe the machine and its configuration, not the vulnerable
package. The set of fact names is closed: a rule can only read names from the
[catalog](#fact-catalog), plus parametrised `file.match:<id>` facts it requests itself. An **absent**
fact means "unknown", never "false".

**Rule.** A YAML document with: which vulnerabilities and packages it covers (`vulns`,
`packages`), which facts it reads (`facts`, `fact_requests`), and two CEL conditions
(`exploitable_if`, optional `not_affected_if`). Rules are data. They never run code on a host; the only
thing a rule can make an agent do is read matching lines of a configuration file
([file.match](#filematch-policy)), and only after human review.

**Package selector.** An entry of `packages` says which findings the rule applies to:

| Selector | Matches | Use it when |
|---|---|---|
| `name: <glob>` | the **binary** package name, as a `path.Match` glob (`nginx*`, `linux-image-*`) | the CVE concerns one binary package, or the names differ per distribution |
| `source: <name>` | the **source** package name, exact (no glob) | one source package builds several binaries (`glibc` builds `libc6`, `libc-bin`, ...) |
| `type: <deb\|rpm\|apk\|...>` | the package type; empty means any | the package name is distribution specific |

A selector has exactly one of `name` and `source`, and optionally `type`. The source package of a
finding is the `upstream` qualifier of its PURL without the version, or the binary package name when
there is none. Syft sets `upstream` for deb (`source@version`), apk (the origin package), Arch (the base
package) and rpm (the source RPM file name, `openssl-3.0.7-27.el9.src.rpm`, reduced to `openssl`).
Inside an expression, `pkg["name"]` and `pkg["source"]` tell the binaries apart.

**Targets, and why host facts never judge image findings.** Facts are collected on the host. They
say nothing about the software inside a container image: the host's `os.libc` is not the image's, the
host's running `sshd` is not in the image. So a rule that reads any host data (a `facts` or
`fact_requests` entry, any `facts[...]` reference, any `host.*` variable) is **never** evaluated
for a finding in a container image. The verdict is `conditions_unknown`, reason `rule evaluates host
facts; not applicable to container image targets`, before any expression runs. Never
`exploitable`, never `affected_not_exploitable`. The optional `targets` list (`host`, `container_image`; default `[host]`) names the target kinds a rule
covers. In the current engine it is enforced only for rules that read host data, and for those the
result for an image is `conditions_unknown` whatever `targets` says. A rule that reads no host data
(a pure `pkg.*` / `version_lt` rule) is evaluated for every target kind, host and image alike. So
write image-capable rules as pure `pkg.*` rules, and do not rely on `targets` to widen or narrow them.

**Layers.** Rules come from three layers, lowest precedence first: built-in (the eight shipped
rules, embedded in the binary), the signed rules feed, and the local database (edits in the web UI and
LLM drafts). A rule from a higher layer replaces a rule with the same `id` from a lower one. See
[rules-feed.md](rules-feed.md#layers-and-precedence).

## How verdicts are decided

| Verdict | Meaning |
|---|---|
| `exploitable` | The package is vulnerable and the rule's conditions hold. Alerts. |
| `affected_not_exploitable` | Vulnerable, but the conditions are not met or are mitigated. Silent. |
| `conditions_unknown` | No rule, a required fact is absent, an expression failed, or the rule does not apply to the target kind. |
| `not_affected` | Reserved. Accepted as a test `want` and displayed, but the rule engine does not produce it today: a true `not_affected_if` yields `affected_not_exploitable`. |
| `resolved` | The finding is gone (package upgraded or removed). |

Algorithm, per finding:

1. Find the applicable rule. None: `conditions_unknown`, reason "no rule".
2. The rule reads host data (facts, `fact_requests` or `host.*`) and the finding is a container image:
   `conditions_unknown`.
3. Any fact listed in `facts` (or any requested `file.match:*` fact) is absent or `null`:
   `conditions_unknown`, reason `missing facts: ...`. **Absent means unknown, never false.**
4. `not_affected_if` is set and true: `affected_not_exploitable`.
5. `exploitable_if` true: `exploitable`; false: `affected_not_exploitable`.
6. An expression error (including a plain `m["key"]` on a missing key, a type error or the 50 ms
   timeout): `conditions_unknown`; the reason contains the error (withheld when the rule reads
   `file.match` facts).
7. **Draft guard** (rules with `status: draft` only). A draft never lowers a verdict. Any result other
   than `exploitable` becomes `conditions_unknown` with the fixed reason "LLM draft suggests not
   exploitable (unreviewed); conditions not verified" (the draft's own text is never put into a reason
   and never relayed to chat). An `exploitable` result is kept only when the rule is grounded in host
   facts; otherwise it becomes `conditions_unknown` ("LLM draft: condition does not depend on host
   facts"). "Depends on a fact" means the result varies over values a real host can report (known
   value sets such as `os.libc` glibc/musl, common distribution IDs, typical service and module names),
   not merely over the literals the expression names: `facts["os.id"] != "zzz-never"` is true on every
   real host and is not grounded. Reviewed rules are never affected.

The reason is short and names the deciding facts, for example
`os.libc=glibc, sshd.config.logingracetime=120`. It never contains `file.match` values, only counts.

**Which rule applies.** A rule matches a finding when the finding's vulnerability ID or one of its
aliases (CVE and GHSA IDs) is in the rule's `vulns` and a `packages` selector matches. Rules with
`status: rejected` are ignored. If several rules apply (for example separate rules for nginx and
Apache), the winner is chosen by status (`reviewed` over `draft`), then layer (local over feed over
built-in), then the first by `id`. A rule in a higher layer with the same `id` replaces the lower
one, except that a local **draft** never replaces a rule from a lower layer (the lower rule stays and a
problem is reported).

## Rule reference

A rule is a YAML file. Unknown keys are errors. Every key:

| Key | Type | Required | Meaning and limits |
|---|---|---|---|
| `id` | string | yes | `^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`. The file name without `.yaml` in a rules repository. Usually the CVE ID; add a suffix when several rules cover one CVE (`CVE-2023-44487-nginx`). |
| `vulns` | list of strings | yes | CVE or GHSA IDs the rule covers. At least one, none empty. A finding matches when its ID or any alias is listed. |
| `title` | string | yes | One line, shown in the UI. |
| `packages` | list of selectors | yes | At least one, at most 50. Each: exactly one of `name` (glob over the binary package name) or `source` (exact source package name, no `*?[]\`), plus optional `type`. |
| `facts` | list of strings | no | Every fact the expressions read. Catalog names only, plus `file.match:*` names declared in `fact_requests`. Any listed fact that is absent gives `conditions_unknown`. |
| `targets` | list of strings | no | `host` and/or `container_image`; default `[host]`. No unknown or duplicate values. Enforced only for rules that read host data; see [Concepts](#concepts). |
| `fact_requests` | list | no | At most 5 `file.match` requests; see [file.match policy](#filematch-policy). Each entry: `name`, `collector: file.match`, `params: {path, pattern}`. |
| `exploitable_if` | CEL string | yes | Must return `bool`. |
| `not_affected_if` | CEL string | no | Must return `bool`. Evaluated first; true gives `affected_not_exploitable`. |
| `explanation` | string | yes | Why the conditions matter. Shown in the UI and in alerts (reviewed rules only). |
| `fix.upgrade` | string | no | Generic upgrade advice. The server also derives a package-manager command for the host's OS. |
| `fix.mitigation` | string | no | A configuration change that removes the condition. |
| `status` | string | yes | `reviewed`, `draft` or `rejected`. Hand-written rules are `reviewed`; the feed accepts only `reviewed`. `rejected` is kept so the drafter does not regenerate a rule and is never applied. |
| `source` | string | yes | `builtin`, `user` or `llm:<model>`. Free text for the engine (not empty); it labels who wrote the rule. Use `user` for your own rules. |
| `references` | list of strings | no | Advisory URLs. |

Whole-rule limits: 32 KiB as JSON. Expressions: cost limit 10 000, evaluation timeout 50 ms.

All problems of a rule are reported together (`panoptes-server rules build`, the web UI's "Validate
and save", and the log line `invalid rule skipped`).

## Test case reference

A test file `tests/<rule-id>.yaml` is a YAML list of cases evaluated by the real engine. Unknown keys
are errors, the file must hold exactly one YAML document and at least one case.

| Key | Type | Required | Meaning |
|---|---|---|---|
| `name` | string | yes | Shown in failures. |
| `finding.vuln` | string | yes | The vulnerability ID. Aliases are not simulated. |
| `finding.package` | string | yes | The **binary** package name. |
| `finding.source` | string | no | The source package. When set, the finding gets a PURL with that `upstream` qualifier so `source` selectors apply. Without it the source is the package name. |
| `finding.type` | string | no | `deb`, `rpm`, `apk`, ... Also drives `version_lt` ordering and `type` selectors. |
| `finding.version` | string | no | The installed version (`pkg["version"]`). |
| `finding.severity` | string | no | `Critical`, `High`, ... |
| `finding.kev` | bool | no | On the CISA KEV list. |
| `finding.target_kind` | string | no | `host` (default) or `container_image`. |
| `facts` | map | no | The host facts, as the agent would send them. Numbers behave as on the wire (whole numbers become ints). An absent key is an absent fact. |
| `host.os_id` | string | no | `host["os_id"]`. |
| `host.os_version_id` | string | no | `host["os_version_id"]`. |
| `host.arch` | string | no | `host["arch"]` (`amd64`, `arm64`). |
| `host.labels` | list | no | `host["labels"]`. |
| `want` | string | yes | `exploitable`, `affected_not_exploitable`, `conditions_unknown` or `not_affected`. |

A case passes only when the rule under test (the file name) is the rule that matched **and** the
verdict equals `want`. Other `host.*` variables (`hostname`, `kernel`) have fixed or empty test values;
do not depend on them in a shipped rule.

A rule published through the feed needs at least one case with `want: exploitable` and at least one
non-exploitable case (`affected_not_exploitable` or `not_affected`; `conditions_unknown` does not
count). The only exemption from the first is a rule whose `exploitable_if` is the literal `false`.
Good suites also cover: a missing fact (`conditions_unknown`), each branch of every `||`, the container
image case for any rule that reads host data, and both a deb and an rpm package when the rule lists both.

## CEL environment

Expressions are [CEL](https://cel.dev/) and must return `bool`. Optional types are enabled.

| Variable | Type | Contents |
|---|---|---|
| `facts` | `map(string, dyn)` | The host facts the rule declared. Read as `facts["literal"]`; the name must be a string literal, `facts[name]` with a computed name is rejected. Only the facts you list are present in the map. |
| `pkg` | `map(string, dyn)` | See below. |
| `host` | `map(string, dyn)` | See below. |

`pkg`:

| Key | Type | Value |
|---|---|---|
| `pkg["name"]` | string | binary package name (`libc6`, `openssh-server`) |
| `pkg["source"]` | string | source package name (see [Concepts](#concepts)) |
| `pkg["version"]` | string | installed version in the package type's own format (`1:9.2p1-2+deb12u3`) |
| `pkg["type"]` | string | `deb`, `rpm`, `apk`, `python`, `npm`, `go-module`, ... |
| `pkg["purl"]` | string | the package URL |
| `pkg["fixed_versions"]` | list of strings | versions that fix the vulnerability; may be empty |
| `pkg["target"]` | string | `host` or the image reference |
| `pkg["target_kind"]` | string | `host` or `container_image` |

`host` (from the enrollment and the last check-in, so they are the agent's claims):

| Key | Type | Value |
|---|---|---|
| `host["hostname"]` | string | host name |
| `host["labels"]` | list of strings | the host's labels |
| `host["os_id"]` | string | `/etc/os-release` `ID`, lowercase |
| `host["os_version_id"]` | string | `VERSION_ID` |
| `host["kernel"]` | string | `uname -r` |
| `host["arch"]` | string | `amd64`, `arm64` |

Dot access works too (`pkg.name`, `host.arch`). A rule that mentions `host` is a host-data rule even if
it reads no fact (it is then not evaluated for images).

Functions:

| Function | Meaning |
|---|---|
| `version_lt(a, b)` | `a` sorts before `b` in the ordering of the **finding's package type**. |
| `version_ge(a, b)` | `a` is equal to or after `b`. |
| `has_module(list, name)` | Sugar for `name in list`. |

The version functions are macros that pass `pkg["type"]` as a third argument, so the ordering follows the
package:

| `pkg["type"]` | Ordering | Examples |
|---|---|---|
| `deb` | dpkg: epoch, upstream, revision; `~` sorts before everything | `2.4.52~rc1 < 2.4.52`, `1.0-1~bpo12+1 < 1.0-1`, `1.0.0+dfsg > 1.0.0`, `1:1.0 > 9.9` |
| `rpm` | rpmvercmp, including `~` and `^` | `1.0~rc1 < 1.0` |
| `apk` | apk-tools: `_rc` < release < `_p`, `-rN` | `1.2.3_rc1 < 1.2.3`, `1.2.3-r1 < 1.2.3-r2` |
| anything else, or a version the parser rejects | loose: numeric segments compared numerically, missing segments are 0 | `"6.1.10" < "6.10.0"` |

Grype already applies the advisory's version range. Use `version_lt` only for a
configuration-dependent version condition (for example "affected only before 2.4.58 when module X is
loaded"). Compare like with like: a deb version against a deb-formatted constant.

**Optional index.** `m[?"key"]` returns an optional; `.orValue(default)` supplies a default:

```
facts["kernel.sysctl"][?"user.max_user_namespaces"].orValue("1") != "0"
facts["nginx.directives"][?"ssl_preread"].orValue([]).exists(v, v == "on")
has_module(facts["nginx.modules"], "http_v2_module")
version_lt(pkg["version"], "2.4.58")
```

A plain `m["key"]` on a missing key is an evaluation error and gives `conditions_unknown` (sometimes what
you want: "the key must be known"). The legacy spelling `m.?["k"]` is rejected by validation. The default
in `orValue` must have the type you compare with: the values of `sshd.config`, `kernel.sysctl` and
`php.ini` are strings, so the default is a string (`"0"`, not `0`).

Types after JSON decoding: strings, bools, whole numbers as ints (ports in `sockets.listening` and
`sockets.ports`), lists, maps. Comparing `"80" == 80` is an error in CEL, not false.

## Fact catalog

Facts are a flat map. Built-in facts are collected on every check-in; `file.match:<id>` only when a
reviewed rule requests it. **Absent means unknown**: the collector is not applicable, the binary is
missing, a command failed, or the tool was skipped. When a collector determines the software is not
installed it sets `<x>.installed = false` and omits the other `<x>.*` facts, so a rule that lists
`nginx.modules` is `conditions_unknown` on a host without nginx. Commands run with a fixed argv (no
shell), a 10 s timeout and stdout capped at 4 MiB. The authoritative table is
[contracts.md section 3](contracts.md#3-fact-catalog); the names are in `internal/server/rules/catalog.go`.

| Fact | Type | Exact value format | Source |
|---|---|---|---|
| `os.id` | string | lowercase `ID`: `debian`, `ubuntu`, `alpine`, `rhel`, `fedora` | `/etc/os-release` |
| `os.version_id` | string | `VERSION_ID` as text: `12`, `22.04`, `3.20.3` | `/etc/os-release` |
| `os.libc` | string | exactly `glibc` or `musl` | `ldd --version`, `/lib/ld-musl-*` |
| `os.libc_version` | string | `2.36`; absent when unreadable | `ldd --version` |
| `kernel.release` | string | `6.1.0-18-amd64` | `uname -r` |
| `kernel.modules` | list of strings | module names, e.g. `nf_tables` | `/proc/modules` |
| `kernel.sysctl` | map of string to string | values as text, only the allowlisted keys that exist: `kernel.unprivileged_userns_clone`, `user.max_user_namespaces`, `kernel.unprivileged_bpf_disabled`, `kernel.kptr_restrict`, `kernel.yama.ptrace_scope`, `kernel.dmesg_restrict`, `net.ipv4.ip_forward`, `net.ipv6.conf.all.disable_ipv6`, `fs.protected_symlinks`, `fs.protected_hardlinks`, `vm.unprivileged_userfaultfd`, `kernel.io_uring_disabled`, `kernel.apparmor_restrict_unprivileged_userns` | `/proc/sys` |
| `services.active` | list of strings | **running** services; see below | `systemctl`, fallback `/proc` |
| `services.source` | string | exactly `systemd` or `proc`; absent together with `services.active` | |
| `sockets.listening` | list of maps | each `{proto, addr, port, process}`: `proto` is `tcp`, `tcp6`, `udp` or `udp6`; `addr` is the bound IP as text (`0.0.0.0`, `127.0.0.1`, `::`); `port` is an int; `process` is the process name, `""` when unknown | `/proc/net/*` plus `/proc/*/fd` |
| `sockets.ports` | list of ints | distinct listening ports | same |
| `sshd.installed` | bool | | `sshd` binary exists |
| `sshd.version` | string | `9.2p1 Debian-2+deb12u3` | `sshd -V` / `ssh -V` |
| `sshd.config` | map of string to string | effective config: **lowercase** keyword to its **first** value (`permitrootlogin` to `without-password`, `logingracetime` to `120`) | `sshd -T` |
| `nginx.installed` | bool | | |
| `nginx.version` | string | `1.22.1` | `nginx -v` |
| `nginx.modules` | list of strings | `--with-*` configure flags without the prefix: `http_v2_module`, `http_ssl_module` | `nginx -V` |
| `nginx.directives` | map of string to list of strings | directive name to every occurrence's arguments joined by one space; comments stripped, secret-looking values `***`, each value at most 256 bytes; bodies of `map`, `geo`, `split_clients`, `charset_map`, `match` and `types` blocks are skipped | `nginx -T` |
| `nginx.http2` | bool | `http2 on` or `listen ... http2` | |
| `apache.installed` | bool | | |
| `apache.version` | string | `2.4.57` | `apachectl -v` / `httpd -v` |
| `apache.modules` | list of strings | `proxy_module`, `http2_module` | `apachectl -M` |
| `apache.http2` | bool | `http2_module` loaded and a `Protocols` directive contains `h2` or `h2c` | |
| `php.installed` | bool | | |
| `php.version` | string | `8.2.7` | `php -v` |
| `php.sapi` | list of strings | subset of `cli`, `php-fpm`, `apache2handler`; see below | |
| `php.ini` | map of string to string | only `allow_url_include`, `allow_url_fopen`, `disable_functions`, `expose_php`, `open_basedir`, `cgi.fix_pathinfo`; `""` when unset | `php -i` (CLI configuration) |
| `openssl.version` | string | `3.0.13` | `openssl version` |
| `docker.installed` | bool | true when the Docker socket exists | |
| `docker.version` | string | engine version | Docker API |
| `docker.containers` | list of maps | running containers, at most 500; each `{name, image, image_id, ports, privileged}`; `ports` is a list of strings (`0.0.0.0:8080->80/tcp` or `80/tcp`); `privileged` is a bool, absent when inspect failed | Docker API |
| `runc.version` | string | `1.1.12` | `runc --version` |
| `sudo.version` | string | `1.9.13p3` | `sudo -V` |
| `agent.inventory_error` | string | last inventory scan error (200 chars); absent when the last scan succeeded | |
| `agent.collector_error` | string | last error the root collector answered with (200 chars) | |
| `agent.skipped` | list of strings | tools not run because their config tree is not trustworthy, e.g. `nginx: /etc/nginx/conf.d writable by gid 33` | |
| `file.match:<id>` | list of strings | matched lines `<file>:<masked line>`; see below | |

**`services.active` has two spellings.** With systemd it holds unit names without `.service`, exactly as
`systemctl list-units --type=service --state=running` prints them: `ssh` on Debian and Ubuntu, `sshd` on
RHEL and Fedora, `php8.2-fpm` on Debian (a versioned name), `php-fpm` on RHEL, `apache2` or `httpd`,
`docker`, `containerd`. Without systemd (containers, minimal hosts; `services.source` is `proc`) the
names come from `/proc/<pid>/comm` through a table of well-known daemons: `sshd` gives both `ssh` and
`sshd`, `apache2` and `httpd` give both, any `php-fpm*` process gives `php-fpm`, other names are
reported lowercase as they are. So a rule must accept **both** spellings and every distribution's name:

```
["ssh", "sshd"].exists(s, s in facts["services.active"])
facts["services.active"].exists(s, s == "php-fpm" || s.startsWith("php") && s.endsWith("-fpm"))
```

An exact `"php-fpm" in facts["services.active"]` misses `php8.2-fpm` on every Debian host; `"sshd"`
alone misses `ssh`. Only running services appear: an installed but stopped daemon is absent.

**`php.sapi` is about files on disk, not about what runs.** `cli` is present when `php -v` ran;
`php-fpm` when `/usr/sbin/php-fpm*` (or `/usr/local/sbin/php-fpm*`) exists; `apache2handler` when a
`libphp*.so` exists in the Apache module directories. A SAPI listed here may be installed and
stopped. To require "actually serving", combine it with `services.active` or `sockets.*`. `php.ini` is
the CLI configuration, which can differ from php-fpm's or Apache's.

**`agent.skipped`.** Before `nginx`, `php`, `sshd`, `apachectl`/`httpd` and `sudo` are run, the
collector checks that their configuration trees and every ancestor directory are root-owned and not
group- or world-writable. Otherwise the tool is skipped and its facts are omitted (so the rules that
need them give `conditions_unknown`); the reason is listed in `agent.skipped`. See
[operations.md](operations.md#troubleshooting). Do not list `agent.*` facts in a rule: they describe
the agent, not exploitability (and the LLM is not offered them).

Not every fact exists on every host. The honest way to see what a host reports is
`panoptes-agent -print-facts`.

## file.match policy

`file.match` lets a reviewed rule ask agents for matching lines of a configuration file when no
built-in fact covers what it needs. It is the only thing a server can ask an agent to collect, and the
policy is deliberately strict because the collector runs as root and the request is written by an
administrator or an LLM. A request is a rule `fact_requests` entry:

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

**Server-side validation** (when a rule is saved, loaded or taken from the feed):

- At most 5 requests per rule. Name `file.match:<rule ID sanitized>.<id>` with `[a-z0-9._-]`: the rule
  ID lowercased with other characters replaced by `-`, at most 64 characters after the prefix.
- `path`: absolute, clean, under `/etc/`, `/opt/<app>/conf/`, `/opt/<app>/etc/` or `/usr/local/etc/`,
  without `[`, `]` or `\`. Wildcards (`*`, `?`) only in the final component, which needs a literal
  prefix or suffix of at least 3 characters. Directory components are literal.
- A denylist for names and locations: `shadow`, `passwd`, `sudoers`, `*.key`, `*.pem`, `*.p12`,
  `*.pfx`, `*.jks`, `.env`, `.htpasswd`, anything containing `secret`, `token`, `credential`, `key`,
  plus credential-bearing directories such as `/etc/kubernetes`, `/etc/ssl`, `/etc/pki`,
  `/etc/letsencrypt`, `/etc/default`, `/etc/sysconfig`, `/etc/docker`, `/etc/mysql`, `/etc/postgresql`,
  `/etc/redis`, `/etc/cron*`, `/etc/ldap`, `/etc/apt/auth.conf*`, `tomcat-users.xml`, `/etc/gitlab`,
  `/etc/ssmtp`. The full list is in `internal/server/rules/filematch.go` and
  [contracts.md](contracts.md#4-rules).
- `pattern`: RE2, at most 256 characters, repeat counts at most 100. It must contain a **mandatory
  literal** of at least 4 characters, must not match the empty string, and must match at most 3 of about
  45 diverse probe lines. So `.*` or a pattern that dumps whole files is rejected.
- Only **reviewed** rules' requests are sent to agents. Drafts are inert.

**Agent-side enforcement** (the collector re-checks everything and does not rely on the server):

- Allowed roots again, symlinks resolved first; a stricter-or-equal denylist on the physical path.
- Only regular, world-readable files, opened with `O_NOFOLLOW` (`openat2` with `RESOLVE_NO_SYMLINKS`
  where available), and every ancestor directory must be traversable by others. Files with a NUL byte
  or a `-----BEGIN ` line are skipped; crypt-hash lines are dropped.
- Secrets are masked **before** the pattern is matched, so a pattern cannot probe secret values
  character by character. Values after keys containing `key`, `secret`, `token`, `pass`, `pw`, `psk`,
  `credential`, `auth` or `community` become `***`; `Bearer ...`, URL user info and long random-looking
  tokens are masked.
- Budgets per check-in: 20 requests, 2 MiB read, 500 lines in total (200 per request), 5 s.

Why so strict: a rule is data from an LLM or an administrator, executed with root's read access on every
host. The allowlist and the masking make the worst case "a non-secret config line leaves the host", and
the review step puts a human in front of every path. Evaluation reasons show only
`file.match:<id>=<N> matching lines`, never the lines.

## Tutorial: a rule from an advisory

Goal: write a rule and its tests for a (fictional) advisory, then check it. The advisory says:

> CVE-2099-0001: heap overflow in the `ssl_preread` handler of nginx. Only servers built with the
> stream SSL preread module and configured with `ssl_preread on;` in a `stream` server are reachable.
> Fixed in nginx 1.27.1.

**1. Decide what the rule must know.** Reachability needs two things: the module is compiled in
(`nginx.modules` contains `stream_ssl_preread_module`) and some server enables it (`nginx.directives`
has `ssl_preread` with value `on`). Both are catalog facts. The version range is already in Grype's
data (fixed in 1.27.1), so the rule does not repeat it.

**2. Pick the selectors.** Debian and Ubuntu build several binaries (`nginx`, `nginx-core`,
`nginx-light`, ...) from the source package `nginx`; Alpine and RHEL use `nginx`. Use `source` for deb
and `name` for the others:

```yaml
packages:
  - {source: nginx, type: deb}
  - {name: nginx, type: rpm}
  - {name: nginx, type: apk}
```

**3. Write the rule** as `rules/CVE-2099-0001-nginx.yaml`:

```yaml
id: CVE-2099-0001-nginx
vulns: [CVE-2099-0001]
title: "nginx example module: heap overflow in the stream proxy handler"
packages:
  - {source: nginx, type: deb}
  - {name: nginx, type: rpm}
  - {name: nginx, type: apk}
facts: [nginx.modules, nginx.directives]
exploitable_if: >
  has_module(facts["nginx.modules"], "stream_ssl_preread_module") &&
  facts["nginx.directives"][?"ssl_preread"].orValue([]).exists(v, v == "on")
explanation: >
  The overflow is in the ssl_preread code, which runs only when the stream module is built in
  and a stream server enables ssl_preread. Hosts without both are not reachable.
fix:
  upgrade: "Upgrade nginx to the distribution's patched package and restart nginx."
  mitigation: "Remove 'ssl_preread on;' from the stream servers and reload nginx."
status: reviewed
source: user
references: [https://example.com/advisories/CVE-2099-0001]
```

Notes: both facts are listed in `facts` because the expression reads them (validation rejects a read
fact that is not listed). `nginx.directives` is optional-indexed with a list default, so a host without
the directive is `affected_not_exploitable`, not an error. A host without nginx facts (nginx missing,
or the collector skipped the tree) is `conditions_unknown`.

**4. Write the tests** as `tests/CVE-2099-0001-nginx.yaml`, one case per branch:

```yaml
- name: module built in and ssl_preread on
  finding: {vuln: CVE-2099-0001, package: nginx-core, source: nginx, type: deb, severity: High}
  facts:
    nginx.modules: [http_ssl_module, stream_ssl_preread_module]
    nginx.directives: {ssl_preread: ["on"], listen: ["443"]}
  host: {os_id: debian, arch: amd64}
  want: exploitable
- name: ssl_preread not configured
  finding: {vuln: CVE-2099-0001, package: nginx-core, source: nginx, type: deb}
  facts:
    nginx.modules: [stream_ssl_preread_module]
    nginx.directives: {listen: ["80"]}
  host: {os_id: debian}
  want: affected_not_exploitable
- name: module not built in
  finding: {vuln: CVE-2099-0001, package: nginx, type: rpm}
  facts:
    nginx.modules: [http_ssl_module]
    nginx.directives: {ssl_preread: ["on"]}
  host: {os_id: rhel}
  want: affected_not_exploitable
- name: nginx facts missing (collector skipped the tree)
  finding: {vuln: CVE-2099-0001, package: nginx-core, source: nginx, type: deb}
  facts: {}
  host: {os_id: debian}
  want: conditions_unknown
- name: container image is not judged on host facts
  finding: {vuln: CVE-2099-0001, package: nginx-core, source: nginx, type: deb, target_kind: container_image}
  facts:
    nginx.modules: [stream_ssl_preread_module]
    nginx.directives: {ssl_preread: ["on"]}
  host: {os_id: debian}
  want: conditions_unknown
```

The first case sets `source: nginx` because the deb selector is a `source` selector; without it the
finding's source would be `nginx-core` and the rule would not match, and the case would fail with "the
finding is matched by no rule, not by CVE-2099-0001-nginx".

**5. Run the checks.** `rules build` validates the rule, runs the tests with the real engine and applies the
coverage policy (needs only a `panoptes-server` binary, no configuration):

```sh
panoptes-server rules build -rules rules -tests tests -seq 1 -out /tmp/out
# built /tmp/out/rules-1.tar.gz: 1 rules, 1 test files
```

On a failure it prints every problem and writes no bundle.

**6. Look at a real host.** `panoptes-agent -print-facts` on a machine with nginx shows what
`nginx.modules` and `nginx.directives` really contain (the literal spelling of the module name and the
directive values). Adjust the rule when the facts differ from what you assumed. For a local trial,
copy the rule into the server's `rules_dir`, restart, and read the verdict reason in the finding page.

**7. Send it.** See [Where to send rules](#where-to-send-rules).

## Pitfalls

- **Treating absent as false.** `facts["x"]` that is absent makes the whole rule `conditions_unknown`.
  Do not "fix" that by dropping the fact from `facts`: validation requires every fact you read to be
  listed. If "absent" really means "not configured", use an optional index with a default on a **map**
  fact (`[?"key"]`), which is present as long as the collector ran.
- **One spelling of a service.** See `services.active` above. `ssh` vs `sshd`, `php8.2-fpm` vs `php-fpm`,
  `apache2` vs `httpd`.
- **Reading `php.sapi` as "running".** It is "installed on disk".
- **Reading host facts for an image.** The finding is `conditions_unknown` by design; do not try to
  force it with `targets`. A rule meant for images can only use `pkg.*`.
- **Case and type.** `sshd.config` keys are lowercase; its values are strings, so `== "0"`, not `== 0`.
  `sockets.ports` holds ints.
- **Comparing versions across formats.** Use the `pkg["type"]` ordering; do not hand-roll string
  comparison with `<`. Do not repeat Grype's version range.
- **A constant or fact-independent condition.** `true`, or a comparison no real host can fail, makes the
  rule a plain "always exploitable" and, in a draft, is neutralised by the grounding check. Reachability
  belongs in facts.
- **Over-wide selectors.** `name: "*"` or a `source` that builds unrelated binaries. Tests cover the package
  you meant and one you did not.
- **Aliases.** List the GHSA ID next to the CVE when the matcher reports GHSA IDs for language packages.
  Only list identifiers of the same vulnerability.
- **Shadowing.** Reusing the `id` of a shipped rule in a local or feed rule replaces it for that
  server. That is intended for overrides, a surprise otherwise.
- **`file.match` as a first resort.** Use it only when no catalog fact covers the condition; every path
  and pattern is reviewed as a read of a host file as root.
- **Slow or large expressions.** The cost limit is 10 000 and evaluation is cut at 50 ms; avoid
  nested comprehensions over `nginx.directives` values.

## Review checklist

- [ ] Every claim in the rule is in the advisory (vendor or upstream text); `references` links it.
- [ ] The `vulns` IDs are the vulnerability's own (CVE, GHSA), nothing else.
- [ ] Selectors match the intended binaries and nothing wider; `source` for multi-binary packages.
- [ ] Every fact read is listed in `facts`, and absence of each means "unknown" for this advisory.
- [ ] Service names accept all distributions' spellings; `php.sapi` is not read as "running".
- [ ] The rule reads host data only for host targets; image behaviour is covered by a test.
- [ ] `exploitable_if` fails safe: unknown or missing input never yields `affected_not_exploitable`
      without being intentional.
- [ ] `explanation`, `fix.upgrade` and `fix.mitigation` are accurate and say what the operator should do.
- [ ] Tests: at least one `exploitable`, one `affected_not_exploitable`, one missing-fact
      `conditions_unknown`, both package types if both are listed, and the image case.
- [ ] No `file.match` request unless unavoidable; its path and pattern pass the policy and are narrow.
- [ ] `panoptes-server rules build` passes locally.

## Where to send rules

New rules for everyone belong in the rules repository,
[DonSosiska/panoptes-rules](https://github.com/DonSosiska/panoptes-rules): a pull request with
`rules/<id>.yaml` and `tests/<id>.yaml`. A merge is the review and is published, signed, to every server that
trusts the feed ([rules-feed.md](rules-feed.md)). Rules only for your servers can live in your own
`rules_dir`, in the database (web UI) or in [your own feed](rules-feed.md#running-your-own-feed).

The eight rules shipped inside this repository (`rules/`, `rules-tests/`) exist in **both**
repositories and are kept byte-identical; the rules repository's CI fails when they differ. Changing a
shipped rule therefore needs a pull request in each repository: change `rules/` and `rules-tests/` here,
then the same files in the rules repository (bump its `PANOPTES_REF` first if the change needs a newer
binary, see [development.md](development.md#bumping-the-rules-repository)). Code changes (a new fact, a
new CEL function, a policy change) go to this repository, see [CONTRIBUTING.md](../CONTRIBUTING.md).

## Testing a rule locally

1. **See the facts.** `panoptes-agent -print-facts` prints exactly the JSON the server will see.
2. **Validate and run the tests.** `panoptes-server rules build -rules <dir> -tests <dir> -seq 1 -out <tmp>`
   needs no server configuration. For the shipped rules `go test ./internal/server/rules/` does the same.
3. **Try it in a server.** Put the YAML in `rules_dir` and restart. An invalid rule is skipped and logged
   as `invalid rule skipped` with the reason (`journalctl -u panoptes-server | grep 'invalid rule'`). In the
   web UI, **Rules**, open the rule, edit the YAML and press "Validate and save": the same validation runs
   and every problem is listed.
4. **See the verdict.** After saving or reloading, all hosts are re-evaluated. The finding page shows the
   reason naming the deciding facts. `conditions_unknown` usually means a fact is missing from the host
   (compare with `-print-facts`) or an expression error (the reason shows it).

Do not test on production alert routes: a new `exploitable` verdict sends a Matrix message to the rooms of
the host's labels.

## Reading the dashboard: attention vs background

Most findings of a fresh host are `conditions_unknown`: there is no rule for them yet. Hundreds of them
are not equally urgent, so the web UI sorts every open finding into a **tier** (computed on the fly from
stored columns, nothing extra is stored):

- **attention**: verdict `exploitable`; or `conditions_unknown` and (the CVE is in CISA KEV, or its EPSS is
  at least `triage.epss_threshold` (default 10%), or its severity is Critical/High and a fix is
  available, `fix_state = fixed`).
- **background**: every other open finding: `conditions_unknown` without any of those signals,
  `affected_not_exploitable`, `not_affected`.

Counts and lists are per **CVE per host**: sibling packages of one source (`openssl` + `libssl3`) are one
entry with the packages listed inside. The Findings and host pages show "needs attention" by default;
"show all" (`tier=all`) and the per-package view (`view=package`) are one click away. An explicit `q`,
`verdict`, `resolved` or `host` filter switches the default to all. A group is "worst verdict wins"
(exploitable, then conditions_unknown, then not exploitable, then not affected).

The tier only changes what the UI emphasises. Matrix alerts follow the verdict rules in
[notifications.md](notifications.md), and the way to move a CVE out of "unknown" is to write or approve a
rule for it.

## Shipped rules

All eight have `status: reviewed`, live in [rules/](../rules/) (embedded in the server binary) and have
tests in [rules-tests/](../rules-tests/). They are the **built-in** layer (`builtin` in the engine).

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

When a High, Critical or KEV finding has no rule and an LLM is configured ([llm.md](llm.md)), the drafter
writes a rule with `status: draft` and `source: llm:<model>`. It is validated like any rule, stored, and
applied under the draft guard, then waits for a human. The UI labels the layers `built-in`,
`feed #<seq>` and `local`; a draft is a `local` rule.

What a draft can and cannot do before review:

- It **never lowers a verdict**: anything other than `exploitable` becomes `conditions_unknown`, and
  `exploitable` is only kept if the expression truly depends on host facts.
- Its `fact_requests` are **not sent to agents**.
- Matrix alerts for it show a warning and a server-generated fix command, not the LLM's text.
- With an LLM configured, `unknown_critical` alerts are held back for 2 hours after the finding first
  appeared, so a draft can arrive first.

Drafts are AI-assisted and can be wrong in ways the validator cannot see (a plausible but incorrect
condition, an over-wide selector). Read them as you would a stranger's patch.

Review in the web UI, **Rules**:

1. Open the draft. The LLM's title, explanation and fix text are shown shortened, as plain text, in a box
   labelled unreviewed (do not follow instructions in it).
2. Read "Before you approve": the `file.match` paths and patterns that every affected agent will read as
   root, the vulnerabilities and the package selectors. Compare with the advisory.
3. Edit the YAML if needed ("Validate and save"). Saving stores a user rule and re-evaluates all hosts; it
   does not change the status.
4. **Approve** or **Reject**. Both ask for **your current password again**; too many wrong passwords end the
   session. Each form carries a rule version: if the rule changed after you opened it (a redraft, another
   admin), the action fails with 409 and you must reload and look again. Approve sets `status: reviewed`;
   Reject keeps the rule as `rejected` so the LLM does not regenerate it, and it is never applied.

Approvals, rejections, edits and settings changes are written to the server log as audit entries with the
actor and client IP (see [operations.md](operations.md#monitoring-and-logs)).
