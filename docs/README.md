# Holealign documentation

Start with the [quick start](quickstart.md) if you want to see it work, or with the
[project README](../README.md) if you want to know what it is.

## Use

| Document | What it covers |
|---|---|
| [quickstart.md](quickstart.md) | A 15-minute path: agentless server, first findings in the UI, a Matrix alert, a first remote agent. |
| [user-guide.md](user-guide.md) | The web UI page by page: verdicts, triage tiers, reviewing draft rules, settings. |
| [notifications.md](notifications.md) | Matrix setup, label routing, message types, deduplication, delivery problems. |
| [faq.md](faq.md) | How it differs from other tools, internet access, what leaves a host, distributions, licensing. |
| [troubleshooting.md](troubleshooting.md) | Symptom, cause and fix tables for the server, agents, TLS, feeds, Matrix and login. |

## Operate

| Document | What it covers |
|---|---|
| [installation.md](installation.md) | Server (Compose, packages, binary), TLS, agents (`install.sh`, packages), privilege separation, agentless mode, verifying releases, upgrade, uninstall. |
| [configuration.md](configuration.md) | Every server and agent configuration key with type, default, environment override and effect. |
| [operations.md](operations.md) | The `holealign-server` CLI, backup and restore, upgrades, retention and limits, health alerts, air-gapped feeds, rotation, re-enrollment, scaling. |
| [api.md](api.md) | HTTP API reference. *Pending: written separately.* |

## Write rules

| Document | What it covers |
|---|---|
| [rules.md](rules.md) | How verdicts are computed, the rule format, the CEL environment, the fact catalog, the `file.match` policy, shipped rules, reviewing drafts. |
| [rules-feed.md](rules-feed.md) | The signed central rules feed: bundle format, signing, keys, publishing, air-gapped import. |
| [llm.md](llm.md) | LLM rule drafting: providers, cost control, what is sent, prompt-injection defenses. |

## Develop

| Document | What it covers |
|---|---|
| [architecture.md](architecture.md) | Components, data flow, privilege separation, storage. |
| [contracts.md](contracts.md) | The formal protocol and interface contracts; the source of truth when documents disagree. |
| [development.md](development.md) | Repository layout, building, tests, release process. |
| [../CONTRIBUTING.md](../CONTRIBUTING.md) | How to contribute. |
| [../CHANGELOG.md](../CHANGELOG.md) | Release notes. |

## Security

| Document | What it covers |
|---|---|
| [security-model.md](security-model.md) | Threat model, mitigations, operator hardening checklist, known limitations. |
| [../SECURITY.md](../SECURITY.md) | How to report a vulnerability and which versions are supported. |

Documents are written for the code in this repository. When a document and the code disagree, the code
and [contracts.md](contracts.md) win; please report the difference.
