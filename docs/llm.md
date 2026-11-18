# LLM rule drafting

The LLM is optional and does one narrow job: when a serious finding has no rule, it drafts one. It
never decides exploitability on its own. A draft is inert until a human approves it, and a draft can
never lower a verdict. This page covers the providers, configuration, cost control, exactly what is
sent to the model, and the defenses against prompt injection.

Contents: [When it runs](#when-it-runs) - [Providers and configuration](#providers-and-configuration) -
[Cost control](#cost-control) - [What is sent to the LLM](#what-is-sent-to-the-llm) -
[Prompt-injection defenses](#prompt-injection-defenses) - [Choosing a model](#choosing-a-model)

## When it runs

A finding is queued for drafting when it has no rule and its severity is High or Critical, or it is
on the CISA KEV list. The drafter then:

1. skips it if a rule with the generated ID (`<vuln id>-<source package>`) already exists
   (including rejected ones), or an existing rule already covers it;
2. fetches the advisory text from OSV (`https://api.osv.dev`), trying the vulnerability ID and its aliases;
3. builds a prompt from the finding, the advisory and the fact catalog, and asks for one JSON rule;
4. validates the reply like any rule (CEL compiles, only catalog facts, `file.match` policy). If it
   is invalid, one retry is made with the validator's messages (never the previous reply). Still
   invalid: the finding is marked failed and is not retried for 24 hours (7 days for the same host);
5. stores a valid rule as `status: draft`, `source: llm:<model>`, re-evaluates the hosts, and
   leaves it for review: [rules.md](rules.md#review-workflow-for-llm-drafts).

One rule covers all binary packages built from the same source package; the prompt lists the
sibling packages seen on your hosts.

## Providers and configuration

| Provider | `llm.provider` | Notes |
|---|---|---|
| none (default) | `none` | No drafting. Only shipped and hand-written rules apply, and `unknown_critical` alerts are not delayed. |
| Anthropic | `anthropic` | Uses the Anthropic API. `llm.model` defaults to `claude-sonnet-5-5`. `llm.base_url` optionally overrides the endpoint. The key is read from the variable named by `llm.api_key_env`; see [Keyless authentication](#keyless-authentication). |
| OpenAI-compatible | `openai-compatible` | Any server with `POST <base_url>/chat/completions` and JSON output mode: Ollama, vLLM, OpenRouter, LiteLLM. `llm.base_url` is required (for example `http://ollama:11434/v1`). The key is optional, sent as a Bearer token. |

Secrets come from the environment, never from `server.yaml`. In `.env` or `server.env`:

```sh
# Anthropic
PANOPTES_LLM_PROVIDER=anthropic
PANOPTES_LLM_API_KEY=sk-ant-...
PANOPTES_LLM_MODEL=claude-sonnet-5-5

# Ollama on the same Docker network (no key needed)
PANOPTES_LLM_PROVIDER=openai-compatible
PANOPTES_LLM_BASE_URL=http://ollama:11434/v1
PANOPTES_LLM_MODEL=llama3.1

# OpenRouter
PANOPTES_LLM_PROVIDER=openai-compatible
PANOPTES_LLM_BASE_URL=https://openrouter.ai/api/v1
PANOPTES_LLM_API_KEY=...
PANOPTES_LLM_MODEL=<model id from the provider>
```

Or in `server.yaml`:

```yaml
llm:
  provider: anthropic
  model: claude-sonnet-5-5
  api_key_env: PANOPTES_LLM_API_KEY     # name of the variable, not the key
  daily_limit: 50
```

All keys: [configuration.md](configuration.md#llm). At start the server logs
`LLM drafter enabled` with the provider and limit, or `LLM drafter disabled` with the reason. The
server warns when `llm.base_url` is plain `http://` to a non-loopback host.

### Keyless authentication

The Anthropic provider does not require `PANOPTES_LLM_API_KEY`. When the variable named by `llm.api_key_env`
is unset or empty the server creates the SDK client without an explicit key and the SDK falls back to its
own credential discovery from the environment (for example `ANTHROPIC_API_KEY`, or workload identity
federation through `ANTHROPIC_FEDERATION_RULE_ID`, `ANTHROPIC_ORGANIZATION_ID`,
`ANTHROPIC_SERVICE_ACCOUNT_ID` and `ANTHROPIC_IDENTITY_TOKEN_FILE`). The project exercises this only in the
rules repository's bot, which stores no API key at all: its workflow exchanges a short-lived GitHub OIDC
token for Anthropic credentials, see [rules-feed.md](rules-feed.md#repository-bot) and the
[bot setup](https://github.com/DonSosiska/panoptes-rules/blob/main/docs/bot-setup.md). For a long-running
server, a dedicated key with a provider-side spend limit remains the documented setup.

Provider details: the Anthropic provider asks for medium effort and, for the `claude-sonnet-5-5`
and `claude-opus-5-5` models, uses the beta endpoint with server-side fallback so a refusal is
re-served by another model in the same call. The OpenAI-compatible provider sends
`response_format: {"type": "json_object"}` and has a 120 s timeout.

## Cost control

| Control | Value |
|---|---|
| `llm.daily_limit` | Maximum calls per day (default 50). Checked before any network call; once reached, drafts are dropped for the day and a WARN is logged once. A value of `0` or less means 50. |
| Per-host enqueue cap | At most 100 queued findings per host per day. |
| Global enqueue cap | At most 1000 queued findings per day. |
| Queue | 256 entries; extra findings are dropped and picked up on a later pipeline run. |
| Deduplication | One rule per vulnerability and source package, however many hosts or packages are affected. Findings already covered by a rule cost nothing. |
| Failure back-off | A refusal sets a 6 h cooldown for that finding; failed drafts are not retried for 24 hours (7 days on the same host). |
| Output size | The model's reply is bounded (max 16 000 tokens requested), title 200 chars, explanation 600, fix text 300. |

Set a spend limit on the provider side too, since a daily call limit is not a cost limit. Counters
are stored in the database, so a restart does not reset them.

## What is sent to the LLM

Sent, in one request per draft:

- **Finding fields:** vulnerability ID and aliases, package name, version and type, source package,
  names and types of sibling packages (up to 50), PURL, fixed versions, severity, CVSS, EPSS, KEV
  flag, fix state, and the host's distribution name (for example "Debian GNU/Linux 12").
- **Advisory text** from OSV for the vulnerability (up to 12 000 characters).
- **Static prompt:** the fact catalog (names, types, descriptions; every fact has a description
  taken from [contracts.md](contracts.md#3-fact-catalog) section 3, and the `agent.*` facts are left out because they
  describe the agent, not exploitability), the CEL environment and three
  example rules.

**Never sent:** host facts, configuration file contents, `file.match` results, hostnames, IP
addresses, labels, host or agent IDs, enrollment tokens or any other secret. Package names and
versions do reveal part of what is installed on your hosts. Separately, the server contacts
`api.osv.dev` with the vulnerability ID (public information). If either is unacceptable, leave
`llm.provider` as `none`, or use an OpenAI-compatible endpoint you operate.

## Prompt-injection defenses

Finding fields (package names come from monitored hosts) and advisory text (third-party) are
treated as hostile. The model's output is treated as hostile too.

**Input.**

- Untrusted data sits between `<untrusted_finding>` and `<untrusted_advisory>` tags, and the system
  prompt says to ignore any instructions inside them.
- Every field is Unicode-normalised (NFKC, so look-alike angle brackets become real ones and are
  caught), control and format characters are removed, newlines in fields are replaced, tag-like
  constructs (including half-written delimiters) are replaced with `[tag removed]`, and each field is
  capped at 256 characters.
- The advisory is stripped the same way and every line is prefixed with `> ` so it reads as quoted
  data.

**Output.**

- The reply must be one JSON object that passes the normal rule validation. Only catalog facts can
  be read; an invented fact name is rejected. `file.match` requests pass the strict server policy
  ([rules.md](rules.md#filematch-policy)) and are not sent to agents until a human approves.
- The reply is never fed back to the model on retry, only the validator's messages (sanitised,
  capped at 2 KiB), so a poisoned answer cannot be amplified.
- Title, explanation and fix text are cleaned and length-capped before storage.

**Effect.**

- A draft cannot lower a verdict and cannot make a fact-independent claim of exploitability: the
  [draft guard](rules.md#how-verdicts-are-decided) turns both into `conditions_unknown`.
- **Draft reasons are fixed strings.** The evaluation reason of a draft is one of
  `LLM draft suggests not exploitable (unreviewed); conditions not verified`,
  `LLM draft: condition does not depend on host facts`, or the engine's own reason (facts and values)
  prefixed with `LLM draft (unreviewed): `. No text the model wrote (explanation, title, literals) is ever
  put into a reason, and the notifier replaces any reason starting with `LLM draft` by a fixed string, so
  draft text is never relayed to Matrix.
- **Grounding is checked against realistic values.** Before a draft may report `exploitable`, the server
  evaluates its condition against synthetic hosts in which each fact it reads takes realistic values (known
  sets for enumerable facts such as `os.libc` and `os.id`, version-like values for version facts, common
  service and module names for open-ended ones, present and absent keys for maps). If the result never
  changes, the condition does not depend on the host however it is written (`facts["os.id"] != "zzz-never"`,
  `size(l) >= 0`, `true || ...`), and the draft stays `conditions_unknown`. A literal only counts as a
  candidate value when it is itself realistic for that fact. The safe direction wins: a legitimate draft that
  needs a value outside the pools stays `conditions_unknown` until a human approves it.
- The web UI shows the LLM's text shortened and as plain text, in a box labelled unreviewed. Matrix
  alerts for draft rules show a warning, a fixed reason (`LLM draft ... (unreviewed); conditions not verified`)
  and a server-generated fix command, never the LLM's explanation, keys or literals.
  Mentions are neutralised in all messages.
- Approving needs a human, with the current password, on the exact rule version they were shown.

## Choosing a model

The default is `claude-sonnet-5-5`; no other model is endorsed or benchmarked here. Drafting needs a model that reliably returns strict JSON, writes valid CEL (including the
`m[?"key"]` form) and respects the fact catalog; the validator rejects anything else, so a weak model
costs calls and produces `failed` drafts rather than wrong rules.

- Hosted: use the strongest model you are comfortable paying for; volumes are small (the daily
  limit defaults to 50 calls).
- Local (Ollama, vLLM): pick a model with good instruction following and JSON mode support, and
  expect more validator retries from small models. Keep it on a trusted network; plain `http://` to
  a non-loopback host triggers a warning.
- Whatever you use, every draft needs the same human review. Drafts are AI-assisted: the validator shows a
  rule is well-formed and cannot lower a verdict, not that it is correct. Compare the conditions and the
  package selectors with the advisory before approving ([rules.md](rules.md#review-workflow-for-llm-drafts)).

## The same drafter in the rules repository

The rules repository's bot uses the same prompt, sanitising and validation through
`panoptes-server rules draft`, with a variant that also writes the test cases, and opens pull requests
instead of storing drafts in a database. Its pull request bodies show everything the model wrote as inert
code, and a human must set `status: reviewed`. See [rules-feed.md](rules-feed.md#repository-bot).
