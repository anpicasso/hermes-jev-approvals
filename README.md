# hermes-jev-approvals

**Smart command approvals for [Hermes Agent](https://github.com/NousResearch/hermes-agent),
served by [TypeSafe's](https://typesafe.ai) Jev decision model.**

> **Approvals only.** This provider serves `auxiliary.approval` when
> `approvals.mode: smart`. It cannot chat or generate text, refuses every other task, and
> registers no hooks. It works with Hermes core as shipped.

## What it does

Hermes already detects commands that need review and asks an auxiliary model for one of three
values:

- `APPROVE` — execute without interrupting the user.
- `DENY` — block the command.
- `ESCALATE` — ask the user.

This plugin replaces only that reviewer. Jev returns typed probabilities instead of prose that
Hermes must parse back into a decision.

## How it decides

One request asks six typed questions in parallel:

| question | type | value |
|---|---|---|
| `verdict` | Choice | `APPROVE`, `DENY`, or `ESCALATE` |
| `policy_allows` | Noul | probability that `approvals.smart_policy` explicitly allows it |
| `blast_radius` | Score | `0` trivial, `1` annoying, `2` severe recovery |
| `self_advocating` | Noul | probability that command text argues for its own approval |
| `reads_secrets` | Noul | probability that it reads or copies credentials |
| `sends_outbound` | Noul | probability that it transmits local content remotely |

The final verdict is deterministic code, in this order:

1. `self_advocating >= 0.6` → `ESCALATE`
2. `reads_secrets >= 0.7` and `sends_outbound >= 0.7` → `DENY`
3. `reads_secrets >= 0.7` → `ESCALATE`
4. `policy_allows >= 0.7`, policy present, and `blast_radius < 2.0` → `APPROVE`
5. Model `APPROVE` with `confidence < 0.55` or `blast_radius >= 1.6` → `ESCALATE`
6. Otherwise keep the model verdict

Malformed or missing answers raise, which makes Hermes escalate to the user.

## Install

```bash
hermes plugins install anpicasso/hermes-jev-approvals/plugin
hermes auth add typesafe-jev
hermes config set approvals.mode smart
hermes config set auxiliary.approval.provider typesafe-jev
hermes config set auxiliary.approval.model jev-latest
systemctl --user restart hermes-gateway
```

Plugins are profile-scoped. Repeat the install for each `$HERMES_HOME` that should use it.

You can select the same defaults interactively:

```text
hermes model
  -> Configure auxiliary models...
     -> Approval
        -> TypeSafe Jev (smart approvals only)
           -> jev-latest
```

The TypeSafe model list is fetched from the upstream API.

## Configure the operator policy

`approvals.smart_policy` is trusted reviewer policy. Describe routine operations that should not
interrupt you, while keeping destructive or production actions under review:

```yaml
approvals:
  mode: smart
  smart_policy: >-
    Killing browser processes and deleting cache or temporary directories are routine.
    Ordinary git and gh operations on feature branches are routine.
    Force-pushing, rewriting published history, pushing to main, production databases,
    and shared infrastructure still require review.
```

## Provider configurations

### TypeSafe — default

The install commands above are the complete setup:

```yaml
auxiliary:
  approval:
    provider: typesafe-jev
    model: jev-latest
```

Credentials resolve through Hermes' provider pool, `~/.hermes/.env`, or the process environment.

### OpenRouter

Store the OpenRouter key:

```bash
hermes auth add openrouter
```

Then edit `config.yaml`:

```yaml
auxiliary:
  approval:
    provider: typesafe-jev
    model: ~typesafe/jev-latest
    base_url: https://openrouter.ai/api/alpha
```

Do **not** add `api_key` or `key_env` under `auxiliary.approval`. Hermes would resolve the task as
`custom` and bypass this plugin. The plugin reads OpenRouter's credential pool itself.

Stock Hermes still requires the normal `typesafe-jev` credential to construct this provider;
that dispatch credential is never sent to OpenRouter.

### OpenCode Zen — free anonymous request

The current limited-time free Jev model accepts an anonymous upstream request:

```yaml
auxiliary:
  approval:
    provider: typesafe-jev
    model: jev-1.13-free
    base_url: https://opencode.ai/zen/v1/systemone
```

No plugin `key_env` is configured, so OpenCode receives no `Authorization` header. The normal
`typesafe-jev` credential is still required by stock Hermes for provider dispatch, but is never
forwarded to OpenCode.

Live verification returned HTTP 200 with valid typed answers. See the
[OpenCode Jev documentation](https://opencode.ai/docs/zen/#jev).

### OpenCode Zen — paid model

Put the Zen key in `~/.hermes/.env`:

```dotenv
OPENCODE_API_KEY=...
```

Configure the endpoint and the plugin-level key variable:

```yaml
auxiliary:
  approval:
    provider: typesafe-jev
    model: jev-1.13
    base_url: https://opencode.ai/zen/v1/systemone

plugins:
  entries:
    jev-approvals:
      settings:
        key_env: OPENCODE_API_KEY
```

The authenticated request was live-tested successfully. The paid model returns HTTP 401 without
that key.

### Any other Jev-compatible endpoint

Use the provider's **complete HTTPS decision endpoint**. No plugin or catalog update is needed.

Authenticated example:

```yaml
auxiliary:
  approval:
    provider: typesafe-jev
    model: provider-model-id
    base_url: https://jev.example/v1/systemone

plugins:
  entries:
    jev-approvals:
      settings:
        key_env: MY_JEV_PROVIDER_KEY
```

Put `MY_JEV_PROVIDER_KEY=...` in the environment or `~/.hermes/.env`.

For anonymous upstream access, omit the `plugins` block. A custom host uses only its explicitly
configured `key_env`; it never inherits TypeSafe or OpenRouter credentials. The custom `base_url`
is used exactly as written, with no hidden suffix.

## Decision log

Each success or failure is appended to:

```text
$HERMES_HOME/jev-approval-decisions.jsonl
```

Rows include raw and final verdicts, the deciding rule, six answer values, latency, attempts,
HTTP status, request ID, policy/question fingerprints, and redaction/truncation metadata. The
file is mode `0600`, rotates at 4 MB, keeps one previous generation, and never changes approval
behavior if logging fails.

Environment controls:

- `JEV_APPROVAL_LOG` — override the path.
- `JEV_APPROVAL_LOG_MAX_BYTES` — resize the cap; `0` disables logging.

## Security boundary

- HTTPS on the default port only.
- URL credentials, query strings, and fragments are rejected.
- Cross-origin redirects are rejected.
- Commands are redacted before egress and capped at 4000 characters.
- A truncated command is never auto-approved.
- Custom hosts receive only their explicitly configured key, or no key.

This is a reviewer, not a sandbox. It sees only commands Hermes routes to smart approval, and it
sends the redacted command plus operator policy to the configured third-party endpoint.

## Verify

Offline suite, from a source checkout:

```bash
python3 -m pytest plugin/tests -q
```

Installed-plugin checks:

```bash
hermes plugins doctor ~/.hermes/plugins/jev-approvals --ci
cd ~/.hermes/plugins/jev-approvals
python3 tests/test_real_load.py
python3 tests/test_hardening.py
python3 tests/test_boundary.py
```

Live provider checks:

```bash
python3 tests/test_routes.py
python3 tests/test_provider.py
```

## Detailed documentation

- [Technical notes, hardening, limitations, and prior art](docs/TECHNICAL.md)
- [Metrics and methodology](docs/METRICS.md)
- [Offline evaluation workflow](docs/EVAL.md)
- [Corpus construction](docs/corpus.md)
- [Benchmark commands](benchmarks/README.md)

## Requirements

- Hermes Agent with plugin support
- `approvals.mode: smart`
- Python 3.10+
- No third-party Python dependencies

## Licence

MIT.
