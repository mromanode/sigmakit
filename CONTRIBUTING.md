# Contributing

Sigma rules live in `rules/sigma/`. CI lints and validates them, then converts them into Splunk SPL and CrowdStrike LogScale queries.

## Add a rule

1. Put the rule under `rules/sigma/<platform>/<category>/`.
2. Name it after its logsource: `proc_creation_lnx_<name>.yml`, `win_<event_id>_<name>.yml`, `proxy_generic_<name>.yml`.
3. Include this metadata:

```yaml
title: Short title
id: <uuid4>
status: experimental | test | stable
description: What the rule detects and why it matters.
author: <github username>
date: YYYY-MM-DD
tags:
    - attack.<tactic>
    - attack.<technique>
logsource:
    product: <product>
    category: <category>
detection:
    selection:
        <field>: <value>
    condition: selection
falsepositives:
    - Legitimate behavior that could match.
level: low | medium | high | critical
```

New rules must use `status: experimental`. Promotions to `test`/`stable` go through a reviewed PR.

## Rule conventions

- 4-space indent, no `---` marker, newline at end of file.
- Detect behavior, not hardcoded paths or versions.
- Tag MITRE ATT&CK techniques (e.g., `attack.t1059.001`).
- No `/` in regex values for CrowdStrike - the backend does not escape slashes. Use `contains` lists instead.
- One unique `id` per rule (`uuidgen`).

## What CI checks

1. **yamllint** - YAML formatting.
2. **Status check** - new rules must be `experimental`.
3. **`sigma check`** - syntax, required fields, logsource, duplicate IDs.
4. **Conversion** - changed rules are converted; stale outputs are pruned. A stamp of pipeline contents and backend versions forces full reconversion when either changes.
5. **Query validation** - every rule has a `.spl` and `.cql`; no empty or orphaned files; no broken CQL regex literals; every SPL query has `index=` and `sourcetype=`.
6. **Auto-commit** - on pushes, the bot commits regenerated queries to the branch. Never edit files under `platform-translations/` by hand.

## Test locally

```bash
pip install sigma-cli pysigma-backend-splunk pysigma-backend-crowdstrike pySigma-validators-sigmahq

python -m yamllint .                                        # formatting
sigma check --fail-on-error --fail-on-issues ./rules/sigma/ # validation

# convert changed rules only
python tests/convert_rules.py --rules rules/sigma --out ./platform-translations/splunk-spl \
    --target splunk --pipeline ./pipelines/sigmakit_pipeline.yml --suffix .spl
python tests/convert_rules.py --rules rules/sigma --out ./platform-translations/crowdstrike-logscale \
    --target log_scale --pipeline crowdstrike_falcon --suffix .cql

# verify outputs
python tests/validate_queries.py ./platform-translations/ ./rules/sigma/
```

## Commit messages

Use conventional prefixes: `feat:` (new rule/feature), `fix:` (bug fix), `chore:` (maintenance).

## Pull requests

- One rule or one logical change per PR.
- PR runs are read-only (lint, validation, conversion checks). Pushes also regenerate queries; the bot commits them to your branch.
