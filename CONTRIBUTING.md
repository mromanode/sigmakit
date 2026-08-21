# Contributing

Thanks for contributing. Sigma rules are linted, validated, and automatically converted into Splunk SPL and CrowdStrike LogScale (CQL) queries by GitHub Actions.

## Adding a rule

1. Author the rule in Sigma format under `rules/sigma/<platform>/<category>/`.
2. Follow the naming convention: `proc_creation_lnx_<name>.yml`, `win_<event_id>_<name>.yml`, `proxy_generic_<name>.yml`, etc.
3. The folder and filename prefix must match the rule's `logsource`.
4. Include the required metadata:

```yaml
title: Short, descriptive title
id: <uuid4>
status: experimental | test | stable
description: Explain what the rule detects and the threat it addresses.
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
    - Describe legitimate behavior that could match.
level: low | medium | high | critical
```

## Rule conventions

- 4-space indentation, no `---` document marker, trailing newline at EOF (enforced by yamllint).
- Prefer behavior-based, generic detection (field/value patterns) over hardcoded paths or versions.
- Use MITRE ATT&CK technique tags (e.g., `attack.t1059.001`).
- Avoid regex values containing `/` in rules targeting CrowdStrike â€” the LogScale backend does not escape slashes in regex literals. Use `contains` with a list instead.
- Generate a unique `id` per rule (e.g., `uuidgen` or `python -c "import uuid; print(uuid.uuid4())"`).

## How CI validates

On every push, the pipeline runs:

1. **yamllint** â€” formatting of all YAML (rules, pipelines, configs).
2. **Status check** â€” new rules must be `experimental`; enforced on pull requests, the merge queue, and pushes to `main` (diffed against the `origin/main` merge-base). Promotions to `test`/`stable` are reviewed in pull requests; `main` is branch-protected, so nothing lands there outside a PR.
3. **`sigma check`** â€” rule syntax, required fields, logsource checks, duplicate IDs.
4. **Conversion** â€” only new/changed rules are converted (`tests/convert_rules.py`); stale outputs from deleted/renamed rules are pruned. A conversion stamp per target directory records the pipeline contents and backend package versions â€” when either changes, all rules are reconverted so translations cannot drift.
5. **Query validation** â€” every rule must have a `.spl` and `.cql` output, no empty files, no orphans, no broken CQL regex literals, every SPL query has `index=` and `sourcetype=`.
6. **Auto-commit** â€” validation runs are read-only; on `push` events a separate job re-runs the conversion and the `github-actions[bot]` commits regenerated queries to the pushed branch. Generated files under `platform-translations/` are owned by the pipeline; do not edit them by hand.

## Testing locally

```bash
pip install sigma-cli pysigma-backend-splunk pysigma-backend-crowdstrike pySigma-validators-sigmahq

python -m yamllint .                          # formatting
sigma check --fail-on-error --fail-on-issues ./rules/sigma/   # validation

# convert changed rules only
python tests/convert_rules.py --rules rules/sigma --out ./platform-translations/splunk-spl \
    --target splunk --pipeline ./pipelines/sigmakit_pipeline.yml --suffix .spl
python tests/convert_rules.py --rules rules/sigma --out ./platform-translations/crowdstrike-logscale \
    --target log_scale --pipeline crowdstrike_falcon --suffix .cql

# verify outputs
python tests/validate_queries.py ./platform-translations/ ./rules/sigma/
```

## Commit message style

Use conventional prefixes matching the repo history: `feat:` (new rule/feature), `fix:` (bug fix), `chore:` (maintenance).

## Pull requests

- Open a PR with your rule change. CI runs the full pipeline on the branch (read-only: lint, validation, conversion, query checks).
- Pushes to a branch additionally regenerate the queries and the bot commits them to that branch â€” you only maintain the Sigma rule. After merge, `main` is brought up to date the same way.
- Keep PRs focused: one rule or one logical change per PR.
