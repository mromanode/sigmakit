# Sigma KIT

[![Pipeline](https://github.com/mromanode/sigmakit/actions/workflows/pipeline.yml/badge.svg)](https://github.com/mromanode/sigmakit/actions/workflows/pipeline.yml)
[![Sigma CLI](https://img.shields.io/badge/sigma--cli-1.x-blue)](https://github.com/SigmaHQ/pySigma)
[![Splunk SPL](https://img.shields.io/badge/Splunk-SPL-green)](https://www.splunk.com/)
[![CrowdStrike LogScale](https://img.shields.io/badge/CrowdStrike-LogScale-red)](https://www.crowdstrike.com/en-us/products/observability/logscale/)

Sigma rules are validated and converted into Splunk SPL and CrowdStrike LogScale (CQL) queries automatically on every push.

- **Rules**: Sigma format under [`rules/sigma/`](rules/sigma/)
- **Queries**: auto-generated under [`platform-translations/`](platform-translations/) (owned by the pipeline)
- **Pipelines**: field mappings and index/sourcetype conditions in [`pipelines/`](pipelines/)
- **CI**: linting, validation, conversion, and auto-commit via GitHub Actions — see [`.github/workflows/pipeline.yml`](.github/workflows/pipeline.yml)

New rules must start as `status: experimental`; promotions to `test`/`stable` go through a pull request. See [CONTRIBUTING.md](CONTRIBUTING.md).