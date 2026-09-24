# cravault-sbom-action

Generate a CycloneDX SBOM from your repository and upload it to
[Cravault](https://cravault.io) so your released versions are monitored for
actively-exploited vulnerabilities and CRA / Article 14 obligations.

Your source never leaves the runner — only the CycloneDX SBOM is sent.

## Usage

```yaml
# .github/workflows/cravault.yml
name: Cravault
on:
  push:
    tags: ['v*']       # upload an SBOM for each release tag

permissions:
  contents: read

jobs:
  sbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: asinta/cravault-sbom-action@v1
        with:
          token: ${{ secrets.CRAV_TOKEN }}
```

`version` defaults to `github.ref_name`, so a tag-triggered workflow needs nothing else.

Create a per-product ingest token in the Cravault app (Product → *Generate ingest token*)
and store it as the `CRAV_TOKEN` repository secret.

> **Pinning.** `@v1` follows the latest v1 release. To pin exactly, use the commit SHA:
> `uses: asinta/cravault-sbom-action@<sha>`. This action pins its own dependency the same
> way — see `syft-version` below.

## Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `token` | yes | — | Cravault product ingest token (repository secret). |
| `version` | no | `${{ github.ref_name }}` | Release version the SBOM belongs to. |
| `kind` | no | `release` | `release` for a shipped version, `snapshot` for a build in between. |
| `path` | no | `.` | Directory to scan for dependencies. |
| `api-url` | no | `https://cravault.io/api` | Cravault API base URL. |
| `sbom-path` | no | — | Path to an existing CycloneDX SBOM; skips generation. |
| `syft-version` | no | `v1.52.0` | Tag of [syft](https://github.com/anchore/syft) to install. |

## Outputs

| Output | Description |
|---|---|
| `sbom-path` | Path to the SBOM that was uploaded. |

## Monitoring between releases

Releases are what CRA reporting hangs off, but a vulnerability that lands in `main` is worth
knowing about before you tag. Upload those as snapshots:

```yaml
on:
  push:
    branches: [main]

jobs:
  sbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: asinta/cravault-sbom-action@v1
        with:
          token: ${{ secrets.CRAV_TOKEN }}
          version: main-${{ github.sha }}
          kind: snapshot
```

## Already generate an SBOM?

Point the action at it and skip generation:

```yaml
      - uses: asinta/cravault-sbom-action@v1
        with:
          token: ${{ secrets.CRAV_TOKEN }}
          sbom-path: sbom.cyclonedx.json
```

## What it does

1. Validates the inputs and refuses anything that cannot be a version, a kind or a path.
2. Generates a CycloneDX SBOM with [syft](https://github.com/anchore/syft), pinned to
   `syft-version` (unless `sbom-path` is provided).
3. `POST`s it to `$API_URL/v1/sboms` with the version and kind as query parameters and the
   token as a bearer credential. Transient failures are retried; ingest is idempotent by
   content hash, so a retry that already landed is a no-op.
4. Fails the job if Cravault doesn't return a `2xx`.

## Security notes

Input values are passed to the shell through the environment, never interpolated into the
script body. That matters because `version` defaults to `github.ref_name` and git accepts a
ref named `v1$(...)` — with `${{ }}` interpolation, anyone able to push a branch or tag
could have run code on the runner alongside your ingest token.

The action installs syft from a pinned tag rather than `main`, so neither the installer nor
the binary can change under you between runs.

## Development

```bash
pip install pyyaml
python3 tests/test_action.py     # runs the action's steps against a stub Cravault
```

`tests/run_action.py` executes a composite action locally the way the runner does — same
shell, same expression resolution — so the steps can be exercised without pushing a workflow.
