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

jobs:
  sbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: asinta/cravault-sbom-action@v1
        with:
          token: ${{ secrets.CRAVAULT_TOKEN }}
          version: ${{ github.ref_name }}
```

Create a per-product ingest token in the Cravault app (Product → *Generate ingest token*)
and store it as the `CRAVAULT_TOKEN` repository secret.

## Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `token` | yes | — | Cravault product ingest token (repository secret). |
| `version` | no | `${{ github.ref_name }}` | Release version the SBOM belongs to. |
| `path` | no | `.` | Directory to scan for dependencies. |
| `api-url` | no | `https://api.cravault.io` | Cravault API base URL. |
| `sbom-path` | no | — | Path to an existing CycloneDX SBOM; skips generation. |

## Already generate an SBOM?

Point the action at it and skip generation:

```yaml
      - uses: asinta/cravault-sbom-action@v1
        with:
          token: ${{ secrets.CRAVAULT_TOKEN }}
          sbom-path: sbom.cyclonedx.json
```

## What it does

1. Generates a CycloneDX SBOM with [syft](https://github.com/anchore/syft) (unless
   `sbom-path` is provided).
2. `POST`s it to `"$API_URL/v1/sboms?version=$VERSION"` with a bearer token.
3. Fails the job if Cravault doesn't return a `2xx`.
