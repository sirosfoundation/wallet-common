# @sirosfoundation/wallet-common

[![build](https://github.com/sirosfoundation/wallet-common/actions/workflows/build.yml/badge.svg)](https://github.com/sirosfoundation/wallet-common/actions/workflows/build.yml)
[![License](https://img.shields.io/badge/license-BSD--2--Clause-blue)](LICENSE)

Reusable wallet components — credential parsing, rendering, verification, and OpenID4VP protocol support.

## Install

```bash
npm install @sirosfoundation/wallet-common
```

## Features

- **Credential Parsing** — SD-JWT-VC, mso_mdoc, JWT VC JSON
- **Credential Rendering** — SVG-based credential display with custom templates
- **Credential Verification** — pluggable verifier engine with X.509 certificate chain validation
- **OpenID4VP** — client and server API for OpenID for Verifiable Presentations
- **Schemas** — Zod schemas for OpenID credential issuer/authorization server metadata
- **AuthZEN** — AuthZEN PDP client
- **Common types** — shared interfaces and type definitions


## Development

### Pre-commit Hook

We use [pre-commit](https://pre-commit.com/) to enforce our `.editorconfig` before code is committed.

#### One-time setup

```
# install pre-commit if you don’t already have it
pip install pre-commit       # or brew install pre-commit / pipx install pre-commit

# enable the git hook in this repo
pre-commit install

# optional: clean up the repo on demand
pre-commit run --all-files

git add -A
```

#### What happens on commit

- Auto-fixers run (e.g. add final newlines).
- After the auto-fixers, the editorconfig-checker runs inside Docker to validate all staged files.
- If violations remain, fix them manually until the commit passes.
