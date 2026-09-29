# Run AAK from Windows Git Bash

## Requirements

- Windows 10 or 11
- Git for Windows with Git Bash
- Python 3.11 or newer (`py -3 --version`)
- Internet access during the first installation for the `cryptography` package

## Setup

Extract the release, open its `aak` folder in Git Bash and run:

```bash
chmod +x setup-gitbash.sh run-tests-gitbash.sh
./setup-gitbash.sh
```

The script creates `.venv`, activates the Windows virtual environment, installs
the tested versions in `requirements-runtime.lock`, installs AAK in editable
mode and runs the deterministic security suite.

## Testing

Fast regression suite:

```bash
./run-tests-gitbash.sh
```

Complete defensive campaign:

```bash
./run-tests-gitbash.sh --full
```

The full mode runs 100,000 compound attacks, 310,000 resilience operations,
100,000 external-assurance attacks and 100,000 distributed staging-boundary
attacks, 100,000 separated-service attacks, plus production-like HTTP and mTLS tests.
It can take several minutes.

To change the compound campaign size:

```bash
AAK_COMPOUND_ATTEMPTS=1000000 ./run-tests-gitbash.sh --full
```

## Start a Git repository

```bash
git init
git branch -M main
git config user.name "Glenn Patrick Murray"
git config user.email "295481264+murrayglenn75-beep@users.noreply.github.com"
git add .
git commit -m "Release AAK v1.6.0-rc1 reverse-path hardening"
```

Before publishing, confirm that no secrets or local databases are staged:

```bash
git status --short
git diff --cached
```

Do not commit private keys, `.env` files, production identities, databases or
real customer data. The supplied `.gitignore` excludes common generated and
local-state files, but staged content must still be reviewed.

## Work with Codex

From the repository root, start Codex:

```bash
codex
```

Use this initial instruction:

```text
Read AGENTS.md, CODEX.md, README.md, SECURITY.md, FUTURE_PROOFING.md and
INTERACTION_THREAT_MODEL.md. Run the deterministic test suite and report the
baseline. Do not change code until the baseline passes. This is an authorized
defensive project; preserve deny-by-default behavior and add regression tests
for every security change.
```

## Push to the private GitHub repository

Create an empty private repository named `ai-authority-kernel` in the
`murrayglenn75-beep` GitHub account. Do not initialize it with a README,
`.gitignore` or license. Then run:

```bash
git remote add origin https://github.com/murrayglenn75-beep/ai-authority-kernel.git
git push -u origin main
```

After the push, confirm the `defensive-verification` workflow passes before
adding collaborators or changing repository visibility.

## Common Git Bash issue

If script execution is blocked, invoke it explicitly:

```bash
bash setup-gitbash.sh
bash run-tests-gitbash.sh
```
