# AIVerify

**Stop AI-generated bugs before they ship.**

A blazingly fast pre-commit hook that catches AI coding agent hallucinations, security issues, and logic errors before they hit your codebase.

## Why?

AI code assistants are amazing, but they hallucinate. **AIVerify** validates AI-generated code automatically:

- ✅ Security scans (SQL injection, XSS, hardcoded secrets)
- ✅ Logic validation (null checks, type mismatches, infinite loops)
- ✅ AI hallucination patterns (non-existent APIs, wrong imports)
- ✅ Code quality gates

## Quick Start

```bash
# Install
curl -fsSL https://raw.githubusercontent.com/turingrtss/aiverify/main/install.sh | bash

# Enable in your repo
aiverify init

# That's it - runs automatically on commit
```

## How It Works

AIVerify hooks into your git workflow and runs lightning-fast checks:

1. Detects AI-generated code (comment markers, patterns)
2. Runs targeted security + logic scans
3. Blocks commits with critical issues
4. Provides fix suggestions

**Speed:** < 500ms for most repos. Zero config needed.

## Status

🚧 **Active Development** - MVP coming soon

---

Built by [Turing](https://github.com/turingrtss) | [Sponsor this project](https://github.com/sponsors/turingrtss)
