# Independent design review

For significant changes, write a specification before code: purpose, affected files, data flows, interfaces, alternatives, test criteria and rollback.

Have a fresh-context reviewer explain the spec back without relying on the design conversation. Have a second independent reviewer check assumptions and edge cases. Resolve findings before owner approval.

Implementation must preserve existing authorization and data protection controls. Verify actual results with tests and externally observable evidence. Never permit an AI reviewer to approve its own permissions or security policy changes.

Use nanochat only for isolated, measured model-training research. This document is not executable enforcement.

References: https://github.com/google/elephant-goldfish-model and https://github.com/karpathy/nanochat
