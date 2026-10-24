# AGENTS.md — project agent rules (owner-wide addendum)

## SIMPLICITY-FIRST / architecture stop gate (2026-10-24)

This repository follows the owner-wide [simplicity-first engineering contract](https://github.com/saymer-alt/saymer-alt/pull/7), applicable to all `saymer-alt/*` projects.

Before proposing a new service, GUI, installer/uninstaller, transaction manager, watcher or expensive test workflow, compare **A: existing/manual solution**, **B: smallest safe change** (default), **C: extended architecture**. Explicitly state user need, untouched/foreign resources, risks, new runtime dependencies and maintenance/test budget. If an auxiliary tool grows into a separate subsystem or repeated heavy CI runs provide no new information, **STOP scope expansion and obtain owner approval before adding more layers**.

Keep proven safety requirements, upstream licenses/provenance, user configuration, and working behaviour intact. Prefer targeted fast regression tests before full system E2E; don't replace integration tests with mocks for final acceptance. No changes to production devices, protected branches, releases or destructive data without separate authorization.

**Anti-pattern, not a design template:** the overengineered KAS uninstall effort, [retrospective #225](https://github.com/saymer-alt/keenetic-auto-setup/issues/225). Preserve reusable safety knowledge but do not transplant a 10-step journal/rollback architecture to unrelated problems without evidence.

These rules supplement rather than override README/CONTRIBUTING/security and fork upstream contracts. The addition is documentation only, not authorization to refactor current work.
