# Changelog

## 0.5.1

- Resolve endpoint credentials through Hermes' active profile secret scope, failing closed instead of borrowing another profile's environment. Adapted from ArchytasEnergyTechnologies/hermes-jev-approvals commit ed08c61adea899b8019d0fd53859226c41266bc7.
- Include the omission marker within the exact command character cap. Inspired by starship-s/hermes-jev-approvals commit 8e6c6fb8545e058bc610c9b96aa400b99df61f68; implemented against the current transport without adopting the fork's policy changes.

## 0.5.0

### Added
- Opt-in `max_questions_per_request` for compatible decision endpoints with per-request question limits (#13, #14). Unset preserves one request containing all six safety questions.
- Bounded concurrent chunks with profile-context propagation, one shared deadline, complete answer validation, and chunk request IDs in the audit schema. Partial or failed results never authorize a command.

### Fixed
- Preserve terminal chunk error details when a sibling reaches the deadline; retry the complete rubric after context-cap reductions.
- Keep the audit schema stable across batched success and failure.

### Documentation
- Explain repeated-state billing, strict response metadata, partial attempt accounting at timeout, and late socket-call limitations.
- Document the official catalog installation command.

No breaking changes or removals. Custom headers and automatic endpoint/model limit detection remain deferred. Verified with offline regression tests and Plugin Validate/Doctor; no live Decision Models inference is claimed.
