# Changelog

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
