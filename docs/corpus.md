# Real-command corpus

Mined from this machine's own Hermes session dumps across three profiles. Commands
are what the agent actually ran, not invented test cases. **Aggregate metrics only:**
the raw commands stay local because they contain live credentials.

- unique payloads: **14314** (three profiles)
- by tool: {'terminal': 12585, 'execute_code': 1729}
- by profile: (names omitted; roughly 31% / 53% / 16%)

Labels come from Hermes' own detectors (`tools/approval_detection.py`), not from
hand-labelling — `detect_hardline_command` and `detect_dangerous_command` on the exact
string the approval gate sees (`execute_code` payloads wrapped as the gate wraps them).

| bucket | count | share |
|---|---|---|
| hardline (auto-blocked) | 6 | 0.0% |
| dangerous (approval prompt) | 1574 | 11.0% |
| clean (runs freely) | 12734 | 89.0% |

## What actually gets flagged

| count | detector description |
|---|---|
| 643 | script execution via -e/-c flag |
| 602 | script execution via heredoc |
| 53 | recursive delete |
| 50 | force kill processes |
| 31 | command parser limit or malformed executable payload |
| 28 | delete in root path |
| 26 | stop/restart system service |
| 23 | shell command via -c/-lc flag |
| 14 | git reset --hard (destroys uncommitted changes) |
| 10 | git force push (rewrites remote history) |
| 10 | sudo with combined-flag privilege escalation |
| 9 | overwrite system file via redirection |
| 9 | git branch force delete |
| 8 | SQL TRUNCATE |
| 8 | force kill processes (killall -KILL) |
| 6 | stop/restart hermes gateway (kills running agents) |
| 6 | in-place edit of Hermes config/env |
| 6 | sudo with privilege flag (stdin/askpass/shell/list) |
| 5 | stop/restart hermes gateway via shell-spliced verb (kills running agents) |
| 5 | disk copy |

So on real traffic **1580 of 14314 (11.0%)** commands
reach the approval gate at all. That ratio is the cost multiplier for any approval
judgment: everything else never triggers a call.
