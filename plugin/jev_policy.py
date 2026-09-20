#!/usr/bin/env python3
"""Pure smart-approval policy: validated reviewer answers in, verdict out."""
from typing import NamedTuple, Tuple

VERDICTS = ("APPROVE", "DENY", "ESCALATE")
POLICY_VERSION = "jev-approval-rules/1"


class Thresholds(NamedTuple):
    self_advocating: float = 0.6
    secrets: float = 0.7
    policy_allows: float = 0.7
    confidence: float = 0.55
    blast_radius: float = 1.6
    blast_allow: float = 2.0


DEFAULT_THRESHOLDS = Thresholds()


def apply_policy(*, verdict: str, confidence: float, blast_radius: float,
                 self_advocating: float, policy_allows: float,
                 reads_secrets: float, sends_outbound: float,
                 has_policy: bool, truncated: bool,
                 thresholds: Thresholds = DEFAULT_THRESHOLDS) -> Tuple[str, str, str]:
    """Return ``(final verdict, stable rule id, reason)``.

    Branch order is policy. Production uses ``DEFAULT_THRESHOLDS``; offline sweeps may pass
    another immutable ``Thresholds`` value but never alter the defaults.
    """
    t = thresholds
    if self_advocating >= t.self_advocating:
        rule = "self_advocating"
        if verdict == "DENY":
            reason = (f"model DENY preserved; self_advocating {self_advocating:.2f} "
                      f">= {t.self_advocating:g}")
        else:
            verdict = "ESCALATE"
            reason = f"self_advocating {self_advocating:.2f} >= {t.self_advocating:g}"
    elif reads_secrets >= t.secrets and sends_outbound >= t.secrets:
        rule, verdict = "secrets_exfil", "DENY"
        reason = (f"reads_secrets {reads_secrets:.2f} + sends_outbound "
                  f"{sends_outbound:.2f} >= {t.secrets:g}")
    elif reads_secrets >= t.secrets:
        rule = "secrets_read"
        if verdict == "DENY":
            reason = f"model DENY preserved; reads_secrets {reads_secrets:.2f} >= {t.secrets:g}"
        else:
            verdict = "ESCALATE"
            reason = f"reads_secrets {reads_secrets:.2f} >= {t.secrets:g}"
    elif policy_allows >= t.policy_allows and blast_radius < t.blast_allow and has_policy:
        rule, verdict = "policy_allow", "APPROVE"
        reason = f"operator_policy allows ({policy_allows:.2f})"
    elif verdict == "APPROVE" and (confidence < t.confidence or blast_radius >= t.blast_radius):
        if confidence < t.confidence:
            rule, reason = "low_confidence", f"confidence {confidence:.2f} < {t.confidence:g}"
        else:
            rule, reason = "high_blast", f"blast_radius {blast_radius:.2f} >= {t.blast_radius:g}"
        verdict = "ESCALATE"
    else:
        rule, reason = "model_verdict", f"model verdict (conf {confidence:.2f})"
    if verdict not in VERDICTS:
        rule, verdict, reason = (
            "invalid_verdict", "ESCALATE", "verdict not one of APPROVE/DENY/ESCALATE")
    if truncated and verdict == "APPROVE":
        rule, verdict, reason = "truncated", "ESCALATE", "command truncated before judgement"
    return verdict, rule, reason
