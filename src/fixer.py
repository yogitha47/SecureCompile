"""Detect -> explain -> fix -> validate workflow (stateless; never touches the caller's source)."""
from __future__ import annotations

import collections

import pipeline
import remediation as rem
from validation import validate_patch


class FixError(ValueError):
    pass


def _scan(source):
    return pipeline.analyze(source, use_compiler=False, use_ml=False)


def _response(original, proposed, applied, items, validation, extra=None):
    return {
        "ok": True,
        "original_sha256": rem.sha256(original),
        "proposed_sha256": rem.sha256(proposed),
        "changed": proposed != original,
        "proposed_source": proposed,
        "diff": rem.unified_diff(original, proposed),
        "changes": rem.describe_changes(original, applied),
        "items": items,
        "validation": validation,
        "note": ("This is a proposal. Your original code has not been modified; apply it in the editor only "
                 "after reviewing the diff, and restore the original at any time."),
        **(extra or {}),
    }


def fix_finding(source: str, finding_id: str) -> dict:
    """Propose and validate a fix for one finding."""
    guard = rem.sha256(source)
    result = _scan(source)
    finding = next((f for f in result["findings"] if f["id"] == finding_id), None)
    if finding is None:
        # It might be an ML-only finding: explain why it cannot drive a repair.
        full = pipeline.analyze(source, use_compiler=False, use_ml=True)
        ml_finding = next((f for f in full["findings"] if f["id"] == finding_id), None)
        if ml_finding is None:
            raise FixError("That finding was not found for this source. Re-run the analysis and try again.")
        proposal = rem.propose_fix(source, ml_finding)
        return _no_fix(source, ml_finding, proposal)

    masked = rem.mask_source(source)
    proposal = rem.propose_fix(source, finding, masked)
    if not proposal.available:
        return _no_fix(source, finding, proposal)
    proposed, applied, _ = rem.apply_edits(source, proposal.edits)
    validation = validate_patch(source, proposed, target_rules={finding["rule_id"]: 1})
    assert rem.sha256(source) == guard
    item = _item(finding, proposal, "fixed")
    return _response(source, proposed, applied, [item], validation,
                     {"finding_id": finding_id, "summary": proposal.summary, "assumptions": proposal.assumptions,
                      "kind": proposal.kind})


def _item(finding, proposal, status):
    return {"finding_id": finding["id"], "rule_id": finding.get("rule_id"), "line": finding.get("line"),
            "status": status, "kind": proposal.kind, "summary": proposal.summary,
            "assumptions": proposal.assumptions, "reason": proposal.reason,
            "guidance": proposal.guidance, "guidance_snippet": proposal.guidance_snippet}


def _no_fix(source, finding, proposal):
    status = "review-required" if proposal.kind == rem.REVIEW else "unavailable"
    return {
        "ok": True, "changed": False, "proposed_source": source, "diff": "", "changes": [],
        "original_sha256": rem.sha256(source), "proposed_sha256": rem.sha256(source),
        "finding_id": finding.get("id"), "kind": proposal.kind, "summary": proposal.summary,
        "items": [_item(finding, proposal, status)], "validation": None, "assumptions": [],
        "note": "No code change is proposed for this finding; the explanation below says why.",
    }


def generate_corrected(source: str) -> dict:
    """Propose corrections for the whole program: syntax repairs + every deterministic fix."""
    guard = rem.sha256(source)
    result = _scan(source)
    masked = rem.mask_source(source)

    edits, items, fixed_rules = [], [], collections.Counter()
    owner = {}
    for repair in result["syntax_repairs"]:
        edit = rem.propose_syntax_repair(repair)
        edits.append(edit)
        items.append({"finding_id": repair["id"], "rule_id": "SYNTAX", "line": repair["line"], "status": "fixed",
                      "kind": rem.DETERMINISTIC, "summary": f"Insert missing ';' (line {repair['line']})",
                      "assumptions": ["The statement was meant to end at the end of this line."],
                      "reason": "", "guidance": "", "guidance_snippet": ""})

    for finding in result["findings"]:
        proposal = rem.propose_fix(source, finding, masked)
        if not proposal.available:
            items.append(_item(finding, proposal, "review-required" if proposal.kind == rem.REVIEW else "unavailable"))
            continue
        edits.extend(proposal.edits)
        for e in proposal.edits:
            owner.setdefault((e.start, e.end, e.replacement), []).append(len(items))
        items.append(_item(finding, proposal, "fixed"))

    if not edits:
        return {"ok": True, "changed": False, "proposed_source": source, "diff": "", "changes": [],
                "original_sha256": guard, "proposed_sha256": guard, "items": items, "validation": None,
                "note": "No automatic corrections are available for this program; see the per-finding explanations."}

    proposed, applied, skipped = rem.apply_edits(source, edits)
    applied_keys = {(e.start, e.end, e.replacement) for e in applied}
    for edit, why in skipped:
        key = (edit.start, edit.end, edit.replacement)
        if key in applied_keys:
            continue  # identical duplicate (e.g. the same #include): the first copy covers it
        for index in owner.get(key, []):
            items[index]["status"] = "conflict"
            items[index]["reason"] = f"Skipped because its edit {why}; apply it separately after reviewing."
    for item in items:
        if item["status"] == "fixed" and item["rule_id"] != "SYNTAX":
            fixed_rules[item["rule_id"]] += 1
    validation = validate_patch(source, proposed, target_rules=dict(fixed_rules))
    assert rem.sha256(source) == guard
    counts = collections.Counter(i["status"] for i in items)
    return _response(source, proposed, applied, items, validation, {"counts": dict(counts)})
