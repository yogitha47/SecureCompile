"""Prepare a labelled function-level dataset from the NIST Juliet C/C++ 1.3 test suite.

Source:  https://samate.nist.gov/SARD/test-suites/112  (public domain / CC0 for foreign rights)
Labels:  derived from the CWE directory and the Juliet naming convention
         (functions whose name contains "bad" are the flawed variant, "good" the fixed variant).
Caveat:  Juliet is synthetic and highly templated. Results on it do not estimate real-world performance.

Usage (from the project root):
    python src/ml/dataset.py download
    python src/ml/dataset.py prepare
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import random
import re
import sys
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from findings import ML_CATEGORIES  # noqa: E402
from ml.features import normalize_code, split_functions  # noqa: E402

JULIET_URL = "https://samate.nist.gov/SARD/downloads/test-suites/2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3.zip"
JULIET_BYTES = 152_957_342
RAW_ZIP = ROOT / "data" / "raw" / "juliet-1.3.zip"
PROCESSED_DIR = ROOT / "data" / "processed"
DATASET_PATH = PROCESSED_DIR / "juliet_functions.jsonl"
STATS_PATH = PROCESSED_DIR / "dataset_stats.json"

SEED = 1337
SPLIT_FRACTIONS = (0.70, 0.15, 0.15)  # train / validation / test, applied to *groups*
MIN_TOKENS = 12                       # drop trivial wrapper functions
NEAR_DUP_COSINE = 0.95

# CWE number -> SecureCompile categories. CWEs outside this table are excluded entirely
# (their "bad" functions would otherwise be mislabelled as safe).
CWE_TO_CATEGORIES = {
    121: ["buffer-overflow"], 122: ["buffer-overflow"], 123: ["buffer-overflow"],
    124: ["buffer-overflow"], 126: ["buffer-overflow"], 127: ["buffer-overflow"],
    680: ["buffer-overflow", "integer-overflow"],
    190: ["integer-overflow"], 191: ["integer-overflow"],
    134: ["format-string"],
    369: ["divide-by-zero"],
    476: ["null-pointer-dereference"],
    415: ["double-free"],
    416: ["use-after-free"],
    401: ["memory-leak"],
    457: ["uninitialized-variable"],
    78: ["command-injection"],
    590: ["invalid-free"], 761: ["invalid-free"],
}
assert all(c in ML_CATEGORIES for cats in CWE_TO_CATEGORIES.values() for c in cats)

_MEMBER = re.compile(r"^C/testcases/(CWE(\d+)_[^/]+)/(?:s\d+/)?([^/]+\.c)$")
_VARIANT_SUFFIX = re.compile(r"_\d{2}[a-z]?\.c$")
_FLAW_COMMENT = re.compile(r"(?i)\bFLAW\b")


def download(force: bool = False) -> None:
    RAW_ZIP.parent.mkdir(parents=True, exist_ok=True)
    if RAW_ZIP.exists() and RAW_ZIP.stat().st_size == JULIET_BYTES and not force:
        print(f"Already downloaded: {RAW_ZIP} ({RAW_ZIP.stat().st_size:,} bytes)")
        return
    print(f"Downloading {JULIET_URL}")
    urllib.request.urlretrieve(JULIET_URL, RAW_ZIP)
    size = RAW_ZIP.stat().st_size
    if size != JULIET_BYTES:
        raise SystemExit(f"Unexpected size {size:,} (expected {JULIET_BYTES:,}); delete the file and retry.")
    print(f"Saved {RAW_ZIP} ({size:,} bytes)")


def _label_for_function(name: str):
    lowered = name.lower()
    if "bad" in lowered:
        return True
    if "good" in lowered:
        return False
    return None


def _flaw_lines(function_text: str):
    """1-based line numbers (relative to the function) of the statement following a FLAW comment."""
    lines = function_text.splitlines()
    flaws = []
    for index, line in enumerate(lines):
        if _FLAW_COMMENT.search(line):
            for follow in range(index + 1, min(index + 6, len(lines))):
                stripped = lines[follow].strip()
                if stripped and not stripped.startswith(("/*", "*", "//")):
                    flaws.append(follow + 1)
                    break
    return flaws


def extract_samples():
    if not RAW_ZIP.exists():
        raise SystemExit("Dataset archive missing. Run: python src/ml/dataset.py download")
    samples = []
    skipped = collections.Counter()
    with zipfile.ZipFile(RAW_ZIP) as archive:
        members = sorted(n for n in archive.namelist() if _MEMBER.match(n))
        for member in members:
            match = _MEMBER.match(member)
            cwe_dir, cwe_number, filename = match.group(1), int(match.group(2)), match.group(3)
            if cwe_number not in CWE_TO_CATEGORIES:
                skipped["cwe-not-mapped"] += 1
                continue
            if "w32" in filename or "wchar_t" in filename:
                skipped["wide-char-or-windows-variant"] += 1
                continue
            text = archive.read(member).decode("utf-8", errors="replace")
            group = f"{cwe_dir}/{_VARIANT_SUFFIX.sub('', filename)}"
            for function in split_functions(text):
                is_bad = _label_for_function(function["name"])
                if is_bad is None:
                    skipped["helper-or-main-function"] += 1
                    continue
                normalized = normalize_code(function["text"], function_names=[function["name"]])
                if len(normalized.split()) < MIN_TOKENS:
                    skipped["too-short"] += 1
                    continue
                samples.append({
                    "id": f"{member}::{function['name']}",
                    "file": member,
                    "cwe": cwe_number,
                    "group": group,
                    "function": function["name"],
                    "labels": list(CWE_TO_CATEGORIES[cwe_number]) if is_bad else [],
                    "text": function["text"],
                    "normalized": normalized,
                    "flaw_lines": _flaw_lines(function["text"]) if is_bad else [],
                })
    return samples, skipped


def assign_splits(samples, rng):
    """Group-wise split stratified by CWE: all flow variants of a test case stay in one split."""
    groups_by_cwe = collections.defaultdict(set)
    for s in samples:
        groups_by_cwe[s["cwe"]].add(s["group"])
    assignment = {}
    for cwe, groups in sorted(groups_by_cwe.items()):
        ordered = sorted(groups)
        rng.shuffle(ordered)
        n = len(ordered)
        if n >= 3:
            n_val = max(1, round(n * SPLIT_FRACTIONS[1]))
            n_test = max(1, round(n * SPLIT_FRACTIONS[2]))
        else:
            n_val = n_test = 0
        for i, group in enumerate(ordered):
            if i < n_test:
                assignment[group] = "test"
            elif i < n_test + n_val:
                assignment[group] = "validation"
            else:
                assignment[group] = "train"
    for s in samples:
        s["split"] = assignment[s["group"]]


def remove_duplicates(samples, stats):
    """Exact duplicates (by normalised text) across the whole set; conflicting labels are dropped."""
    by_hash = collections.defaultdict(list)
    for s in samples:
        by_hash[hashlib.sha256(s["normalized"].encode()).hexdigest()].append(s)
    priority = {"train": 0, "validation": 1, "test": 2}
    keep, dropped_exact, dropped_conflict = [], 0, 0
    for items in by_hash.values():
        if len({tuple(sorted(i["labels"])) for i in items}) > 1:
            dropped_conflict += len(items)
            continue
        items.sort(key=lambda i: (priority[i["split"]], i["id"]))
        keep.append(items[0])
        dropped_exact += len(items) - 1
    stats["exact_duplicates_removed"] = dropped_exact
    stats["conflicting_label_duplicates_removed"] = dropped_conflict
    return sorted(keep, key=lambda s: s["id"])


def remove_near_duplicates(samples, stats):
    """Drop validation/test samples that are near-copies of a training sample (TF-IDF cosine)."""
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.neighbors import NearestNeighbors

    train = [s for s in samples if s["split"] == "train"]
    vectorizer = TfidfVectorizer(token_pattern=r"\S+", lowercase=False, ngram_range=(1, 3),
                                 min_df=2, sublinear_tf=True)
    x_train = vectorizer.fit_transform([s["normalized"] for s in train])
    nn = NearestNeighbors(n_neighbors=1, metric="cosine", algorithm="brute").fit(x_train)
    removed = collections.Counter()
    keep = list(train)
    for split in ("validation", "test"):
        part = [s for s in samples if s["split"] == split]
        if not part:
            continue
        distances, _ = nn.kneighbors(vectorizer.transform([s["normalized"] for s in part]))
        for s, d in zip(part, distances[:, 0]):
            if 1.0 - d >= NEAR_DUP_COSINE:
                removed[split] += 1
            else:
                keep.append(s)
    stats["near_duplicates_removed"] = dict(removed)
    stats["near_duplicate_cosine_threshold"] = NEAR_DUP_COSINE
    return sorted(keep, key=lambda s: s["id"])


MIN_POSITIVES_PER_SPLIT = 15
MAX_SEED_ATTEMPTS = 40
EXTRACT_CACHE = PROCESSED_DIR / "extracted.jsonl"


def _load_or_extract():
    if EXTRACT_CACHE.exists():
        with EXTRACT_CACHE.open(encoding="utf-8") as handle:
            rows = [json.loads(line) for line in handle]
        skipped = json.loads((PROCESSED_DIR / "extract_skipped.json").read_text(encoding="utf-8"))
        return rows, skipped
    samples, skipped = extract_samples()
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    with EXTRACT_CACHE.open("w", encoding="utf-8") as handle:
        for s in samples:
            handle.write(json.dumps(s) + "\n")
    (PROCESSED_DIR / "extract_skipped.json").write_text(json.dumps(dict(skipped)), encoding="utf-8")
    return samples, dict(skipped)


def _split_counts(samples):
    result = {}
    for split in ("train", "validation", "test"):
        part = [s for s in samples if s["split"] == split]
        result[split] = {
            "samples": len(part),
            "groups": len({s["group"] for s in part}),
            "vulnerable": sum(bool(s["labels"]) for s in part),
            "safe": sum(not s["labels"] for s in part),
            "positives_per_category": {c: sum(c in s["labels"] for s in part) for c in ML_CATEGORIES},
        }
    return result


def prepare():
    extracted, skipped = _load_or_extract()
    attempts = []
    chosen = None
    for attempt in range(MAX_SEED_ATTEMPTS):
        seed = SEED + attempt
        samples = [dict(s) for s in extracted]
        stats = {"seed": seed}
        assign_splits(samples, random.Random(seed))
        samples = remove_duplicates(samples, stats)
        samples = remove_near_duplicates(samples, stats)
        counts = _split_counts(samples)
        lacking = {split: [c for c, n in counts[split]["positives_per_category"].items()
                           if n < MIN_POSITIVES_PER_SPLIT] for split in ("validation", "test")}
        attempts.append({"seed": seed, "categories_below_minimum": lacking})
        print(f"seed {seed}: categories below {MIN_POSITIVES_PER_SPLIT} positives -> {lacking}")
        if not lacking["validation"] and not lacking["test"]:
            chosen = (seed, samples, stats, counts)
            break
    if chosen is None:
        raise SystemExit("No seed produced enough positives in every category; see attempts above.")
    seed, samples, stats, counts = chosen
    stats.update({
        "source": JULIET_URL, "split_seed": seed, "skipped": skipped,
        "samples_extracted": len(extracted), "min_tokens": MIN_TOKENS,
        "seed_selection_rule": (f"first seed from {SEED} whose validation and test splits each have >= "
                                f"{MIN_POSITIVES_PER_SPLIT} positives in every category (data counts only; "
                                "no model performance was consulted)"),
        "seed_attempts": attempts, "final": counts,
        "group_overlap_between_splits": 0 if not (
            {s["group"] for s in samples if s["split"] == "train"} &
            {s["group"] for s in samples if s["split"] == "test"}) else "NON-ZERO (bug)",
    })
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    with DATASET_PATH.open("w", encoding="utf-8") as handle:
        for s in samples:
            handle.write(json.dumps(s) + "\n")
    STATS_PATH.write_text(json.dumps(stats, indent=2), encoding="utf-8")
    print(json.dumps({k: v for k, v in stats.items() if k != "seed_attempts"}, indent=2))
    print(f"Wrote {DATASET_PATH}")


def load_dataset():
    if not DATASET_PATH.exists():
        raise SystemExit("Prepared dataset missing. Run: python src/ml/dataset.py prepare")
    with DATASET_PATH.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle]


if __name__ == "__main__":
    cli = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    cli.add_argument("command", choices=["download", "prepare"])
    cli.add_argument("--force", action="store_true")
    args = cli.parse_args()
    if args.command == "download":
        download(args.force)
    else:
        prepare()
