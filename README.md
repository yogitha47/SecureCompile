# SecureCompile

A local Flask web app that analyses C source with a PLY-based parser (with syntax-error recovery), AST and text-pattern security rules, an optional trained ML model and an optional GCC/Clang front end. Every finding shows which engine reported it and how uncertain it is, and the app can propose (never silently apply) fixes and validate them.

Submitted code is **never executed**; the only external process is `gcc/clang -fsyntax-only`, when installed.

## What is implemented (verified)

| Area | Status |
|---|---|
| Parser with error recovery | Missing `;` is repaired by a restricted semicolon-insertion step (only when the parser's state accepts `;` and the next token starts a new line, `}`, a type or statement keyword). Other errors use grammar `error` productions (statements, `if`/`while` conditions, call arguments). Diagnostics have line/column; the user's source is never changed. |
| Syntax vs security | Syntax/lexical/delimiter diagnostics are a separate list from security findings. If a compiler is installed and accepts the code, parser complaints are labelled `unsupported-construct` instead of `syntax-error`. |
| Rules | AST analyzer (division by zero, uninitialised use, constant conditions, unsafe calls, format strings) plus text-pattern checks (gets/strcpy/strcat/sprintf, unbounded scanf, free/double-free/use-after-free/NULL deref/leak heuristics, etc.). |
| ML | TF-IDF + one-vs-rest logistic regression, 11 categories, per-category thresholds chosen on a validation split. Trained on NIST Juliet (see limits below). |
| Correlation | Same issue from two rule engines is merged (engines listed); different issues on one line stay separate. ML findings carry `ml_confidence`; rule findings never do. Rule/ML agreement and disagreement are shown for review, not auto-resolved. |
| Fixes | `Fix this issue` and `Generate corrected code`: exact-offset edits, diff, per-change explanation, assumptions, reject/restore, and validation (parser, compiler if present, fresh rule scan, ML re-scan if available). |
| Web UI | Filters (severity, category, engine, agreement, uncertainty, search), provenance chips, ML probability panel, syntax panel, fix panel, report download, batch review, measured-evaluation panel. |

### Fixable rules (deterministic, with stated assumptions)
`gets`→`fgets`, unbounded `scanf %s`→width from a literal array size, `sprintf`→`snprintf`, `strcpy`→bounded `snprintf`, `strcat`→`strncat`, `printf(x)`→`printf("%s", x)`, free of an uninitialised pointer→`= NULL`, double free→`p = NULL` after the first free, uninitialised scalar→placeholder `0`, and missing `;`. A fix is only offered when the destination is a char array visible in the same function; otherwise (or for division by zero, NULL dereference, use-after-free, leaks, command execution, array-size errors, logic warnings) the result is **review required** with guidance, never a guessed value. ML-only findings never produce a fix.

### Validation status
`Passed` = parser did not get worse, the compiler ran with 0 errors, and the rescan shows the targeted finding gone with nothing new. `Failed` = any executed check found a problem. `Unable to verify` = no compiler ran, or compiler errors remain in the proposed code. Regression tests are always reported as **not run** (the submitted program is never executed). Validation is evidence, not a guarantee.

## Setup

Windows PowerShell:
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py            # http://127.0.0.1:5000
```
Ubuntu: `python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt && python app.py`

Compiler diagnostics need `gcc`, `clang` or `cc` on PATH (this project was tested with MinGW GCC 6.3; **Clang was not available**, so no Clang results exist). Without one, the app says so and skips those checks.

### Train and evaluate the ML model
The app works without a model (the UI reports "ML unavailable"). To reproduce:
```powershell
python src/ml/dataset.py download   # 153 MB NIST Juliet 1.3 archive -> data/raw (git-ignored)
python src/ml/dataset.py prepare    # extraction, dedup, grouped split (~6 min first time)
python src/ml/train.py              # ~8 min; writes models/ (git-ignored)
python src/ml/evaluate.py           # ~1.5 min; writes reports/ml_evaluation.{json,md}
```

### Tests
```powershell
pip install -r requirements-dev.txt
python -m pytest tests -q            # 91 passed on the last run (see below)
python tests/ui_smoke.py             # browser end-to-end test (needs Chrome or Edge); all checks passed on the last run
python src/test_all.py; python src/test_control_flow.py; python src/test_extended_source.py   # original script tests, unchanged
python src/evaluate_dataset.py       # original 20-case regression set (12 TP / 8 TN, 0 FP / 0 FN)
```
`tests/test_ml.py` skips model-dependent tests when no model has been trained; the skip is reported by pytest.

## ML model and evaluation (measured)

**Dataset:** [NIST SARD Juliet C/C++ 1.3](https://samate.nist.gov/SARD/test-suites/112). The site states it is "not subject to copyright protection and is in the public domain", with CC0 1.0 for foreign rights. The zip itself contains no license file. Only narrow-char C files for 19 CWEs that map to the model's 11 categories were used; Windows/wide-char variants and unmapped CWEs were excluded. Labels come from the CWE directory plus Juliet's `bad`/`good` function naming (so helper functions such as `badSource` are labelled vulnerable, which adds label noise; functions with identical normalised text but different labels, 22,667 of them, were dropped).

**Split and leakage control:** 97,872 functions extracted; grouped by Juliet test case (all flow variants of one CWE/source/sink stay in one split), stratified by CWE; 43,149 exact duplicates and (validation/test only) 805/914 near-duplicates (TF-IDF cosine ≥ 0.95 to a training sample) removed. Final: 23,770 train / 3,409 validation / 3,158 test, no group or text shared between splits. The split seed (1338) was the first one in which every category had ≥ 15 positives in validation and test (seed 1337 left `format-string` with 0 test positives); this rule used only data counts. Comments and label-leaking identifiers (`*bad*`, `*good*`, `CWE…`) are removed before featurisation.

**Features compared** (test micro-F1 / macro-F1; selection used validation only): text TF-IDF 0.946 / 0.808, lexer-derived "structure" tokens 0.962 / 0.780, combined 0.959 / 0.853 (selected on validation, C=10). "Structure" means a token-class abstraction of this project's own lexer output; it is **not** compiler IR (no Clang/GCC AST features were used).

**Ground truth and matching:** a function's label set is its CWE's categories if it is a Juliet `bad` function, else empty. A configuration scores a TP for a category that it reports and the label set contains. This is *detection*, not localisation. Localisation is measured separately for rules only (the ML model has no line output): 153 of 156 detected flaws with Juliet `FLAW` annotations were reported within ±2 lines.

**Configurations compared on the same test set** (hybrid = union of rule and ML categories, chosen over intersection on validation; micro-F1 95% CI by bootstrapping test-case groups):

| Configuration | Micro F1 | 95% CI | Macro F1 |
|---|---|---|---|
| Rule-based only | 0.170 | 0.086–0.267 | 0.264 |
| ML only | 0.959 | 0.925–0.986 | 0.853 |
| Hybrid (union) | 0.845 | 0.773–0.917 | 0.809 |

Per-category test results (precision/recall/F1, then false positives and false negatives; `n/a` = undefined because nothing was predicted):

| Category | Support | Rule P/R/F1 (FP,FN) | ML P/R/F1 (FP,FN) | Hybrid P/R/F1 (FP,FN) |
|---|---|---|---|---|
| buffer-overflow | 404 | 0.27/0.16/0.20 (171,340) | 1.00/0.98/0.99 (1,10) | 0.70/0.98/0.81 (172,10) |
| format-string | 42 | 1.00/0.50/0.67 (0,21) | 1.00/0.98/0.99 (0,1) | 1.00/0.98/0.99 (0,1) |
| integer-overflow | 441 | n/a/0.00/0.00 (0,441) | 1.00/0.98/0.99 (0,10) | 1.00/0.98/0.99 (0,10) |
| divide-by-zero | 56 | n/a/0.00/0.00 (0,56) | 0.98/0.91/0.94 (1,5) | 0.98/0.91/0.94 (1,5) |
| null-pointer-dereference | 18 | 0.00/0.00/0.00 (18,18) | 0.50/1.00/0.67 (18,0) | 0.33/1.00/0.50 (36,0) |
| double-free | 29 | 0.74/0.59/0.65 (6,12) | 1.00/0.59/0.74 (0,12) | 0.74/0.59/0.65 (6,12) |
| use-after-free | 19 | 0.68/0.89/0.77 (8,2) | 1.00/0.16/0.27 (0,16) | 0.69/0.95/0.80 (8,1) |
| memory-leak | 75 | 0.00/0.00/0.00 (110,75) | 1.00/1.00/1.00 (0,0) | 0.41/1.00/0.58 (110,0) |
| uninitialized-variable | 72 | 1.00/0.22/0.36 (0,56) | 1.00/0.78/0.88 (0,16) | 1.00/0.99/0.99 (0,1) |
| command-injection | 63 | n/a/0.00/0.00 (0,63) | 1.00/1.00/1.00 (0,0) | 1.00/1.00/1.00 (0,0) |
| invalid-free | 78 | 0.22/0.27/0.24 (74,57) | 0.85/1.00/0.92 (14,0) | 0.47/1.00/0.64 (87,0) |

### What these numbers do and do not mean
- **Juliet is synthetic and templated.** High ML scores here do not estimate real-world performance. Several categories have small test support (e.g. 18 NULL-dereference, 19 use-after-free functions), so per-category figures are noisy.
- **Out-of-distribution check (n=10, tiny):** on the project's 10 hand-written in-scope vulnerable snippets (e.g. `char buf[10]; gets(buf);`), the ML model flagged the expected category in **0**; the rules flagged **10** (but those rules were written for those snippets, so that is optimistic). The model also flags the bundled "safe" `fgets` example as `buffer-overflow` (p≈0.65), shown in the UI as an ML-only lead with high uncertainty.
- **`use-after-free` had validation F1 = 0.0** (held-out validation group); on test its recall is 0.16.
- The rules score poorly on Juliet partly because of how Juliet is written (e.g. `system` hidden behind macros, allocation split across files), not only because the rules are weak; they were not tuned on this data.
- On synthetic multi-vulnerability files (400 files built by concatenating 2–3 vulnerable test functions plus a safe one): micro-F1 rule 0.34, ML 0.86, union hybrid 0.84; exact-match 3%, 54%, 49%. This only exercises the file-level code path.
- Because rule false positives accumulate, the union hybrid is *worse* than ML-only on Juliet. The app still shows both engines side by side because the ML model is not a safe sole authority outside Juliet.

Full output: `reports/ml_evaluation.md` / `.json`.

## Parser: supported C and known limits
The grammar covers: scalar/pointer/array declarations (including multiple declarators, initialisers, `const`/`unsigned`/`long long`/`struct X` type words), function definitions/prototypes with `(void)`, assignments incl. compound, `if`/`else if`/`while`/`for`, `return`/`break`/`continue`, calls, casts, `sizeof`, `&`/`*`, member access in expressions, hex/suffixed numbers.
**Not supported** (reported as diagnostics, text-pattern checks still run): `switch`/`case`, `do…while`, `goto`, ternary `?:`, assignment as an expression, struct/union/enum/typedef definitions, function pointers, assignments to members (`p->x = 1`), designated initialisers, preprocessor semantics (directives are skipped). Full C conformance is **not** claimed and was not tested against a conformance suite. Clang integration as a primary front end was evaluated conceptually but not implemented (none installed here); GCC/Clang is used only for `-fsyntax-only` diagnostics.

## Other known limitations / remaining work
- Text-pattern rules are regex heuristics: no aliasing, path sensitivity or inter-procedural reasoning. Many are low confidence and the UI says so.
- Fixes cover only the rules listed above; behaviour changes (e.g. truncation) are stated as assumptions but are not tested by running the program.
- No dynamic sandboxed testing exists. Real-world C vulnerability data (e.g. DiverseVul, Big-Vul) was not used; adding it would be the main route to a more credible model.
- Dataset and model files are git-ignored; a fresh clone shows "ML unavailable" until trained.
- `src/*_backup*` files are leftovers from earlier work and are unused.
