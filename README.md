# SecureCompile Intelligence

### Compiler-Based Static Security Analysis with Syntax Error Recovery and ML-Assisted Multi-Vulnerability Detection

SecureCompile is an educational software-security project that analyzes C source code using compiler-design techniques and static security analysis. Its planned evolution combines a compiler-aware frontend, syntax error recovery, rule-based vulnerability detection, machine learning, explainable findings, and guided remediation.

The goal is to help developers identify multiple potential vulnerabilities in a single scan, understand why code may be unsafe, and receive useful guidance for correcting it.

> **Development status:** The existing project contains a Flask application and a custom compiler-inspired analysis pipeline. ML-assisted vulnerability detection, improved syntax error recovery, advanced data-flow analysis, and guided remediation must be treated as planned features until implemented and tested.

---

# PART A — PROJECT DOCUMENTATION

## 1. Project Vision

SecureCompile aims to go beyond a basic syntax checker or a security scanner that only displays warnings.

The intended platform combines:

1. Compiler-based source-code processing.
2. Recovery from common syntax errors.
3. Rule-based security analysis.
4. ML-assisted multi-label vulnerability prediction.
5. Compiler-aware evidence and source-location mapping.
6. Finding correlation and duplicate detection.
7. Explainable findings and suggested corrections.
8. Reproducible evaluation and transparent reporting.

The proposed contribution is the integration and evaluation of these capabilities in one educational C-code analysis workflow. Claims of uniqueness must be supported by research and comparison with existing tools.

## 2. Problem Statement

C programs may contain syntax errors, programming mistakes, and security vulnerabilities. A parser that stops at the first syntax error can prevent subsequent statements from being analyzed. Rule-based scanners may also miss patterns outside their implemented rules, while machine-learning models can produce false positives and false negatives.

SecureCompile aims to combine compiler analysis, syntax recovery, deterministic rules, and ML-assisted predictions to improve multi-vulnerability detection and explainability.

## 3. Objectives

- Analyze C source code through a compiler-inspired pipeline.
- Support multiple potential vulnerability findings in a single scan.
- Recover from common syntax errors, including missing semicolons, wherever safe.
- Continue analyzing unaffected statements after recoverable errors.
- Detect known vulnerability patterns using deterministic security rules.
- Train and evaluate an ML model that predicts multiple vulnerability categories.
- Combine results from different analysis engines without hiding distinct findings.
- Explain vulnerabilities with evidence, source locations, severity, and suggested corrections where supported.
- Provide a functional web interface for code submission and result inspection.
- Evaluate the system using held-out data and document its limitations.

## 4. Current Project Architecture

The existing project uses Python, Flask, and a custom compiler-inspired pipeline.

```text
C Source Code
     |
     v
Lexical Analysis
     |
     v
Parsing and AST Construction
     |
     v
Semantic Analysis and Symbol Table
     |
     v
Rule-Based Security Analysis
     |
     v
Supplementary Source-Level Checks
     |
     v
Security Findings and Reports
```

The actual capabilities of each stage must be verified against the current repository.

### Existing project files

| File or directory | Purpose |
|---|---|
| `app.py` | Flask application and request handling |
| `src/lexer.py` | Lexical analysis |
| `src/parser.py` | Parsing and AST construction |
| `src/ast_nodes.py` | AST node definitions |
| `src/semantic.py` | Semantic analysis |
| `src/symbol_table.py` | Symbol-table functionality |
| `src/security_analyzer.py` | Rule-based security checks |
| `src/source_analyzer.py` | Supplementary source-level checks |
| `src/test_all.py` | Test-suite entry point, if present |
| `src/evaluate_dataset.py` | Dataset evaluation, if present |
| `templates/` | Flask HTML templates |
| `static/` | CSS, JavaScript, and static assets |
| `reports/` | Generated analysis and evaluation reports |

This is an expected inventory, not a guarantee that every file is present in the same form. Inspect the actual project before modifying it.

## 5. Planned Hybrid Architecture

```text
                  C Source Code
                        |
             Source and Syntax Checks
                        |
              Lexer and Error Recovery
                        |
                 Parser and AST
                        |
             Semantic and Symbol Analysis
                        |
           +------------+------------+
           |                         |
           v                         v
    Rule-Based Engine          ML Prediction Engine
           |                         |
           v                         v
     Rule Findings              ML Predictions
           |                         |
           +------------+------------+
                        |
             Finding Correlation Layer
             - Deduplication
             - Evidence association
             - Source-location mapping
             - Confidence and uncertainty
                        |
                        v
                Unified Security Report
                        |
                        v
                 SecureCompile Website
```

Source-level fallback analysis must remain possible when parsing fails. The absence of a complete AST must not automatically suppress every potential security finding.

## 6. Multi-Vulnerability Detection

The intended system should detect multiple supported vulnerability categories in one scan.

Potential categories include:

- Division by zero.
- Modulo by zero.
- Uninitialized variables.
- Unsafe input functions.
- Potential buffer overflows.
- Unsafe string operations.
- Format-string vulnerabilities.
- Suspicious command execution.
- Null-pointer dereferences.
- Out-of-bounds array access.
- Integer overflow where reliably analyzable.
- Other categories after their detection logic has been implemented and evaluated.

The presence of a function name alone does not always prove a vulnerability. Each rule must define its evidence requirements, severity policy, and known limitations.

## 7. Syntax Error Recovery

SecureCompile should attempt to analyze code containing common syntax mistakes.

Example:

```c
int main() {
    int x = 10
    int y = 0;
    int result = x / y
    gets(name);
    return 0;
}
```

The intended behavior is to report missing semicolons and continue analyzing later statements wherever possible.

Requirements:

- Report syntax errors with line and column information where available.
- Recover from common missing-semicolon errors.
- Continue analyzing unaffected statements.
- Run source-level fallback checks when parsing fails.
- Separate syntax diagnostics from security findings.
- Mark findings that could not be verified because parsing was incomplete.
- Preserve the user's original source.
- Show any proposed syntax repair separately.

Do not claim that arbitrary malformed C can always be recovered. Severely malformed code may remain only partially analyzable.

## 8. ML-Assisted Multi-Label Detection

The planned ML engine must use a genuine trained model, not a keyword-matching function presented as machine learning.

### Proposed approach

Begin with a lightweight multi-label classification baseline using scikit-learn, such as TF-IDF or code-token features with an appropriate multi-label classifier.

The model should:

1. Learn from labeled C-code examples.
2. Predict multiple supported vulnerability categories.
3. Use a reproducible preprocessing and training pipeline.
4. Save the trained model and preprocessing artifacts.
5. Load the model for inference without retraining on every request.
6. Distinguish predictions from deterministic rule findings.
7. Handle malformed input and model-loading failures safely.
8. Be evaluated on held-out examples.

### Dataset research

Investigate the NIST Software Assurance Reference Dataset (SARD) and other suitable labeled datasets. Verify dataset availability, licensing, labels, preprocessing requirements, and relevance to the chosen vulnerability categories.

Avoid training/test leakage caused by duplicate or near-duplicate code. Keep training, validation, and held-out test data separate.

### Evaluation requirements

Compare:

- Rule-based analysis alone.
- ML-based analysis alone.
- The combined hybrid system.

Report per-category precision, recall, F1-score, false positives, false negatives, dataset details, and the evaluation methodology.

Do not invent metrics or reuse results from a small predefined regression set as evidence of ML performance. Model confidence is not proof that a vulnerability exists.

## 9. Compiler Compatibility

Aim for broad, standards-aware C support.

Inspect the existing PLY-based parser and identify supported and unsupported constructs. Evaluate whether Clang or another established C frontend would provide more reliable parsing, source locations, type information, and compiler diagnostics while preserving the existing custom security-analysis contribution.

Potential language features include pointers, arrays, structures, unions, function pointers, scope, types, macros, preprocessor directives, and standard-library calls.

Do not claim complete C standards compliance until it has been verified with suitable conformance tests. When a construct is unsupported, report the limitation clearly and continue independent analysis where safe.

## 10. Finding Correlation and Explainability

Each finding should contain appropriate fields such as:

- Finding identifier.
- Vulnerability category or rule ID.
- Severity.
- Source file and location, when available.
- Evidence or relevant code snippet.
- Explanation.
- Detection engine.
- Confidence or uncertainty, where applicable.
- Suggested correction, when supported.
- Verification status.

Deduplicate only findings that refer to the same underlying issue. Do not merge distinct vulnerabilities simply because they occur on the same line.

Explain why a finding matters and show evidence supporting it. Suggested fixes must remain suggestions until validated. ML predictions should be clearly labeled as predictions.

## 11. Website Requirements

Preserve and improve the existing Flask website rather than replacing it with a static mockup.

The intended experience includes:

1. Source-code editor or upload area.
2. Analyze/scan action.
3. Syntax diagnostics separated from security findings.
4. Summary of findings by category and severity.
5. Source-code locations where supported.
6. Filters for severity, category, and detection engine.
7. Evidence and explanation panels.
8. ML predictions with uncertainty labels.
9. Suggested corrections and before/after comparisons.
10. Rescanning after code changes.
11. A genuine model-evaluation page.
12. Structured report export, if implemented.

Keep the existing lavender, purple, white, and dark-code-editor visual direction where compatible with the current UI.

All buttons and controls must perform real actions. Do not display hardcoded metrics as actual results.

Do not execute submitted C code as part of ordinary static analysis.

## 12. Evaluation and Testing

Add regression tests for:

- Safe C programs.
- One recognized vulnerability.
- Multiple vulnerabilities in a single program.
- Duplicate findings.
- Missing semicolons followed by security issues.
- Multiple recoverable syntax errors.
- Severely malformed source.
- Unsupported C constructs.
- Empty input.
- ML predictions on unseen examples.
- ML model-loading and inference failures.
- Flask routes and invalid requests.
- Correct report serialization.
- Suggested fixes that preserve the original source.

Compare rule-only, ML-only, and combined results using the same appropriately held-out evaluation set.

Report the evaluation unit, matching criteria, data splits, category distribution, and limitations. Do not use accuracy alone or claim perfect real-world detection.

## 13. Setup and Usage

### Requirements

- A compatible Python version.
- Flask and PLY.
- Other dependencies recorded in `requirements.txt`.
- Additional ML dependencies, such as scikit-learn, once implemented.
- Optional external compiler tools, if used by the final architecture.

### Windows PowerShell

```powershell
git clone <YOUR_GITHUB_REPOSITORY_URL>
cd SecureCompile

python -m venv venv
.\venv\Scripts\Activate.ps1

python -m pip install -r requirements.txt
python app.py
```

Open the local address shown in the terminal, normally `http://127.0.0.1:5000`.

The actual repository name and setup commands must be confirmed against the final repository.

### Existing test commands

```powershell
python src\test_all.py
python src\evaluate_dataset.py
```

Use the actual test entry points present in the repository.

After ML implementation, document the verified commands for dataset preparation, model training, evaluation, regression tests, and application startup. Training must remain separate from normal website requests.

## 14. Limitations and Responsible Claims

SecureCompile is an educational prototype, not a replacement for professional security testing.

- Parser support may be incomplete.
- Syntax recovery may fail on severely malformed source.
- Static rules can produce false positives and false negatives.
- ML models can miss vulnerabilities or incorrectly flag safe code.
- Exact source locations require supporting evidence.
- Suggested fixes must be reviewed and tested.
- Results apply only to the tested data and methodology.
- No findings does not mean that code is secure.

## 15. Future Work

- Improve standards-aware C parsing.
- Expand syntax error recovery.
- Implement ML-based multi-label vulnerability prediction.
- Improve compiler-aware data-flow analysis.
- Expand labeled vulnerability coverage.
- Improve finding correlation and localization.
- Add validated patch suggestions.
- Compare the hybrid system with established security-analysis tools.
- Evaluate on more diverse, previously unseen C code.

---

# PART B — MASTER AI IMPLEMENTATION PROMPT

**Instructions for the AI coding assistant**

The following section is a complete development specification. Copy it into the AI coding tool when you are ready to implement the planned features. Provide access to the actual repository or upload the project ZIP.

## 16. Your Role

Act as a senior software engineer, compiler engineer, machine-learning engineer, application security specialist, and UI/UX developer.

Work on my existing SecureCompile project. Do not create an unrelated demo, replace the project with a generic scanner, or rebuild the application from scratch.

Inspect the repository before editing files. Use the README as the specification, but verify all current functionality against the actual source code.

## 17. Repository Inspection

Before modifying anything:

1. Inspect the complete project structure.
2. Identify the Python version and dependencies.
3. Inspect Flask routes and request/response handling.
4. Inspect templates, stylesheets, and JavaScript.
5. Inspect lexer tokens, parser grammar, AST nodes, semantic analysis, and symbol table.
6. Inspect all security rules and source-level heuristic checks.
7. Inspect tests, evaluation scripts, and reports.
8. Identify duplicate findings, parser conflicts, broken routes, and other bugs.
9. Check Git status and uncommitted changes.
10. Run the existing tests when possible and record actual results.

Then provide a short architecture summary, confirmed issues, missing features, and an implementation plan with the files expected to change.

Do not overwrite working files without understanding their dependencies.

## 18. Stabilize the Existing Website

Preserve the existing Flask application and its visual direction.

Fix genuine bugs, broken routes, invalid responses, duplicate findings, and frontend/backend integration problems. Keep the current working functionality.

Make the website usable for source-code submission, scanning, findings inspection, filtering, explanations, and report viewing.

Use clear loading, empty, warning, success, and error states. Ensure controls perform real actions.

## 19. Implement Syntax Error Recovery

Modify the existing parser to recover from common syntax mistakes, particularly missing semicolons.

Requirements:

- Report syntax diagnostics with source locations where available.
- Continue parsing unaffected statements.
- Run source-level fallback checks against the original source when parsing fails.
- Separate syntax diagnostics from security findings.
- Preserve the original source.
- Show proposed repairs without silently applying them.
- Mark uncertain findings when parsing is incomplete.
- Test recovery against multiple errors and malformed statements.

Inspect the existing PLY parser's recovery mechanisms before changing the grammar. Do not attempt arbitrary repair with unrestricted regular expressions.

## 20. Improve C Language Support

Document the existing parser's capabilities and limitations.

Aim for broad, standards-aware C support. Evaluate whether integrating Clang as an optional or primary frontend would improve parsing, type information, diagnostics, and source locations while preserving the custom security-analysis components.

Implement and test improvements incrementally.

Do not claim complete C support until verified against appropriate conformance tests. If Clang is unavailable, document the fallback and do not claim that Clang diagnostics were produced.

## 21. Implement a Genuine ML Model

Research and select a suitable labeled C-code vulnerability dataset. Verify its source, license, labels, availability, and preprocessing requirements.

Build a reproducible multi-label classifier using a justified baseline, such as TF-IDF/code-token features with scikit-learn.

The implementation must include:

- Dataset preparation.
- Reproducible training.
- Separate training, validation, and held-out test data.
- Protection against duplicate and near-duplicate data leakage.
- Model and preprocessing serialization.
- A separate inference module.
- Category-specific predictions and validation-selected thresholds.
- Error handling for empty input and model-loading failures.
- Evaluation scripts and actual reported results.

Compare text-based features with compiler-derived features where practical.

Do not call keyword matching ML. Do not fabricate training results, performance metrics, or dataset details. If the dataset cannot be obtained, build the pipeline and document how to obtain it without claiming that training has completed.

## 22. Integrate Rule-Based and ML Analysis

Create a unified finding schema and correlation layer.

Combine findings from the parser, semantic analyzer, existing security rules, source-level checks, ML predictions, and optional external compiler diagnostics where available.

For each finding, show the category, severity, evidence, supported source location, detection engine, explanation, and uncertainty.

Include ML confidence only for ML-originated predictions.

Deduplicate only findings that represent the same underlying issue. Preserve distinct vulnerabilities and their evidence.

When the engines disagree, show the disagreement for review rather than automatically trusting the ML model.

## 23. Improve Explanations and Fix Suggestions

Explain what was detected, why it may be unsafe, what evidence supports it, and how it could be corrected.

Offer proposed fixes or before/after comparisons where appropriate.

Never silently change the original source. If AI is used to generate a patch, validate it with suitable checks and tests before describing it as verified.

## 24. Implement Website Integration

Integrate the new features into the existing Flask backend and frontend.

The website should display syntax diagnostics separately from security findings, support multiple findings, show engine provenance, provide useful filters, and present ML predictions with uncertainty.

Connect every new control to real functionality. Use measured evaluation results instead of hardcoded metrics.

Validate input, handle oversized or malformed requests, and ensure ML inference failures do not crash the application.

Do not execute potentially malicious source code during normal static analysis.

## 25. Evaluate the System Honestly

Compare three configurations on the same appropriately held-out dataset:

1. Rule-based analysis only.
2. ML-based analysis only.
3. Combined hybrid analysis.

Report per-category precision, recall, F1-score, false positives, false negatives, relevant aggregate metrics, dataset details, and data-splitting methodology.

Define how findings are matched to ground truth. Distinguish vulnerability detection from exact source localization.

Do not claim perfect accuracy or real-world performance based on a small predefined regression set.

## 26. Add Regression Tests

Preserve existing tests and add coverage for:

- Safe programs.
- Single and multiple vulnerabilities.
- Duplicate findings.
- Missing semicolons.
- Multiple syntax errors.
- Severely malformed code.
- Unsupported C constructs.
- Empty input.
- Unseen ML examples.
- Model-loading and inference failures.
- Flask routes and invalid requests.
- Correct report serialization.
- Suggested fixes that preserve original code.

Run the relevant tests after each major change and fix regressions before proceeding.

Never claim tests passed if they were not executed.

## 27. Update Dependencies and Documentation

Adapt the repository structure to the actual project. Add new modules only where justified.

Update `requirements.txt`, `README.md`, and `.gitignore`.

Keep virtual environments, secrets, Python caches, and unnecessary datasets out of Git.

Provide exact Windows PowerShell commands for setup, training, evaluation, testing, and running the website. Provide Ubuntu equivalents if useful.

Update the README after implementation so it describes actual functionality, dataset licensing, measured results, limitations, and remaining work.

## 28. Work in Verifiable Stages

Implement the project in this order:

1. Repository inspection and baseline testing.
2. Stabilize existing functionality.
3. Implement syntax error recovery and source-level fallback.
4. Prepare the dataset and train the first ML baseline.
5. Evaluate ML and compare it with rule-only analysis.
6. Integrate ML inference and finding deduplication.
7. Improve the UI, explanations, and reports.
8. Add regression tests and compare all three analysis configurations.
9. Update documentation and dependencies.
10. Perform final end-to-end verification.

Before each major stage, explain which files will change and why. After each stage, run the relevant tests, report actual results, and fix regressions before proceeding.

If an operation is blocked by missing data, dependencies, external tools, network access, or permissions, explain the limitation and provide a practical alternative.

## 29. Final Acceptance Criteria

The implementation should be considered ready for review only when:

- The existing website starts successfully.
- Existing functionality remains available.
- Syntax diagnostics and security findings are distinct.
- Common missing-semicolon cases recover where possible.
- Later statements remain analyzable after recoverable errors.
- A genuine trained multi-label ML model can be loaded and used.
- Rule findings and ML predictions are distinguishable.
- Multiple distinct vulnerabilities can be displayed in one scan.
- Duplicate findings are controlled without suppressing different risks.
- Reports preserve evidence and supported source locations.
- Rule-only, ML-only, and combined evaluation is reproducible.
- Existing and new tests have been executed and their results documented.
- The README and setup commands match the actual implementation.
- No unsupported claims or invented metrics remain.

**Begin by inspecting the existing repository, running the baseline tests, and presenting a concise implementation plan. Then implement and verify the project in stages.**

---

# Final Project Goal

SecureCompile aims to combine compiler design, syntax error recovery, static security rules, ML-assisted multi-vulnerability prediction, explainable findings, and guided remediation into one functional web application.

The goal is not merely to label code as safe or unsafe. It is to help developers understand potential risks, inspect supporting evidence, and improve their code through an explainable and measurable analysis workflow.

**The project status, supported C features, and ML performance must always reflect what has actually been implemented and tested.**
