# SecureCompile Intelligence
### Compiler-Based Static Security Analysis with Syntax Error Recovery and ML-Assisted Vulnerability Detection

SecureCompile is an educational software-security project that analyzes C source code using compiler-design techniques and static security analysis. The project aims to evolve into a hybrid analysis platform that combines deterministic security rules, compiler-derived information, machine learning, and syntax error recovery.

The goal is to help developers identify multiple potential vulnerabilities in one scan, understand why code may be unsafe, and receive useful guidance for correcting it—even when the submitted source contains common syntax mistakes.

> **Development status:** The existing project includes a Flask web application, a custom PLY-based lexer and parser, AST structures, semantic and security analysis components, source-level heuristic checks, and test/evaluation scripts. ML-assisted detection, robust parser error recovery, advanced data-flow analysis, and guided remediation must be treated as planned work until implemented and verified.

---

## 1. Project Vision

SecureCompile is intended to go beyond a simple syntax checker or a security scanner that only displays a list of warnings.

The proposed system combines:

1. Compiler-based source-code processing.
2. Recovery from common syntax errors.
3. Rule-based vulnerability detection.
4. ML-assisted multi-label vulnerability prediction.
5. Compiler-aware evidence and source-location mapping.
6. Duplicate finding detection and result correlation.
7. Explainable findings and suggested corrections.
8. Transparent evaluation of detection quality.

The intended contribution is the integration and evaluation of these components in a single educational C-code analysis workflow. The project must not claim to be the first or only tool with these capabilities without supporting research.

## 2. Problem Statement

Developers may introduce security vulnerabilities and ordinary programming errors into C programs. Traditional parsing can also fail when source code contains syntax mistakes, potentially preventing later statements from being analyzed.

A useful educational analysis tool should attempt to recover from common syntax errors, continue analyzing unaffected portions of the source, identify multiple supported vulnerability categories, and clearly distinguish confirmed rule matches from uncertain ML predictions.

SecureCompile aims to address these challenges using a hybrid architecture that combines compiler analysis, security rules, and machine learning.

## 3. Objectives

- Analyze supported C source code through a compiler-inspired pipeline.
- Identify multiple potential security issues in a single scan.
- Recover from common syntax mistakes, including missing semicolons, where safe recovery is possible.
- Continue analyzing valid statements after a recoverable syntax error.
- Detect selected vulnerability patterns through deterministic rules.
- Train and evaluate an ML model that predicts multiple vulnerability categories.
- Combine findings from different analysis engines without hiding distinct issues.
- Explain findings with evidence, source locations, severity, and suggested fixes where supported.
- Provide a usable web interface for code submission and result inspection.
- Evaluate the system using held-out test examples and report limitations honestly.

## 4. Existing Architecture

The existing project contains a Python/Flask application and a custom compiler-inspired analysis pipeline.

```text
C Source Code
     |
     v
Lexical Analysis (PLY)
     |
     v
Parsing (PLY)
     |
     v
Abstract Syntax Tree (AST)
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

The actual supported grammar and analysis capabilities must be verified against the current source files.

### Existing project components

- `app.py` — Flask application and request handling.
- `src/lexer.py` — lexical analysis.
- `src/parser.py` — parsing and AST construction.
- `src/ast_nodes.py` — AST node definitions.
- `src/semantic.py` — semantic analysis.
- `src/symbol_table.py` — symbol-table functionality.
- `src/security_analyzer.py` — rule-based security checks.
- `src/source_analyzer.py` — supplementary source-level heuristic checks.
- `src/test_all.py` — regression and test-suite entry point, if present.
- `src/evaluate_dataset.py` — predefined dataset evaluation, if present.
- `templates/` — Flask HTML templates.
- `static/` — CSS, JavaScript, and static assets.
- `reports/` — generated analysis or evaluation reports, depending on current configuration.

Before making changes, inspect the actual repository. Do not assume every listed file or feature is present in the same form.

## 5. Planned Architecture

The target architecture is a hybrid analysis pipeline.

```text
                 C Source Code
                       |
             Source and Syntax Checks
                       |
             Lexer and Error Recovery
                       |
                Parser and AST
                       |
             Semantic/Symbol Analysis
                       |
          +------------+------------+
          |                         |
          v                         v
    Rule-Based Engine          ML Prediction Engine
          |                         |
          v                         v
    Rule Findings             ML Predictions
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

The source-level fallback must also be able to run when parsing fails. A parse failure must not automatically suppress every possible security finding from the original source.

The system must record which engine produced each finding and whether the result is a deterministic rule match, a semantic/data-flow result, or an ML prediction.

---

## 6. Feature Requirements

### 6.1 Multi-Vulnerability Detection

The system should identify multiple supported vulnerability categories in one program, rather than stopping after the first finding.

Potential categories include:

- Division by zero.
- Modulo by zero.
- Uninitialized variables.
- Unsafe input functions, such as `gets`.
- Potential buffer overflows.
- Unsafe string operations, including risky `strcpy` and `strcat` usage.
- Potential format-string vulnerabilities, such as unsafe use of `printf`.
- Suspicious command execution through functions such as `system`.
- Other categories only after their detection logic has been implemented and evaluated.

The presence of a function name alone does not always prove a vulnerability. Findings must consider available context and provide evidence appropriate to the detection method.

### 6.2 Syntax Error Recovery

The website should attempt to analyze code that contains common syntax mistakes.

Examples include:

- Missing semicolons.
- Recoverable malformed statements.
- Some incomplete expressions or declarations.

Expected behavior:

1. Identify the syntax error and its approximate location.
2. Attempt safe parser recovery.
3. Continue analyzing subsequent valid statements.
4. Run supported source-level checks against the original source even if parsing remains incomplete.
5. Return both syntax diagnostics and security findings.
6. Clearly identify which findings could not be verified because parsing failed.

Do not silently modify the user's original source code. If a semicolon insertion or another repair is suggested, show it as a proposed repair and retain the original source.

Use PLY's supported error-recovery mechanisms and test recovery against real examples. Do not attempt to repair arbitrary malformed code using unrestricted regular expressions.

### 6.3 ML-Assisted Multi-Label Vulnerability Detection

Implement a genuine, trained machine-learning model.

The model should predict multiple vulnerability categories rather than only returning a single program-level `safe` or `vulnerable` label.

Requirements:

- Select and document a suitable labeled C-code dataset.
- Inspect its licensing, labels, source format, and duplicate examples.
- Build reproducible preprocessing and training scripts.
- Begin with a simple baseline model, such as TF-IDF or code-token features with a multi-label scikit-learn classifier.
- Compare the baseline with compiler-derived features where practical.
- Keep training and evaluation data separate.
- Prevent duplicate or near-duplicate examples from leaking across training and test sets.
- Save the trained model and its preprocessing pipeline.
- Load the model once where appropriate, rather than retraining on every website request.
- Validate input, handle empty or malformed code, and handle model-loading errors.
- Use category-specific thresholds selected on validation data.
- Report the model's predictions separately from deterministic rule findings.
- Measure per-category precision, recall, F1-score, support, and relevant aggregate metrics.
- Evaluate on a held-out test set that is not used to train or tune the model.
- Report false positives and false negatives.
- Compare rule-only, ML-only, and combined-system performance.

A baseline using TF-IDF and scikit-learn is the recommended starting point because it is relatively lightweight. More advanced models should be considered only if they provide measurable benefits.

ML confidence is not proof of a vulnerability. An ML prediction must be labeled as a prediction, and the system must not claim that code is secure merely because the model produces no finding.

### 6.4 Compiler-Aware Features

Where supported by the existing parser, explore features such as:

- Function calls and their arguments.
- Variable declarations and initialization.
- Arithmetic and logical expressions.
- Array declarations and indexing.
- Assignment relationships.
- AST structure.
- Selected source-to-sink data-flow patterns.

Use these features to complement source-text features. Do not claim complete data-flow or control-flow analysis unless it has actually been implemented and tested.

### 6.5 Finding Correlation and Deduplication

The current project can produce duplicate findings when rule-based and heuristic checks flag the same issue.

Create a unified finding representation containing fields such as:

- Finding ID.
- Rule or vulnerability category.
- Source file and line/column, when available.
- Severity.
- Detection engine.
- Evidence or relevant code snippet.
- Explanation.
- Suggested correction, when supported.
- ML confidence, for ML-originated predictions only.
- Verification status or uncertainty.

Merge duplicate findings only when they refer to the same underlying issue. Preserve separate findings when they represent distinct risks, even if they occur on the same line.

Do not invent exact line locations when only approximate source-level evidence is available.

### 6.6 Explainable Findings and Fix Suggestions

For each finding, display:

- What was detected.
- Why the code may be unsafe.
- The relevant source location.
- Evidence supporting the finding.
- The engine that produced it.
- A practical correction or safer alternative where possible.
- Any uncertainty or assumptions.

If an AI service is used to generate explanations or code patches, treat its output as a suggestion that must be validated. Do not label a patch as verified merely because it was generated.

### 6.7 Website Experience

Preserve the existing Flask website and improve it incrementally.

The intended user experience includes:

1. A source-code editor or submission area.
2. A clear scan/analyze action.
3. Syntax diagnostics separated from security findings.
4. A summary of findings by category and severity.
5. A code view with source locations where available.
6. Filters for severity, category, and detection engine.
7. An explanation and remediation panel.
8. An explicit distinction between rule-based findings and ML predictions.
9. A proposed fix or before/after comparison, where implemented.
10. A rescan action to compare results after edits.
11. An evaluation page showing measured model performance, dataset details, and limitations.

Do not replace the working website with a static mockup. Every displayed metric and action must be connected to actual functionality or clearly labeled as a demonstration.

---

## 7. Implementation Instructions for OpenAI

When modifying this repository, follow these instructions in order.

### Step 1: Inspect Before Editing

- Inspect the complete project structure and relevant Python, HTML, CSS, JavaScript, and test files.
- Review the current Git state.
- Run the existing application and tests if possible.
- Identify current bugs, parser conflicts, duplicate findings, missing dependencies, and broken routes.
- Distinguish verified existing behavior from planned functionality.
- Do not replace working files before understanding their dependencies.

### Step 2: Establish a Working Baseline

- Confirm the Flask application starts.
- Confirm the existing lexer, parser, semantic checks, and security analyzer work on supported inputs.
- Run the existing test suite and evaluation script.
- Record the baseline outputs.
- Add regression tests for any bugs fixed during implementation.

### Step 3: Improve Error Recovery

- Implement recoverable syntax diagnostics in the existing PLY parser.
- Preserve line and column information.
- Test missing semicolons, multiple syntax errors, incomplete statements, and valid statements after errors.
- Run supplementary source-level checks when parsing fails.
- Keep syntax diagnostics separate from security findings.
- Verify that recovery does not introduce false AST nodes or hide later statements.

### Step 4: Implement and Evaluate ML

- Select a suitable labeled C vulnerability dataset and document the source and license.
- Create separate preprocessing, training, evaluation, and inference modules.
- Train a multi-label baseline model.
- Keep training data separate from validation and held-out test data.
- Add reproducible random seeds and record the model configuration.
- Save the model and preprocessing pipeline as versioned artifacts.
- Add tests for model loading, malformed input, predictions, and multiple vulnerability categories.
- Compare ML-only results with the existing rule-only system.
- Do not use the held-out test set to tune the model repeatedly.

### Step 5: Integrate Both Engines

- Use a shared finding schema.
- Merge findings from the parser, semantic analyzer, security rules, source-level checks, and ML model.
- Deduplicate overlapping findings while retaining distinct vulnerabilities.
- Preserve source locations and evidence.
- Show the detection engine and uncertainty for every result.
- Prevent ML errors from crashing the Flask application.

### Step 6: Improve the Website

- Keep the existing application structure unless a change is justified.
- Improve the interface for syntax errors, multiple findings, model predictions, explanations, and suggested fixes.
- Connect each control to actual backend functionality.
- Display measured evaluation metrics rather than hardcoded performance claims.
- Keep the original source code available when showing suggested repairs.

### Step 7: Verify the Entire Project

Test at least:

1. Valid safe C code.
2. Code with one known vulnerability.
3. Code with several different vulnerabilities.
4. Code with duplicate potential findings.
5. Code with a missing semicolon followed by a recognizable vulnerability.
6. Code containing multiple syntax mistakes.
7. Empty input.
8. Unsupported C syntax.
9. Code with no ML predictions.
10. Model-loading or inference failure.

Run the existing tests and all newly added tests. Check the website manually and inspect the final Git diff.

### Step 8: Document the Real Result

Update this README only after features are implemented.

Document:

- Implemented features.
- Installation and run instructions.
- Dataset name, source, license, and preprocessing.
- Training and evaluation commands.
- Actual test results and ML metrics.
- Known limitations.
- Remaining work.

Never claim 100% real-world accuracy, complete C-language support, guaranteed vulnerability detection, or worldwide uniqueness without evidence.

---

## 8. Suggested Repository Structure

Adapt this layout to the current project rather than blindly moving existing files.

```text
SecureCompile_web/
├── app.py
├── requirements.txt
├── README.md
├── .gitignore
├── src/
│   ├── lexer.py
│   ├── parser.py
│   ├── ast_nodes.py
│   ├── semantic.py
│   ├── symbol_table.py
│   ├── security_analyzer.py
│   ├── source_analyzer.py
│   ├── finding_schema.py
│   ├── finding_merger.py
│   ├── ml/
│   │   ├── preprocess.py
│   │   ├── train.py
│   │   ├── evaluate.py
│   │   └── predictor.py
│   └── tests/
├── data/
│   └── README.md
├── models/
│   └── README.md
├── templates/
├── static/
└── reports/
```

The `src/ml/`, `data/`, and `models/` directories are proposed additions. Avoid committing large datasets, private data, or model artifacts without checking repository size and licensing.

---

## 9. Installation and Usage

### Requirements

- Python version compatible with the existing project dependencies.
- Flask.
- PLY.
- Other dependencies recorded in `requirements.txt`.
- Additional ML dependencies, such as scikit-learn, after the ML implementation is added.

### Windows Setup

```powershell
git clone <YOUR_GITHUB_REPOSITORY_URL>
cd SecureCompile_web

python -m venv venv
.\venv\Scripts\Activate.ps1

python -m pip install -r requirements.txt
python app.py
```

Open the local address shown in the terminal, normally:

`http://127.0.0.1:5000`

### Existing Tests

Run the commands supported by the current repository:

```powershell
python src\test_all.py
python src\evaluate_dataset.py
```

If a script is not present or its command differs, inspect the repository and use the actual test entry point.

### Planned ML Workflow

Once implemented, document the exact commands for:

```text
Prepare the labeled dataset
        |
        v
Train the model
        |
        v
Evaluate on held-out data
        |
        v
Load the saved model in Flask
        |
        v
Run hybrid security analysis
```

Training should not happen on every website request. The website should use a saved, previously trained model.

---

## 10. Evaluation Plan

Evaluate the project at three levels.

### A. Syntax Error Recovery

Measure:

- Number of syntax errors correctly reported.
- Whether analysis continues after recoverable errors.
- Whether later findings are preserved.
- Whether recovery creates incorrect diagnostics or findings.

### B. Vulnerability Detection

Report:

- True positives.
- False positives.
- True negatives.
- False negatives.
- Per-category precision, recall, and F1-score.
- Macro and micro F1-score for multi-label evaluation, where appropriate.
- Dataset size, category distribution, and test-split methodology.

### C. System Comparison

Compare:

1. Rule-based engine only.
2. ML engine only.
3. Combined rule-based and ML system.

Use the same held-out evaluation set for a fair comparison. Explain differences in coverage and error types instead of reporting only accuracy.

A small predefined dataset can be useful for regression testing, but it is not sufficient to establish real-world performance.

---

## 11. Limitations and Responsible Claims

SecureCompile is an educational prototype, not a replacement for professional security testing.

- The parser supports a restricted subset of C unless broader compatibility is demonstrated.
- Syntax recovery can fail on severely malformed source.
- Heuristic checks may produce false positives and false negatives.
- ML models can miss vulnerabilities or incorrectly flag safe code.
- Exact source locations require sufficient supporting evidence.
- Suggested fixes must be reviewed and tested.
- Evaluation scores apply only to the tested data and methodology.
- No system can guarantee that code with no reported findings is secure.

The project should report uncertainty clearly and avoid treating the absence of findings as proof of safety.

---

## 12. Future Work

- Expand the supported C grammar and parser recovery.
- Improve compiler-aware data-flow analysis.
- Expand labeled vulnerability coverage.
- Evaluate additional ML models.
- Improve finding correlation and source-location precision.
- Add validated patch suggestions.
- Evaluate on more diverse, previously unseen C code.
- Compare against established static-analysis tools using a fair methodology.

## 13. Project Summary

SecureCompile aims to combine compiler design, static security analysis, syntax error recovery, and ML-assisted multi-vulnerability prediction into a single web application.

The central goal is not simply to display warnings, but to help users understand potential security issues, inspect supporting evidence, and improve their code through an explainable and measurable workflow.

**Project status must always reflect the functionality that has actually been implemented and tested.**
