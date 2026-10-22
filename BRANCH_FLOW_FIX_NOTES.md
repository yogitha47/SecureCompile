# SecureCompile branch-flow fix

## What changed
- Added `else_body` to the `IfStatement` AST node.
- Updated the parser to recognize `if (...) { ... } else { ... }`.
- Updated `SecurityAnalyzer` to analyze both possible paths for unknown conditions and merge definite initialization using the intersection of branch states.
- Added constant truth evaluation for numeric conditions and identifiers with known constant values.
- Added `src/test_control_flow.py` with four targeted regression tests.
- Changed the evaluation script's module docstring to a raw string to remove the Windows-path SyntaxWarning.

## Install
Back up your current `SecureCompile_web` folder first. Extract this ZIP into a separate folder and compare it before copying the changed files into your working project.

Changed files:
- `src/ast_nodes.py`
- `src/parser.py`
- `src/security_analyzer.py`
- `src/evaluate_dataset.py`
- `src/test_control_flow.py` (new)

## Run tests on Windows PowerShell
From the project root, with the project's existing virtual environment:

```powershell
.\venv\Scripts\python.exe src\test_control_flow.py
.\venv\Scripts\python.exe src\test_all.py
.\venv\Scripts\python.exe src\evaluate_dataset.py
```

Keep your local Flask server stopped while copying files, then restart it with:

```powershell
.\venv\Scripts\python.exe app.py
```

## Interpretation
The branch tests use an uninitialized `condition` so it is unknown to this restricted analyzer. That variable itself may correctly trigger `SC-DATA-001`; the test specifically checks whether `x` is or is not reported depending on whether every possible branch initializes it.

This is an academic static-analysis prototype for a restricted C subset. Review findings and parser limitations; passing these tests does not prove all C code is safe.
