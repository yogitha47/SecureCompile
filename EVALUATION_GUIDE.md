# SecureCompile evaluation dataset

## Run it on Windows

Open the SecureCompile project folder in VS Code, then run this in PowerShell from the project root:

```powershell
.\venv\Scripts\python.exe src\evaluate_dataset.py
```

The script reads `evaluation/manifest.json` and the snippets in `evaluation/cases/`. It writes:

- `reports/evaluation_report.json`
- `reports/evaluation_results.csv`

## Dataset contents

There are 12 hand-labelled vulnerable snippets and 8 safe snippets. They cover only rules and syntax currently implemented in SecureCompile. Several snippets are intentionally small restricted-C fragments rather than complete compilable C programs.

## Interpreting the results

- **TP/FN** are computed over labelled vulnerable snippets using whether any finding was produced.
- **FP/TN** are computed over labelled safe snippets using whether any finding was produced.
- The per-case `expected_rule_detected` column separately checks the expected rule ID (or no findings for a safe case). Review `CHECK` cases and parse errors.
- Precision, recall, specificity and accuracy are preliminary case-level metrics for this small hand-labelled dataset. They are not a general security-coverage claim.

## Important scope note

SecureCompile supports a restricted C subset, not all of C. A result with no findings means only that no implemented rule matched the analyzed snippet. It is not a guarantee of security. The current analyzer uses simplified state tracking, so findings should be reviewed and validated.
