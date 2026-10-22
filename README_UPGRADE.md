# SecureCompile — Extended Analyzer & Learning UX

This update builds on the current SecureCompile web app and adds optional compiler diagnostics, extra conservative source checks, learning aids, a pointer/lifetime overview, rule-based fix previews, code sharing through URL fragments, and multi-file local review.

## Setup (Windows / VS Code)

1. Close the website with `Ctrl+C` in its terminal, then back up the current `SecureCompile_web` folder.
2. Extract this ZIP to a temporary folder.
3. Copy `app.py`, the **entire `src/` folder**, `static/`, `templates/`, `requirements.txt`, and this README into your existing `SecureCompile_web` folder. Allow matching files to be replaced. Keep your existing `venv/` folder and do not copy any `venv/` from elsewhere.
4. For compiler syntax/type diagnostics, install Clang and make sure `clang` is on PATH. GCC/`cc` is used as a fallback if present. If no compiler frontend is installed, SecureCompile still runs its source-level checks.
5. Start the app from the project root:

   ```powershell
   .\venv\Scripts\python.exe app.py
   ```

6. Open `http://127.0.0.1:5000` and keep the terminal running.

## Test the update

```powershell
.\venv\Scripts\python.exe src\test_extended_source.py
.\venv\Scripts\python.exe src\test_all.py
.\venv\Scripts\python.exe src\evaluate_dataset.py
```

The original test suite and evaluation files are preserved in the package. The new tests cover the extra source-level checks.

## New features

- **Compiler diagnostics:** Uses Clang, GCC, or `cc` with syntax-only flags when available. This can report C syntax/type errors beyond the custom parser's grammar. It does not run the submitted program. If no compiler is installed, the web app still performs source-level checks.
- **Additional heuristic rules:** scalar indexed as an array, free without visible allocation, direct null dereference, possible double free, possible use-after-free, possible memory leak, unmatched preprocessor conditionals, unmatched delimiters, and possible switch fall-through.
- **Educational UX:** source-line preview, jump-to-line actions, plain-language explanations, severity and confidence, and rule-based smart-fix attempts for a few highly recognizable patterns.
- **Memory & pointer map:** approximate view inferred from declarations and visible allocation/free calls. It is not a runtime stack/heap simulation.
- **Code sharing:** copies source in a URL fragment for sharing. The source is not saved to a server database by this feature. Share links work only where the same web app is accessible; a localhost link generally only works on the same computer.
- **Multi-file review:** select multiple `.c` files and view an in-browser summary. This is not a persistent teacher dashboard or multi-user database.
- **JSON reports:** now include compiler diagnostic and memory-summary metadata.

## Important limitations

No custom static analyzer can promise to understand or detect every possible C program. Clang diagnostics improve syntax and type coverage, but SecureCompile's security checks remain conservative source heuristics and may produce false positives or miss issues involving macros, complex control flow, pointer aliases, interprocedural behavior, compiler extensions, or conditional compilation. A clean report is not proof of safety. Review every finding and validate results before presenting evaluation metrics.

The Smart Fix controls are rule-based suggestions, not an integrated AI model. They only apply a small edit for a few recognizable patterns and ask for confirmation; other issues require a manual fix. The pointer map is illustrative, not a debugger or execution simulator.

## Security note

The Flask development server binds to `127.0.0.1`. Do not expose it to a public network without adding appropriate production security controls. Compiler checking runs syntax-only and never executes the submitted program.
