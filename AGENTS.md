# AGENTS.md

Security warning: this toolkit is for authorized/ethical testing only. Many modules
open sockets, send packets, or crack hashes. Do not aim it at systems you lack
written permission to test.

## Running
- Recommended UI: `python3 ui.py` — a working terminal UI that discovers every
  `BaseModule` under `modules/` dynamically and runs it. Use this instead of the
  `main.py` menu (see Known breakage below).
- Legacy entrypoint: `python3 main.py --ui` now delegates to `ui.py`; plain
  `python3 main.py` renders the original broken rich menu (do not rely on it).
- No package/venv, no `pyproject.toml`. Install deps with `pip install -r requirements.txt`.
  The interpreter is `python3` (no `python` on PATH here).
- `main.py`/`ui.py` import `rich`/`pyfiglet`; if missing, `main.py` auto-runs
  `pip install rich pyfiglet` at import. Don't trust a missing-import traceback there.
- Web UI: `python3 app.py` starts a FastAPI server at http://127.0.0.1:8000
  (serves `static/index.html`, exposes `/api/modules` and `/api/run`). Requires
  `fastapi` + `uvicorn` (optional deps in requirements.txt). Modules run in a
  thread pool and results save to `output/`. Bind to localhost only.

## Architecture
- `config/settings.py` defines `config` (singleton `ToolkitConfig`). Import it directly;
  API keys come from env vars `SHODAN_API_KEY`, `VIRUSTOTAL_API_KEY`, `HUNTER_API_KEY`.
- Every module subclasses `core/base_module.BaseModule` and implements `run(target, **kwargs)`.
  `BaseModule.execute()` wraps `run()` with authorization + logging.
- Logging: `core/logger.py` writes per-run logs to `logs/<ModuleName>_<timestamp>.log`
  and results to `output/`.
- Modules live under `modules/<category>/` (recon, vuln_scanner, network, mobile,
  malware_analysis, forensics, defensive, password, reporting, exploitation,
  reverse_engineering). Each category needs an `__init__.py`.

## Known breakage (verify before relying on it)
- `main.py:206-230` calls `_execute_module(choice)` and reads `MODULE_CONFIG`, but
  neither is defined anywhere in the repo. The menu cannot actually launch modules —
  the module registry/dispatch layer is missing. Don't assume module selection works.
  Use `ui.py` instead, which discovers modules dynamically and is the working entrypoint.

## Module inventory mismatch
- `folder-structure.txt` lists many module files that do NOT exist (e.g. most of
  `exploitation/`, `reverse_engineering/`, and many listed files under other
  categories are absent — only `init.py`). Trust the actual `modules/` tree, not that file.

## Conventions
- `requirements.txt` pins substitutes that differ from common names:
  `python-magic` (not `magic`), `pySSDeep` (not `ssdeep`). Import accordingly.
- `config.SCOPE_ENFORCEMENT` is `True` by default; `BaseModule.check_authorization`
  prompts the user for out-of-scope targets. Keep scope checks in place.
- No CI, lint, formatter, or typecheck config exists. There is no enforced code style
  beyond PEP 8; verify changes by running the relevant module/test script manually.
