# Financial Web Security Scanner — Starter

This starter scanner is for an authorised local lab such as OWASP Juice Shop.

## Features
- Same-origin page discovery
- Link, form, input-point and API-candidate discovery
- Basic HTTP security-header checks
- Observable cookie attribute checks
- JSON reporting
- Localhost-only target restriction
- GET requests only; forms are not submitted and exploit payloads are not sent

## Setup (Windows PowerShell)

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

If PowerShell blocks activation, you can use the virtual environment's Python directly:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

## Run against local Juice Shop

Make sure Juice Shop is running at `http://localhost:3000`, then run:

```powershell
python scanner.py --target http://localhost:3000 --max-pages 20 --output report.json
```

## Report
The generated `report.json` contains pages, forms, links, input points, API candidates, cookie observations, findings, errors, and a summary.

## Limitations
- This is a foundation, not a complete OWASP Top 10 scanner.
- It does not submit forms, authenticate, exploit vulnerabilities, or prove business-logic flaws.
- Missing headers and cookie attributes are indicators and require manual verification.
- Only localhost targets are accepted in this version.
