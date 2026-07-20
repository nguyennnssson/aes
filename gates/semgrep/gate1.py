import sys
import os
import subprocess
import json
import shutil
from pathlib import Path


def _resolve_semgrep():
    """
    Locate the semgrep executable. Semgrep is deliberately NOT installed in the
    project's main Python env — its pinned deps (click, opentelemetry) conflict
    with chromadb. It lives in an isolated venv at .tools/semgrep-venv instead.
    Resolution order: SEMGREP_BIN override → project venv → PATH.
    """
    env_bin = os.environ.get("SEMGREP_BIN")
    if env_bin and Path(env_bin).exists():
        return env_bin
    root = Path(__file__).resolve().parents[2]
    for cand in (root / ".tools" / "semgrep-venv" / "Scripts" / "semgrep.exe",
                 root / ".tools" / "semgrep-venv" / "bin" / "semgrep"):
        if cand.exists():
            return str(cand)
    return shutil.which("semgrep") or "semgrep"


def run_gate1(target_file_path):
    print(f"[GATE 1] Scanning target file: {target_file_path}")
    rules_path = "aes_rules.yaml"
    
    if not os.path.exists(rules_path):
        print(f"[ERROR] Rules file {rules_path} not found!")
        return {"passed": False, "error": "Missing rules configuration"}

    # Modify the file path to avoid recognition errors in Windows CMD.
    target_file_clean = os.path.abspath(target_file_path).replace("\\", "/")
    rules_path_clean = os.path.abspath(rules_path).replace("\\", "/")

    # Run Semgrep with forced local scan configuration.
    cmd = [_resolve_semgrep(), "--config", rules_path_clean, "--json", "--metrics=off", target_file_clean]
    print(f"[GATE 1] Running command: {' '.join(cmd)}")
    print(f"[GATE 1] cwd: {os.getcwd()}")
    print(f"[GATE 1] rules file exists: {os.path.exists(rules_path_clean)}")
    print(f"[GATE 1] target file exists: {os.path.exists(target_file_clean)}")

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    print(f"[GATE 1] semgrep exited with returncode={result.returncode}")
    print(f"[GATE 1] stdout ({len(result.stdout)} chars): {result.stdout[:300]}")
    if result.stderr:
        print(f"[GATE 1] stderr: {result.stderr[:300]}")

    try:
        output_json = json.loads(result.stdout)
        results = output_json.get("results", [])
        
        if len(results) > 0:
            print(f"[GATE 1 REJECTED] Found {len(results)} security violations!")
            failures = []
            for issue in results:
                failures.append({
                    "rule_id": issue["check_id"],
                    "line": issue["start"]["line"],
                    "message": issue["extra"]["message"]
                })
            return {"passed": False, "failures": failures}
        else:
            print("[GATE 1 PASSED] No security vulnerabilities found in the patch.")
            return {"passed": True, "failures": []}
            
    except json.JSONDecodeError:
        # In the event of a buffer error, print the raw error directly for debugging purposes.
        print("[DEBUG RAW OUTPUT]:", result.stdout, result.stderr)
        return {"passed": False, "error": "Internal scanner error or parse failure"}

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python gate1.py <file_to_scan.c>")
        sys.exit(1)
    
    scan_result = run_gate1(sys.argv[1])
    print("\n--- GATE 1 OUTPUT RESULT ---")
    print(json.dumps(scan_result, indent=4))