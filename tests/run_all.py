"""Run every offline test suite: python -m tests.run_all"""
import subprocess, sys
MODS = ["test_core", "test_stage4", "test_stage5", "test_report", "test_viewer", "test_freetext", "test_app_smoke"]
ok = True
for m in MODS:
    r = subprocess.run([sys.executable, "-m", f"tests.{m}"], capture_output=True, text=True)
    print(("PASS " if r.returncode == 0 else "FAIL ") + m)
    if r.returncode: ok = False; print(r.stdout[-1200:], r.stderr[-1200:])
sys.exit(0 if ok else 1)
