"""Run the SBOM Analyzer from the repository root with ``py app.py``."""

import os
import runpy
import sys
from pathlib import Path


APP_DIR = Path(__file__).resolve().parent / "sbom-scanner"
os.chdir(APP_DIR)
sys.path.insert(0, str(APP_DIR))
runpy.run_path(str(APP_DIR / "app.py"), run_name="__main__")
