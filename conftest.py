"""Pin the project root on sys.path so ``import evidence_seal`` works in tests."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
