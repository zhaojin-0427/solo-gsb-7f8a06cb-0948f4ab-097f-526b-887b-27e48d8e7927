import os
import sys
from pathlib import Path

# Make the project root importable and provide a default secret so that
# importing app.main never fails; individual tests override the env.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("WEBHOOK_SECRET", "test-secret")
