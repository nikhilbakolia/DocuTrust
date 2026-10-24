"""Make the backend/ folder importable (backend uses flat imports like `import models`)."""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
