import os
import sys
import tempfile

CURRENT_DIR = os.path.dirname(__file__)
SERVICE_ROOT = os.path.abspath(os.path.join(CURRENT_DIR, os.pardir))
if SERVICE_ROOT not in sys.path:
    sys.path.insert(0, SERVICE_ROOT)
SOURCE_ROOT = os.path.join(SERVICE_ROOT, "src")
if SOURCE_ROOT not in sys.path:
    sys.path.insert(0, SOURCE_ROOT)

_TEST_STATE = tempfile.mkdtemp(prefix="unison-auth-tests-")
os.environ.setdefault("UNISON_AUTH_KEYS_DIR", os.path.join(_TEST_STATE, "keys"))
os.environ.setdefault("UNISON_AUTH_IDENTITY_DATABASE_PATH", os.path.join(_TEST_STATE, "identity.db"))
