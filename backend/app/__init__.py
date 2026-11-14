import os

# Ensure pure-python SQLAlchemy mode to avoid Windows AppLocker blocks on dynamic C-extensions
os.environ.setdefault("DISABLE_SQLALCHEMY_CEXT", "1")

