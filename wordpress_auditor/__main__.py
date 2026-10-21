"""Allow python -m wordpress_auditor without a separate console script."""
from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
