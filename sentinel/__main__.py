"""Enable `python -m sentinel` — delegates to the CLI entry point."""

from sentinel.cli import main

raise SystemExit(main())
