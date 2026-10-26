"""Config loading & strict §8 validation (fail-closed)."""

from sentinel.config.loader import ConfigError, load_config, validate_config

__all__ = ["ConfigError", "load_config", "validate_config"]
