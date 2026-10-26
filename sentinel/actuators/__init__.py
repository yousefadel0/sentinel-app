"""Actuator adapters (ABC #2, §4). Each consumes the shared §3.1 Validator."""
from sentinel.actuators.nftables_local import NftablesLocalActuator
from sentinel.actuators.webhook_soar import WebhookSoarActuator

__all__ = ["NftablesLocalActuator", "WebhookSoarActuator"]
