"""Test configuration: private-target automation is explicitly enabled here."""
from km_worker.config import config

config.ALLOW_PRIVATE = True
