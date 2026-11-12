"""Constants for the BMC E5/E6 integration."""
from __future__ import annotations

DOMAIN = "bmc_e6"

CONF_TARGET_NAME = "target_name"  # advertisement name: BMC_<serial number>
CONF_PROTOCOL_PEM = "protocol_pem"  # user-supplied PKCS#1 PEM (from own APK)
CONF_CLOUD_TOKENS = "cloud_tokens"  # optional cloud backup credentials
CONF_PUSH_SECRET = "push_secret"  # optional bearer token for the mini-agent push webhook

NAME_PREFIX = "BMC_"
FE60_UUID_16 = "fe60"
MANUFACTURER_ID = 682
SUPPORTED_MODELS = ("E5", "E6")

# Interval/window policy lives in coordinator.py (BLE_INTERVAL, BACKFILL_INTERVAL).
# There is no therapy-hours gate: the device only serves records on request and the
# client stays read-only, so no hour-based block is applied.

# Verified units (confirmed against the official app, 2026-11-11):
# AHI/ODI family /10, leak /10 L/min, pressure /100 cmH2O, MV /1000 L/min,
# treat/run time seconds, VT mL, RR breaths/min.
