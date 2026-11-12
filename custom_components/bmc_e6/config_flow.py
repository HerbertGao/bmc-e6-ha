"""Config flow: BLE discovery (E5/E6) + credentials for the BMC ventilator."""
from __future__ import annotations

import base64
import re

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.components.bluetooth import BluetoothServiceInfoBleak
from homeassistant.helpers.selector import TextSelector, TextSelectorConfig, TextSelectorType

from .const import (
    CONF_CLOUD_TOKENS,
    CONF_PROTOCOL_PEM,
    CONF_PUSH_SECRET,
    CONF_TARGET_NAME,
    DOMAIN,
    NAME_PREFIX,
)
from .bmc_ble import auth_frames as af
from .bmc_ble.client import is_supported_advertisement, model_from_name

# The name reaches filesystem paths and store keys, so keep it to what a serial can
# actually be: a crafted advertisement must not be able to break setup.
_NAME_RE = re.compile(r"^BMC_E[56][A-Za-z0-9]{1,32}$")


def _valid_target_name(name: str) -> bool:
    return bool(_NAME_RE.match(name)) and model_from_name(name) is not None


class BmcE6ConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Discovery picks the ventilator; user supplies the protocol key once."""

    VERSION = 1

    def __init__(self) -> None:
        self.target_name: str | None = None
        self._pem: str | None = None

    async def async_step_bluetooth(self, discovery_info: BluetoothServiceInfoBleak):
        name = discovery_info.name or ""
        if not _valid_target_name(name) or not is_supported_advertisement(
            name, discovery_info.service_uuids, discovery_info.manufacturer_data
        ):
            return self.async_abort(reason="not_supported")
        await self.async_set_unique_id(name)
        self._abort_if_unique_id_configured()
        self.target_name = name
        return await self.async_step_credentials()

    async def async_step_user(self, user_input=None):
        """Manual setup when discovery is unavailable (weak signal / proxy)."""
        errors = {}
        if user_input is not None:
            name = (user_input.get(CONF_TARGET_NAME) or "").strip()
            if not name.startswith(NAME_PREFIX) or not _valid_target_name(name):
                errors[CONF_TARGET_NAME] = "invalid_name"
            else:
                await self.async_set_unique_id(name)
                self._abort_if_unique_id_configured()
                self.target_name = name
                return await self.async_step_credentials()
        schema = vol.Schema({
            vol.Required(CONF_TARGET_NAME): str,
        })
        return self.async_show_form(step_id="user", data_schema=schema, errors=errors,
                                    description_placeholders={
                                        "hint": "Advertisement name BMC_<serial>, e.g. BMC_E6xxxxxxxx (E5/E6 only)."
                                    })

    async def async_step_credentials(self, user_input=None):
        """Protocol RSA key stays local; it is never bundled with the integration."""
        errors = {}
        if user_input is not None:
            encoded = (user_input.get(CONF_PROTOCOL_PEM) or "").strip()
            try:
                # Single-line Base64 keeps the PASSWORD mask effective (HA
                # ignores PASSWORD on multiline textareas). Decoded for storage.
                pem_bytes = base64.b64decode(encoded, validate=True)
                n, _e, _d = af.parse_pkcs1_private_pem(pem_bytes)
                if n.bit_length() != 1024:
                    raise ValueError("not an RSA-1024 key")
                pem = pem_bytes.decode("ascii")
            except Exception:
                errors[CONF_PROTOCOL_PEM] = "invalid_pem"  # parsed at config time, never logged
            if not errors:
                self._pem = pem
                return await self.async_step_cloud()
        schema = vol.Schema({
            vol.Required(CONF_PROTOCOL_PEM): TextSelector(
                TextSelectorConfig(type=TextSelectorType.PASSWORD)
            ),
        })
        return self.async_show_form(step_id="credentials", data_schema=schema, errors=errors,
                                    description_placeholders={
                                        "hint": "Base64-encoded PKCS#1 PEM (single line, see tools/ to encode)."
                                    })

    async def async_step_cloud(self, user_input=None):
        """Optional cloud backup credentials (all fields empty = BLE only)."""
        errors = {}
        if user_input is not None:
            tokens = {}
            for key in ("access_token", "refresh_token", "serial", "terminal_id", "base_url"):
                value = (user_input.get(key) or "").strip()
                if value:
                    tokens[key] = value
            if tokens and len(tokens) < 5:
                errors["base"] = "cloud_incomplete"
            else:
                data = {CONF_TARGET_NAME: self.target_name, CONF_PROTOCOL_PEM: self._pem}
                if tokens:
                    data[CONF_CLOUD_TOKENS] = tokens
                secret = (user_input.get(CONF_PUSH_SECRET) or "").strip()
                if secret:
                    # Turns on the mini-agent push webhook for this entry.
                    data[CONF_PUSH_SECRET] = secret
                return self.async_create_entry(title=self.target_name or "BMC ventilator", data=data)
        schema = vol.Schema({
            vol.Optional("access_token"): TextSelector(TextSelectorConfig(type=TextSelectorType.PASSWORD)),
            vol.Optional("refresh_token"): TextSelector(TextSelectorConfig(type=TextSelectorType.PASSWORD)),
            vol.Optional("serial"): str,
            vol.Optional("terminal_id"): str,
            vol.Optional("base_url"): str,
            vol.Optional(CONF_PUSH_SECRET): TextSelector(
                TextSelectorConfig(type=TextSelectorType.PASSWORD)
            ),
        })
        return self.async_show_form(step_id="cloud", data_schema=schema, errors=errors,
                                    description_placeholders={
                                        "hint": "Optional Remot cloud backup: all five fields, or leave all empty for BLE only. "
                                                "Optional push secret turns on the mini-agent webhook."
                                    })
