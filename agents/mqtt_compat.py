"""
AES — paho-mqtt version compatibility
=====================================
Owner: Son Nguyen (AI Infra)

paho-mqtt 2.x made the callback API version a required first argument to
mqtt.Client() and renamed/re-signed the callbacks. Every AES component uses the
v1 callback signatures (on_connect(client, userdata, flags, rc), etc.), so this
helper constructs a client that works on BOTH paho 1.x and 2.x without touching
any callback code.

Use this instead of calling mqtt.Client(...) directly:

    from agents.mqtt_compat import make_mqtt_client
    client = make_mqtt_client("aes-monitor-agent")
"""

import os
import ssl
import warnings
from pathlib import Path

import paho.mqtt.client as mqtt


class MQTTConfigurationError(RuntimeError):
    """MQTT authentication/TLS is missing in secure mode."""


def make_mqtt_client(client_id: str = "") -> mqtt.Client:
    """Return an mqtt.Client with v1 callback signatures on paho 1.x or 2.x."""
    if hasattr(mqtt, "CallbackAPIVersion"):        # paho-mqtt >= 2.0
        with warnings.catch_warnings():
            # VERSION1 is deprecated upstream but intentional here: it keeps the
            # v1 callback signatures working across both major versions.
            warnings.simplefilter("ignore", DeprecationWarning)
            return mqtt.Client(mqtt.CallbackAPIVersion.VERSION1, client_id=client_id)
    return mqtt.Client(client_id=client_id)        # paho-mqtt 1.x


def configure_mqtt_client(client: mqtt.Client, role: str = "client") -> mqtt.Client:
    """Apply TLS and per-role credentials to an MQTT client.

    Secure mode is the default. Local plaintext/anonymous brokers require the
    explicit AES_INSECURE_DEV_MQTT=1 opt-in and must never be used on a routed
    network. Role-specific variables (for example MQTT_MONITOR_USERNAME) take
    precedence over MQTT_USERNAME.
    """
    if os.getenv("AES_INSECURE_DEV_MQTT") == "1":
        warnings.warn(
            "AES_INSECURE_DEV_MQTT=1 disables broker authentication and TLS; development only",
            RuntimeWarning,
            stacklevel=2,
        )
        return client

    prefix = f"MQTT_{role.upper()}_"
    username = os.getenv(prefix + "USERNAME") or os.getenv("MQTT_USERNAME")
    password = os.getenv(prefix + "PASSWORD") or os.getenv("MQTT_PASSWORD")
    ca_path = os.getenv("MQTT_CA_CERT")
    missing = [
        name for name, value in (
            (prefix + "USERNAME", username),
            (prefix + "PASSWORD", password),
            ("MQTT_CA_CERT", ca_path),
        ) if not value
    ]
    if missing:
        raise MQTTConfigurationError(
            "secure MQTT requires credentials and a CA certificate; missing " + ", ".join(missing)
        )
    if len(password) < 16:
        raise MQTTConfigurationError("secure MQTT passwords must contain at least 16 characters")
    ca = Path(ca_path).expanduser().resolve()
    if not ca.is_file():
        raise MQTTConfigurationError(f"MQTT_CA_CERT does not exist: {ca}")

    client.username_pw_set(username, password)
    client.tls_set(
        ca_certs=str(ca),
        cert_reqs=ssl.CERT_REQUIRED,
        tls_version=ssl.PROTOCOL_TLS_CLIENT,
    )
    client.tls_insecure_set(False)
    return client
