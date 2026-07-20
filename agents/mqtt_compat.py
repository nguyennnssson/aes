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

import warnings

import paho.mqtt.client as mqtt


def make_mqtt_client(client_id: str = "") -> mqtt.Client:
    """Return an mqtt.Client with v1 callback signatures on paho 1.x or 2.x."""
    if hasattr(mqtt, "CallbackAPIVersion"):        # paho-mqtt >= 2.0
        with warnings.catch_warnings():
            # VERSION1 is deprecated upstream but intentional here: it keeps the
            # v1 callback signatures working across both major versions.
            warnings.simplefilter("ignore", DeprecationWarning)
            return mqtt.Client(mqtt.CallbackAPIVersion.VERSION1, client_id=client_id)
    return mqtt.Client(client_id=client_id)        # paho-mqtt 1.x
