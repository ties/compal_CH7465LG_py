"""
Set 'creative' WiFi SSID's using the calls.

The interface is quite permissive with what it accepts. When you use special
(unicode) characters, smileys, or other inputs, strange things happen.

"""
import argparse
import os
import pprint
import sys

from compal import (Compal, DHCPSettings, PortForwards, Proto,  # noqa
                    WifiSettings)

# Push the parent directory onto PYTHONPATH before compal module is imported
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


def modem_setup(host, passwd, wifi_passwd):
    modem = Compal(host, passwd)
    modem.login()

    # And/or change wifi settings
    wifi = WifiSettings(modem)
    settings = wifi.wifi_settings

    settings.radio_2g.ssid = "🏚  Open"  # \u1F3DA'
    settings.radio_2g.mode = 1
    settings.radio_2g.security = 0
    # 8 = WPA2/PSK
    # 20/40MHz
    settings.radio_5g.ssid = "\U0001F916\u2028\u2028\u0085🏚\u00A0 Open"
    settings.radio_5g.mode = 1
    settings.radio_5g.security = 0

    if settings.radio_5g.security == 0 or settings.radio_2g.security == 0:
        print("[warning]: WiFi security is disabled")

    settings.radio_2g.pre_shared_key = wifi_passwd
    settings.radio_5g.pre_shared_key = wifi_passwd

    wifi.update_wifi_settings(settings)

    wifi = WifiSettings(modem)
    settings = wifi.wifi_settings

    pprint.pprint(settings)

    modem.logout()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Connect Box configuration")
    parser.add_argument("--host", type=str, default=os.environ.get("CB_HOST", None))
    parser.add_argument(
        "--password", type=str, default=os.environ.get("CB_PASSWD", None)
    )

    parser.add_argument(
        "--wifi_pw", type=str, default=os.environ.get("CB_WIFI_PASSWD", None)
    )

    args = parser.parse_args()

    modem_setup(args.host, args.password, args.wifi_pw)
