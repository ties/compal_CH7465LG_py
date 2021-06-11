"""
Toggles the enabling state of the 3rd 2g-interface guest network (the one also editable via the UI).
"""
import argparse
import os
import pprint
import sys

from compal import (Compal, DHCPSettings, PortForwards, Proto,  # noqa
                    WifiGuestNetworkSettings, WifiSettings)

# Push the parent directory onto PYTHONPATH before compal module is imported
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


def modem_setup(host, passwd):
    modem = Compal(host, passwd)
    modem.login()

    guest = WifiGuestNetworkSettings(modem)
    settings = guest.wifi_guest_network_settings

    old_enabling_state = settings.enabling_2g.enabled
    pprint.pprint('Current GUEST-NETWORK state: ' + ('ON' if old_enabling_state else 'OFF'))

    guest.update_wifi_guest_network_settings(settings.properties, not old_enabling_state)

    settings = guest.wifi_guest_network_settings
    new_enabling_state = settings.enabling_2g.enabled
    pprint.pprint('New GUEST-NETWORK state: ' + ('ON' if new_enabling_state else 'OFF'))
    pprint.pprint(settings)

    modem.logout()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Connect Box configuration")
    parser.add_argument("--host", type=str, default=os.environ.get("CB_HOST", None))
    parser.add_argument(
        "--password", type=str, default=os.environ.get("CB_PASSWD", None)
    )

    args = parser.parse_args()

    modem_setup(args.host, args.password)
