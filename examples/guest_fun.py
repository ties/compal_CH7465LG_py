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

    # Change enabling state of the 3rd (index 2) 2g-interface (the one also editable via the UI)
    interface_index = 2
    old_enabling_state = settings.guest_networks_2g[interface_index].enable
    pprint.pprint('Current GUEST-NETWORK state: ' + ('ON' if old_enabling_state == 1 else 'OFF'))

    settings.guest_networks_2g[interface_index].enable = 1 if old_enabling_state == 2 else 2
    guest.update_interface_guest_network_settings(settings, interface_index)

    new_enabling_state = guest.wifi_guest_network_settings.guest_networks_2g[interface_index].enable
    pprint.pprint('New GUEST-NETWORK state: ' + ('ON' if new_enabling_state == 1 else 'OFF'))

    pprint.pprint(guest.wifi_guest_network_settings)

    modem.logout()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Connect Box configuration")
    parser.add_argument("--host", type=str, default=os.environ.get("CB_HOST", None))
    parser.add_argument(
        "--password", type=str, default=os.environ.get("CB_PASSWD", None)
    )

    args = parser.parse_args()

    modem_setup(args.host, args.password)
