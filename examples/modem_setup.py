"""
Provioning my Ziggo modem using the Compal/Ziggo Connect Box [web interface
wrapper](https://github.com/ties/compal_CH7465LG_py).
"""
import argparse
import os
import sys
import time

from compal import (Compal, DHCPSettings, PortForwards, Proto,  # noqa
                    WifiSettings)

# Push the parent directory onto PYTHONPATH before compal module is imported
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


def modem_setup(host, passwd, wifi_passwd, factory_reset=False):
    print("Attempting connection to %s with password: %s" % (host, passwd))
    try:
        modem = Compal(host, passwd)
        modem.login()
    except Exception as err:
        print("Login to modem failed! Error: %s" % err)
        return

    if factory_reset:
        # Factory reset
        print("Performing factory reset...")
        modem.factory_reset()
        print("Sleeping for 5 minutes")
        time.sleep(300)

        # New connection + login again
        print("Logging in again...")
        modem = Compal(host, passwd)
        modem.login()

    # And/or change wifi settings
    wifi = WifiSettings(modem)
    settings = wifi.wifi_settings

    if wifi_passwd:
        settings.radio_2g.ssid = "modem_setup-2.4"
        settings.radio_2g.mode = False
        settings.radio_2g.security = 8
        # 20/40MHz
        settings.radio_2g.bandwidth = 2
        settings.radio_5g.ssid = "modem_setup-5"
        settings.radio_5g.mode = False
        settings.radio_5g.security = 8

        settings.radio_2g.pre_shared_key = wifi_passwd
        settings.radio_5g.pre_shared_key = wifi_passwd

        wifi.update_wifi_settings(settings)

    dhcp = DHCPSettings(modem)
    dhcp.add_static_lease("192.168.178.17", "d0:50:99:0a:65:52")
    dhcp.add_static_lease("192.168.178.16", "BC:5F:F4:FE:05:15")
    dhcp.set_upnp_status(False)

    fw = PortForwards(modem)
    # Disable the firewall
    fw.update_firewall(enabled=True)

    # Delete all old rules
    rules = list(fw.rules)
    for rule in rules:
        rule.delete = True

    fw.update_rules(rules)

    # Create the new forwards
    fw.add_forward("192.168.178.17", 80, 80, Proto.tcp)
    fw.add_forward("192.168.178.17", 1022, 22, Proto.tcp)
    fw.add_forward("192.168.178.17", 443, 443, Proto.tcp)
    fw.add_forward("192.168.178.17", 32400, 32400, Proto.tcp)

    modem.logout()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Connect Box configuration")
    parser.add_argument("--factory_reset", action="store_true", default=False)
    parser.add_argument("--host", type=str, default=os.environ.get("CB_HOST", None))
    parser.add_argument(
        "--password", type=str, default=os.environ.get("CB_PASSWD", None)
    )

    parser.add_argument(
        "--wifi_pw", type=str, default=os.environ.get("CB_WIFI_PASSWD", None)
    )

    args = parser.parse_args()

    modem_setup(args.host, args.password, args.wifi_pw, args.factory_reset)
