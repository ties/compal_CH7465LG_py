"""
Provioning my Ziggo modem using the Compal/Ziggo Connect Box [web interface
wrapper](https://github.com/ties/compal_CH7465LG_py).
"""
import argparse
import time

from compal import Compal, WifiSettings, DHCPSettings, PortForwards, Proto

CB_PASSWD = '60451811'
CB_HOST = '192.168.178.1'
PW = 'distends_shout_adding_bandies_bleating'


def modem_setup(host, passwd, factory_reset=False):
    modem = Compal(host, passwd)
    modem.login()

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

    settings.radio_2g.ssid = '00-CB'
    settings.radio_2g.mode = False
    # 20/40MHz
    settings.radio_2g.bandwidth = 2
    settings.radio_5g.ssid = '00-CB-5G'
    settings.radio_5g.mode = False

    settings.radio_2g.pre_shared_key = PW
    settings.radio_5g.pre_shared_key = PW

    wifi.update_wifi_settings(settings)

    dhcp = DHCPSettings(modem)
    dhcp.add_static_lease('192.168.178.15', 'BC:5F:F4:FE:05:15')
    dhcp.add_static_lease('192.168.178.17', 'd0:50:99:0a:65:52')
    dhcp.set_upnp_status(False)

    fw = PortForwards(modem)
    # Disable the firewall
    fw.update_firewall(enabled=False)

    # Delete all old rules
    rules = list(fw.rules)
    for rule in rules:
        rule.delete=True

    fw.update_rules(rules)

    # Create the new forwards
    fw.add_forward('192.168.178.17', 80, 80, Proto.tcp)
    fw.add_forward('192.168.178.17', 1022, 22, Proto.tcp)
    fw.add_forward('192.168.178.17', 443, 443, Proto.tcp)
    # fw.add_forward('192.168.178.17', 51413, 51413, Proto.both)

    modem.logout()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Connect Box configuration')
    parser.add_argument('--factory_reset', action='store_true', default=False)
    parser.add_argument('--host', type=str, default=CB_HOST)
    parser.add_argument('--password', type=str, default=CB_PASSWD)

    args = parser.parse_args()

    modem_setup(args.host, args.password, args.factory_reset) 
