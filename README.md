Compal CH7465LG (Ziggo Connect Box) tools
=============================================

This repository contains a simple api to wrap the web interface of the Ziggo Connect Box (i.e. the
Compal CH7465LG). It is implemented in **Python >= 3.7**.

At the moment it *only* contains the functionality that I needed while I was investigating my
device, but pull requests that improve the documentation or add features are welcome.

About the hardware
------------------
Compal does not provide information about the hardware. The modem has no FCC registration.
However, the related Arris TG2492 modem was submitted to the FCC. The FCC documents for this
modem are [available][0]. Some interesting documents (internal photos) have been mirrored to
`docs/fcc`.
danman [performed][2] an (excellent) analysis of the modem where the procedure for extracting
the content of the firmware and modifying it is discussed. This writeup also examines the
DOCSIS certificates used.

The modem seems to be based on the Intel Puma 6 chipset. There is a long thead on (perceived)
performance problems caused by jitter on DSLReports. See [[ALL] SB6190 is a terrible modem - Intel Puma 6 / MaxLinear mistake][1]


The modem *most likely* contains open source components. Requests to Compal requesting source
code of these components, to an e-mail address on the Compal site, have not been answered yet.

[0]: https://fccid.io/UIDTG2492
[1]: https://www.dslreports.com/forum/r31079834-ALL-SB6190-is-a-terrible-modem-Intel-Puma-6-MaxLinear-mistake
[2]: https://blog.danman.eu/about-adding-a-static-route-to-my-docsis-modem/

Changelog
---------

### 0.6.0
  * Support for static DHCP leases was added by @do3cc

### 0.5.1
  * Support for hashed (single-sha256) passwords was added by @7FM

### 0.5.0
  * Added support for get/create/disable/delete IPv6 filter rules by @7FM

### 0.4.0:
  * Updated guest network settings for firmware [6.15.30-1p3-1-NOSH](https://github.com/ties/compal_CH7465LG_py/pull/32) by @frimtec.

### 0.3.2:
  * Add [system information methods](https://github.com/ties/compal_CH7465LG_py/pull/28)
	  by @reitermarkus.

### 0.3.1:
  * [Fix](https://github.com/ties/compal_CH7465LG_py/pull/26) for [python url parsing change](https://bugs.python.org/issue42967) by @Kiskae.

### 0.3.0:
  * Guest network settings added by @frimtec.

Security
--------
A security evaluation of the Connect Box was [posted](https://packetstormsecurity.com/files/137996/compalch7465lglc-bypassexec.txt)
on-line. This report is included in the `docs` folder.

How to use it?
--------------
The `examples` directory contains some example scripts. My main use case is re-provisioning the
modem. An example script for this task is included.

Want to get started really quickly?
```python
import os
import time
from compal import *

modem = Compal('192.168.178.1', os.environ['ROUTER_CODE'])
modem.login()

fw = PortForwards(modem)

def toggle_all_rules(fw, goal):
	rules = list(fw.rules)
	for idx, r in enumerate(rules):
	  rules[idx] = r._replace(enabled=goal)

	fw.update_rules(rules)
	print(list(fw.rules))

# Disable all rules
toggle_all_rules(fw, False)
time.sleep(5)
# And re-enable
toggle_all_rules(fw, True)

# Or find all possible functions of the modem:
scan = FuncScanner(modem, 0, os.environ['ROUTER_CODE'])
while scan.current_pos < 101:
	print(scan.scan().text)

# And/or change wifi settings
wifi = WifiSettings(modem)
settings = wifi.wifi_settings
print(settings)

new_settings = settings._replace(radio_2g=settings.radio_2g._replace(ssid='api_works'))
wifi.update_wifi_settings(new_settings)

print(wifi.wifi_settings)

# And/or Make all dhcp adresses static:

dhcp = DHCPSettings(modem)
lan_table = LanTable(modem)
for client in (*lan_table.get_lan(), *lan_table.get_wifi()):
    dhcp.add_static_lease(
        lease_ip=client["IPv4Addr"].split("/")[0], lease_mac=client["MACAddr"]
    )


# If you want to go back to 'normal':
# modem.reboot() # or
# modem.factory_reset()

# And logout
modem.logout()
```
