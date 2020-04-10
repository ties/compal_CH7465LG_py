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

The modem seems to be based on the Intel Puma 6 chipset. There is a long thead on (perceived)
performance problems caused by jitter on DSLReports. See [[ALL] SB6190 is a terrible modem - Intel Puma 6 / MaxLinear mistake][1]


The modem *most likely* contains open source components. Requests to Compal requesting source
code of these components, to an e-mail address on the Compal site, have not been answered yet.

[0]: https://fccid.io/UIDTG2492
[1]: https://www.dslreports.com/forum/r31079834-ALL-SB6190-is-a-terrible-modem-Intel-Puma-6-MaxLinear-mistake

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

# And/or DHCPSettings

# If you want to go back to 'normal':
# modem.reboot() # or
# modem.factory_reset()

# And logout
modem.logout()
```
