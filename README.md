Compal CH7465LG (Ziggo Connect Box) tools
=============================================

This repository contains a simple api to wrap the web interface of the Ziggo Connect Box (i.e. the
Compal CH7465LG). It is implemented in **Python > 3.4**.

At the moment it *only* contains the functionality that I needed while I was investigating my
device, but pull requests that improve the documentation or add features are welcome.

How to use it?
```python
import os
import time
from compal import *

modem = Compal('192.168.178.1')
modem.login(os.environ['ROUTER_CODE'])

fw = CompalPortForwards(modem)

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

# And logout
modem.logout()
```
