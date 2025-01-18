"""
Client for the Compal CH7465LG/Ziggo Connect box cable modem
"""

import inspect
import io
import itertools
import logging
import re
import time
import urllib
from collections import OrderedDict
from datetime import timedelta
from enum import Enum
from hashlib import sha256
from xml.dom import minidom

import requests
from lxml import etree

from .functions import GetFunction, SetFunction
from .models import (
    BandSetting,
    FilterAction,
    FilterIpRange,
    GuestNetworkEnabling,
    GuestNetworkProperties,
    GuestNetworkSettings,
    IPv6FilterRule,
    IPv6FilterRuleProto,
    NatMode,
    PortForward,
    Proto,
    RadioSettings,
    RuleDir,
    SystemInfo,
    TimerMode,
)

LOGGER = logging.getLogger(__name__)
logging.basicConfig()

LOGGER.setLevel(logging.INFO)


class Compal:
    """
    Basic functionality for the router's API
    """

    def __init__(
        self,
        router_ip,
        key=None,
        send_token=True,
        send_hash=False,
        username="admin",
        timeout=10,
    ):
        self.router_ip = router_ip
        self.send_token = send_token
        self.send_hash = send_hash
        self.username = username
        self.timeout = timeout
        self.key = self.sanitize_key(key)

        self.session = requests.Session()
        # limit the number of redirects
        self.session.max_redirects = 3

        # after a response is received, process the token field of the response
        self.session.hooks["response"].append(self.token_handler)
        # session token is initially empty
        self.session_token = None

        LOGGER.debug("Getting initial token")
        # check the initial URL. If it is redirected, perform the initial
        # installation
        self.initial_res = self.get("/")

        if self.initial_res.url.endswith("common_page/FirstInstallation.html"):
            self.initial_setup()
        elif not self.initial_res.url.endswith("common_page/login.html"):
            LOGGER.error("Was not redirected to login page:" " concurrent session?")

    def sanitize_key(self, key):
        if key:
            if self.send_hash:
                key = sha256(key.encode("utf-8")).hexdigest()
            else:
                key = key[:31]
        return key

    def initial_setup(self, new_key=None):
        """
        Replay the settings made during initial setup
        """
        LOGGER.info("Initial setup: english.")

        self.key = self.sanitize_key(new_key)

        if not self.key:
            raise ValueError("No key/password availalbe")

        self.xml_getter(GetFunction.MULTILANG, {})
        self.xml_getter(GetFunction.LANGSETLIST, {})
        self.xml_getter(GetFunction.MULTILANG, {})

        self.xml_setter(SetFunction.LANGUAGE, {"lang": "en"})
        # Login or change password? Not sure.
        self.xml_setter(
            SetFunction.LOGIN,
            OrderedDict([("Username", self.username), ("Password", self.key)]),
        )
        # Get current wifi settings (?)
        self.xml_getter(GetFunction.WIRELESSBASIC, {})

        # Some sheets with hints, no request
        # installation is done:
        self.xml_setter(SetFunction.INSTALL_DONE, {"install": 0, "iv": 1, "en": 0})

    def url(self, path):
        """
        Calculate the absolute URL for the request
        """
        while path.startswith("/"):
            path = path[1:]

        return "http://{ip}/{path}".format(ip=self.router_ip, path=path)

    def token_handler(self, res, *args, **kwargs):
        """
        Handle the anti-replace token system
        """
        self.session_token = res.cookies.get("sessionToken")

        if res.status_code == 302:
            LOGGER.info(
                "302 [%s] => '%s' [token: %s]",
                res.url,
                res.headers["Location"],
                self.session_token,
            )
        else:
            LOGGER.debug(
                "%s [%s] [token: %s]",
                res.status_code,
                res.url,
                self.session_token,
            )

    def post(self, path, _data, **kwargs):
        """
        Prepare and send a POST request to the router

        Wraps `requests.get` and sets the 'token' and 'fun' fields at the
        correct position in the post data.

        **The router is sensitive to the ordering of the fields**
        (Which is a code smell)
        """
        data = OrderedDict()
        if self.send_token:
            data["token"] = self.session_token

        if "fun" in _data:
            data["fun"] = _data.pop("fun")

        data.update(_data)

        LOGGER.debug("POST [%s]: %s", path, data)

        res = self.session.post(
            self.url(path),
            data=data,
            allow_redirects=False,
            timeout=self.timeout,
            **kwargs,
        )

        return res

    def post_binary(self, path, binary_data, filename, **kwargs):
        """
        Perform a post request with a file as form-data in it's body.
        """

        headers = {
            "Content-Disposition": f'form-data; name="file"; filename="{filename}"',
            "Content-Type": "application/octet-stream",
        }
        self.session.post(self.url(path), data=binary_data, headers=headers, **kwargs)

    def get(self, path, **kwargs):
        """
        Perform a GET request to the router

        Wraps `requests.get` and sets the required referer.
        """
        res = self.session.get(self.url(path), timeout=self.timeout, **kwargs)

        self.session.headers.update({"Referer": res.url})
        return res

    def xml_getter(self, fun, params):
        """
        Call `/xml/getter.xml` for the given function and parameters
        """
        params["fun"] = fun

        return self.post("/xml/getter.xml", params)

    def xml_setter(self, fun, params=None):
        """
        Call `/xml/setter.xml` for the given function and parameters.
        The params are optional
        """
        params["fun"] = fun

        return self.post("/xml/setter.xml", params)

    def login(self, key=None):
        """
        Login. Allow this function to override the key.
        """

        key = self.sanitize_key(key) if key else self.key
        res = self.xml_setter(
            SetFunction.LOGIN,
            OrderedDict(
                [
                    ("Username", self.username),
                    ("Password", key),
                ]
            ),
        )

        if res.status_code != 200:
            if res.headers["Location"].endswith("common_page/Access-denied.html"):
                raise ValueError("Access denied. " "Still logged in somewhere else?")
            else:
                raise ValueError("Login failed for unknown reason!")

        def parse_response(text):
            # As per python 3.9.2 parse_qs does not split on ';' by default
            if "separator" in inspect.signature(urllib.parse.parse_qs).parameters:
                return urllib.parse.parse_qs(text, separator=";")
            else:
                return urllib.parse.parse_qs(text)

        tokens = parse_response(res.text)

        token_sids = tokens.get("SID")
        if not token_sids:
            raise ValueError("No valid session-Id received! Wrong password?")

        token_sid = token_sids[0]
        LOGGER.info("[login] SID %s", token_sid)

        self.session.cookies.update({"SID": token_sid})

        return res

    def system_info(self):
        """
        Get system information
        """
        system_info = SystemInfo()

        parser = etree.XMLParser(recover=True)
        res = self.xml_getter(GetFunction.CM_SYSTEM_INFO, {})
        xml = etree.fromstring(res.content, parser=parser)

        cm_docsis_mode = xml.find("cm_docsis_mode")
        if cm_docsis_mode is not None:
            system_info.docsis_mode = cm_docsis_mode.text

        cm_hardware_version = xml.find("cm_hardware_version")
        if cm_hardware_version is not None:
            system_info.hardware_version = cm_hardware_version.text

        cm_mac_addr = xml.find("cm_mac_addr")
        if cm_mac_addr is not None:
            system_info.mac_address = cm_mac_addr.text

        cm_serial_number = xml.find("cm_serial_number")
        if cm_serial_number is not None:
            system_info.serial_number = cm_serial_number.text

        cm_system_uptime = xml.find("cm_system_uptime")
        if cm_system_uptime is not None:
            match = re.match(
                r"^(\d+)day(?:\(s\))?(\d+)h?\:(\d+)m?\:(\d+)s?$", cm_system_uptime.text
            )
            system_info.uptime = timedelta(
                days=int(match[1]),
                hours=int(match[2]),
                minutes=int(match[3]),
                seconds=int(match[4]),
            )

        cm_network_access = xml.find("cm_network_access")
        if cm_network_access is not None:
            system_info.network_access = cm_network_access.text

        return system_info

    def reboot(self):
        """
        Reboot the router
        """
        try:
            LOGGER.info("Performing a reboot - this will take a while")
            return self.xml_setter(SetFunction.REBOOT, {})
        except requests.exceptions.ReadTimeout:
            return None

    def factory_reset(self):
        """
        Perform a factory reset
        """
        default_settings = self.xml_getter(GetFunction.DEFAULTVALUE, {})

        try:
            LOGGER.info("Initiating factory reset - this will take a while")
            self.xml_setter(SetFunction.FACTORY_RESET, {})
        except requests.exceptions.ReadTimeout:
            pass
        return default_settings

    def logout(self):
        """
        Logout of the router. This is required since only a single session can
        be active at any point in time.
        """
        return self.xml_setter(SetFunction.LOGOUT, {})

    def set_modem_mode(self):
        """
        Set router to Modem-mode
        After setting this, router will not be reachable by IP!
        It needs factory reset to function as a router again!
        """
        return self.xml_setter(SetFunction.NAT_MODE, {"NAT": NatMode.disabled.value})

    def set_router_mode(self):
        """
        Set router to Modem-mode
        After setting this, router will not be reachable by IP!
        It needs factory reset to function as a router again!
        """
        return self.xml_setter(SetFunction.NAT_MODE, {"NAT": NatMode.enabled.value})

    def change_password(self, old_password, new_password):
        """
        Change the admin password
        """
        return self.xml_setter(
            SetFunction.CHANGE_PASSWORD,
            OrderedDict([("oldpassword", old_password), ("newpassword", new_password)]),
        )


class PortForwards(object):
    """
    Manage the port forwards on the modem
    """

    def __init__(self, modem):
        # The modem sometimes returns invalid XML when 'strange' values are
        # present in the settings. The recovering parser from lxml is used to
        # handle this.
        self.parser = etree.XMLParser(recover=True)

        self.modem = modem

    @property
    def rules(self):
        """
        Retrieve the current port forwarding rules

        @returns generator of PortForward rules
        """
        res = self.modem.xml_getter(GetFunction.FORWARDING, {})

        xml = etree.fromstring(res.content, parser=self.parser)
        router_ip = xml.find("LanIP").text

        def r_int(rule, attr):
            """
            integer value for rule's child's text
            """
            return int(rule.find(attr).text)

        for rule in xml.findall("instance"):
            yield PortForward(
                local_ip=rule.find("local_IP").text,
                lan_ip=router_ip,
                id=r_int(rule, "id"),
                ext_port=(r_int(rule, "start_port"), r_int(rule, "end_port")),
                int_port=(
                    r_int(rule, "start_portIn"),
                    r_int(rule, "end_portIn"),
                ),
                proto=Proto(r_int(rule, "protocol")),
                enabled=bool(r_int(rule, "enable")),
                idd=bool(r_int(rule, "idd")),
            )

    def update_firewall(
        self,
        enabled=False,
        fragment=False,
        port_scan=False,
        ip_flood=False,
        icmp_flood=False,
        icmp_rate=15,
    ):
        """
        Update the firewall rules
        """
        assert enabled or not (fragment or port_scan or ip_flood or icmp_flood)

        def b2i(_bool):
            """
            Bool-2-int with non-standard mapping
            """
            return 1 if _bool else 2

        return self.modem.xml_setter(
            SetFunction.FIREWALL,
            OrderedDict(
                [
                    ("firewallProtection", b2i(enabled)),
                    ("blockIpFragments", ""),
                    ("portScanDetection", ""),
                    ("synFloodDetection", ""),
                    ("IcmpFloodDetection", ""),
                    ("IcmpFloodDetectRate", icmp_rate),
                    ("action", ""),
                    ("IPv6firewallProtection", ""),
                    ("IPv6blockIpFragments", ""),
                    ("IPv6portScanDetection", ""),
                    ("IPv6synFloodDetection", ""),
                    ("IPv6IcmpFloodDetection", ""),
                    ("IPv6IcmpFloodDetectRate", ""),
                ]
            ),
        )

    def add_forward(self, local_ip, ext_port, int_port, proto: Proto, enabled=True):
        """
        Add a port forward. int_port and ext_port can be ranges. Deletion
        param is ignored for now.
        """
        start_int, end_int = itertools.islice(itertools.repeat(int_port), 0, 2)
        start_ext, end_ext = itertools.islice(itertools.repeat(ext_port), 0, 2)

        return self.modem.xml_setter(
            SetFunction.PORT_FORWARDING,
            OrderedDict(
                [
                    ("action", "add"),
                    ("instance", ""),
                    ("local_IP", local_ip),
                    ("start_port", start_ext),
                    ("end_port", end_ext),
                    ("start_portIn", start_int),
                    ("end_portIn", end_int),
                    ("protocol", proto.value),
                    ("enable", int(enabled)),
                    ("delete", int(False)),
                    ("idd", ""),
                ]
            ),
        )

    def update_rules(self, rules):
        """
        Update the port forwarding rules
        """
        # Will iterate multiple times, ensure it is a list.
        rules = list(rules)

        empty_asterisk = "*" * (len(rules) - 1)

        # Order of parameters matters (code smell: YES)
        params = OrderedDict(
            [
                ("action", "apply"),
                ("instance", "*".join([str(r.id) for r in rules])),
                ("local_IP", ""),
                ("start_port", ""),
                ("end_port", ""),
                ("start_portIn", empty_asterisk),
                ("end_portIn", ""),
                ("protocol", "*".join([str(r.proto.value) for r in rules])),
                ("enable", "*".join([str(int(r.enabled)) for r in rules])),
                ("delete", "*".join([str(int(r.delete)) for r in rules])),
                ("idd", empty_asterisk),
            ]
        )

        LOGGER.info("Updating port forwards")
        LOGGER.debug(params)

        return self.modem.xml_setter(SetFunction.PORT_FORWARDING, params)


class Filters(object):
    """
    Provide filters for accessing the internet.

    Supports access-restriction via parental control (Keywords, url-lists,
    timetable), client's MAC address and by specific ports.
    """

    def __init__(self, modem):
        self.modem = modem
        self.parser = etree.XMLParser(recover=True)

    def set_parental_control(
        self,
        safe_search,
        keyword_list,
        allow_list,
        deny_list,
        timer_mode,
        enable,
    ):
        """
        Filter internet access by keywords or block/allow whole urls
        Allowed times can be set too
        """
        data = "EN=%s;" % ("1" if enable else "2")
        data += "SAFE=%s;" % ("1" if safe_search else "2")

        data += "KEY=%s;" % ("1" if len(keyword_list) else "0")
        data += "KEYLIST="
        if len(keyword_list):
            data += ",".join(keyword_list) + ";"
        else:
            data += "empty" + ";"

        data += "ALLOW=%s;" % ("1" if len(allow_list) else "0")
        data += "ALLOWLIST="
        if len(keyword_list):
            data += ",".join(keyword_list) + ";"
        else:
            data += "empty" + ";"

        data += "DENY=%s;" % ("1" if len(deny_list) else "0")
        data += "DENYLIST="
        if len(keyword_list):
            data += ",".join(keyword_list) + ";"
        else:
            data += "empty" + ";"

        if TimerMode.generaltime == timer_mode:
            timer_rule = "0,0"
        elif TimerMode.dailytime == timer_mode:
            timer_rule = "0,0"
        else:
            timer_rule = "empty"

        data += "TMODE=%i;" % timer_mode.value
        data += "TIMERULE=%s;" % timer_rule

        self.modem.xml_setter(SetFunction.PARENTAL_CONTROL, {"data": data})

    def set_mac_filter(self, action, device_name, mac_addr, timer_mode, enable):
        """
        Restrict access to the internet via client MAC address
        """
        if FilterAction.add == action:
            data = "ADD,"
        elif FilterAction.delete == action:
            data = "DEL,"
        elif FilterAction.enable == action:
            data = "EN,"
        else:
            LOGGER.error("No action supplied for MAC filter rule")
            return

        data += device_name + ","
        data += mac_addr + ","
        data += "%i" % (1 if enable else 2) + ";"

        if TimerMode.generaltime == timer_mode:
            timerule = "0,0"
        elif TimerMode.dailytime == timer_mode:
            timerule = "0,0"
        else:
            timerule = "0"

        data += "MODE=%i," % timer_mode.value
        data += "TIME=%s;" % timerule

        return self.modem.xml_setter(SetFunction.MACFILTER, {"data": data})

    def get_ipv6_filter_rules(self):
        """
        Get the list of IPv6 filter rules for incoming and outgoing traffic
        """

        def r_int(rule, attr):
            """
            integer value for rule's child's text
            """
            return int(rule.find(attr).text)

        def getFilterRules(direction):
            """
            Get the list of IPv6 filter rules for traffic in specified direction
            """
            res = self.modem.xml_getter(
                GetFunction.IPV6FILTERING, OrderedDict([("rule", int(direction))])
            )
            xml = etree.fromstring(res.content, parser=self.parser)
            for rule in xml.findall("instance"):
                yield IPv6FilterRule(
                    dir=direction,
                    idd=r_int(rule, "idd"),
                    src_addr=rule.find("src_addr").text,
                    src_prefix=r_int(rule, "src_prefix"),
                    dst_addr=rule.find("dst_addr").text,
                    dst_prefix=r_int(rule, "dst_prefix"),
                    src_sport=r_int(rule, "src_sport"),
                    src_eport=r_int(rule, "src_eport"),
                    dst_sport=r_int(rule, "dst_sport"),
                    dst_eport=r_int(rule, "dst_eport"),
                    protocol=IPv6FilterRuleProto(r_int(rule, "protocol")),
                    allow=bool(r_int(rule, "allow")),
                    enabled=bool(r_int(rule, "enabled")),
                )

        inRules = getFilterRules(RuleDir.incoming)
        outRules = getFilterRules(RuleDir.outgoing)
        return list(inRules), list(outRules)

    def set_ipv6_filter_rule(self, rule):
        """
        Add a new IPv6 traffic filter rule
        """

        def getOrDefault(val, defaultValue):
            return condGetOrDefault(RuleDir.incoming, val, defaultValue, defaultValue)

        def condGetOrDefault(direction, val, defaultValueIn, defaultValueOut):
            if direction == RuleDir.incoming:
                return val if val is not None else defaultValueIn
            else:
                return val if val is not None else defaultValueOut

        direction = getOrDefault(rule.dir, RuleDir.incoming)
        src_prefix = getOrDefault(rule.src_prefix, 128)
        src_addr = condGetOrDefault(direction, rule.src_addr, "::", None)
        dst_prefix = getOrDefault(rule.dst_prefix, 128)
        dst_addr = condGetOrDefault(direction, rule.dst_addr, None, "::")
        params = OrderedDict(
            [
                ("act", "2"),
                ("dir", int(direction)),
                ("enabled", int(getOrDefault(rule.enabled, True))),
                (
                    "allow_traffic",
                    1 - int(condGetOrDefault(direction, rule.allow, True, False)),
                ),  # 0 actually stands for allowing the traffic.. TODO introduce enum?
                ("protocol", int(rule.protocol)),
                ("src_addr", src_addr),
                ("src_prefix", src_prefix),
                ("dst_addr", dst_addr),
                ("dst_prefix", dst_prefix),
                ("ssport", condGetOrDefault(direction, rule.src_sport, "1", None)),
                ("seport", condGetOrDefault(direction, rule.src_eport, "65535", None)),
                ("dsport", condGetOrDefault(direction, rule.dst_sport, None, "1")),
                ("deport", condGetOrDefault(direction, rule.dst_eport, None, "65535")),
                ("del", ""),
                ("idd", ""),
                (
                    "sIpRange",
                    int(
                        FilterIpRange.all
                        if src_addr == "::"
                        else (
                            FilterIpRange.range
                            if src_prefix != 128
                            else FilterIpRange.single
                        )
                    ),
                ),
                (
                    "dsIpRange",
                    int(
                        FilterIpRange.all
                        if dst_addr == "::"
                        else (
                            FilterIpRange.range
                            if dst_prefix != 128
                            else FilterIpRange.single
                        )
                    ),
                ),
                ("PortRange", "2"),  # manual port selection
                (
                    "TMode",
                    "0",
                ),  # No timed rule
                ("TRule", "0"),  # No timed rule
            ]
        )
        return self.modem.xml_setter(SetFunction.IPV6_FILTER_RULE, params)

    def update_ipv6_filter_rules(
        self, ruleCount, disableIds={}, deleteIds={}, direction=RuleDir.incoming
    ):
        """
        Update the existing filter set. I.e. disable or delete them.
        """
        if ruleCount == 0 or (len(disableIds) == 0 and len(deleteIds)):
            pass

        def genIddString():
            return "*".join([str(i) for i in range(1, ruleCount + 1)])

        def genBitfield(ids, matchStr, noMatchStr):
            return "*".join(
                [matchStr if i in ids else noMatchStr for i in range(1, ruleCount + 1)]
            )

        enableBitfield = genBitfield(disableIds, "0", "1")
        deleteBitfield = genBitfield(deleteIds, "1", "0")

        params = OrderedDict(
            [
                ("act", "1"),
                ("dir", int(direction)),
                ("enabled", enableBitfield),
                ("allow_traffic", ""),
                ("protocol", ""),
                ("src_addr", ""),
                ("src_prefix", ""),
                ("dst_addr", ""),
                ("dst_prefix", ""),
                ("ssport", ""),
                ("seport", ""),
                ("dsport", ""),
                ("deport", ""),
                ("del", deleteBitfield),
                ("idd", genIddString()),
                ("sIpRange", ""),
                ("dsIpRange", ""),
                ("PortRange", ""),
                ("TMode", "0"),  # No timed rule
                ("TRule", "0"),  # No timed rule
            ]
        )
        return self.modem.xml_setter(SetFunction.IPV6_FILTER_RULE, params)

    def delete_all_ipv6_filter_rules(self):
        """
        Delete all ipv6 filter rules
        """
        inRules, outRules = self.get_ipv6_filter_rules()
        countInRules = len(inRules)
        self.update_ipv6_filter_rules(
            countInRules, {}, set(range(1, countInRules + 1)), RuleDir.incoming
        )
        countOutRules = len(outRules)
        self.update_ipv6_filter_rules(
            countOutRules, {}, set(range(1, countOutRules + 1)), RuleDir.outgoing
        )

        return inRules, outRules

    def set_filter_rule(self):
        """
        To be integrated...
        """
        params = OrderedDict(
            [
                ("act", ""),
                ("enabled", ""),
                ("protocol", ""),
                ("src_addr_s", ""),
                ("src_addr_e", ""),
                ("dst_addr_s", ""),
                ("dst_addr_e", ""),
                ("ssport", ""),
                ("seport", ""),
                ("dsport", ""),
                ("deport", ""),
                ("del", ""),
                ("idd", ""),
                ("sIpRange", ""),
                ("dsIpRange", ""),
                ("PortRange", ""),
                ("TMode", ""),
                ("TRule", ""),
            ]
        )
        return self.modem.xml_setter(SetFunction.FILTER_RULE, params)


class WifiSettings(object):
    """
    Configures the WiFi settings
    """

    def __init__(self, modem):
        # The modem sometimes returns invalid XML when 'strange' values are
        # present in the settings. The recovering parser from lxml is used to
        # handle this.
        self.parser = etree.XMLParser(recover=True)

        self.modem = modem

    @property
    def wifi_settings_xml(self):
        """
        Get the current wifi settings as XML
        """
        xml_content = self.modem.xml_getter(GetFunction.WIRELESSBASIC, {}).content
        return etree.fromstring(xml_content, parser=self.parser)

    @staticmethod
    def band_setting(xml, band):
        """
        Get the wifi settings for the given band (2g, 5g)
        """
        assert band in (
            "2g",
            "5g",
        )

        def xml_value(attr, coherce=True):
            """
            'XmlValue'

            Coherce the value if requested. First the value is parsed as an
            integer, if this fails it is returned as a string.
            """
            val = xml.find(attr).text
            try:  # Try to coherce to int. If it fails, return string
                if not coherce:
                    return val
                return int(val)
            except (TypeError, ValueError):
                return val

        def band_xv(attr, coherce=True):
            """
            xml value for the given band
            """
            try:
                return xml_value(f"{attr}{band.upper()}", coherce)
            except AttributeError:
                return xml_value(f"{attr}{band}", coherce)

        return BandSetting(
            radio=band,
            bss_enable=band_xv(
                "BssEnable"
            ),  # bss_enable is the on/off mode, 'mode' was removed
            ssid=band_xv("SSID", False),
            hidden=band_xv("HideNetwork"),
            bandwidth=band_xv("BandWidth"),
            tx_rate=band_xv("TransmissionRate"),
            tx_mode=band_xv("TransmissionMode"),
            security=band_xv("SecurityMode"),
            multicast_rate=band_xv("MulticastRate"),
            channel=band_xv("ChannelSetting"),
            pre_shared_key=band_xv("PreSharedKey"),
            re_key=band_xv("GroupRekeyInterval"),
            wpa_algorithm=band_xv("WpaAlgorithm"),
        )

    @property
    def wifi_settings(self):
        """
        Read the wifi settings
        """
        xml = self.wifi_settings_xml

        radio_2g = WifiSettings.band_setting(xml, "2g")
        radio_5g = WifiSettings.band_setting(xml, "5g")

        """
        Correct the - in the router xml-File - not changing BandMode,
        so that all settings are up to date in the settings object
        """

        def get_band_mode():
            if radio_2g.bss_enable == 1:
                band_mode = 1 if radio_5g.bss_enable == 2 else 3
            elif radio_2g.bss_enable == 2:
                band_mode = 2 if radio_5g.bss_enable == 1 else 4
            else:
                band_mode = None
            return band_mode

        radio_settings = RadioSettings()

        properties = {
            "nv_country": "NvCountry",
            "channel_range": "ChannelRange",
            "bss_coexistence": "BssCoexistence",
            "son_admin_status": "SONAdminStatus",
            "smart_wifi": "SONOperationalStatus",
        }

        for prop, tag in properties.items():
            elem = xml.find(tag)
            if elem is not None and elem.text is not None:
                setattr(radio_settings, prop, int(elem.text))

        radio_settings.band_mode = get_band_mode()
        radio_settings.radio_2g = radio_2g
        radio_settings.radio_5g = radio_5g

        return radio_settings

    def __set_wifi_settings(self, settings, setter_code, debug=True):
        """
        Set the wifi settings either for fun:301 or fun:319 depending
        on the the setter_code parameter
        """

        # Create the object.
        def transform_radio(radio_settings):  # rs = radio_settings
            """
            Prepare radio settings object for the request.
            Returns a OrderedDict with the correct keys for this band
            """
            # Create the dict
            out = []
            if setter_code == SetFunction.WIFI_CONFIGURATION:
                out = [("BandMode", radio_settings.bss_enable)]

            out.extend(
                [
                    ("Ssid", radio_settings.ssid),
                    ("Bandwidth", radio_settings.bandwidth),
                    ("TxMode", radio_settings.tx_mode),
                    ("MCastRate", radio_settings.multicast_rate),
                    ("Hiden", radio_settings.hidden),
                    ("PSkey", radio_settings.pre_shared_key),
                    ("Txrate", radio_settings.tx_rate),
                    ("Rekey", radio_settings.re_key),
                    ("Channel", radio_settings.channel),
                    ("Security", radio_settings.security),
                    ("Wpaalg", radio_settings.wpa_algorithm),
                ]
            )

            # Prefix 'wl', Postfix the band
            return [(f"wl{k}{radio_settings.radio}", v) for (k, v) in out]

        # Alternate the two setting lists
        out_s = []  # change
        if setter_code == SetFunction.WIFI_SIGNAL:
            out_s.append(("wlBandMode", settings.band_mode))  # change

        for item_2g, item_5g in zip(
            transform_radio(settings.radio_2g),
            transform_radio(settings.radio_5g),
        ):
            out_s.append(item_2g)
            out_s.append(item_5g)

            if item_5g[0] == "wlHiden5g":
                out_s.append(("wlCoexistence", settings.bss_coexistence))

        if setter_code == SetFunction.WIFI_SIGNAL:
            out_s.append(("wlSmartWiFi", settings.smart_wifi))  # change
        # Join the settings
        out_settings = OrderedDict(out_s)

        if debug:
            print(
                f"\nThe following variables will be sent over 'fun:{setter_code}'"
                f" to the router for settting it:\n" + str(out_settings)
            )

        return self.modem.xml_setter(setter_code, out_settings)  # change

    def print_xml_content(self, point=""):
        """
        Print out xml-entries in the router that contain wifi-settings
        """
        print(f"\n--- SETTINGS {point} ---:")
        # WIFI State
        xml_content = self.modem.xml_getter(315, {}).content
        print(
            "\n ------------------------- WIRELESSBASIC_2 (315) IN ROUTER: : -------------------------\n"
            + xml_content.decode("utf8")
        )
        xml_content = self.modem.xml_getter(326, {}).content
        print(
            "\n ------------------------- WIFISTATE (326) IN ROUTER: : -------------------------\n"
            + xml_content.decode("utf8")
        )
        xml_content = self.modem.xml_getter(300, {}).content
        print(
            "\n ------------------------- WIRELESSBASIC (300) IN ROUTER: : -------------------------\n"
            + xml_content.decode("utf8")
        )
        print(str(self.wifi_settings))
        time.sleep(1)

    @staticmethod
    def __compare_wifi_settings(old_settings, new_settings):
        """
        Compare two settings objects for changes and
        return:
            bln_changes: True if there were changes
            changes: Python dict that contains the changes
        """

        def iterate_changes(old_settings, new_settings, changes):
            for attr, old_value in old_settings.__dict__.items():
                if isinstance(old_value, BandSetting):
                    changes.update({attr: {}})
                    iterate_changes(
                        getattr(old_settings, attr),
                        getattr(new_settings, attr),
                        changes[attr],
                    )
                else:
                    new_value = getattr(new_settings, attr)
                    if old_value != new_value:
                        changes.update({attr: f"{old_value} -> {new_value}"})
                        bln_changes[0] = True

        changes = {}
        bln_changes = [False]
        iterate_changes(old_settings, new_settings, changes)
        return bln_changes[0], changes

    def __check_router_status(self, new_settings, debug=True):
        """
        Checks if (1) the new user settings were changed in the router (via checking
        the getter fun:300 [WIRELESSBASIC] in the router-xml-file), (2) prints out a
        progress bar and (3) prints out if the process was successful.
        """
        router_settings = None

        def print_progress_bar(progress, total, postfix=""):
            progress = total if progress > total else progress
            per_progress = int(progress / total * 100)
            postfix = f"[{postfix}]" if postfix != "" else ""
            print(
                f"\r|{'█' * progress}{'-' * (total - progress)}| {per_progress}%, {progress}sec\t{postfix}",
                end="",
            )

        progress = 0
        total = 24
        bln_changes = True
        start_time = time.time()
        changes = ""
        if debug:
            print("\n--- WAITING FOR ROUTER TO UPDATE ---")
        while progress < total and bln_changes is True:
            progress = int(time.time() - start_time)
            if debug:
                print_progress_bar(progress, total, changes)
            time.sleep(3)
            try:
                router_settings = self.wifi_settings
                bln_changes, changes = self.__compare_wifi_settings(
                    router_settings, new_settings
                )
            except Exception as e:
                changes = str(e)
        if debug:
            if not bln_changes:
                print("\n\n--- ROUTER SUCESSFULLY UPDATED ALL NEW WIFI SETTINGS! ---")
            else:
                print("\n\n--- CHANGES THAT DID NOT GET SET ---")
                _, changes = self.__compare_wifi_settings(router_settings, new_settings)
                print(changes)
        return bln_changes

    @staticmethod
    def __update_new_settings(old_settings, new_settings):
        """
        Needed for 'self.update_wifi_settings', if the user only changes
        band_mode or only changes radio_2g.bss_enable or radio_5g.bss_enable.
        """
        new = new_settings
        if old_settings.band_mode != new.band_mode:
            new.radio_2g.bss_enable = 1 if (new_settings.band_mode & 1) else 2
            new.radio_5g.bss_enable = (
                1 if int(f"{new_settings.band_mode:03b}"[1]) else 2
            )
        elif (
            old_settings.radio_2g.bss_enable != new.radio_2g.bss_enable
            or old_settings.radio_5g.bss_enable != new.radio_5g.bss_enable
        ):
            if new.radio_2g.bss_enable == 1:
                new.band_mode = 1 if new.radio_5g.bss_enable == 2 else 3
            elif new.radio_2g.bss_enable == 2:
                new.band_mode = 2 if new.radio_5g.bss_enable == 1 else 4
            else:
                new.band_mode = None
        return new

    def update_wifi_settings(self, new_settings, debug=True):
        """
        New method for updating the wifi settings. Uses either fun:301 or fun:319
        or both, depending on what the user changed.
        """
        old_settings = self.wifi_settings
        if debug:
            print("\n--- SETTINGS BEFORE UPDATING ---:")
            print(str(old_settings))

        if debug:
            print("\n--- CHANGES THAT SHOULD BE SET ---")
        _, changes = self.__compare_wifi_settings(old_settings, new_settings)
        if debug:
            print(changes)

        configuration_page = [
            "bss_enable",
            "ssid",
            "hidden",
            "pre_shared_key",
            "re_key",
            "wpa_algorithm",
        ]
        signal_page = ["band_mode", "bandwidth", "tx_mode", "channel", "smart_wifi"]
        config_page_update = any(e in str(changes) for e in configuration_page)
        signal_page_update = any(e in str(changes) for e in signal_page)

        new_settings = self.__update_new_settings(old_settings, new_settings)

        # both_pages also checks if both wifi pages (signal and configuration) are not
        # changed, so that it request fun:301 and fun:319 for settings changes that
        # cannot be set
        both_pages = (config_page_update and signal_page_update) or (
            not config_page_update and not signal_page_update
        )
        if both_pages:
            self.__set_wifi_settings(new_settings, SetFunction.WIFI_SIGNAL, debug)
        elif config_page_update and not signal_page_update:
            self.__set_wifi_settings(
                new_settings, SetFunction.WIFI_CONFIGURATION, debug
            )
        elif not config_page_update and signal_page_update:
            self.__set_wifi_settings(new_settings, SetFunction.WIFI_SIGNAL, debug)
        not_updated = self.__check_router_status(new_settings, debug)

        if both_pages and not_updated:
            self.__set_wifi_settings(
                new_settings, SetFunction.WIFI_CONFIGURATION, debug
            )
            self.__check_router_status(new_settings, debug)

    def turn_on_2g(self, debug=False):
        settings = self.wifi_settings
        settings.radio_2g.bss_enable = 1
        self.update_wifi_settings(settings, debug)

    def turn_off_2g(self, debug=False):
        settings = self.wifi_settings
        settings.radio_2g.bss_enable = 2
        self.update_wifi_settings(settings, debug)

    def turn_on_5g(self, debug=False):
        settings = self.wifi_settings
        settings.radio_5g.bss_enable = 1
        self.update_wifi_settings(settings, debug)

    def turn_off_5g(self, debug=False):
        settings = self.wifi_settings
        settings.radio_5g.bss_enable = 2
        self.update_wifi_settings(settings, debug)

    def turn_off(self, debug=False):
        settings = self.wifi_settings
        settings.band_mode = 4
        self.update_wifi_settings(settings, debug)


class WifiGuestNetworkSettings(object):
    """
    Configures the WiFi guest network settings
    """

    def __init__(self, modem):
        # The modem sometimes returns invalid XML when 'strange' values are
        # present in the settings. The recovering parser from lxml is used to
        # handle this.
        self.parser = etree.XMLParser(recover=True)

        self.modem = modem

    @property
    def wifi_guest_network_settings_xml(self):
        """
        Get the current wifi guest network settings as XML
        """
        xml_content = self.modem.xml_getter(
            GetFunction.WIRELESSGUESTNETWORK, {}
        ).content
        return etree.fromstring(xml_content, parser=self.parser)

    @staticmethod
    def __xml_value(interface, attr, coherce=True):
        """
        'XmlValue' of an interface

        Coherce the value if requested. First the value is parsed as an
        integer, if this fails it is returned as a string.
        """
        val = interface.find(attr).text
        try:  # Try to coherce to int. If it fails, return string
            if not coherce:
                return val
            return int(val)
        except (TypeError, ValueError):
            return val

    @property
    def wifi_guest_network_settings(self):
        """
        Read the current wifi guest network settings for all wifi bands (2g and 5g).
        """
        xml = self.wifi_guest_network_settings_xml

        # the compal modem returns 7 entries per band, the only used element is index 2
        one_and_only_relevant_index = 2

        interfaces = {
            "2g": list(xml.iter("Interface"))[one_and_only_relevant_index],
            "5g": list(xml.iter("Interface5G"))[one_and_only_relevant_index],
        }

        def guest_xv(band, attr, coherce=True):
            """
            xml value for the given band
            """
            try:
                return WifiGuestNetworkSettings.__xml_value(
                    interfaces[band], f"{attr}{band.upper()}", coherce
                )
            except AttributeError:
                return WifiGuestNetworkSettings.__xml_value(
                    interfaces[band], f"{attr}{band}", coherce
                )

        return GuestNetworkSettings(
            GuestNetworkEnabling(
                guest_xv("2g", "Enable") == 1, guest_xv("2g", "GuestMac")
            ),
            GuestNetworkEnabling(
                guest_xv("5g", "Enable") == 1, guest_xv("5g", "GuestMac")
            ),
            GuestNetworkProperties(
                guest_xv("2g", "BSSID"),
                guest_xv("2g", "HideNetwork"),
                guest_xv("2g", "GroupRekeyInterval"),
                guest_xv("2g", "SecurityMode"),
                guest_xv("2g", "PreSharedKey"),
                guest_xv("2g", "WpaAlgorithm"),
            ),
        )

    def update_wifi_guest_network_settings(self, properties, enable):
        """
        Method for updating the wifi guest network settings. Uses fun:308.
        The given properties are applied to all wifi bands (2g and 5g).
        The enabling has only effect on wifi bands that are currently switched on.
        Requires at least firmware CH7465LG-NCIP-6.15.30-1p3-1-NOSH.
        """
        out_settings = OrderedDict(
            [
                ("wlEnable", 1 if enable else 2),
                ("wlSsid", properties.ssid),
                ("wlHiden", properties.hidden),
                ("wlRekey", properties.re_key),
                ("wlSecurity", properties.security),
                ("wlPSkey", properties.pre_shared_key),
                ("wlWpaalg", properties.wpa_algorithm),
            ]
        )
        self.modem.xml_setter(
            SetFunction.WIFI_GUEST_NETWORK_CONFIGURATION, out_settings
        )


class DHCPSettings:
    """
    Confgure the DHCP settings
    """

    def __init__(self, modem):
        self.modem = modem
        self.parser = etree.XMLParser(recover=True)

    def add_static_lease(self, lease_ip, lease_mac):
        """
        Add a static DHCP lease
        """
        return self.modem.xml_setter(
            SetFunction.STATIC_DHCP_LEASE,
            {"data": "ADD,{ip},{mac};".format(ip=lease_ip, mac=lease_mac)},
        )

    def del_static_lease(self, lease_ip, lease_mac):
        """
        Delete a static DHCP lease
        """
        return self.modem.xml_setter(
            SetFunction.STATIC_DHCP_LEASE,
            {"data": "DEL,{ip},{mac};".format(ip=lease_ip, mac=lease_mac)},
        )

    def get_static_leases(self):
        """
        Get all static leases
        """
        xml_content = self.modem.xml_getter(GetFunction.BASICDHCP, {}).content
        tree = etree.fromstring(xml_content, parser=self.parser)
        for host in tree.findall("ReserveIpadrr"):
            yield {
                "lease_ip": host.find("LeasedIP").text,
                "lease_mac": host.find("MacAddress").text,
            }

    def set_upnp_status(self, enabled):
        """
        Ensure that UPnP is set to the given value
        """
        return self.modem.xml_setter(
            SetFunction.UPNP_STATUS,
            OrderedDict(
                [
                    ("LanIP", ""),
                    ("UPnP", 1 if enabled else 2),
                    ("DHCP_addr_s", ""),
                    ("DHCP_addr_e", ""),
                    ("subnet_Mask", ""),
                    ("DMZ", ""),
                    ("DMZenable", ""),
                ]
            ),
        )

    # Changes Router IP too, according to given range
    def set_ipv4_dhcp(self, addr_start, addr_end, num_devices, lease_time, enabled):
        """
        Change the DHCP range. This implies a change to the router IP
        **check**: The router takes the first IP in the given range
        """
        return self.modem.xml_setter(
            SetFunction.DHCP_V4,
            OrderedDict(
                [
                    ("action", 1),
                    ("addr_start_s", addr_start),
                    ("addr_end_s", addr_end),
                    ("numberOfCpes_s", num_devices),
                    ("leaseTime_s", lease_time),
                    ("mac_addr", ""),
                    ("reserved_addr", ""),
                    ("_del", ""),
                    ("enable", 1 if enabled else 2),
                ]
            ),
        )

    def set_ipv6_dhcp(
        self,
        autoconf_type,
        addr_start,
        addr_end,
        num_addrs,
        vlifetime,
        ra_lifetime,
        ra_interval,
        radvd,
        dhcpv6,
    ):
        """
        Configure IPv6 DHCP settings
        """
        return self.modem.xml_setter(
            SetFunction.DHCP_V6,
            OrderedDict(
                [
                    ("v6type", autoconf_type),
                    ("Addr_start", addr_start),
                    ("NumberOfAddrs", num_addrs),
                    ("vliftime", vlifetime),
                    ("ra_lifetime", ra_lifetime),
                    ("ra_interval", ra_interval),
                    ("radvd", radvd),
                    ("dhcpv6", dhcpv6),
                    ("Addr_end", addr_end),
                ]
            ),
        )


class MiscSettings(object):
    """
    Miscellanious settings
    """

    def __init__(self, modem):
        self.modem = modem

    def set_mtu(self, mtu_size):
        """
        Sets the MTU
        """
        return self.modem.xml_setter(SetFunction.MTU_SIZE, {"MTUSize": mtu_size})

    def set_remoteaccess(self, enabled, port=8443):
        """
        Ensure that remote access is enabled/disabled on the given port
        """
        return self.modem.xml_setter(
            SetFunction.REMOTE_ACCESS,
            OrderedDict([("RemoteAccess", 1 if enabled else 2), ("Port", port)]),
        )

    def set_forgot_pw_email(self, email_addr):
        """
        Set email address for Forgot Password function
        """
        return self.modem.xml_setter(
            SetFunction.SET_EMAIL,
            OrderedDict(
                [("email", email_addr), ("emailLen", len(email_addr)), ("opt", 0)]
            ),
        )

    def send_forgot_pw_email(self, email_addr):
        """
        Send an email to receive new or forgotten password
        """
        return self.modem.xml_setter(
            SetFunction.SEND_EMAIL,
            OrderedDict(
                [("email", email_addr), ("emailLen", len(email_addr)), ("opt", 0)]
            ),
        )


class DiagToolName(Enum):
    """
    Enumeration of diagnostic tool names
    """

    ping = "ping"
    traceroute = "traceroute"


class Diagnostics(object):
    """
    Diagnostic functions
    """

    def __init__(self, modem):
        self.modem = modem

    def start_pingtest(self, target_addr, ping_size=64, num_ping=3, interval=10):
        """
        Start Ping-Test
        """
        return self.modem.xml_setter(
            SetFunction.PING_TEST,
            OrderedDict(
                [
                    ("Type", 1),
                    ("Target_IP", target_addr),
                    ("Ping_Size", ping_size),
                    ("Num_Ping", num_ping),
                    ("Ping_Interval", interval),
                ]
            ),
        )

    def stop_pingtest(self):
        """
        Stop Ping-Test
        """
        return self.modem.xml_setter(
            SetFunction.STOP_DIAGNOSTIC, {"Ping": DiagToolName.ping}
        )

    def get_pingtest_result(self):
        """
        Get Ping-Test results
        """
        return self.modem.xml_getter(GetFunction.PING_RESULT, {})

    def start_traceroute(
        self, target_addr, max_hops, data_size, base_port, resolve_host
    ):
        """
        Start Traceroute
        """
        return self.modem.xml_setter(
            SetFunction.TRACEROUTE,
            OrderedDict(
                [
                    ("type", 1),
                    ("Tracert_IP", target_addr),
                    ("MaxHops", max_hops),
                    ("DataSize", data_size),
                    ("BasePort", base_port),
                    ("ResolveHost", 1 if resolve_host else 0),
                ]
            ),
        )

    def stop_traceroute(self):
        """
        Stop Traceroute
        """
        return self.modem.xml_setter(
            SetFunction.STOP_DIAGNOSTIC,
            {"Traceroute": DiagToolName.traceroute},
        )

    def get_traceroute_result(self):
        """
        Get Traceroute results
        """
        return self.modem.xml_getter(GetFunction.TRACEROUTE_RESULT, {})


class BackupRestore(object):
    """
    Configuration backup and restore
    """

    def __init__(self, modem):
        # The modem sometimes returns invalid XML when 'strange' values are
        # present in the settings. The recovering parser from lxml is used to
        # handle this.
        self.parser = etree.XMLParser(recover=True)

        self.modem = modem

    def backup(self, filename=None):
        """
        Backup the configuration and return it's content
        """
        res = self.modem.xml_getter(GetFunction.GLOBALSETTINGS, {})
        xml = etree.fromstring(res.content, parser=self.parser)

        if not filename:
            fname = xml.find("ConfigVenderModel").text + "-Cfg.bin"
        else:
            fname = filename

        res = self.modem.get(
            "/xml/getter.xml",
            params={"filename": fname},
            allow_redirects=False,
        )
        if res.status_code != 200:
            LOGGER.error("Did not get configfile response!" " Wrong config file name?")
            return None

        return res.content

    def restore(self, data):
        """
        Restore the configuration from the binary string in `data`
        """
        LOGGER.info("Restoring config. Modem will reboot after that")
        return self.modem.post_binary(
            "/xml/getter.xml",
            data,
            "Cfg_Restore.bin",
            params={"Restore": len(data)},
        )


class FuncScanner(object):
    """
    Scan the modem for existing function calls
    """

    def __init__(self, modem, pos, key):
        self.modem = modem
        self.current_pos = pos
        self.key = modem.sanitize_key(key)
        self.last_login = -1

    @property
    def is_valid_session(self):
        """
        Is the current sesion valid?
        """
        LOGGER.debug("Last login %d", self.last_login)
        res = self.modem.xml_getter(GetFunction.CM_SYSTEM_INFO, {})
        return res.status_code == 200

    def scan(self, quiet=False):
        """
        Scan the modem for functions. This iterates of the function calls
        """
        res = None
        while not res or res.text == "":
            if not quiet:
                LOGGER.info("func=%s", self.current_pos)

            res = self.modem.xml_getter(self.current_pos, {})
            if res.text == "":
                if not self.is_valid_session:
                    self.last_login = self.current_pos
                    self.modem.login(self.key)
                    if not quiet:
                        LOGGER.info("Had to login at index %s", self.current_pos)
                    continue

            if res.status_code == 200:
                self.current_pos += 1
            else:
                raise ValueError("HTTP {}".format(res.status_code))

        return res

    def scan_to_file(self):
        """
        Scan and write results to `func_i.xml` for all indices
        """
        while True:
            res = self.scan()
            xmlstr = minidom.parseString(res.content).toprettyxml(indent="   ")
            with io.open(
                "func_%i.xml" % (self.current_pos - 1), "wt"
            ) as f:  # noqa pylint: disable=invalid-name
                f.write("===== HEADERS =====\n")
                f.write(str(res.headers))
                f.write("\n===== DATA ======\n")
                f.write(xmlstr)

    def enumerate(self):
        """
        Enumerate the function calls, outputting id <=> response tag name pairs
        """
        while True:
            res = self.scan(quiet=True)
            xml = minidom.parseString(res.content)
            LOGGER.info(
                "%s = %d",
                xml.documentElement.tagName.upper(),
                self.current_pos - 1,
            )


class LanTable:
    """Table of known devices."""

    ETHERNET = "Ethernet"
    WIFI = "WIFI"
    TOTAL = "totalClient"

    def __init__(self, modem):
        self.modem = modem
        self.parser = etree.XMLParser(recover=True)
        self.table = None
        self.refresh()

    def _parse_lan_table_xml(self, xml):
        table = {LanTable.ETHERNET: [], LanTable.WIFI: []}
        for con_type in table.keys():
            for client in xml.find(con_type).findall("clientinfo"):
                client_info = {}
                for prop in client:
                    client_info[prop.tag] = prop.text
                table[con_type].append(client_info)
        table[LanTable.TOTAL] = xml.find(LanTable.TOTAL).text
        self.table = table

    def _check_data(self):
        if self.table is None:
            self.refresh()

    def refresh(self):
        resp = self.modem.xml_getter(GetFunction.LANUSERTABLE, {})
        if resp.status_code != 200:
            LOGGER.error(
                "Didn't receive correct response, try to call " "LanTable.refresh()"
            )
            return
        xml = etree.fromstring(resp.content, parser=self.parser)
        self._parse_lan_table_xml(xml)

    def get_lan(self):
        self._check_data()
        return self.table.get(LanTable.ETHERNET)

    def get_wifi(self):
        self._check_data()
        return self.table.get(LanTable.WIFI)

    def get_client_count(self):
        self._check_data()
        return self.table.get(LanTable.TOTAL)
