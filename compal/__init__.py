"""
Client for the Compal CH7465LG/Ziggo Connect box cable modem
"""
import io
import itertools
import logging
import urllib
from collections import OrderedDict
from dataclasses import dataclass
from enum import Enum
from typing import Optional
from xml.dom import minidom

import requests
from lxml import etree

from .functions import GetFunction, SetFunction

LOGGER = logging.getLogger(__name__)
logging.basicConfig()

LOGGER.setLevel(logging.INFO)


class NatMode(Enum):
    """
    Values for NAT-Mode
    """

    enabled = 1
    disabled = 2


class Compal(object):
    """
    Basic functionality for the router's API
    """

    def __init__(self, router_ip, key=None, timeout=10):
        self.router_ip = router_ip
        self.timeout = timeout
        self.key = key

        self.session = requests.Session()
        # limit the number of redirects
        self.session.max_redirects = 3

        # after a response is received, process the token field of the response
        self.session.hooks["response"].append(self.token_handler)
        # session token is initially empty
        self.session_token = None

        LOGGER.debug("GetFunctionting initial token")
        # check the initial URL. If it is redirected, perform the initial
        # installation
        self.initial_res = self.get("/")

        if self.initial_res.url.endswith("common_page/FirstInstallation.html"):
            self.initial_setup()
        elif not self.initial_res.url.endswith("common_page/login.html"):
            LOGGER.error("Was not redirected to login page:" " concurrent session?")

    def initial_setup(self, new_key=None):
        """
        Replay the settings made during initial setup
        """
        LOGGER.info("Initial setup: english.")

        if new_key:
            self.key = new_key

        if not self.key:
            raise ValueError("No key/password availalbe")

        self.xml_getter(GetFunction.MULTILANG, {})
        self.xml_getter(GetFunction.LANGSETLIST, {})
        self.xml_getter(GetFunction.MULTILANG, {})

        self.xml_setter(SetFunction.LANGUAGE, {"lang": "en"})
        # Login or change password? Not sure.
        self.xml_setter(
            SetFunction.LOGIN,
            OrderedDict([("Username", "admin"), ("Password", self.key)]),
        )
        # GetFunction current wifi settings (?)
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
                "%s [%s] [token: %s]", res.status_code, res.url, self.session_token,
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
            "Content-Disposition": 'form-data; name="file"; filename="%s"'
            % filename,  # noqa
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

        res = self.xml_setter(
            SetFunction.LOGIN,
            OrderedDict(
                [("Username", "admin"), ("Password", key if key else self.key)]
            ),
        )

        if res.status_code != 200:
            if res.headers["Location"].endswith("common_page/Access-denied.html"):
                raise ValueError("Access denied. " "Still logged in somewhere else?")
            else:
                raise ValueError("Login failed for unknown reason!")

        tokens = urllib.parse.parse_qs(res.text)

        token_sids = tokens.get("SID")
        if not token_sids:
            raise ValueError("No valid session-Id received! Wrong password?")

        token_sid = token_sids[0]
        LOGGER.info("[login] SID %s", token_sid)

        self.session.cookies.update({"SID": token_sid})

        return res

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


class Proto(Enum):
    """
    protocol (from form): 1 = tcp, 2 = udp, 3 = both
    """

    tcp = 1
    udp = 2
    both = 3


@dataclass
class PortForward:
    local_ip: Optional[str] = None
    ext_port: Optional[int] = None
    int_port: Optional[int] = None
    proto: Optional[str] = None
    enabled: Optional[bool] = None
    delete: Optional[bool] = None
    idd: Optional[str] = None
    id: Optional[str] = None
    lan_ip: Optional[str] = None


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
                int_port=(r_int(rule, "start_portIn"), r_int(rule, "end_portIn"),),
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


class FilterAction(Enum):
    """
    Filter action, used by internet access filters
    """

    add = 1
    delete = 2
    enable = 3


class TimerMode(Enum):
    """
    Timermodes used for internet access filtering
    """

    generaltime = 1
    dailytime = 2


class Filters(object):
    """
    Provide filters for accessing the internet.

    Supports access-restriction via parental control (Keywords, url-lists,
    timetable), client's MAC address and by specific ports.
    """

    def __init__(self, modem):
        self.modem = modem

    def set_parental_control(
        self, safe_search, keyword_list, allow_list, deny_list, timer_mode, enable,
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

    def set_ipv6_filter_rule(self):
        """
        To be integrated...
        """
        params = OrderedDict(
            [
                ("act", ""),
                ("dir", ""),
                ("enabled", ""),
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
                ("del", ""),
                ("idd", ""),
                ("sIpRange", ""),
                ("dsIpRange", ""),
                ("PortRange", ""),
                ("TMode", ""),
                ("TRule", ""),
            ]
        )
        return self.modem.xml_setter(SetFunction.IPV6_FILTER_RULE, params)

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


@dataclass
class RadioSetFunctiontings:
    bss_coexistence: Optional[str] = None
    radio_2g: Optional[str] = None
    radio_5g: Optional[str] = None
    nv_country: Optional[str] = None
    channel_range: Optional[str] = None


@dataclass
class BandSetting:
    mode: Optional[str] = None
    ssid: Optional[str] = None
    bss_enable: Optional[str] = None
    radio: Optional[str] = None
    bandwidth: Optional[str] = None
    tx_mode: Optional[str] = None
    multicast_rate: Optional[str] = None
    hidden: Optional[str] = None
    pre_shared_key: Optional[str] = None
    tx_rate: Optional[str] = None
    re_key: Optional[str] = None
    channel: Optional[str] = None
    security: Optional[str] = None
    wpa_algorithm: Optional[str] = None


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
        assert band in ("2g", "5g",)
        band_number = int(band[0])

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
                return xml_value("{}{}".format(attr, band.upper()), coherce)
            except AttributeError:
                return xml_value("{}{}".format(attr, band), coherce)

        return BandSetting(
            radio=band,
            mode=bool(xml_value("Bandmode") & band_number),
            ssid=band_xv("SSID", False),
            bss_enable=bool(band_xv("BssEnable")),
            bandwidth=band_xv("BandWidth"),
            tx_mode=band_xv("TransmissionMode"),
            multicast_rate=band_xv("MulticastRate"),
            hidden=band_xv("HideNetwork"),
            pre_shared_key=band_xv("PreSharedKey"),
            tx_rate=band_xv("TransmissionRate"),
            re_key=band_xv("GroupRekeyInterval"),
            channel=band_xv("CurrentChannel"),
            security=band_xv("SecurityMode"),
            wpa_algorithm=band_xv("WpaAlgorithm"),
        )

    @property
    def wifi_settings(self):
        """
        Read the wifi settings
        """
        xml = self.wifi_settings_xml

        return RadioSetFunctiontings(
            radio_2g=WifiSettings.band_setting(xml, "2g"),
            radio_5g=WifiSettings.band_setting(xml, "5g"),
            nv_country=int(xml.find("NvCountry").text),
            channel_range=int(xml.find("ChannelRange").text),
            bss_coexistence=bool(xml.find("BssCoexistence").text),
        )

    def update_wifi_settings(self, settings):
        """
        Update the wifi settings
        """
        # Create the object.
        def transform_radio(radio_settings):  # rs = radio_settings
            """
            Perpare radio settings object for the request.
            Returns a OrderedDict with the correct keys for this band
            """
            # Create the dict
            out = OrderedDict(
                [
                    ("BandMode", int(radio_settings.mode)),
                    ("Ssid", radio_settings.ssid),
                    ("Bandwidth", radio_settings.bandwidth),
                    ("TxMode", radio_settings.tx_mode),
                    ("MCastRate", radio_settings.multicast_rate),
                    ("Hiden", int(radio_settings.hidden)),
                    ("PSkey", radio_settings.pre_shared_key),
                    ("Txrate", radio_settings.tx_rate),
                    ("Rekey", radio_settings.re_key),
                    ("Channel", radio_settings.channel),
                    ("Security", radio_settings.security),
                    ("Wpaalg", radio_settings.wpa_algorithm),
                ]
            )

            # Prefix 'wl', Postfix the band
            return OrderedDict(
                [
                    ("wl{}{}".format(k, radio_settings.radio), v)
                    for (k, v) in out.items()
                ]
            )

        # Alternate the two setting lists
        out_s = []

        for item_2g, item_5g in zip(
            transform_radio(settings.radio_2g).items(),
            transform_radio(settings.radio_5g).items(),
        ):
            out_s.append(item_2g)
            out_s.append(item_5g)

            if item_2g[0] == "wlHiden5g":
                out_s.append(("wlCoexistence", settings.bss_coexistence))

        # Join the settings
        out_settings = OrderedDict(out_s)

        return self.modem.xml_setter(SetFunction.WIFI_SETTINGS, out_settings)


class DHCPSettings:
    """
    Confgure the DHCP settings
    """

    def __init__(self, modem):
        self.modem = modem

    def add_static_lease(self, lease_ip, lease_mac):
        """
        Add a static DHCP lease
        """
        return self.modem.xml_setter(
            SetFunction.STATIC_DHCP_LEASE,
            {"data": "ADD,{ip},{mac};".format(ip=lease_ip, mac=lease_mac)},
        )

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


class MiscSetFunctiontings(object):
    """
    Miscellanious settings
    """

    def __init__(self, modem):
        self.modem = modem

    def set_mtu(self, mtu_size):
        """
        SetFunctions the MTU
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
        SetFunction email address for Forgot Password function
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
            SetFunction.STOP_DIAGNOSTIC, {"Traceroute": DiagToolName.traceroute},
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
            "/xml/getter.xml", params={"filename": fname}, allow_redirects=False,
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
            "/xml/getter.xml", data, "Cfg_Restore.bin", params={"Restore": len(data)},
        )


class FuncScanner(object):
    """
    Scan the modem for existing function calls
    """

    def __init__(self, modem, pos, key):
        self.modem = modem
        self.current_pos = pos
        self.key = key
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
                "%s = %d", xml.documentElement.tagName.upper(), self.current_pos - 1,
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
