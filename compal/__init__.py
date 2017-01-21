import io
import itertools
import logging
import urllib

import xml.etree.ElementTree as ET
from xml.dom import minidom

from collections import OrderedDict
from enum import Enum

import requests

from recordclass import recordclass

from .functions import Set, Get

LOGGER = logging.getLogger(__name__)
logging.basicConfig()

LOGGER.setLevel(logging.INFO)


class Compal(object):
    def __init__(self, ip, key=None, timeout=10):
        self.ip = ip
        self.timeout = timeout
        self.key = key

        self.session = requests.Session()

        self.session.hooks['response'].append(self.token_handler)

        LOGGER.debug("Getting initial token")
        self.initial_res = self.get('/', allow_redirects=False)

        if self.initial_res.url.endswith('common_page/FirstInstallation.html'):
            self.initial_setup()
        elif not self.initial_res.url.endswith('common_page/login.html'):
            LOGGER.error("Was not redirected to login page:"
                         " concurrent session?")

    def initial_setup(self, newKey=None):
        """
        Replay the settings made during initial setup
        """
        LOGGER.info("Initial setup: english.")

        if newKey:
            self.key = newKey

        if not self.key:
            raise ValueError("No key/password availalbe")


        self.xml_getter(Get.MULTILANG, {})
        self.xml_getter(Get.LANGSETLIST, {})
        self.xml_getter(Get.MULTILANG, {})

        self.xml_setter(Set.LANGUAGE, {'lang': 'en'})
        # Login or change password? Not sure.
        self.xml_setter(Set.LOGIN, OrderedDict([
            ('Username', 'admin'),
            ('Password', self.key)
        ]))
        # Get current wifi settings (?)
        self.xml_getter(Get.WIRELESSBASIC, {})

        # Some sheets with hints, no request
        # installation is done:
        self.xml_setter(Set.INSTALL_DONE, {
            'install': 0,
            'iv': 1,
            'en': 0
        })

    def url(self, path):
        while path.startswith('/'):
            path = path[1:]

        return "http://{ip}/{path}".format(ip=self.ip, path=path)

    def token_handler(self, res, *args, **kwargs):
        """
        Handle the anti-replace token system
        """
        self.session_token = res.cookies.get('sessionToken')

        if res.status_code == 302:
            LOGGER.info("302 [%s] => '%s' [token: %s]", res.url,
                        res.headers['Location'], self.session_token)
        else:
            LOGGER.debug("%s [%s] [token: %s]", res.status_code, res.url,
                         self.session_token)

    def post(self, path, _data, **kwargs):
        data = OrderedDict()
        data['token'] = self.session_token

        if 'fun' in _data:
            data['fun'] = _data.pop('fun')

        data.update(_data)

        LOGGER.debug("POST [%s]: %s", path, data)

        res = self.session.post(self.url(path), data=data,
                                allow_redirects=False, timeout=self.timeout,
                                **kwargs)

        return res

    def post_binary(self, path, binary_data, filename, **kwargs):
        headers = {
            'Content-Disposition':'form-data; name=\"file\"; filename=\"%s\"' % filename,
            'Content-Type':'application/octet-stream'
        }
        self.session.post(self.url(path), data=binary_data, headers=headers, **kwargs)

    def get(self, path, **kwargs):
        res = self.session.get(self.url(path), timeout=self.timeout, **kwargs)

        self.session.headers.update({'Referer': res.url})
        return res

    def xml_getter(self, fun, params):
        params['fun'] = fun

        return self.post('/xml/getter.xml', params)

    def xml_setter(self, fun, params=None):
        params['fun'] = fun

        return self.post('/xml/setter.xml', params)

    def login(self, key=None):
        """
        Login. Allow this function to override the key.
        """

        res = self.xml_setter(Set.LOGIN, OrderedDict([
            ('Username', 'admin'),
            ('Password', key if key else self.key)
        ]))

        assert res.status_code == 200

        tokens = urllib.parse.parse_qs(res.text)
        SID = tokens.get('SID')
        if not SID:
            raise ValueError('No valid session-Id received! Wrong password?')

        SID = SID[0]
        LOGGER.info("[login] SID %s", SID)

        self.session.cookies.update({'SID': SID})

        return res

    def reboot(self):
        try:
            return self.xml_setter(Set.REBOOT, {})
        except:
            return None


    def factory_reset(self):
        default_settings = self.xml_getter(Get.DEFAULTVALUE, {})

        try:
            self.xml_setter(Set.FACTORY_RESET, {})
        except:
            pass
        return default_settings


    def logout(self):
        return self.xml_setter(Set.LOGOUT, {})


class Proto(Enum):
    """
    protocol (from form): 1 = tcp, 2 = udp, 3 = both
    """
    tcp = 1
    udp = 2
    both = 3


PortForward = recordclass('PortForward', ['local_ip', 'ext_port', 'int_port',
        'proto', 'enabled', 'delete', 'idd', 'id', 'lan_ip'])
# idd, id, lan_ip are None by default, delte is False by default
PortForward.__new__.__defaults__ = (False, None, None, None,)



class PortForwards(object):
    def __init__(self, modem):
        self.modem = modem

    @property
    def rules(self):
        res = self.modem.xml_getter(Get.FORWARDING, {})

        xml = ET.fromstring(res.content)
        router_ip = xml.find('LanIP').text

        for rule in xml.findall('instance'):
            def r_int(attr):  # integer value for rule's child's text
                return int(rule.find(attr).text)

            yield PortForward(
                local_ip=rule.find('local_IP').text,
                lan_ip=router_ip,
                id=r_int('id'),
                ext_port=(r_int('start_port'), r_int('end_port')),
                int_port=(r_int('start_portIn'), r_int('end_portIn')),
                proto=Proto(r_int('protocol')),
                enabled=bool(r_int('enable')), idd=bool(r_int('idd'))
            )

    def update_firewall(self, enabled=False, fragment=False, port_scan=False,
                        ip_flood=False, icmp_flood=False, icmp_rate=15):
        assert enabled or not (fragment or port_scan or ip_flood or icmp_flood)

        def b2i(b):  # Bool-2-int
            return 1 if b else 2

        return self.modem.xml_setter(Set.FIREWALL, OrderedDict([
            ('firewallProtection', b2i(enabled)),
            ('blockIpFragments', ''),
            ('portScanDetection', ''),
            ('synFloodDetection', ''),
            ('IcmpFloodDetection', ''),
            ('IcmpFloodDetectRate', icmp_rate),
            ('action', ''),
            ('IPv6firewallProtection', ''),
            ('IPv6blockIpFragments', ''),
            ('IPv6portScanDetection', ''),
            ('IPv6synFloodDetection', ''),
            ('IPv6IcmpFloodDetection', ''),
            ('IPv6IcmpFloodDetectRate', '')
        ]))

    def add_forward(self, local_ip, ext_port, int_port, proto: Proto,
                    enabled=True):
        """
        Add a port forward. int_port and ext_port can be ranges. Deletion param
        is ignored for now.
        """
        start_int, end_int = itertools.islice(itertools.repeat(int_port), 0, 2)
        start_ext, end_ext = itertools.islice(itertools.repeat(ext_port), 0, 2)

        return self.modem.xml_setter(Set.PORT_FORWARDING, OrderedDict([
            ('action', 'add'),
            ('instance', ''),
            ('local_IP', local_ip),
            ('start_port', start_ext), ('end_port', end_ext),
            ('start_portIn', start_int), ('end_portIn', end_int),
            ('protocol', proto.value),
            ('enable', int(enabled)), ('delete', int(False)),
            ('idd', '')
        ]))

    def update_rules(self, rules):
        # Will iterate multiple times, ensure it is a list.
        rules = list(rules)

        empty_asterisk = '*'*(len(rules) - 1)

        # Order of parameters matters (code smell: YES)
        params = OrderedDict([
            ('action', 'apply'),
            ('instance', '*'.join([str(r.id) for r in rules])),
            ('local_IP', ''),
            ('start_port', ''), ('end_port', ''),
            ('start_portIn', empty_asterisk),
            ('end_portIn', ''),
            ('protocol', '*'.join([str(r.proto.value) for r in rules])),
            ('enable', '*'.join([str(int(r.enabled)) for r in rules])),
            ('delete', '*'.join([str(int(r.delete)) for r in rules])),
            ('idd', empty_asterisk)
        ])

        LOGGER.info("Updating port forwards")
        LOGGER.debug(params)

        return self.modem.xml_setter(Set.PORT_FORWARDING, params)

RadioSettings = recordclass('RadioSettings', ['bss_coexistence', 'radio_2g',
    'radio_5g', 'nv_country', 'channel_range'])
BandSetting = recordclass('BandSetting', ['mode', 'ssid', 'bss_enable', 'radio',
    'bandwidth', 'tx_mode', 'multicast_rate', 'hidden', 'pre_shared_key',
    'tx_rate', 're_key', 'channel', 'security', 'wpa_algorithm'])


class WifiSettings(object):
    def __init__(self, modem):
        self.modem = modem

    @property
    def wifi_settings_xml(self):
        return ET.fromstring(self.modem.xml_getter(Get.WIRELESSBASIC, {}).content)

    @staticmethod
    def band_setting(xml, band):
        assert band in ('2g', '5g',)
        band_number = int(band[0])

        def xv(attr, coherce=True):
            val = xml.find(attr).text
            try:  # Try to coherce to int. If it fails, return string
                if not coherce:
                    return val
                return int(val)
            except ValueError:
                return val

        def band_xv(attr, coherce=True):
            try:
                return xv('{}{}'.format(attr, band.upper()), coherce)
            except AttributeError:
                return xv('{}{}'.format(attr, band), coherce)


        return BandSetting(
            radio=band,
            mode=bool(xv('Bandmode') & band_number),
            ssid=band_xv('SSID', False),
            bss_enable=bool(band_xv('BssEnable')),
            bandwidth=band_xv('BandWidth'),
            tx_mode=band_xv('TransmissionMode'),
            multicast_rate=band_xv('MulticastRate'),
            hidden=band_xv('HideNetwork'),
            pre_shared_key=band_xv('PreSharedKey'),
            tx_rate=band_xv('TransmissionRate'),
            re_key=band_xv('GroupRekeyInterval'),
            channel=band_xv('CurrentChannel'),
            security=band_xv('SecurityMode'),
            wpa_algorithm=band_xv('WpaAlgorithm')
        )

    @property
    def wifi_settings(self):
        xml = self.wifi_settings_xml

        return RadioSettings(
                radio_2g=WifiSettings.band_setting(xml, '2g'),
                radio_5g=WifiSettings.band_setting(xml, '5g'),
                nv_country=int(xml.find('NvCountry').text),
                channel_range=int(xml.find('ChannelRange').text),
                bss_coexistence=bool(xml.find('BssCoexistence').text)
        )

    def update_wifi_settings(self, settings):
        # Create the object.
        def transform_radio(rs): # rs = radio_settings
            # Create the dict
            out = OrderedDict([
                ('BandMode', int(rs.mode)),
                ('Ssid', rs.ssid),
                ('Bandwidth', rs.bandwidth),
                ('TxMode', rs.tx_mode),
                ('MCastRate', rs.multicast_rate),
                ('Hiden', int(rs.hidden)),
                ('PSkey', rs.pre_shared_key),
                ('Txrate', rs.tx_rate),
                ('Rekey', rs.re_key),
                ('Channel', rs.channel),
                ('Security', rs.security),
                ('Wpaalg', rs.wpa_algorithm)
            ])

            # Prefix 'wl', Postfix the band
            return OrderedDict([('wl{}{}'.format(k, rs.radio), v) for (k, v) in
                                out.items()])

        # Alternate the two setting lists
        out_s = []

        for x, y in zip(transform_radio(settings.radio_2g).items(),
                        transform_radio(settings.radio_5g).items()):
            out_s.append(x)
            out_s.append(y)

            if y[0] == 'wlHiden5g':
                out_s.append(('wlCoexistence', settings.bss_coexistence))

        # Join the settings
        out_settings = OrderedDict(out_s)

        return self.modem.xml_setter(Set.WIFI_SETTINGS, out_settings)


class DHCPSettings(object):
    def __init__(self, modem):
        self.modem = modem

    def add_static_lease(self, ip, mac):
        return self.modem.xml_setter(Set.STATIC_DHCP_LEASE, {
            'data': 'ADD,{ip},{mac};'.format(ip=ip, mac=mac)
        })

    def set_upnp_status(self, enabled):
        return self.modem.xml_setter(Set.UPNP_STATUS, OrderedDict([
            ('LanIP', ''),
            ('UPnP', 1 if enabled else 2),
            ('DHCP_addr_s', ''), ('DHCP_addr_e', ''),
            ('subnet_Mask', ''),
            ('DMZ', ''), ('DMZenable', '')
        ]))

    # Changes Router IP too, according to given range
    def set_ipv4_dhcp(self, addr_start, addr_end, num_devices, lease_time, enabled):
        return self.modem.xml_setter(Set.DHCP_V4, OrderedDict([
            ('action', 1),
            ('addr_start_s', addr_start), ('addr_end_s', addr_end),
            ('numberOfCpes_s', num_devices),
            ('leaseTime_s', lease_time),
            ('mac_addr', ''),
            ('reserved_addr', ''),
            ('_del', ''),
            ('enable', 1 if enabled else 2)
        ]))

    def set_ipv6_dhcp(autoconf_type, addr_start, addr_end, num_addrs,
                        vlifetime, ra_lifetime, ra_interval, radvd, dhcpv6):
        return self.modem.xml_setter(Set.DHCP_V6, OrderedDict([
            ('v6type', autoconf_type),
            ('Addr_start', addr_start),
            ('NumberOfAddrs', num_addrs),
            ('vliftime', vlifetime),
            ('ra_lifetime', ra_lifetime),
            ('ra_interval', ra_interval),
            ('radvd', radvd),
            ('dhcpv6', dhcpv6),
            ('Addr_end', addr_end)
        ]))

class MiscSettings(object):
    def __init__(self, modem):
        self.modem

    def set_mtu(self, mtu_size):
        return self.modem.xml_setter(Set.MTU_SIZE, OrderedDict([
            ('MTUSize', mtu_size)
        ]))

    def set_remoteaccess(self, enabled, port=8443):
        return self.modem.xml_setter(Set.REMOTE_ACCESS, OrderedDict([
            ('RemoteAccess', 1 if enabled else 2),
            ('Port', port)
        ]))

class Diagnostics(object):
    def __init__(self, modem):
        self.modem = modem

    def test_ping(self, target_addr, ping_size=64, num_ping=3, interval=10):
        return self.modem.xml_setter(Set.PING_TEST, OrderedDict([
            ('Target_IP', target_addr),
            ('Ping_Size', ping_size),
            ('Num_Ping', num_ping),
            ('Ping_Interval', interval)
        ]))

    def traceroute(self, target_addr, max_hops, data_size, base_port, resolve_host):
        return self.modem.xml_setter(Set.TRACEROUTE, OrderedDict([
            ('Tracert_IP', target_addr),
            ('MaxHops', max_hops),
            ('DataSize', data_size),
            ('BasePort', base_port),
            ('ResolveHost', 1 if resolve_host else 0)
        ]))

class BackupRestore(object):
    def __init__(self, modem):
        self.modem = modem

    def backup(self):
        res = self.modem.xml_getter(Get.GLOBALSETTINGS, {})
        xml = ET.fromstring(res.content)
        vendor_model = xml.find('ConfigVenderModel').text

        res = self.modem.get("/xml/getter.xml?filename=%s-Cfg.bin" % 
                                vendor_model, allow_redirects=False)
        if res.status_code != 200:
            LOGGER.error("Did not get configfile response!"
                        " Wrong config file name?")
            return None

        return res.content

    def restore(self, data):
        LOGGER.info("Restoring config. Modem will be unresponsive for a while!")
        res = self.modem.post_binary("/xml/getter.xml?Restore=%i" %
                                        len(data), data, "Config_Restore.bin")
        return res

class FuncScanner(object):
    def __init__(self, modem, pos, key):
        self.modem = modem
        self.current_pos = pos
        self.key = key
        self.last_login = -1

    @property
    def is_valid_session(self):
        LOGGER.debug("Last login %d", self.last_login)
        res = self.modem.xml_getter(Get.CM_SYSTEM_INFO, {})
        return res.status_code == 200

    def scan(self, quiet=False):
        res = None
        while not res or res.text is '':
            if not quiet:
                LOGGER.info("func=%s", self.current_pos)

            res = self.modem.xml_getter(self.current_pos, {})
            if res.text == '':
                if not self.is_valid_session:
                    self.last_login = self.current_pos
                    self.modem.login(self.key)
                    if not quiet:
                        LOGGER.info("Had to login at index %d", self.current_pos)
                    continue

            if res.status_code == 200:
                self.current_pos += 1
            else:
                raise ValueError("HTTP {}".format(res.status_code))

        return res

    def scan_to_file(self):
        while True:
            res = self.scan()
            xmlstr = minidom.parseString(res.content).toprettyxml(indent="   ")
            with io.open("func_%i.xml" % (self.current_pos - 1), "wt") as f:
                f.write("===== HEADERS =====\n")
                f.write(str(res.headers))
                f.write("\n===== DATA ======\n")
                f.write(xmlstr)

    def enumerate(self):
        while True:
            res = self.scan(quiet=True)
            xml = minidom.parseString(res.content)
            LOGGER.info("%s = %i" % (xml.documentElement.tagName.upper(), self.current_pos - 1))

# How to use?
# modem = Compal('192.168.178.1', '1234567')
# modem.login()
# Or provide key on login:
# modem.login('1234567')
# fw = PortForwards(modem)
# print(list(fw.rules))
