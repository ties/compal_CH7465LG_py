"""
POST /xml/getter.xml HTTP/1.1
Host: 192.168.178.1
Connection: keep-alive
Content-Length: 7
Accept: application/xml, text/xml, */*; q=0.01
Origin: http://192.168.178.1
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2566.0 Safari/537.36
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
DNT: 1
Referer: http://192.168.178.1/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.8,nl;q=0.6
Cookie: SID=1519658240

fun=121


fun=3 ==> login page
fun=16 ==> logout

UPNP/DHCP settings
/setter.xml, fun=101
    LanIP:
    UPnP:2
    DHCP_addr_s:
    DHCP_addr_e:
    subnet_Mask:
    DMZ:
    DMZenable:
2 => disabled.

Firewall settings:
/setter.xml, fun=116
    firewallProtection:2
    blockIpFragments:2
    portScanDetection:2
    synFloodDetection:2
    IcmpFloodDetection:2
    IcmpFloodDetectRate:15
    action:
    IPv6firewallProtection:
    IPv6blockIpFragments:
    IPv6portScanDetection:
    IPv6synFloodDetection:
    IPv6IcmpFloodDetection:
    IPv6IcmpFloodDetectRate:
=> disabled=2


fun = 300+ => wifi settings
  324: default wifi pwd

503: MTA/Docsis errors?
504: MTA Provisioning?

/setter.xml fun=126:
    ping
    Type: 0
    Target_IP: <ip>
    Ping_size: 64
    Num_Ping: 3
    Ping_Interval: 1
=>
/getter.xml fun=128
Many posts (only fun/token as params) for results.

/setter.xml fun=127:
    traceroute
    type: 0
    Tracert_IP: "hostname"
    MaxHops: "30"
    DatSize: "32"
    BasePort: "33424"
    ResolveHost: "0"
=>
/getter.xml fun=129
Many posts (only fun/token as params) for results.

Port forward:
/setter.xml fun=122
    action:add
    instance:
    local_IP:192.168.178.17
    start_port:443
    end_port:443
    start_portIn:443
    end_portIn:443
    protocol:1
    enable:1
    delete:0
    idd:

Disable/Enable port forward:
/setter.xml fun=122
    action:apply
    instance:1*2*3
    local_IP:
    start_port:
    end_port:
    start_portIn:**
    end_portIn:
    protocol:1*1*1
    enable:1*1*1
    delete:0*0*0
    idd:**

/getter.xml fun=121
  Firewall rules (XML)

Get IP leases
/getter.xml, fun=123
  method: 2 => static lease

Static DHCP leases:
/setter.xml fun=148
  token:1246383104
  fun:148
  data:ADD,<ip>,<mac>;

/getter.xml fun=300
  Wifi settings

/setter.xml fun=301
  Change wifi settings

  fun:301
wlBandMode2g:1
wlBandMode5g:1
wlSsid2g:ssid24
wlSsid5g:ssid5g
wlBandwidth2g:2
wlBandwidth5g:3
wlTxMode2g:6
wlTxMode5g:14
wlMCastRate2g:1
wlMCastRate5g:1
wlHiden2g:2
wlHiden5g:2
wlCoexistence:1
wlPSkey2g: keykeykey
wlPSkey5g: key5gkey5g
wlTxrate2g:0
wlTxrate5g:0
wlRekey2g:0
wlRekey5g:0
wlChannel2g:13
wlChannel5g:0
wlSecurity2g:8
wlSecurity5g:8
wlWpaalg2g:3
wlWpaalg5g:3

/setter.xml fun=319
  Wifi enable/disable radio's

Similar to 301 except for bandmode (single value)

fun:319
wlBandMode:4
wlSsid2g:ssid24
wlSsid5g:ssid5g
wlBandwidth2g:1
wlBandwidth5g:3
wlTxMode2g:6
wlTxMode5g:14
wlMCastRate2g:1
wlMCastRate5g:1
wlHiden2g:2
wlHiden5g:2
wlCoexistence:1
wlPSkey2g:keykeykey
wlPSkey5g:key5gkey5g
wlTxrate2g:0
wlTxrate5g:0
wlRekey2g:0
wlRekey5g:0
wlChannel2g:0
wlChannel5g:0
wlSecurity2g:4
wlSecurity5g:4
wlWpaalg2g:2
wlWpaalg5g:2

/setter.xml fun=133
 -> modem reboot

## Factory reset:
  * /getter.xml fun=324
    * Response that contains the default ssid and password
  * /setter.xml fun=7
    * Factory reset starts
"""
import itertools
import logging
import urllib



import xml.etree.ElementTree as ET

from collections import OrderedDict
from enum import Enum

import requests

from recordclass import recordclass


LOGGER = logging.getLogger(__name__)
logging.basicConfig()

LOGGER.setLevel(logging.INFO)


class Compal(object):
    def __init__(self, ip):
        self.ip = ip
        self.session = requests.Session()

        self.session.hooks['response'].append(self.token_handler)

        LOGGER.debug("Getting initial token")
        self.initial_res = self.get('/')

        if self.initial_res.url.endswith('common_page/FirstInstallation.html'):
            self.initial_setup()
        elif not self.initial_res.url.endswith('common_page/login.html'):
            LOGGER.error("Was not redirected to login page:"
                         " concurrent session?")

    def initial_setup(self):
        """
        Replay the settings made during initial setup
        """
        LOGGER.info("Initial setup: english.")

        self.xml_setter(4, {'lang': 'en'})
        self.xml_setter(20, {
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
                                allow_redirects=False, **kwargs)

        return res

    def get(self, path, **kwargs):
        res = self.session.get(self.url(path), **kwargs)

        self.session.headers.update({'Referer': res.url})
        return res

    def xml_getter(self, fun, params):
        params['fun'] = fun

        return self.post('/xml/getter.xml', params)

    def xml_setter(self, fun, params=None):
        params['fun'] = fun

        return self.post('/xml/setter.xml', params)

    def login(self, key):
        res = self.xml_setter(15, OrderedDict([
            ('Username', 'admin'),
            ('Password', key)
        ]))

        assert res.status_code == 200

        tokens = urllib.parse.parse_qs(res.text)
        SID = tokens['SID'][0]

        LOGGER.info("[login] SID %s", SID)

        self.session.cookies.update({'SID': SID})

        return res

    def reboot(self):
        return self.xml_setter(133, {})


    def factory_reset(self):
        default_settings = self.xml_getter(324, {})

        self.xml_setter(7, {})
        return default_settings


    def logout(self):
        return self.xml_setter(16, {})


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
        res = self.modem.xml_getter(121, {})

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

        return self.modem.xml_setter(116, OrderedDict([
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

        return self.modem.xml_setter(122, OrderedDict([
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

        return self.modem.xml_setter(122, params)

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
        return ET.fromstring(self.modem.xml_getter(300, {}).content)

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

        return self.modem.xml_setter(301, out_settings)


class DHCPSettings(object):
    def __init__(self, modem):
        self.modem = modem

    def add_static_lease(self, ip, mac):
        return self.modem.xml_setter(148, {
            'data': 'ADD,{ip},{mac};'.format(ip=ip, mac=mac)
        })

    def set_upnp_status(self, enabled):
        return self.modem.xml_setter(101, OrderedDict([
            ('LanIP', ''),
            ('UPnP', 1 if enabled else 2),
            ('DHCP_addr_s', ''), ('DHCP_addr_e', ''),
            ('subnet_Mask', ''),
            ('DMZ', ''), ('DMZenable', '')
        ]))

class FuncScanner(object):
    def __init__(self, modem, pos, key):
        self.modem = modem
        self.current_pos = pos
        self.key = key
        self.last_login = -1

    @property
    def is_valid_session(self):
        LOGGER.info("Last login %d", self.last_login)
        res = self.modem.xml_getter(2, {})
        return res.status_code == 200

    def scan(self):
        res = None
        while not res or res.text is '':
            LOGGER.info("func=%s", self.current_pos)

            res = self.modem.xml_getter(self.current_pos, {})
            if res.text == '':
                if not self.is_valid_session:
                    self.last_login = self.current_pos
                    self.modem.login(self.key)
                    LOGGER.info("Had to login at index %d", self.current_pos)
                    continue

            if res.status_code == 200:
                self.current_pos += 1
            else:
                raise ValueError("HTTP {}".format(res.status_code))

        return res

# How to use?
# modem = Compal('192.168.178.1')
# modem.login('1234567')
# fw = PortForwards(modem)
# print(list(fw.rules))
