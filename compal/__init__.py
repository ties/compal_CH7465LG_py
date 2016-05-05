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
"""
import itertools
import logging
import urllib

import xml.etree.ElementTree as ET

from collections import OrderedDict, namedtuple
from enum import Enum

import requests


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

        if not self.initial_res.url.endswith('common_page/login.html'):
            LOGGER.error("Was not redirected to login page - concurrent session?")
    
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


    def logout(self):
        return self.xml_setter(16, {})


class Proto(Enum):
    """
    protocol (from form): 1 = tcp, 2 = udp, 3 = both
    """
    tcp = 1
    udp = 2
    both = 3


PortForward = namedtuple('PortForward', ['local_ip', 'ext_port', 'int_port',
        'proto', 'enabled', 'delete', 'idd', 'id', 'lan_ip'])
# idd, id, lan_ip are None by default, delte is False by default
PortForward.__new__.__defaults__ = (False, None, None, None,)



class CompalPortForwards(object):
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


    def add_forward(self, local_ip, ext_port, int_port, proto: Proto,
                    enabled=True):
        """
        Add a port forward. int_port and ext_port can be ranges. Deletion param
        is ignored for now.
        """
        start_int, end_int = itertools.repeat(int_port)
        start_ext, end_ext = itertools.repeat(ext_port)

        return self.modem.xml_setter(122, {
            'action': 'add',
            'local_IP': local_ip,
            'start_port': start_ext, 'end_port': end_ext,
            'start_portIn': start_int, 'end_portIn': end_int,
            'protocol': proto.value,
            'enable': int(enabled), 'delete': int(False),
            'idd': ''
        })

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
# fw = CompalPortForwards(modem)
# print(list(fw.rules))
