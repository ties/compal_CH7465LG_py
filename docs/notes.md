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

/setter.xml fun=126: ping
    Type: 0
    Target_IP: <ip>
    Ping_size: 64
    Num_Ping: 3
    Ping_Interval: 1
=>
/getter.xml fun=128
Many posts (only fun/token as params) for results.

/setter.xml fun=127: traceroute
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
  
---
#### CHANGE WIFI SETTINGS WITH '/setter.xml' `fun= 319` or `fun=301`

* VARIABLES THAT WILL BE SENT OVER `fun:301` (Wifi Configuration Page):

    `OrderedDict([('wlBandMode2g', var), ('wlBandMode5g', var), ('wlSsid2g', var), ('wlSsid5g', var), ('wlBandwidth2g', var), ('wlBandwidth5g', var), ('wlTxMode2g', var), ('wlTxMode5g', var), ('wlMCastRate2g', var), ('wlMCastRate5g', var), ('wlHiden2g', var), ('wlHiden5g', var), ('wlCoexistence', var), ('wlPSkey2g', var), ('wlPSkey5g', var), ('wlTxrate2g', var), ('wlTxrate5g', var), ('wlRekey2g', var), ('wlRekey5g', var), ('wlChannel2g', var), ('wlChannel5g', var), ('wlSecurity2g', var), ('wlSecurity5g', var), ('wlWpaalg2g', var), ('wlWpaalg5g', var)])`
    
* VARIABLES THAT WILL BE SENT OVER `fun:319` (Wireless Signal Page):

    `OrderedDict([('wlBandMode', var), ('wlSsid2g', var), ('wlSsid5g', var),('wlBandwidth2g', var), ('wlBandwidth5g', var), ('wlTxMode2g', var), ('wlTxMode5g', var), ('wlMCastRate2g', var), ('wlMCastRate5g', var), ('wlHiden2g', var), ('wlHiden5g', var), ('wlCoexistence', var), ('wlPSkey2g', var), ('wlPSkey5g', var), ('wlTxrate2g', var), ('wlTxrate5g', var), ('wlRekey2g', var), ('wlRekey5g', var), ('wlChannel2g', var), ('wlChannel5g', var), ('wlSecurity2g', var), ('wlSecurity5g', var), ('wlWpaalg2g', var), ('wlWpaalg5g', var), ('wlSmartWiFi', var)])`
---
* VARIABLES THAT CAN NOT BE SET/CHANGED OR DON'T GET SENT OVER `fun=301` or `fun= 319` (after tests) :
    * **`nv_country (=doesn't get sent over fun:301 or fun:319)`**: So it always stays `1`
    * **`band_mode (=wlBandMode)`**: 
        > This is a special variable that can be set, but not changed (see below `fun:319`)
    * **`channel_range (=doesn't get sent over fun:301 or fun:319)`**: So it always stays `1`
    * **`bss_coexistence (=wlCoexistence)`**: Stays always `1`
    * **`son_admin_status (=doesn't get sent over fun:301 or fun:319)`**: So it always stays `1`
    * **`radio_2g.multicast_rate  (=wlMCastRate2g)` or `radio_5g.multicast_rate  (=wlMCastRate5g)`**: Stays always `1`
    * **`radio_2g.tx_rate  (=wlTxrate2g)` or `radio_5g.tx_rate  (=wlTxrate5g)`**: Stays always `0`  
---
* VARIABLES THAT CAN BE SET OVER `fun:301` (Wifi Configuration Page):
    * **`radio_2g.bss_enable (=wlBandMode2g)`**: Possible integer input values -> `1`,`2`
        > (`wlBandMode2g=1`) means 2g is on <br>
        (`wlBandMode2g=2`) means 2g is off 
                                                     
        _What changes in the router-xml-file is the following: <br>_
        > FROM: /getter.xml fun=326 <br>
        `<primary24g>var</primary24g>`                      // var -> (1=on / 0=off)
    * **`radio_5g.bss_enable (=wlBandMode5g)`**: Possible integer input values -> `1`,`2`
        > (`wlBandMode5g=1`) means 5g is on <br>
        (`wlBandMode5g=2`) means 5g is off 
                                                     
        _What changes in the router-xml-file is the following: <br>_
        > FROM: /getter.xml fun=326 <br>
        `<primary5g>var</primary5g>`                      // var -> (1=on / 0=off)
    * **`radio_2g.hidden  (=wlHiden2g)`**:
        > (`wlHiden2g=1`) means 2g broadcast is on <br>
        (`wlHiden2g=2`) means 2g broadcast is off
                                              
        _What changes in the router-xml-file is the following: <br>_
        > FROM: /getter.xml fun=300 <br>
        `<HideNetwork2G>var</HideNetwork2G>`                      // var -> (1=on / 0=off)
    * **`radio_5g.hidden  (=wlHiden5g)`**:
        > (`wlHiden5g=1`) means 5g broadcast is on <br>
        (`wlHiden5g=2`) means 5g broadcast is off
                                              
        _What changes in the router-xml-file is the following: <br>_
        > FROM: /getter.xml fun=300 <br>
        `<HideNetwork5G>var</HideNetwork5G>`                      // var -> (1=on / 0=off)
    * **`radio_2g.pre_shared_key  (=wlPSkey2g)`**:
        > (`wlPSkey2g=var`) means setting the password for 2g
                                              
        _What changes in the router-xml-file is the following: <br>_
        > FROM: /getter.xml fun=300 <br>
        `<PreSharedKey2g>var</PreSharedKey2g>`                      // var -> password
    * **`radio_5g.pre_shared_key  (=wlPSkey5g)`**:
        > (`wlPSkey5g=var`) means setting the password for 5g
                                              
        _What changes in the router-xml-file is the following: <br>_
        > FROM: /getter.xml fun=300 <br>
        `<PreSharedKey5g>var</PreSharedKey5g>`                      // var -> password
   * **`radio_2g.re_key  (=wlRekey2g)`**: standard = `0`
   
        _What changes in the router-xml-file is the following: <br>_
        > FROM: /getter.xml fun=300 <br>
        `<GroupRekeyInterval2g>var</GroupRekeyInterval2g>`
    * **`radio_5g.re_key  (=wlRekey5g)`**: standard = `0`
   
        _What changes in the router-xml-file is the following: <br>_
        > FROM: /getter.xml fun=300 <br>
        `<GroupRekeyInterval5g>var</GroupRekeyInterval5g>`
   * **`radio_2g.security (=wlSecurity2g)`**: Possible integer input values -> `0`,`4`,`8`
        > (`wlSecurity2g=0`) means 'Disabled' <br>
        (`wlSecurity2g=4`) means 'WPA2-PSK' (router software sets with `radio_2g.security=4` also `radio_2g.wpa_algorithm` to `2`)<br>
        (`wlSecurity2g=8`) means 'WPA-PSK/WPA2-PSK' (router software sets with `radio_2g.security=8` also `radio_2g.wpa_algorithm` to `3`)<br>

        _What changes in the router-xml-file is the following: <br>_
        > FROM: /getter.xml fun=300 <br>
        `<SecurityMode2g>var</SecurityMode2g>`
   * **`radio_5g.security (=wlSecurity5g)`**: Possible integer input values -> `0`,`4`,`8`
        > (`wlSecurity5g=0`) means 'Disabled' <br>
        (`wlSecurity5g=4`) means 'WPA2-PSK' (router software sets with `radio_5g.security=4` also `radio_5g.wpa_algorithm` to `2`)<br>
        (`wlSecurity5g=8`) means 'WPA-PSK/WPA2-PSK' (router software sets with `radio_5g.security=8` also `radio_5g.wpa_algorithm` to `3`)<br>

        _What changes in the router-xml-file is the following: <br>_
        > FROM: /getter.xml fun=300 <br>
        `<SecurityMode5g>var</SecurityMode5g>`
    * **`radio_2g.wpa_algorithm (=wlWpaalg2g)`**: Should be `2` or `3` after router software, depending on security value. See under radio_2g.security.
    
        _What changes in the router-xml-file is the following: <br>_
        > FROM: /getter.xml fun=300 <br>
        `<WpaAlgorithm2G>var</WpaAlgorithm2G>`
   * **`radio_5g.wpa_algorithm (=wlWpaalg5g)`**: Should be `2` or `3` after router software, depending on security value. See under radio_5g.security.
       
        _What changes in the router-xml-file is the following: <br>_
        > FROM: /getter.xml fun=300 <br>
        `<WpaAlgorithm5G>var</WpaAlgorithm5G>`                                                 
---                                         
* VARIABLES THAT CAN BE SET OVER `fun:319` (Wireless Signal Page):
    * **`band_mode (=wlBandMode)`**: Possible integer input values -> `1`,`2`,`3`,`4` 
        > (`wlBandMode=1`) means 2g is on an 5g is off <br>
        (`wlBandMode=2`) means 2g is off an 5g is on <br>
        (`wlBandMode=3`) means 2g is on an 5g is on <br>
        (`wlBandMode=4`) means 2g is off an 5g is off <br>
                                                                             
        `<Bandmode>3</Bandmode>` in the router-xml-file stays always at value=`3`. But when you set `band_mode` `radio_2g.bss_enable` and `radio_5g.bss_enable` changes. 
        
        _What changes in the router-xml-file is the following: <br>_
        > FROM: /getter.xml fun=300 <br>
        `<BssEnable2g>var</BssEnable2g>`                    // var -> (1=on / 2=off) <br>
        `<BssEnable5g>var</BssEnable5g>`                    // var -> (1=on / 2=off) <br>
        FROM: /getter.xml fun=315 <br>
        `<BssEnable2g>var</BssEnable2g>`                    // var -> (1=on / 2=off) <br>
        `<BssEnable5g>var</BssEnable5g>`                    // var -> (1=on / 2=off) <br>
        FROM: /getter.xml fun=326 <br>
        `<primary24g>var</primary24g>`                      // var -> (1=on / 0=off) <br>
        `<primary5g>var</primary5g>`                        // var -> (1=on / 0=off)
    
    * **`radio_2g.bandwidth (=wlBandwidth2g)`**: Possible integer input values -> `1`,`2`
        > (`wlBandwidth2g=1`) means '20 MHz' <br>
        (`wlBandwidth2g=2`) means '20/40 MHz' <br>

        _What changes in the router-xml-file is the following xml-content: <br>_
        > FROM: /getter.xml fun=300 <br>
          `<BandWidth2G>var</BandWidth2G>`    // var -> (1, 2)                                                                      
    * **`radio_5g.bandwidth (=wlBandwidth5g)`**: Possible integer input values -> `1`,`2`,`3`
        > (`wlBandwidth5g=1`) means '20 MHz' <br>
        (`wlBandwidth5g=2`) means '20/40 MHz' <br>
        (`wlBandwidth5g=3`) means '20/40/80 MHz' <br>

        _What changes in the router-xml-file is the following xml-content: <br>_
        > FROM: /getter.xml fun=300 <br>
          `<BandWidth5G>var</BandWidth5G>`    // var -> (1, 2, 3)

    * **`radio_2g.tx_mode (=wlTxMode2g)`**: Possible integer input values -> `1`,`5`,`6`
        > (`wlTxMode2g=1`) means '802.11b/g/n mixed' <br>
        (`wlTxMode2g=5`) means '802.11n' <br>
        (`wlTxMode2g=6`) means '802.11g/n mixed' <br>
                                                                        
        _What changes in the router-xml-file is the following xml-content: <br>_
        > FROM: /getter.xml fun=300 <br>
          `<TransmissionMode2g>var</TransmissionMode2g>`    // var -> (1, 5, 6)                                                                   
    * **`radio_5g.tx_mode (=wlTxMode5g)`**: Possible integer input values -> `14`,`15`,`16`
        > (`wlTxMode5g=14`) means '802.11a/n/ac mixed' <br>
        (`wlTxMode5g=15`) means '802.11n/ac mixed' <br>
        (`wlTxMode5g=16`) means '802.11ac' <br>
                                                                           
        _What changes in the router-xml-file is the following xml-content: <br>_
        > FROM: /getter.xml fun=300 <br>
        `<TransmissionMode5g>var</TransmissionMode5g>`    // var -> (14, 15, 16)                                                                             
    * **`radio_2g.channel (=wlChannel2g)`**: Possible integer input values -> `0`,`1`-`11`, `step 1`
        > Set var=0 for automatic channel selection <br>
       
        _What changes in the router-xml-file is the following xml-content: <br>_
        > FROM: /getter.xml fun=300 <br>
        `<ChannelSetting2G>var</ChannelSetting2G>`    // var -> (0, 1-11)                                                                                     
    * **`radio_5g.channel (=wlChannel5g)`**: Possible integer input values -> `0`,`36`-`128`, `step 4`
        > Set var=0 for automatic channel selection <br>
        Some Channel are DFS channels.
                                                                                      
        _What changes in the router-xml-file is the following xml-content: <br>_
        > FROM: /getter.xml fun=300 <br>
        `<ChannelSetting5G>var</ChannelSetting5G>`    // var -> (0, 36-128, step 4)                                                                                      
    * **`smart_wifi (=wlSmartWiFi)`**: Possible integer input values -> `1 or 2`        
        > (`wlSmartWiFi=1`) means 'Enable Channel Optimization' <br>
        (`wlSmartWiFi=2`) means 'Disable Channel Optimization' <br>
                                                                                      
        _What changes in the router-xml-file is the following xml-content: <br>_
        > FROM: /getter.xml fun=300 <br>
          `<SONOperationalStatus>var</SONOperationalStatus>`    // var -> (1=on / 2=off)
---
<br>
/setter.xml fun=301
  Change wifi settings

fun:301            
wlBandMode2g:1,
wlBandMode5g:1,
wlSsid2g:ssid24,
wlSsid5g:ssid5g,
wlBandwidth2g:2,
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
