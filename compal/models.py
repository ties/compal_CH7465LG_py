"""Objects used by CH7465LG"""
from dataclasses import dataclass
from enum import Enum
from typing import Optional


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


class FilterAction(Enum):
    """
    Filter action, used by internet access filters
    """

    add = 1
    delete = 2
    enable = 3


class NatMode(Enum):
    """
    Values for NAT-Mode
    """

    enabled = 1
    disabled = 2


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


class Proto(Enum):
    """
    protocol (from form): 1 = tcp, 2 = udp, 3 = both
    """

    tcp = 1
    udp = 2
    both = 3


@dataclass
class RadioSettings:
    bss_coexistence: Optional[str] = None
    radio_2g: Optional[str] = None
    radio_5g: Optional[str] = None
    nv_country: Optional[str] = None
    channel_range: Optional[str] = None


class TimerMode(Enum):
    """
    Timermodes used for internet access filtering
    """

    generaltime = 1
    dailytime = 2
