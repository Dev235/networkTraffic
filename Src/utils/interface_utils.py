# util/interface_utils.py
import wmi
import re
from scapy.all import get_if_list

def get_interface_list():
    # Map of GUID -> Friendly Name
    wmi_interface_map = {}
    try:
        c = wmi.WMI()
        for nic in c.Win32_NetworkAdapterConfiguration(IPEnabled=True):
            if nic.SettingID:
                wmi_interface_map[nic.SettingID.strip('{}').lower()] = nic.Description
    except Exception as e:
        print("WMI error:", e)

    # Final mapping of Scapy name -> Friendly name
    friendly_list = []
    name_map = {}

    for scapy_iface in get_if_list():
        friendly_name = scapy_iface  # default
        match = re.search(r'\{([0-9a-fA-F\-]{36})\}', scapy_iface)
        if match:
            guid = match.group(1).lower()
            if guid in wmi_interface_map:
                friendly_name = wmi_interface_map[guid]
        elif "loopback" in scapy_iface.lower():
            friendly_name = "Loopback Adapter"
        friendly_list.append(friendly_name)
        name_map[friendly_name] = scapy_iface

    return friendly_list, name_map

def get_interface_by_friendly_name(name):
    _, name_map = get_interface_list()
    return name_map.get(name)       
