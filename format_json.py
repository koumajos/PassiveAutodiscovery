#!/usr/bin/python3.6
"""format_json module contains function that work with json output of device_analyzer module.


    Copyright (C) 2020 CESNET

    LICENSE TERMS

        Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
            1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
  
            2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

            3. Neither the name of the Company nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

        ALTERNATIVELY, provided that this notice is retained in full, this product may be distributed under the terms of the GNU General Public License (GPL) version 2 or later, in which case the provisions of the GPL apply INSTEAD OF those given above. 

        This software is provided as is'', and any express or implied warranties, including, but not limited to, the implied warranties of merchantability and fitness for a particular purpose are disclaimed. In no event shall the company or contributors be liable for any direct, indirect, incidental, special, exemplary, or consequential damages (including, but not limited to, procurement of substitute goods or services; loss of use, data, or profits; or business interruption) however caused and on any theory of liability, whether in contract, strict liability, or tort (including negligence or otherwise) arising in any way out of the use of this software, even if advised of the possibility of such damage.
"""
# Standard Library Imports
import json
import socket
import ipaddress

# Local Application Imports
from passive_autodiscovery import check_str


def read_json(filename):
    """Read JSON document from file to prom data.

    Parameters
    -----------
    filename : str
        Name of the output JSON document file.
    Returns
    --------
    data : JSON
        JSON format in python.
    """
    if check_str(filename, ".json") is False:
        filename = filename + ".json"
    with open(filename, "r") as file:
        data = json.load(file)
    return data


def write_json(data, filename):
    """Write JSON in python to JSON document file. 

    Parameters
    -----------
    data : JSON
        JSON file loaded in python filled with information.
    filename : str
        Name of the output JSON document file.
    """
    if check_str(filename, ".json") is False:
        filename = filename + ".json"
    with open(filename, "w") as file:
        json.dump(data, file, indent=4)


def create_json_for_device():
    """Create JSON format for safe output of analyze for device and return it. 

    Returns:
        json: JSON format analyze of device.
    """
    return {
        "DeviceID": 0,
        "IP": [],
        "MAC": "",
        "RouterMAC": "",
        "Vendor": "",
        "Country": "",
        "Labels": [],
        "DHCP": [],
        "LocalDependencies": [],
        "LocalStatistic": [],
        "GlobalDependencies": [],
        "GlobalStatistic": [],
    }


def create_json_format_for_network():
    """Create JSON format for analyze single network and return it. 

    Returns:
        json: JSON format for analyze network.
    """
    return {
        "Name": "AnalyzeNetwork",
        "Network": "",
        "DateAnalyze": "",
        "NumberDevice": 0,
        "Routers": [],
        "Services": [],
        "ip_address_statistics": [],
        "Devices": [],
        "Files": [],
    }


def crete_json_format_for_single_device():
    """Create JSON format for analyze single device and return it. 

    Returns:
        json: JSON format for analyze device.
    """
    return {
        "Name": "AnalyzeSingleDevice",
        "DateAnalyze": "",
        "Routers": [],
        "Services": [],
        "ip_address_statistics": [],
        "Devices": [],
        "Files": [],
    }


def crete_json_format_for_full_analyze():
    """Create JSON format for analyze all devices safed in sqlite3 database and return it. 

    Returns:
        json: JSON format for analyze.
    """
    return {
        "Name": "PassiveAutodiscovery",
        "DateAnalyze": "",
        "NumberDevice": 0,
        "Routers": [],
        "Services": [],
        "ip_address_statistics": [],
        "Devices": [],
        "Files": [],
    }


def safe_local_dependency_to_json(
    device_json, dependency, num_packets, device_ipaddress, cursor
):
    """Safe local dependency to json.

    Args:
        device_json (json): JSON document for single device.
        dependency (list): List created from row in database, taht contains ifnormationa bout one dependency.
        device_ipaddress (str): String of device IP address.
        cursor (sqlite3): Cursor to sqlite3 database.
    """
    src_ip = ipaddress.ip_address(dependency[1])
    depencency_ip = ""
    verb = "provides"
    services = ""
    port = 0
    packets = num_packets

    cursor.execute(
        "SELECT * FROM Services WHERE PortNumber='{portS}'".format(portS=dependency[3])
    )
    src_services = cursor.fetchone()
    if src_services:
        if src_ip == device_ipaddress:
            depencency_ip = dependency[2]
            if src_services[1] == "DHCP Client":
                services = "DHCP Server"
                port = 67
            else:
                verb = "requires"
                services = src_services[1]
                port = dependency[3]
        else:
            depencency_ip = dependency[1]
            services = src_services[1]
            port = dependency[3]
        add_dependency_to_json(
            device_json,
            "LocalDependencies",
            depencency_ip,
            verb,
            services,
            port,
            packets,
        )
        return

    cursor.execute(
        "SELECT * FROM Services WHERE PortNumber='{portD}'".format(portD=dependency[4])
    )
    dst_services = cursor.fetchone()
    if dst_services:
        if src_ip == device_ipaddress:
            depencency_ip = dependency[2]
        else:
            depencency_ip = dependency[1]
            verb = "requires"
        services = dst_services[1]
        port = dependency[4]
        add_dependency_to_json(
            device_json,
            "LocalDependencies",
            depencency_ip,
            verb,
            services,
            port,
            packets,
        )
        return

    if src_ip == device_ipaddress:
        depencency_ip = dependency[2]
        cursor.execute(
            "SELECT * FROM Ports WHERE PortNumber='{port}'".format(port=dependency[4])
        )
        dst_port = cursor.fetchone()
        if dst_port:
            services = dst_port[1]
            port = dependency[4]
        else:
            port = dependency[4]
    else:
        depencency_ip = dependency[1]
        verb = "requires"
        cursor.execute(
            "SELECT * FROM Ports WHERE PortNumber='{port}'".format(port=dependency[3])
        )
        src_port = cursor.fetchone()
        if src_port:
            services = src_port[1]
            port = dependency[3]
        else:
            port = dependency[3]
    add_dependency_to_json(
        device_json, "LocalDependencies", depencency_ip, verb, services, port, packets
    )


def safe_global_dependency_to_json(
    device_json, global_dependency, num_packets, cursor, device_ip, promtp
):
    """[summary]

    Args:
        device_json ([type]): [description]
        global_dependency ([type]): [description]
        cursor ([type]): [description]
        device_ip ([type]): [description]
        promtp ([type]): [description]
    """
    src_ip = ipaddress.ip_address(global_dependency[1])
    # ==========================================
    cursor.execute(
        "SELECT * FROM Services WHERE PortNumber='{portS}'".format(
            portS=global_dependency[3]
        )
    )
    src_service = cursor.fetchone()
    cursor.execute(
        "SELECT * FROM Services WHERE PortNumber='{portD}'".format(
            portD=global_dependency[4]
        )
    )
    dst_service = cursor.fetchone()
    # ========================================================
    depencency_ip = ""
    verb = "provides"
    services = ""
    port = 0
    num_packets = num_packets
    domain = ""
    # ========================================================
    if src_service:
        if src_ip == device_ip:
            depencency_ip = global_dependency[2]
            if src_service[1] == "DHCP Client":
                services = "DHCP Server"
            else:
                verb = "requires"
        else:
            depencency_ip = global_dependency[1]
        if promtp < 15:
            services = src_service[1]
            port = global_dependency[3]
            if src_service[1] == "WEB Server" and src_ip == device_ip:
                try:
                    sck = socket.gethostbyaddr(global_dependency[2])
                    domain = "(Domain:" + sck[0] + ")"
                except:
                    None
            elif src_service[1] == "WEB Server":
                try:
                    sck = socket.gethostbyaddr(global_dependency[1])
                    domain = "(Domain:" + sck[0] + ")"
                except:
                    None
            else:
                None
        else:
            services = src_service[1]
            port = global_dependency[3]
    elif dst_service:
        if src_ip == device_ip:
            depencency_ip = global_dependency[2]
        else:
            depencency_ip = global_dependency[1]
            verb = "requires"
        if promtp < 15:
            services = dst_service[1]
            port = global_dependency[4]
            if dst_service[1] == "WEB Server" and src_ip == device_ip:
                try:
                    sck = socket.gethostbyaddr(global_dependency[2])
                    domain = "(Domain:" + sck[0] + ")"
                except:
                    None
            elif dst_service[1] == "WEB Server":
                try:
                    sck = socket.gethostbyaddr(global_dependency[1])
                    domain = "(Domain:" + sck[0] + ")"
                except:
                    None
            else:
                None
        else:
            services = dst_service[1]
            port = global_dependency[4]
    else:
        if src_ip == device_ip:
            depencency_ip = global_dependency[2]
            cursor.execute(
                "SELECT * FROM Ports WHERE PortNumber='{portD}'".format(
                    portD=global_dependency[4]
                )
            )
            dst_port = cursor.fetchone()
            if dst_port:
                services = dst_port[1]
                port = global_dependency[4]
            else:
                port = global_dependency[4]
        else:
            depencency_ip = global_dependency[1]
            verb = "requires"
            cursor.execute(
                "SELECT * FROM Ports WHERE PortNumber='{portS}'".format(
                    portS=global_dependency[3]
                )
            )
            src_port = cursor.fetchone()
            if src_port:
                services = src_port[1]
                port = global_dependency[3]
            else:
                port = global_dependency[3]
            # ========================================================
    add_dependency_to_json(
        device_json,
        "GlobalDependencies",
        depencency_ip,
        verb,
        services,
        port,
        num_packets,
    )


def add_dependency_to_json(
    device_json, type_dependencies, depencency_ip, verb, services, port, packets
):
    """Add local dependency to json in specific format.

    Args:
        device_json (json): JSON document.
        depencency_ip (str): String of device IP address.
        verb (str): Provides or requires the services/protocol.
        services (str): Service of protocol used by device.
        port (int): Integer of used port.
        packets (int): Integer of packets number.
    """
    device_json[type_dependencies].append(
        {
            "IP": f"{depencency_ip}",
            "Verb": f"{verb}",
            "Service": f"{services}",
            "Port": f"{port}",
            "Packets": f"{packets}",
        }
    )
