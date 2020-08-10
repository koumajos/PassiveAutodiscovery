#!/usr/bin/python3.6
"""device_analyzer script:

    device_analyzer script connect to sqlite3 database which is created by CreateScript and filled by PassiveAutodiscovery script. After connect to database, script will analyzed database acccording to setted arguments of script. Only one mandatory output of the script is JSON document with default name PassiveAutodiscovery.

    Analyze:
        For all device will script get these information from database:
            IP address of device (if mac address is use more IP address and isn't router, it will be list of IP address where first one is for comunication analyzed in the section)        
            Time of last comunication
            Labels of roles that device is (provides these services for other device on network)
            DHCP records (requests and answers) by time.
            List of local dependencies sorted by number of carryed packet. ()
            Statistic of local dependencies by transport layer protocol.            
            List of global dependencies sorted by number of carryed packet.
            Statistic of global dependencies by transport layer protocol.            
        For database can be created:
            Graph of local dependencies. [-l]
            Graph of local device and global devices, which local device communication with. [-g]
            Graph of local devices and globla devices, where global device is in graph only if two or more local devices had communicate with. It will create bipartite graph. [-b]
            Statistical of using network by devices.
    Setting of the script:
        Outputs:
            JSON document - mandatory output, can be setted name of the document [-J name] (default name is PassiveAutodiscovery)
            Command Line - optinional output [-p]
            File .txt - optinional output, can be setted name of the document (hasn't default value) [-f name]
        Analyze:
            Default state - analyze all database [without -D and -N]
            Device - analyze only one inserted device (if exists in database) [-D]
            Network - analyze only one network subnet [-N]
        Number of dependencies in output to command line or File .txt (JSON document contains all dependencies):
            Set the number of local dependencies. [-L]
            Set the number of global dependencies. [-G]
        Dependencies and device with label [WEB Server] can be translate to domain name:
            The domain name will be in output (command line/file). [-DNS] 
        Can ignored global dependencies:
            In output will be only local dependencies. [-o]
        Can create graphs of dependencies in time.
            For local dependencies. [-t]
            For local to gloval dependencies. [-T]


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
import sys
import os
import ipaddress
import sqlite3
import json
import socket
import time
import datetime
import argparse
from argparse import RawTextHelpFormatter

# Local Application Imports
import create_graphs
import print_analyze
from create_script import check_str
import format_json


def add_mac_address(device_id, ip_address, cursor, sqlite_connection, device_json):
    """Find if for device IP is in database MAC address record in table MAC or table Routers. If in table MAC, the device with IP has this MAC address. If in Router, the device with IP has this MAC address or is behind router with this MAC address (Ussualy cant resolve this by program).

    Parameters
    -----------
    device_id : int
        ID of device in analyze.
    ip_address : str
        IP address of device.
    cursor : sqlite3
        Cursor to sqlite3 database for execute SQL queries.
    sqlite_connection : sqlite3
        Connection to sqlite3 database.
    device_json : JSON
        JSON file for device with device_id ID loaded in python.    
    """
    cursor.execute(
        "SELECT * FROM MAC WHERE IP='{ip}' AND LastUse='{lu}'".format(
            ip=ip_address, lu=""
        )
    )
    row = cursor.fetchone()
    cursor.execute("SELECT * FROM Routers WHERE IP='{ip}'".format(ip=ip_address))
    router = cursor.fetchone()
    mac = ""
    if row:
        device_json["MAC"] = row[2]
        mac = [row[2][i : i + 8] for i in range(0, len(row[2]), 8)][0]
    elif router:
        cursor.execute(f"SELECT * FROM Routers WHERE MAC='{router[1]}'")
        rows = cursor.fetchall()
        cnt_private = 0
        for row in rows:
            ip = ipaddress.ip_address(row[2])
            if ip.is_private:
                cnt_private += 1
        if cnt_private > 1:
            device_json["RouterMAC"] = router[1]
        else:
            device_json["MAC"] = router[1]
        mac = [router[1][i : i + 8] for i in range(0, len(router[1]), 8)][0]
    else:
        None
    if mac != "":
        cursor.execute(f"SELECT * FROM VendorsMAC WHERE VendorMAC='{mac.upper()}'")
        row = cursor.fetchone()
        if row:
            device_json["Vendor"] = row[3]
            device_json["Country"] = row[4]
        else:
            device_json["Vendor"] = f"Not Find: {mac.upper()}"
            device_json["Country"] = f"Not Find: {mac.upper()}"


def find_labels(
    device_id, ip_address, cursor, sqlite_connection, device_json, json_output, gl
):
    """Find all labels (of roles/services) for device in database table LocalServices. Also create new label out of dependencies like [End Device].

    Parameters
    -----------
    device_id : int
        ID of device in analyze.
    ip_address : str
        IP address of device.
    cursor : sqlite3
        Cursor to sqlite3 database for execute SQL queries.
    sqlite_connection : sqlite3
        Connection to sqlite3 database.
    device_json : JSON
        JSON file for device with device_id ID loaded in python.    
    json_output : JSON
        JSON file for all analyze loaded in python.
    gl : bool
        True if global dependencies exists.
    """
    cursor.execute(
        "SELECT S.PortNumber, S.DeviceType, S.Shortcut, S.Description FROM LocalServices LS JOIN services S ON LS.PortNumber=S.PortNumber WHERE LS.IP='{ip}'".format(
            ip=ip_address
        )
    )
    labels = cursor.fetchall()
    tmp = 0
    if labels:
        for service in labels:
            if gl == True:
                cursor.execute(
                    "SELECT * FROM Global WHERE (IP_origin='{ip}' AND Port_origin='{port}') OR (IP_target='{ip}' AND Port_target='{port}')".format(
                        port=service[0], ip=ip_address
                    )
                )
                Global = cursor.fetchone()
                cursor.execute(
                    "SELECT * FROM Dependencies WHERE (IP_origin='{ip}' AND Port_origin='{port}') OR (IP_target='{ip}' AND Port_target='{port}') ".format(
                        port=service[0], ip=ip_address
                    )
                )
                Local = cursor.fetchone()
                if not Global and not Local:
                    continue
            tmp = 1

            if service[1] == "Router" and not ip_address in json_output["Routers"]:
                json_output["Routers"].append(ip_address)
            if not service[1] in json_output["Services"]:
                json_output["Services"].append(service[1])

            if service[1] == "WEB Server":
                try:
                    domain = socket.gethostbyaddr(ip_address)
                    label = {
                        "Label": f"{service[1]}",
                        "Description": f"{domain[0]}",
                    }
                    if not label in device_json["Labels"]:
                        device_json["Labels"].append(label)
                    continue
                except:
                    None
            label = {"Label": "%s" % service[1], "Description": "%s" % service[3]}
            if not label in device_json["Labels"]:  # add to output only unique labels
                device_json["Labels"].append(label)
    # ============================================================================================================================================================
    # Create new labels from dependencies from access to Web Sevices, Mail Services, or record in table Routers
    cursor.execute(
        "SELECT * FROM Global G JOIN GlobalServices GS ON G.IP_target=GS.IP JOIN Services S ON S.PortNumber=GS.PortNumber WHERE G.IP_origin='{ipo}' AND S.DeviceType='{t}'".format(
            ipo=ip_address, t="WEB Server"
        )
    )
    WebServer = cursor.fetchone()
    if WebServer:
        tmp = 1
        if not "End Device" in json_output["Services"]:
            json_output["Services"].append("End Device")
        device_json["Labels"].append(
            {
                "Label": "End Device",
                "Description": "PC, Mobile Phone,... (everything that can access web services)",
            }
        )
    cursor.execute(
        "SELECT * FROM Global G JOIN GlobalServices GS ON G.IP_target=GS.IP JOIN Services S ON S.PortNumber=GS.PortNumber WHERE G.IP_origin='{ipo}' AND S.DeviceType='{t}'".format(
            ipo=ip_address, t="Mail Server"
        )
    )
    MailServer = cursor.fetchone()
    if MailServer:
        tmp = 1
        if not "End Device" in json_output["Services"]:
            json_output["Services"].append("End Device")
        device_json["Labels"].append(
            {
                "Label": "End Device",
                "Description": "PC, Mobile Phone,... (everything that can send emails)",
            }
        )
    cursor.execute("SELECT * FROM Routers WHERE IP='{ip}'".format(ip=ip_address))
    router = cursor.fetchone()
    if router:
        cursor.execute("SELECT * FROM Routers WHERE MAC='{mac}'".format(mac=router[1]))
        Routers = cursor.fetchall()
        devices4 = 0
        devices6 = 0
        for i in Routers:
            ipd = ipaddress.ip_address(i[2])
            if ipd.is_global == False:
                if ipd.version == 4:
                    devices4 = devices4 + 1
                else:
                    devices6 = devices6 + 1
            if devices6 > 1 or devices4 > 1:
                break
        if devices6 > 1 or devices4 > 1:
            None
        else:
            tmp = 1
            if not "Router" in json_output["Services"]:
                json_output["Services"].append("Router")
            device_json["Labels"].append(
                {"Label": "Router", "Description": "Routing network device"}
            )
            if not ip_address in json_output["Routers"]:
                json_output["Routers"].append(ip_address)
    if tmp == 0:  # if no label was for device find give it label [Unknown]
        if not "Unknown" in json_output["Services"]:
            json_output["Services"].append("Unknown")
        device_json["Labels"].append({"Label": "Unknows", "Description": ""})


def add_dhcp_records_for_device(
    device_id, ip_address, cursor, sqlite_connection, device_json
):
    """Funkcion finds for device all record of DHCP comunicationa nd set it to output.

    Parameters
    -----------
    device_id : int
        ID of device in analyze.
    ip_address : str
        IP address of device.
    cursor : sqlite3
        Cursor to sqlite3 database for execute SQL queries.
    sqlite_connection : sqlite3
        Connection to sqlite3 database.
    device_json : JSON
        JSON file for device with device_id ID loaded in python.        
    """
    cursor.execute(
        "SELECT * FROM DHCP WHERE DeviceIP='{ip}' ORDER BY Time DESC".format(
            ip=ip_address
        )
    )
    dhcp_records = cursor.fetchall()
    for dhcp_record in dhcp_records:
        device_json["DHCP"].append(
            {
                "DHCPServ": f"{dhcp_record[2]}",
                "DHCPTime": f"{time.ctime(float(dhcp_record[3]))}",
            }
        )


def stats_of_services(services_statistic, dependency, cursor, sqlite_connection):
    """Function find if source or destination port of dependency isn't some services in network. If yes, then the packet number carry the dependendy add in services_statistic to the services. (this create with cyclus counter of packet by protocol in network) 
    
    Parameters
    -----------
    services_statistic : dictionary
        Disctionary of protocols and number packet taht was carry over network by protocols.
    dependency : array
        The one dependency for count packets and protocols.    
    cursor : sqlite3
        Cursor to sqlite3 database for execute SQL queries.
    sqlite_connection : sqlite3
        Connection to sqlite3 database.
    """
    cursor.execute(
        "SELECT * FROM Services WHERE PortNumber={po}".format(po=dependency[3])
    )
    servicestat = cursor.fetchone()
    if servicestat:
        st = servicestat[2].replace(" ", "_")
        if st in services_statistic:
            services_statistic[st] = services_statistic[st] + dependency[5]
        else:
            services_statistic[st] = dependency[5]

    cursor.execute(
        "SELECT * FROM Services WHERE PortNumber={pt}".format(pt=dependency[4])
    )
    servicestat = cursor.fetchone()
    if servicestat:
        st = servicestat[2].replace(" ", "_")
        if st in services_statistic:
            services_statistic[st] = services_statistic[st] + dependency[5]
        else:
            services_statistic[st] = dependency[5]


def add_or_update_statistic_of_device(dependency, ip_address, ip_address_statistics):
    """Function check if devices from dependency are in statistic, that contains devices ip addresses and number of packets that was carryed by device. 
    If device exists in statistic then update number of packets, else add new device in statistic. 

    Args:
        dependency (list): List conains information about dependency from sqlite3 database.
        ip_address (str): String of IP address.
        ip_address_statistics (dictionary): Statistic dicitonary. 
    """
    if dependency[1] == ip_address:
        if dependency[1] in ip_address_statistics:
            ip_address_statistics[dependency[1]] = (
                ip_address_statistics[dependency[1]] + dependency[5]
            )
        else:
            ip_address_statistics[dependency[1]] = dependency[5]
    if dependency[2] == ip_address:
        if dependency[2] in ip_address_statistics:
            ip_address_statistics[dependency[2]] = (
                ip_address_statistics[dependency[2]] + dependency[5]
            )
        else:
            ip_address_statistics[dependency[2]] = dependency[5]


def local_dependencies(
    device_id,
    ip_address,
    device_ipaddress,
    local_services_statistic,
    ip_address_statistics,
    cursor,
    sqlite_connection,
    device_json,
    args,
    json_output,
):
    """Function for device find in database all local dependencies and set in to output JSON. Also create statistic of local dependencies and statistic of using network by deveices. 

    Parameters
    -----------
    device_id : int
        Number of device in analyze.
    ip_address : str
        Device IP address in format str.
    device_ipaddress : ipaddress
        Device IP address in format ipaddress.
    local_services_statistic : dictionary
        Statistic of local dependencies.
    ip_address_statistics : dictionary
        Statistic of using network by device.
    cursor : sqlite3
        Cursor to sqlite3 database for execute SQL queries.
    sqlite_connection : sqlite3
        Connection to sqlite3 database.
    device_json : JSON
        JSON file for device with device_id ID loaded in python.        
    """
    cursor.execute(
        "SELECT * FROM Dependencies WHERE IP_origin='{ip}' OR IP_target='{ip}' ORDER BY NumPackets DESC".format(
            ip=ip_address
        )
    )
    dependencies = cursor.fetchall()
    tmp = 0
    for dependency in dependencies:
        if args.timeL > tmp:
            create_graphs.graph_activity_of_dependency(
                dependency, "Dependencies", cursor, json_output
            )
            tmp = tmp + 1

        stats_of_services(
            local_services_statistic, dependency, cursor, sqlite_connection
        )
        add_or_update_statistic_of_device(dependency, ip_address, ip_address_statistics)

        format_json.safe_local_dependency_to_json(
            device_json, dependency, device_ipaddress, cursor
        )


def global_dependencies(
    device_id,
    ip_address,
    device_ip,
    global_statistic,
    ip_address_statistics,
    cursor,
    sqlite_connection,
    device_json,
    args,
    json_output,
):
    """Function for device find in database all global dependencies and set in to output JSON. Also create statistic of global dependencies and statistic of using network by deveices. 

    Parameters
    -----------
    device_id : int
        Number of device in analyze.
    ip_address : str
        Device IP address in format str.
    device_ip : ipaddress
        Device IP address in format ipaddress.
    global_statistic : dictionary
        Statistic of local dependencies.
    ip_address_statistics : dictionary
        Statistic of using network by device.
    cursor : sqlite3
        Cursor to sqlite3 database for execute SQL queries.
    sqlite_connection : sqlite3
        Connection to sqlite3 database.
    device_json : JSON
        JSON file for device with device_id ID loaded in python.        
    """
    cursor.execute(
        "SELECT * FROM Global WHERE IP_origin='{ipo}' OR IP_target='{ipt}' ORDER BY NumPackets DESC".format(
            ipo=ip_address, ipt=ip_address
        )
    )
    global_dependencies = cursor.fetchall()
    tmp = 0
    if global_dependencies:
        promtp = 0
        for global_dependency in global_dependencies:
            if args.timeG > tmp:
                create_graphs.graph_activity_of_dependency(
                    global_dependency, "Global", cursor, json_output
                )
                tmp = tmp + 1
            stats_of_services(
                global_statistic, global_dependency, cursor, sqlite_connection
            )
            add_or_update_statistic_of_device(
                global_dependency, ip_address, ip_address_statistics
            )

            format_json.safe_global_dependency_to_json(
                device_json, global_dependency, cursor, device_ip, promtp
            )


def transfer_statistic_to_percents(statistic, device_json, type_statistic):
    """Function receive dictionary. The dictionarz number of packets calculate and create from it Percents.

    Parameters
    -----------
    statistic : dictionary
        The dictionary of statistic with protocols/devices and number of packets that was carryed in network by it.
    device_json : JSON
        JSON file for device with device_id ID loaded in python.        
    type_statistic : int
        Magic value represent the type of statistic (Local statistic == 0, Global statistic == 1, Network use statistic == 2).
    """
    if statistic == {}:
        return
    total_num_packets = 0
    for i, j in statistic.items():
        total_num_packets += j
    # ==========================
    statistic = {
        r: statistic[r] for r in sorted(statistic, key=statistic.get, reverse=True)
    }
    for i, j in statistic.items():
        statistic[i] = float(j / total_num_packets * 100)
        if type_statistic == 0:
            device_json["LocalStatistic"].append(
                {"Service": "%s" % i, "Percents": "%s" % statistic[i]}
            )
        elif type_statistic == 1:
            device_json["GlobalStatistic"].append(
                {"Service": "%s" % i, "Percents": "%s" % statistic[i]}
            )
        else:
            device_json["ip_address_statistics"].append(
                {"IP": "%s" % i, "Percents": "%s" % statistic[i]}
            )
    if type_statistic == 2:
        create_graphs.plot_statistics(statistic.items())


def find_ip_addresses_of_device(ip_address, cursor, device_json):
    """Function finds in database all IP address of the device (more then one only when device used both version of IP address or change IP address while monitoring network (DHCP)).

    Parameters
    -----------
    ip_address : str
        IP address of analyzed device.
    cursor : sqlite3
        Cursor to sqlite3 database for execute SQL queries.
    device_json : JSON
        JSON file for device with device_id ID loaded in python.            
    """
    device_json["IP"].append(ip_address)
    cursor.execute("SELECT * FROM Routers WHERE IP='{ip}'".format(ip=ip_address))
    router = cursor.fetchone()
    if not router:
        cursor.execute(
            "SELECT * FROM MAC WHERE IP='{ip}' AND LastUse='{lu}'".format(
                ip=ip_address, lu=""
            )
        )
        ip_addreses = cursor.fetchall()
        for ip in ip_addreses:
            if not ip[1] == ip_address:
                device_json["IP"].append(ip[1])
    else:
        cursor.execute(
            "SELECT DeviceType FROM LocalServices LS JOIN Services S ON LS.PortNumber=S.PortNumber WHERE LS.IP='{ip}' AND S.DeviceType='{device}'".format(
                ip=ip_address, device="Router"
            )
        )
        router = cursor.fetchall()
        if router:
            cursor.execute(
                "SELECT * FROM Routers WHERE MAC='{mac}'".format(mac=router[1])
            )
            routers = cursor.fetchall()
            dst_ip = ipaddress.ip_address(ip_address)
            for ip in routers:
                ipd = ipaddress.ip_address(ip[2])
                if (
                    ipd.is_private
                    and ip[2] != ip_address
                    and dst_ip.version == ipd.version
                ):
                    device_json["DeviceBehindRouter"].append(ip[2])


def analyze_device(
    device_id,
    ip_address,
    TIME,
    cursor,
    sqlite_connection,
    json_output,
    ip_address_statistics,
    gl,
    args,
    sample,
):
    """Analyze a device and output of it add to JSON document.

    Parameters
    -----------
    device_id : int
        Number of device in analyze.
    ip_address : str
        Device IP address.
    TIME : int
        Time of last comunication.
    cursor : sqlite3
        Cursor to sqlite3 database for execute SQL queries.
    sqlite_connection : sqlite3
        Connection to sqlite3 database.
    json_output : JSON
        JSON file loaded in python.        
    ip_address_statistics : dictionary
        Dictionary contains statistic of using network by devices.
    gl : bool
        True if global dependencies exists.
    args : argparse
        Setted arguments of the script.
    sample : opened file
        Output file.    
    """
    # ==================================================================
    device_json = format_json.create_json_for_device()
    # ==================================================================
    device_json["DeviceID"] = device_id
    # ==================================================================
    find_ip_addresses_of_device(ip_address, cursor, device_json)
    # ==================================================================
    device_json["LastCom"] = float(TIME)
    device_ip = ipaddress.ip_address(ip_address)
    # ==================================================================
    add_mac_address(device_id, ip_address, cursor, sqlite_connection, device_json)
    # ==================================================================
    find_labels(
        device_id, ip_address, cursor, sqlite_connection, device_json, json_output, gl
    )
    # ==================================================================
    add_dhcp_records_for_device(
        device_id, ip_address, cursor, sqlite_connection, device_json
    )
    # ==================================================================
    local_services_statistic = {}
    local_dependencies(
        device_id,
        ip_address,
        device_ip,
        local_services_statistic,
        ip_address_statistics,
        cursor,
        sqlite_connection,
        device_json,
        args,
        json_output,
    )
    transfer_statistic_to_percents(local_services_statistic, device_json, 0)
    # ==================================================================
    if args.onlylocal == False:
        global_statistic = {}
        global_dependencies(
            device_id,
            ip_address,
            device_ip,
            global_statistic,
            ip_address_statistics,
            cursor,
            sqlite_connection,
            device_json,
            args,
            json_output,
        )
        transfer_statistic_to_percents(global_statistic, device_json, 1)
    # ==================================================================
    if args.print == True:
        print_analyze.print_device_from_json(device_json, args)
    if args.file != "":
        print("Output for device ", ip_address, " printed to file: ", args.file)
        print_analyze.print_device_to_file_from_json(device_json, args, sample)
    if args.activity == True:
        create_graphs.graph_activity_of_device(ip_address, cursor, json_output)
    # ==================================================================
    json_output["Devices"].append(device_json)


def analyze_network(sqlite_connection, args):
    """Analyze network subnet from arguments.

    Parameters
    -----------
    sqlite_connection : sqlite3
        Connection to sqlite3 database.
    args : argparse
        Setted arguments of the script.
    """
    # ==================================================================
    json_output = format_json.create_json_format_for_network()
    format_json.write_json(json_output, args.json)
    json_output = format_json.read_json(args.json)
    # ==================================================================
    ip_address_statistics = {}
    cursor = sqlite_connection.cursor()
    device_id = 1
    # ==================================================================
    gl = True
    cursor.execute("SELECT COUNT(*) FROM Global")
    GlobalC = cursor.fetchone()
    if GlobalC[0] == 0:
        gl = False
    # ==================================================================
    if args.file != "":
        if check_str(args.file, ".txt") == True:
            file = args.file
        else:
            file = args.file + ".txt"
        sample = open(file, "w")
    else:
        sample = ""
    NET = ipaddress.ip_network(args.network)
    cursor.execute("SELECT * FROM LocalDevice")
    LocalDevices = cursor.fetchall()
    for LocalDevice in LocalDevices:
        if LocalDevice[0] == "255.255.255.255" or LocalDevice[0] == "0.0.0.0":
            continue
        ip_address = ipaddress.ip_address(LocalDevice[0])
        if ip_address in NET:
            analyze_device(
                device_id,
                LocalDevice[0],
                LocalDevice[1],
                cursor,
                sqlite_connection,
                json_output,
                ip_address_statistics,
                gl,
                args,
                sample,
            )
            device_id = device_id + 1
    # ==================================================================
    if args.localgraph == True:
        create_graphs.graph_of_local_dependencies(
            cursor, sqlite_connection, json_output
        )
    if args.globalgraph == True:
        create_graphs.graph_of_global_dependencies(
            cursor, sqlite_connection, json_output
        )
    if args.bipartite == True:
        create_graphs.graph_of_dependencies_between_local_and_global_devices(
            cursor, sqlite_connection, json_output
        )
    # ==================================================================
    transfer_statistic_to_percents(ip_address_statistics, json_output, 3)
    if args.file != "":
        print(
            "######################################################################",
            file=sample,
        )
        print("  Print Statistic of using network by devices in %:", file=sample)
        for i, j in ip_address_statistics.items():
            print("    ", i, "\t\t\t", j, "%", file=sample)
    if args.print == True:
        print("######################################################################")
        print("  Print Statistic of using network by devices in %:")
        transfer_statistic_to_percents(ip_address_statistics, json_output, 2)
    # ==================================================================
    if args.file != "":
        sample.close()
    x = datetime.datetime.now()
    json_output["Network"] = args.network
    json_output["DateAnalyze"] = str(x)
    json_output["NumberDevice"] = device_id - 1
    format_json.write_json(json_output, args.json)
    print("Output json_output: ", args.json)


def analyze_single_device(sqlite_connection, args):
    """Analyze single device from arguments. If isn't in database print error and end. Else analyze it.

    Parameters
    -----------
    sqlite_connection : sqlite3
        Connection to sqlite3 database.
    args : argparse
        Setted arguments of the script.
    """
    try:
        ip_address = ipaddress.ip_address(args.device)
    except:
        print("ERROR: Entered value isn't IP address")
        sys.exit()
    cursor = sqlite_connection.cursor()
    cursor.execute("SELECT * FROM LocalDevice WHERE IP='{ip}'".format(ip=args.device))
    device = cursor.fetchone()
    if not device:
        print("ERROR: Entered IP address isn't in database")
        sys.exit()
    json_output = format_json.crete_json_format_for_single_device()
    format_json.write_json(json_output, args.json)
    json_output = format_json.read_json(args.json)
    ip_address_statistics = {}
    if args.file != "":
        if check_str(args.file, ".txt") == True:
            file = args.file
        else:
            file = args.file + ".txt"
        sample = open(file, "w")
    else:
        sample = ""
    analyze_device(
        "XXX",
        device[0],
        device[1],
        cursor,
        sqlite_connection,
        json_output,
        ip_address_statistics,
        True,
        args,
        sample,
    )
    transfer_statistic_to_percents(ip_address_statistics, json_output, 3)
    if args.file != "":
        print(
            "######################################################################",
            file=sample,
        )
        print("  Print Statistic of using network by devices in %:", file=sample)
        for i, j in ip_address_statistics.items():
            print("    ", i, "\t\t\t", j, "%", file=sample)
    if args.print == True:
        print("######################################################################")
        print("  Print Statistic of using network by devices in %:")
        transfer_statistic_to_percents(ip_address_statistics, json_output, 2)
    if args.file != "":
        sample.close()
    x = datetime.datetime.now()
    json_output["DateAnalyze"] = str(x)
    format_json.write_json(json_output, args.json)
    print("Output json_output: ", args.json)


def do_analyze_by_arguments(sqlite_connection, args):
    """Analyze all "local" devices from database table LocalDevice.

    Parameters
    -----------
    sqlite_connection : sqlite3
        Connection to sqlite3 database.
    args : argparse
        Setted arguments of the script.
    """
    # ==================================================================
    json_output = format_json.crete_json_format_for_full_analyze()
    format_json.write_json(json_output, args.json)
    json_output = format_json.read_json(args.json)
    # ==================================================================
    ip_address_statistics = {}
    cursor = sqlite_connection.cursor()
    device_id = 1
    # ==================================================================
    gl = True
    cursor.execute("SELECT COUNT(*) FROM Global")
    GlobalC = cursor.fetchone()
    if GlobalC[0] == 0:
        gl = False
    # ==================================================================
    if args.file != "":
        if check_str(args.file, ".txt") == True:
            file = args.file
        else:
            file = args.file + ".txt"
        sample = open(file, "w")
    else:
        sample = ""
    cursor.execute("SELECT * FROM LocalDevice")
    LocalDevices = cursor.fetchall()
    for LocalDevice in LocalDevices:
        if LocalDevice[0] == "255.255.255.255" or LocalDevice[0] == "0.0.0.0":
            continue
        analyze_device(
            device_id,
            LocalDevice[0],
            LocalDevice[1],
            cursor,
            sqlite_connection,
            json_output,
            ip_address_statistics,
            gl,
            args,
            sample,
        )
        device_id = device_id + 1
    # ==================================================================
    if args.localgraph == True:
        create_graphs.graph_of_local_dependencies(
            cursor, sqlite_connection, json_output
        )
    if args.globalgraph == True:
        create_graphs.graph_of_global_dependencies(
            cursor, sqlite_connection, json_output
        )
    if args.bipartite == True:
        create_graphs.graph_of_dependencies_between_local_and_global_devices(
            cursor, sqlite_connection, json_output
        )
    # ==================================================================
    transfer_statistic_to_percents(ip_address_statistics, json_output, 3)
    if args.file != "":
        print(
            "######################################################################",
            file=sample,
        )
        print("  Print Statistic of using network by devices in %:", file=sample)
        for i, j in ip_address_statistics.items():
            print("    ", i, "\t\t\t", j, "%", file=sample)
    if args.print == True:
        print("######################################################################")
        print("  Print Statistic of using network by devices in %:")
        transfer_statistic_to_percents(ip_address_statistics, json_output, 3)
    # ==================================================================
    if args.file != "":
        sample.close()
    x = datetime.datetime.now()
    json_output["DateAnalyze"] = str(x)
    json_output["NumberDevice"] = device_id - 1
    format_json.write_json(json_output, args.json)
    print("Output json_output: ", args.json)


def parse_arguments():
    """Arguments of the DeviceAnalyzer script.

    Returns
    --------
    args : argparse
        Setted arguments of the script.
    """
    parser = argparse.ArgumentParser(
        description="""Analyze of captured network flow in database. 
    Database is created by CreateScript. Filled with PassiveAutodiscovery.py NEMEA modul with coaporate Collector.py.

    Usage:""",
        formatter_class=RawTextHelpFormatter,
    )
    # =====================================================
    parser.add_argument(
        "-D",
        "--device",
        help="Analyze single device [DEVICE = IP address of device to analyze]",
        type=str,
        metavar="DEVICE",
        default="",
    )
    # =====================================================
    parser.add_argument(
        "-N",
        "--network",
        help="Analyze single netowkr subnet [NETWORK = IP address of network and mask: 192.168.1.0/24]",
        type=str,
        metavar="NETWORK",
        default="",
    )
    # =====================================================
    parser.add_argument(
        "-d",
        "--database",
        help="Set name of the database without . part,  default is Database",
        type=str,
        metavar="NAME",
        default="Database",
    )
    # =====================================================
    parser.add_argument(
        "-G",
        "--GlobalNumber",
        help="Number of global dependencies to print, default: all dependencies",
        type=int,
        metavar="NUMBER",
        default=-1,
    )
    # =====================================================
    parser.add_argument(
        "-L",
        "--LocalNumber",
        help="Number of local dependencies to print, default: all dependencies",
        type=int,
        metavar="NUMBER",
        default=-1,
    )
    # =====================================================
    parser.add_argument(
        "-J",
        "--json",
        help="print to JSON file [NAME = name of the file without . part (file will be automatic set to .json), default = PassiveAutodiscovery ]",
        type=str,
        metavar="NAME",
        default="PassiveAutodiscovery",
    )
    # =====================================================
    parser.add_argument(
        "-f",
        "--file",
        help="print to file [NAME = name of the file without . part (file will be automatic set to .txt) ]",
        type=str,
        metavar="NAME",
        default="",
    )
    # =====================================================
    parser.add_argument(
        "-p", "--print", help="print to command line", action="store_true"
    )
    # =====================================================
    parser.add_argument(
        "-P",
        "--printJSON",
        help="print from json file that was created by DeviceAnalyzer script. Need define where print output (command line/file) with parameter [-p], [-f].",
        type=str,
        metavar="NAME",
        default="",
    )
    # =====================================================
    parser.add_argument(
        "-DNS",
        "--DNS",
        help="transalte [WEB Servers] IP to domain name and show in output",
        action="store_true",
    )
    # =====================================================
    parser.add_argument(
        "-t",
        "--timeL",
        help="Generate graphs of using dependencies in time for setted number of local dependencies from mostly used. (for workign must be run PassiveAutodiscovery.py wiht parameter -T)",
        type=int,
        metavar="NUMBER",
        default=-1,
    )
    # =====================================================
    parser.add_argument(
        "-T",
        "--timeG",
        help="Generate graphs of using dependencies in time for setted number of dependencies of local device with global devices from mostly used. (for workign must be run PassiveAutodiscovery.py wiht parameter -T)",
        type=int,
        metavar="NUMBER",
        default=-1,
    )
    # =====================================================
    parser.add_argument(
        "-A",
        "--activity",
        help="print graph of activity device in network over time.",
        action="store_true",
    )
    # =====================================================
    parser.add_argument(
        "-l",
        "--localgraph",
        help="create graph of dependencies between local devices and safe it to file",
        action="store_true",
    )
    # =====================================================
    parser.add_argument(
        "-g",
        "--globalgraph",
        help="create graph of dependencies between local device and all global devices which was visited by local device, then safe it to file",
        action="store_true",
    )
    # =====================================================
    parser.add_argument(
        "-b",
        "--bipartite",
        help="create graph of dependencies between local devices and  global devices that was visited by more local devices, then safe it to file",
        action="store_true",
    )
    # =====================================================
    parser.add_argument(
        "-o", "--onlylocal", help="Analyze only local dependencies", action="store_true"
    )
    # =====================================================
    args = parser.parse_args()
    if args.device != "" and args.network != "":
        print("Parameters -D and -N can't be combinated. Choose only one")
        sys.exit()
    if args.network != "":
        try:
            NET = ipaddress.ip_network(args.network)
        except:
            print("Badly inserted ip address of network ", args.network)
            sys.exit()
    return args


def connect_to_slite3_database(args):
    """Connect to sqlite3 database which analyze.

    Parameters
    -----------
    args : argparse
        Setted arguments of the script.
    Returns
    --------
    sqlite_connection : sqlite3
        Connection to sqlite3 database with name from arguments.
    """
    try:  # connect to a database
        print("Connecting to a database....", end="")
        if check_str(args.database, ".db") == True:
            file = args.database
        else:
            file = args.database + ".db"
        if not os.path.exists(file):
            print("")
            print("can't connect to ", file)
            sys.exit()
        sqlite_connection = sqlite3.connect(file)
        print("done")
    except sqlite3.Error as error:
        print("Can't connect to a database:  ", error)
    return sqlite_connection


def main():
    """Main function call one of three function by arguments where it is set.

    """
    args = parse_arguments()
    if args.printJSON != "":
        if args.print == False and args.file == "":
            print(
                "Need define output method (print to command line or file [-p], [-f])"
            )
            sys.exit()
        json_output = format_json.read_json(args.json)
        print_analyze.print_json(json_output, args)
        sys.exit()
    sqlite_connection = connect_to_slite3_database(args)
    if args.device != "":
        analyze_single_device(sqlite_connection, args)
    elif args.network != "":
        analyze_network(sqlite_connection, args)
    else:
        do_analyze_by_arguments(sqlite_connection, args)
    # =====================================================
    # Close database connection
    if sqlite_connection:
        sqlite_connection.close()


if __name__ == "__main__":
    main()

