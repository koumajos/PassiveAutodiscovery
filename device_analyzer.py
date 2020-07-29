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
import math
import socket
import time
import datetime
import tempfile
import argparse
from argparse import RawTextHelpFormatter

# Third Part Imports
from termgraph import termgraph
import pandas
import numpy
import networkx
import matplotlib.pyplot as plt
import matplotlib.ticker as plticker

# Local Application Imports
from create_script import check_str


def bubble_sort(times, num_packets):
    """Bubble sort for sorting Activity data in arrays times and num_packets. Function sort array of time times and array num_packets sort by times (time and number of packets must stay on same index after sort)

    Parameters
    -----------
    times : array
        Array of times.
    num_packets : array
        Array contains on index i number of packets at time times[i].
    """
    n = len(times)
    for i in range(n - 1):
        for j in range(0, n - i - 1):
            if times[j] > times[j + 1]:
                times[j], times[j + 1] = times[j + 1], times[j]
                num_packets[j], num_packets[j + 1] = num_packets[j + 1], num_packets[j]


def graph_activity_of_device(device, cursor, device_json):
    """Plot graph of using dependency in time and safe it to file. Line times is time and line num_packets is number of packets.

    Parameters
    -----------
    device : str
        Name of device to analyze.
    cursor : sqlite3
        Cursor to sqlite3 database for execute SQL queries.
    device_json : JSON  
        JSON file loaded in python.    
    """
    times = []
    num_packets = []
    cursor.execute(
        f"SELECT * FROM Dependencies WHERE (IP_origin='{device}' OR IP_target='{device}')"
    )
    devrows = cursor.fetchall()
    for devrow in devrows:
        cursor.execute(
            f"SELECT * FROM DependenciesTime WHERE DependenciesID='{devrow[0]}'"
        )
        rows = cursor.fetchall()
        for row in rows:
            time = float(row[2])
            if time.ctime((time - (time % 60))) in times:
                tmp = times.index(time.ctime((time - (time % 60))))
                num_packets[tmp] = num_packets[tmp] + row[3]
            else:
                times.append(time.ctime((time - (time % 60))))
                num_packets.append(row[3])

    cursor.execute(
        f"SELECT * FROM Global WHERE (IP_origin='{device}' OR IP_target='{device}')"
    )
    devrows = cursor.fetchall()
    for devrow in devrows:
        cursor.execute(f"SELECT * FROM GlobalTime WHERE GlobalID='{devrow[0]}'")
        rows = cursor.fetchall()
        for row in rows:
            time = float(row[2])
            if time.ctime((time - (time % 60))) in times:
                tmp = times.index(time.ctime((time - (time % 60))))
                num_packets[tmp] = num_packets[tmp] + row[3]
            else:
                times.append(time.ctime((time - (time % 60))))
                num_packets.append(row[3])

    bubble_sort(times, num_packets)

    plt.rcParams["figure.figsize"] = (20, 3)
    plt.plot_statistics(times, num_packets)
    plt.setp(plt.gca().xaxis.get_majorticklabels(), rotation=0)
    loc = plticker.MultipleLocator(
        base=40
    )  # this locator puts ticks at regular intervals
    plt.gca().xaxis.set_major_locator(loc)  # naming the x axis
    plt.xlabel("Time (in minutes)")
    # naming the y axis
    plt.ylabel("Number of Packets")
    # giving a title to my graph
    plt.title("Active of device " + device)
    plt.savefig("ActiveOfDevice_" + device + ".png")
    device_json["Files"].append("ActiveOfDevice_" + device + ".png")
    print(
        f"Graph of activity of device {device} in time safe in file: ActiveOfDevice_{device}.png"
    )
    plt.clf()


def graph_activity_of_dependency(dependency, table, cursor, device_json):
    """Plot graph of using dependency in time and safe it to file. Line times is time and line num_packets is number of packets.

    Parameters
    -----------
    dependency : sqlite3.fetchone()
        Record of dependency that may be ploted.
    table : str
        Name of table where is record of dependency safed (Dependencies or Global).
    cursor : sqlite3
        Cursor to sqlite3 database for execute SQL queries.
    device_json : JSON  
        JSON file loaded in python.    
    """
    if table == "Dependencies":
        cursor.execute(
            f"SELECT * FROM DependenciesTime WHERE DependenciesID='{dependency[0]}'"
        )
        rows = cursor.fetchall()
    else:
        cursor.execute(f"SELECT * FROM GlobalTime WHERE GlobalID='{dependency[0]}'")
        rows = cursor.fetchall()
    if not rows:
        return

    times = []
    num_packets = []
    time = rows[0][2]
    tmp_packets = 0

    for row in rows:
        if float(row[2]) <= (float(time) + 60):
            tmp_packets = tmp_packets + row[3]
        else:
            times.append(time.ctime(float(time)))
            num_packets.append(tmp_packets)
            while float(row[2]) > (float(time) + 60):
                time = str(float(time) + 60)
                times.append(time.ctime(float(time)))
                num_packets.append(0)
            tmp_packets = row[3]

    plt.rcParams["figure.figsize"] = (20, 3)
    plt.plot_statistics(times, num_packets)
    plt.setp(plt.gca().xaxis.get_majorticklabels(), rotation=0)
    loc = plticker.MultipleLocator(
        base=40
    )  # this locator puts ticks at regular intervals
    plt.gca().xaxis.set_major_locator(loc)  # naming the x axis
    plt.xlabel("Time (in minutes)")
    # naming the y axis
    plt.ylabel("Number of Packets")
    # giving a title to my graph
    plt.title(
        f"dependency between {dependency[1]}({str(dependency[3])}) and {dependency[2]}({str(dependency[4])})"
    )
    plt.savefig(
        f"TimeGraph_{dependency[1]}({str(dependency[3])})_{dependency[2]}({str(dependency[4])}).png"
    )
    device_json["Files"].append(
        f"TimeGraph_{dependency[1]}({str(dependency[3])})_{dependency[2]}({str(dependency[4])}).png"
    )
    print(
        f"Graph of using dependency in time safe in file: TimeGraph_{dependency[1]}({str(dependency[3])})_{dependency[2]}({str(dependency[4])}).png"
    )
    plt.clf()


def plot_statistics(data):
    """Plot the statistical graph of using network (by protocols or devices) in %. Only for output in command line.

    Parameters
    -----------
    data : list
        List of deveces/protocols with Percent of use the network.  
    """
    with tempfile.NamedTemporaryFile(mode="a+") as f:
        # Save data in temporary file
        for row in data:
            f.write("\t".join(map(str, row)) + "\n")
        # Move cursor in order to make sure that script will
        # start reading file from the beggining.
        f.seek(0)
        # Overwrite args in case if there were some other
        # arguments passed to the main script
        #
        # Additional arguments can be passed in the same way.
        original_argv = sys.argv
        sys.argv = [sys.argv[0], f.name]
        termgraph.main()
        # Revert back changes to the original arguemnts
        sys.argv = original_argv


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


def graph_of_local_dependencies(cursor, sqlite_connection, json_output):
    """Function create graph of local dependencies for IP address version 4 and IP address version 6. Then safe it to file named Graph_Local_[ip verison].

    Parameters
    -----------
    cursor : sqlite3
        Cursor to sqlite3 database for execute SQL queries.
    sqlite_connection : sqlite3
        Connection to sqlite3 database.
    json_output : JSON
        JSON file loaded in python.    
    """
    cursor.execute("SELECT * FROM Dependencies")
    rows = cursor.fetchall()
    if not rows:
        return
    print("######################################################################")
    print("Graph of local dependencies is safed in file:\tGraph_Local.png")
    # =================================
    plt.figure(
        "Map of Local Dependencies IPv4",
        figsize=(20, 10),
        dpi=80,
        facecolor="w",
        edgecolor="k",
    )
    graph_ipv4 = networkx.Graph()
    for row in rows:
        if (
            row[1] == "255.255.255.255"
            or row[1] == "0.0.0.0"
            or row[2] == "255.255.255.255"
            or row[2] == "0.0.0.0"
        ):
            continue
        ipa = ipaddress.ip_address(row[1])
        if ipa.version == 4:
            graph_ipv4.add_edge(row[1], row[2])
    pos = networkx.spring_layout(graph_ipv4)
    networkx.draw(graph_ipv4, pos, with_labels=True)
    plt.axis("off")
    plt.savefig("Graph_Local_IPv4.png")
    json_output["Files"].append("Graph_Local_IPv4.png")
    # =================================
    plt.figure(
        "Map of Local Dependencies IPv6",
        figsize=(20, 10),
        dpi=80,
        facecolor="w",
        edgecolor="k",
    )
    graph_ipv6 = networkx.Graph()
    for row in rows:
        if (
            row[1] == "255.255.255.255"
            or row[1] == "0.0.0.0"
            or row[2] == "255.255.255.255"
            or row[2] == "0.0.0.0"
        ):
            continue
        ipa = ipaddress.ip_address(row[1])
        if ipa.version == 6:
            graph_ipv6.add_edge(row[1], row[2])
    pos = networkx.spring_layout(graph_ipv6)
    networkx.draw(graph_ipv6, pos, with_labels=True)
    plt.axis("off")
    plt.savefig("Graph_Local_IPv6.png")
    json_output["Files"].append("Graph_Local_IPv6.png")


def graph_of_global_dependencies(cursor, sqlite_connection, json_output):
    """Function create graph of global dependencies for each device. Then safe them to files named Graph_Global_[IP address].

    Parameters
    -----------
    cursor : sqlite3
        Cursor to sqlite3 database for execute SQL queries.
    sqlite_connection : sqlite3
        Connection to sqlite3 database.
    json_output : JSON
        JSON file loaded in python.    
    """
    cursor.execute("SELECT * FROM LocalDevice")
    local_devices = cursor.fetchall()
    if local_devices is not None:
        print("######################################################################")
    for device in local_devices:
        cursor.execute(f"SELECT * FROM Global WHERE IP_origin='{device[0]}'")
        global_dependencies = cursor.fetchall()
        if not global_dependencies:
            continue

        plt.figure(
            f"Map of Global Dependencies for device: {device[0]}",
            figsize=(20, 10),
            dpi=80,
            facecolor="w",
            edgecolor="k",
        )
        global_graph = networkx.Graph()
        for global_dependency in global_dependencies:
            global_graph.add_edge(global_dependency[1], global_dependency[2])
        pos = networkx.spring_layout(global_graph)
        networkx.draw(global_graph, pos, with_labels=True)
        plt.axis("off")
        plt.savefig(f"Graph_Global_{device[0]}.png")
        print(
            f"Global Dependencies for device {device[0]} is safed in file:\t{device[0]}.png"
        )
        json_output["Files"].append(f"Graph_Global_{device[0]}.png")


def graph_of_dependencies_between_local_and_global_devices(
    cursor, sqlite_connection, json_output
):
    """Function create graph of dependencies between local and global device, where global is only if two or more local device have communication with. Then safe them to files named Graph_GlobalsToLocals_[number]. (Graph are for visibility safe to more files by small number of devices)

    Parameters
    -----------
    cursor : sqlite3
        Cursor to sqlite3 database for execute SQL queries.
    sqlite_connection : sqlite3
        Connection to sqlite3 database.
    json_output : JSON
        JSON file loaded in python.    
    """
    print("######################################################################")
    cursor.execute(
        "SELECT * FROM (SELECT IP_origin AS IP FROM Global GROUP BY IP_origin HAVING COUNT(*) > 1 UNION ALL SELECT IP_target AS IP FROM Global GROUP BY IP_target HAVING COUNT(*) > 1) GROUP BY IP"
    )
    IP = cursor.fetchall()
    bipartite_graph = networkx.Graph()
    graph_number = 0
    for i in IP:
        ip = ipaddress.ip_address(i[0])
        if ip.is_global == True:
            cursor.execute(
                "SELECT * FROM (SELECT IP_target AS IP, IP_origin AS IPM FROM Global WHERE IP_origin='{ipo}' UNION ALL SELECT IP_origin AS IP, IP_target AS IPM FROM Global WHERE IP_target='{ipo}') GROUP BY IP".format(
                    ipo=i[0], ipt=i[0]
                )
            )
            Dependencies = cursor.fetchall()
            if len(Dependencies) > 1:
                for j in Dependencies:
                    bipartite_graph.add_node(j[0], bipartite=0)
                    bipartite_graph.add_node(j[1], bipartite=1)
                    bipartite_graph.add_edge(j[0], j[1])
                if len(bipartite_graph) > 15:
                    try:
                        # Separate by group
                        l, r = networkx.bipartite.sets(bipartite_graph)
                        pos = {}
                        # Update position for node from each group
                        pos.update((node, (1, index)) for index, node in enumerate(l))
                        pos.update((node, (2, index)) for index, node in enumerate(r))
                        networkx.draw(bipartite_graph, pos, with_labels=True)
                        x_values, y_values = zip(*pos.values())
                        x_max = max(x_values)
                        x_min = min(x_values)
                        x_margin = (x_max - x_min) * 0.25
                        plt.xlim(x_min - x_margin, x_max + x_margin)
                        plt.axis("off")
                        plt.savefig("Graph_GlobalsToLocals_%s.png" % graph_number)
                        # plt.show()
                        plt.clf()
                        json_output["Files"].append(
                            "Graph_GlobalsToLocals_%s.png" % graph_number
                        )
                        graph_number = graph_number + 1
                        bipartite_graph.clear()
                    except:
                        bipartite_graph.clear()


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
        "SELECT S.PortNumber, S.DeviceType, S.Shortcut, S.Description FROM LocalServices LS JOIN Services S ON LS.PortNumber=S.PortNumber WHERE LS.IP='{ip}'".format(
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
    Router = cursor.fetchone()
    if Router:
        cursor.execute("SELECT * FROM Routers WHERE MAC='{mac}'".format(mac=Router[1]))
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


def LOCALDEPENDENCIES(
    device_id,
    ip_address,
    device_ipaddress,
    local_services_statistic,
    ip_address_statistics,
    cursor,
    sqlite_connection,
    device_json,
    arguments,
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
    if dependencies:
        for dependency in dependencies:
            if arguments.timeL > tmp:
                graph_activity_of_dependency(
                    dependency, "Dependencies", cursor, json_output
                )
                tmp = tmp + 1
            stats_of_services(
                local_services_statistic, dependency, cursor, sqlite_connection
            )
            # ==========================================
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
            # ==========================================
            src_ip = ipaddress.ip_address(dependency[1])
            cursor.execute(
                "SELECT * FROM Services WHERE PortNumber='{portS}'".format(
                    portS=dependency[3]
                )
            )
            src_services = cursor.fetchone()
            cursor.execute(
                "SELECT * FROM Services WHERE PortNumber='{portD}'".format(
                    portD=dependency[4]
                )
            )
            dst_services = cursor.fetchone()
            # ==========================================
            depencency_ip = ""
            verb = "provides"
            services = ""
            port = 0
            packets = dependency[5]
            # ==========================================
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
            elif dst_services:
                if src_ip == device_ipaddress:
                    depencency_ip = dependency[2]
                else:
                    depencency_ip = dependency[1]
                    verb = "requires"
                services = dst_services[1]
                port = dependency[4]
            else:
                if src_ip == device_ipaddress:
                    depencency_ip = dependency[2]
                    cursor.execute(
                        "SELECT * FROM Ports WHERE PortNumber='{port}'".format(
                            port=dependency[4]
                        )
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
                        "SELECT * FROM Ports WHERE PortNumber='{port}'".format(
                            port=dependency[3]
                        )
                    )
                    src_port = cursor.fetchone()
                    if src_port:
                        services = src_port[1]
                        port = dependency[3]
                    else:
                        port = dependency[3]
            # ========================================================
            device_json["LocalDependencies"].append(
                {
                    "IP": "%s" % depencency_ip,
                    "Verb": "%s" % verb,
                    "Service": "%s" % services,
                    "Port": "%s" % port,
                    "Packets": "%s" % packets,
                }
            )


def GLOBALDEPENDENCIES(
    device_id,
    IP,
    DeviceIP,
    GlobalStatistic,
    ip_address_statistics,
    cursor,
    sqlite_connection,
    device_json,
    arguments,
    json_output,
):
    """Function for device find in database all global dependencies and set in to output JSON. Also create statistic of global dependencies and statistic of using network by deveices. 

    Parameters
    -----------
    device_id : int
        Number of device in analyze.
    IP : str
        Device IP address in format str.
    DeviceIP : ipaddress
        Device IP address in format ipaddress.
    GlobalStatistic : dictionary
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
            ipo=IP, ipt=IP
        )
    )
    GlobalDependencies = cursor.fetchall()
    tmp = 0
    if GlobalDependencies:
        promtp = 0
        for GlobalDependency in GlobalDependencies:
            if arguments.timeG > tmp:
                graph_activity_of_dependency(
                    GlobalDependency, "Global", cursor, json_output
                )
                tmp = tmp + 1
            stats_of_services(
                GlobalStatistic, GlobalDependency, cursor, sqlite_connection
            )
            # ==========================================
            SrcIP = ipaddress.ip_address(GlobalDependency[1])
            # ==========================================
            if GlobalDependency[1] == IP:
                if GlobalDependency[1] in ip_address_statistics:
                    ip_address_statistics[GlobalDependency[1]] = (
                        ip_address_statistics[GlobalDependency[1]] + GlobalDependency[5]
                    )
                else:
                    ip_address_statistics[GlobalDependency[1]] = GlobalDependency[5]
            else:
                if GlobalDependency[2] in ip_address_statistics:
                    ip_address_statistics[GlobalDependency[2]] = (
                        ip_address_statistics[GlobalDependency[2]] + GlobalDependency[5]
                    )
                else:
                    ip_address_statistics[GlobalDependency[2]] = GlobalDependency[5]
            # ==========================================
            cursor.execute(
                "SELECT * FROM Services WHERE PortNumber='{portS}'".format(
                    portS=GlobalDependency[3]
                )
            )
            ServiceS = cursor.fetchone()
            cursor.execute(
                "SELECT * FROM Services WHERE PortNumber='{portD}'".format(
                    portD=GlobalDependency[4]
                )
            )
            ServiceD = cursor.fetchone()
            # ========================================================
            depencency_ip = ""
            verb = "provides"
            Services = ""
            Port = 0
            Packets = GlobalDependency[5]
            Domain = ""
            # ========================================================
            if ServiceS:
                if SrcIP == DeviceIP:
                    depencency_ip = GlobalDependency[2]
                    if ServiceS[1] == "DHCP Client":
                        Services = "DHCP Server"
                    else:
                        verb = "requires"
                else:
                    depencency_ip = GlobalDependency[1]
                if promtp < 15:
                    Services = ServiceS[1]
                    Port = GlobalDependency[3]
                    if ServiceS[1] == "WEB Server" and SrcIP == DeviceIP:
                        try:
                            sck = socket.gethostbyaddr(GlobalDependency[2])
                            Domain = "(Domain:" + sck[0] + ")"
                        except:
                            None
                    elif ServiceS[1] == "WEB Server":
                        try:
                            sck = socket.gethostbyaddr(GlobalDependency[1])
                            Domain = "(Domain:" + sck[0] + ")"
                        except:
                            None
                    else:
                        None
                else:
                    Services = ServiceS[1]
                    Port = GlobalDependency[3]
            elif ServiceD:
                if SrcIP == DeviceIP:
                    depencency_ip = GlobalDependency[2]
                else:
                    depencency_ip = GlobalDependency[1]
                    verb = "requires"
                if promtp < 15:
                    Services = ServiceD[1]
                    Port = GlobalDependency[4]
                    if ServiceD[1] == "WEB Server" and SrcIP == DeviceIP:
                        try:
                            sck = socket.gethostbyaddr(GlobalDependency[2])
                            Domain = "(Domain:" + sck[0] + ")"
                        except:
                            None
                    elif ServiceD[1] == "WEB Server":
                        try:
                            sck = socket.gethostbyaddr(GlobalDependency[1])
                            Domain = "(Domain:" + sck[0] + ")"
                        except:
                            None
                    else:
                        None
                else:
                    Services = ServiceD[1]
                    Port = GlobalDependency[4]
            else:
                if SrcIP == DeviceIP:
                    depencency_ip = GlobalDependency[2]
                    cursor.execute(
                        "SELECT * FROM Ports WHERE PortNumber='{portD}'".format(
                            portD=GlobalDependency[4]
                        )
                    )
                    PortD = cursor.fetchone()
                    if PortD:
                        Services = PortD[1]
                        Port = GlobalDependency[4]
                    else:
                        Port = GlobalDependency[4]
                else:
                    depencency_ip = GlobalDependency[1]
                    verb = "requires"
                    cursor.execute(
                        "SELECT * FROM Ports WHERE PortNumber='{portS}'".format(
                            portS=GlobalDependency[3]
                        )
                    )
                    PortS = cursor.fetchone()
                    if PortS:
                        Services = PortS[1]
                        Port = GlobalDependency[3]
                    else:
                        Port = GlobalDependency[3]
            # ========================================================
            device_json["GlobalDependencies"].append(
                {
                    "IP": "%s" % depencency_ip,
                    "Verb": "%s" % verb,
                    "Service": "%s" % Services,
                    "Port": "%s" % Port,
                    "Packets": "%s" % Packets,
                }
            )


def StatPercent(Statistic, device_json, TMP):
    """Function receive dictionary. The dictionarz number of packets calculate and create from it Percents.

    Parameters
    -----------
    Statistic : dictionary
        The dictionary of statistic with protocols/devices and number of packets that was carryed in network by it.
    device_json : JSON
        JSON file for device with device_id ID loaded in python.        
    TMP : int
        Magic value represent the type of statistic (Local statistic == 0, Global statistic == 1, Network use statistic == 2).
    """
    if Statistic == {}:
        return
    tmp = 0
    for i, j in Statistic.items():
        tmp = tmp + j
    # ==========================
    Statistic = {
        r: Statistic[r] for r in sorted(Statistic, key=Statistic.get, reverse=True)
    }
    for i, j in Statistic.items():
        Statistic[i] = float(j / tmp * 100)
        if TMP == 0:
            device_json["LocalStatistic"].append(
                {"Service": "%s" % i, "Percents": "%s" % Statistic[i]}
            )
        elif TMP == 1:
            device_json["GlobalStatistic"].append(
                {"Service": "%s" % i, "Percents": "%s" % Statistic[i]}
            )
        else:
            device_json["ip_address_statistics"].append(
                {"IP": "%s" % i, "Percents": "%s" % Statistic[i]}
            )
    if TMP == 2:
        plot_statistics(Statistic.items())


def IPAddress(IP, cursor, device_json):
    """Function finds in database all IP address of the device (more then one only when device used both version of IP address or change IP address while monitoring network (DHCP)).

    Parameters
    -----------
    IP : str
        IP address of analyzed device.
    cursor : sqlite3
        Cursor to sqlite3 database for execute SQL queries.
    device_json : JSON
        JSON file for device with device_id ID loaded in python.            
    """
    device_json["IP"].append(IP)
    cursor.execute("SELECT * FROM Routers WHERE IP='{ip}'".format(ip=IP))
    Router = cursor.fetchone()
    if not Router:
        cursor.execute(
            "SELECT * FROM MAC WHERE IP='{ip}' AND LastUse='{lu}'".format(ip=IP, lu="")
        )
        IPs = cursor.fetchall()
        for ip in IPs:
            if not ip[1] == IP:
                device_json["IP"].append(ip[1])
    else:
        cursor.execute(
            "SELECT DeviceType FROM LocalServices LS JOIN Services S ON LS.PortNumber=S.PortNumber WHERE LS.IP='{ip}' AND S.DeviceType='{device}'".format(
                ip=IP, device="Router"
            )
        )
        Router = cursor.fetchall()
        if Router:
            cursor.execute(
                "SELECT * FROM Routers WHERE MAC='{mac}'".format(mac=Router[1])
            )
            Routers = cursor.fetchall()
            IPD = ipaddress.ip_address(IP)
            for ip in Routers:
                ipd = ipaddress.ip_address(ip[2])
                if ipd.is_private and ip[2] != IP and IPD.version == ipd.version:
                    device_json["DeviceBehindRouter"].append(ip[2])


def PrintDeviceFromJSON(json_output, arguments):
    """Print device from output JSON document to command line.

    Parameters
    -----------
    json_output : JSON
        Ouput JSON document.
    arguments : argparse
        Setted arguments of the DeviceAnalyzer script.    
    """
    if (
        not json_output["LocalDependencies"]
        and not json_output["GlobalDependencies"]
        and not json_output["Labels"]
    ):
        return
    print("######################################################################")
    print("Device ID: ", json_output["DeviceID"])
    # =================================================================================
    print("  IP: ", end="")
    tmp = 0
    for i in json_output["IP"]:
        if tmp == 0:
            print(i, end="")
            tmp = i
        else:
            print(" <", i, ">", end="")
    print("")
    # =================================================================================
    print("  Last communication: ", time.ctime(float(json_output["LastCom"])))
    # =================================================================================
    print("  MAC: ", end="")
    if json_output["MAC"] == "" and json_output["RouterMAC"] == "":
        print("---")
    elif json_output["RouterMAC"] == "":
        print(json_output["MAC"], end="")
        if json_output["Vendor"] != "":
            print(", ", json_output["Vendor"], ", ", json_output["Country"])
    else:
        print(
            " of router behind this device or this device itself is this router: ",
            json_output["RouterMAC"],
            end="",
        )
        if json_output["Vendor"] != "":
            print(", ", json_output["Vendor"], ", ", json_output["Country"])
    # =================================================================================
    print("  Labels:")
    if not json_output["Labels"]:
        print("    ---")
    for i in json_output["Labels"]:
        if arguments.DNS == True and i["Label"] == "WEB Server":
            try:
                domain = socket.gethostbyaddr(i)
                print("    [", i["Label"], "] - DomainName:", domain)
            except:
                print("    [", i["Label"], "] - ", i["Description"])
        else:
            print("    [", i["Label"], "] - ", i["Description"])
    # =================================================================================
    print("  DHCP:")
    if not json_output["DHCP"]:
        print("    ---")
    for i in json_output["DHCP"]:
        print("    ", i["DHCPServ"], " in ", i["DHCPTime"])
    # =================================================================================
    print("  Local Dependencies:")
    if not json_output["LocalDependencies"]:
        print("    ---")
    if arguments.LocalNumber != -1:
        tmp = 0
        for i in json_output["LocalDependencies"]:
            if tmp < arguments.LocalNumber:
                if i["Verb"] == "provides":
                    print(
                        "    -> ",
                        i["IP"],
                        " ",
                        i["Verb"],
                        " [",
                        i["Service"],
                        "(",
                        i["Port"],
                        ")] - number of packets: ",
                        i["Packets"],
                    )
                else:
                    print(
                        "    <- ",
                        i["IP"],
                        " ",
                        i["Verb"],
                        " [",
                        i["Service"],
                        "(",
                        i["Port"],
                        ")] - number of packets: ",
                        i["Packets"],
                    )
                tmp = tmp + 1
            else:
                break
    else:
        for i in json_output["LocalDependencies"]:
            if i["Verb"] == "provides":
                print(
                    "    -> ",
                    i["IP"],
                    " ",
                    i["Verb"],
                    " [",
                    i["Service"],
                    "(",
                    i["Port"],
                    ")] - number of packets: ",
                    i["Packets"],
                )
            else:
                print(
                    "    <- ",
                    i["IP"],
                    " ",
                    i["Verb"],
                    " [",
                    i["Service"],
                    "(",
                    i["Port"],
                    ")] - number of packets: ",
                    i["Packets"],
                )
    # =================================================================================
    if not json_output["LocalStatistic"]:
        print("")
    else:
        ip_address_statistics = {}
        for i in json_output["LocalStatistic"]:
            ip_address_statistics[i["Service"]] = i["Percents"]
        plot_statistics(ip_address_statistics.items())
    # =================================================================================
    print("  Global Dependencies:")
    if not json_output["GlobalDependencies"]:
        print("    ---")
    if arguments.GlobalNumber == -1:
        for i in json_output["GlobalDependencies"]:
            if arguments.DNS == True:
                try:
                    domain = socket.gethostbyaddr(i["IP"])
                    if i["Verb"] == "provides":
                        print(
                            "    -> ",
                            i["IP"],
                            " ",
                            i["Verb"],
                            " [",
                            i["Service"],
                            "(",
                            i["Port"],
                            ")]  Domain: ",
                            domain[0],
                            "  - number of packets: ",
                            i["Packets"],
                        )
                    else:
                        print(
                            "    <- ",
                            i["IP"],
                            " ",
                            i["Verb"],
                            " [",
                            i["Service"],
                            "(",
                            i["Port"],
                            ")]  Domain: ",
                            domain[0],
                            "  - number of packets: ",
                            i["Packets"],
                        )
                except:
                    if i["Verb"] == "provides":
                        print(
                            "    -> ",
                            i["IP"],
                            " ",
                            i["Verb"],
                            " [",
                            i["Service"],
                            "(",
                            i["Port"],
                            ")] - number of packets: ",
                            i["Packets"],
                        )
                    else:
                        print(
                            "    <- ",
                            i["IP"],
                            " ",
                            i["Verb"],
                            " [",
                            i["Service"],
                            "(",
                            i["Port"],
                            ")] - number of packets: ",
                            i["Packets"],
                        )
            else:
                print(
                    "    -> ",
                    i["IP"],
                    " ",
                    i["Verb"],
                    " [",
                    i["Service"],
                    "(",
                    i["Port"],
                    ")] - number of packets: ",
                    i["Packets"],
                )
    else:
        tmp = 0
        for i in json_output["GlobalDependencies"]:
            if tmp < arguments.GlobalNumber:
                if arguments.DNS == True:
                    try:
                        domain = socket.gethostbyaddr(i["IP"])
                        if i["Verb"] == "provides":
                            print(
                                "    -> ",
                                i["IP"],
                                " ",
                                i["Verb"],
                                " [",
                                i["Service"],
                                "(",
                                i["Port"],
                                ")]  Domain: ",
                                domain[0],
                                "  - number of packets: ",
                                i["Packets"],
                            )
                        else:
                            print(
                                "    <- ",
                                i["IP"],
                                " ",
                                i["Verb"],
                                " [",
                                i["Service"],
                                "(",
                                i["Port"],
                                ")]  Domain: ",
                                domain[0],
                                "  - number of packets: ",
                                i["Packets"],
                            )
                    except:
                        if i["Verb"] == "provides":
                            print(
                                "    -> ",
                                i["IP"],
                                " ",
                                i["Verb"],
                                " [",
                                i["Service"],
                                "(",
                                i["Port"],
                                ")] - number of packets: ",
                                i["Packets"],
                            )
                        else:
                            print(
                                "    <- ",
                                i["IP"],
                                " ",
                                i["Verb"],
                                " [",
                                i["Service"],
                                "(",
                                i["Port"],
                                ")] - number of packets: ",
                                i["Packets"],
                            )
                else:
                    if i["Verb"] == "provides":
                        print(
                            "    -> ",
                            i["IP"],
                            " ",
                            i["Verb"],
                            " [",
                            i["Service"],
                            "(",
                            i["Port"],
                            ")] - number of packets: ",
                            i["Packets"],
                        )
                    else:
                        print(
                            "    <- ",
                            i["IP"],
                            " ",
                            i["Verb"],
                            " [",
                            i["Service"],
                            "(",
                            i["Port"],
                            ")] - number of packets: ",
                            i["Packets"],
                        )
                tmp = tmp + 1
            else:
                break
    # =================================================================================
    if not json_output["GlobalStatistic"]:
        print("")
    else:
        ip_address_statistics = {}
        for i in json_output["GlobalStatistic"]:
            ip_address_statistics[i["Service"]] = i["Percents"]
        plot_statistics(ip_address_statistics.items())


def PrintDeviceToFileFromJSON(json_output, arguments, sample):
    """Print device from output JSON document to file.

    Parameters
    -----------
    json_output : JSON
        Ouput JSON document.
    arguments : argparse
        Setted arguments of the DeviceAnalyzer script.    
    sample : opened file
        Opened output file.
    """
    if not json_output["LocalDependencies"] and not json_output["GlobalDependencies"]:
        return
    print(
        "######################################################################",
        file=sample,
    )
    print("Device ID: ", json_output["DeviceID"], file=sample)
    # =================================================================================
    print("  IP: ", end="", file=sample)
    tmp = 0
    for i in json_output["IP"]:
        if tmp == 0:
            print(i, end="", file=sample)
            tmp = i
        else:
            print(" <", i, ">", end="", file=sample)
    print("", file=sample)
    # =================================================================================
    print(
        "  Last communication: ", time.ctime(float(json_output["LastCom"])), file=sample
    )
    # =================================================================================
    print("  MAC: ", end="", file=sample)
    if json_output["MAC"] == "" and json_output["RouterMAC"] == "":
        print("---", file=sample)
    elif json_output["RouterMAC"] == "":
        print(json_output["MAC"], end="", file=sample)
        if json_output["Vendor"] != "":
            print(
                ", ", json_output["Vendor"], ", ", json_output["Country"], file=sample
            )
    else:
        print(
            " of router behind this device or this device itself is this router: ",
            json_output["RouterMAC"],
            end="",
            file=sample,
        )
        if json_output["Vendor"] != "":
            print(
                ", ", json_output["Vendor"], ", ", json_output["Country"], file=sample
            )
    # =================================================================================
    print("  Labels:", file=sample)
    if not json_output["Labels"]:
        print("    ---", file=sample)
    for i in json_output["Labels"]:
        if arguments.DNS == True:
            try:
                domain = socket.gethostbyaddr(i)
                print("    [", i["Label"], "] - DomainName:", domain, file=sample)
            except:
                print("    [", i["Label"], "] - ", i["Description"], file=sample)
        else:
            print("    [", i["Label"], "] - ", i["Description"], file=sample)
    # =================================================================================
    print("  DHCP:", file=sample)
    if not json_output["DHCP"]:
        print("    ---", file=sample)
    for i in json_output["DHCP"]:
        print("    ", i["DHCPServ"], " in ", i["DHCPTime"], file=sample)
    # =================================================================================
    print("  Local Dependencies:", file=sample)
    if not json_output["LocalDependencies"]:
        print("    ---", file=sample)
    if arguments.LocalNumber != -1:
        tmp = 0
        for i in json_output["LocalDependencies"]:
            if tmp < arguments.LocalNumber:
                if i["Verb"] == "provides":
                    print(
                        "    -> ",
                        i["IP"],
                        " ",
                        i["Verb"],
                        " [",
                        i["Service"],
                        "(",
                        i["Port"],
                        ")] - number of packets: ",
                        i["Packets"],
                        file=sample,
                    )
                else:
                    print(
                        "    <- ",
                        i["IP"],
                        " ",
                        i["Verb"],
                        " [",
                        i["Service"],
                        "(",
                        i["Port"],
                        ")] - number of packets: ",
                        i["Packets"],
                        file=sample,
                    )
                tmp = tmp + 1
            else:
                break
    else:
        for i in json_output["LocalDependencies"]:
            if i["Verb"] == "provides":
                print(
                    "    -> ",
                    i["IP"],
                    " ",
                    i["Verb"],
                    " [",
                    i["Service"],
                    "(",
                    i["Port"],
                    ")] - number of packets: ",
                    i["Packets"],
                    file=sample,
                )
            else:
                print(
                    "    <- ",
                    i["IP"],
                    " ",
                    i["Verb"],
                    " [",
                    i["Service"],
                    "(",
                    i["Port"],
                    ")] - number of packets: ",
                    i["Packets"],
                    file=sample,
                )
    # =================================================================================
    if not json_output["LocalStatistic"]:
        print("", file=sample)
    else:
        ip_address_statistics = {}
        for i in json_output["LocalStatistic"]:
            ip_address_statistics[i["Service"]] = i["Percents"]
        print("  Print Local Statistic:", file=sample)
        for i, j in ip_address_statistics.items():
            print("    ", i, "\t\t\t", j, "%", file=sample)
    # =================================================================================
    print("  Global Dependencies:", file=sample)
    if not json_output["GlobalDependencies"]:
        print("    ---", file=sample)
    if arguments.GlobalNumber == -1:
        for i in json_output["GlobalDependencies"]:
            if arguments.DNS == True:
                try:
                    domain = socket.gethostbyaddr(i["IP"])
                    print(
                        "    -> ",
                        i["IP"],
                        " ",
                        i["Verb"],
                        " [",
                        i["Service"],
                        "(",
                        i["Port"],
                        ")]  Domain: ",
                        domain[0],
                        "  - number of packets: ",
                        i["Packets"],
                        file=sample,
                    )
                except:
                    print(
                        "    -> ",
                        i["IP"],
                        " ",
                        i["Verb"],
                        " [",
                        i["Service"],
                        "(",
                        i["Port"],
                        ")] - number of packets: ",
                        i["Packets"],
                        file=sample,
                    )
            else:
                print(
                    "    -> ",
                    i["IP"],
                    " ",
                    i["Verb"],
                    " [",
                    i["Service"],
                    "(",
                    i["Port"],
                    ")] - number of packets: ",
                    i["Packets"],
                    file=sample,
                )
    else:
        tmp = 0
        for i in json_output["GlobalDependencies"]:
            if tmp < arguments.GlobalNumber:
                if arguments.DNS == True:
                    try:
                        domain = socket.gethostbyaddr(i["IP"])
                        if i["Verb"] == "provides":
                            print(
                                "    -> ",
                                i["IP"],
                                " ",
                                i["Verb"],
                                " [",
                                i["Service"],
                                "(",
                                i["Port"],
                                ")]  Domain: ",
                                domain[0],
                                "  - number of packets: ",
                                i["Packets"],
                                file=sample,
                            )
                        else:
                            print(
                                "    <- ",
                                i["IP"],
                                " ",
                                i["Verb"],
                                " [",
                                i["Service"],
                                "(",
                                i["Port"],
                                ")]  Domain: ",
                                domain[0],
                                "  - number of packets: ",
                                i["Packets"],
                                file=sample,
                            )
                    except:
                        if i["Verb"] == "provides":
                            print(
                                "    -> ",
                                i["IP"],
                                " ",
                                i["Verb"],
                                " [",
                                i["Service"],
                                "(",
                                i["Port"],
                                ")] - number of packets: ",
                                i["Packets"],
                                file=sample,
                            )
                        else:
                            print(
                                "    <- ",
                                i["IP"],
                                " ",
                                i["Verb"],
                                " [",
                                i["Service"],
                                "(",
                                i["Port"],
                                ")] - number of packets: ",
                                i["Packets"],
                                file=sample,
                            )
                else:
                    if i["Verb"] == "provides":
                        print(
                            "    -> ",
                            i["IP"],
                            " ",
                            i["Verb"],
                            " [",
                            i["Service"],
                            "(",
                            i["Port"],
                            ")] - number of packets: ",
                            i["Packets"],
                            file=sample,
                        )
                    else:
                        print(
                            "    <- ",
                            i["IP"],
                            " ",
                            i["Verb"],
                            " [",
                            i["Service"],
                            "(",
                            i["Port"],
                            ")] - number of packets: ",
                            i["Packets"],
                            file=sample,
                        )
                tmp = tmp + 1
            else:
                break
    # =================================================================================
    if not json_output["GlobalStatistic"]:
        print("", file=sample)
    else:
        ip_address_statistics = {}
        for i in json_output["GlobalStatistic"]:
            ip_address_statistics[i["Service"]] = i["Percents"]
        print("  Print Global Statistic:", file=sample)
        for i, j in ip_address_statistics.items():
            print("    ", i, "\t\t\t", j, "%", file=sample)


def PrintJSON(json_output, arguments):
    """Print safed analyze from JSON file. Into file or command line.

    Parameters
    -----------
    json_output : JSON
        JSON file loaded in python.        
    arguments : argparse
        Setted arguments of the script.
    """
    if arguments.print == True:
        for Dev in json_output["Devices"]:
            PrintDeviceFromJSON(Dev, arguments)
    if arguments.file != "":
        if check_str(arguments.file, ".txt") == True:
            FILE = arguments.file
        else:
            FILE = arguments.file + ".txt"
        sample = open(FILE, "w")
        for Dev in json_output["Devices"]:
            PrintDeviceToFileFromJSON(Dev, arguments, sample)


def AnalyzeLocalDevice(
    device_id,
    IP,
    TIME,
    cursor,
    sqlite_connection,
    json_output,
    ip_address_statistics,
    gl,
    arguments,
    sample,
):
    """Analyze a device and output of it add to JSON document.

    Parameters
    -----------
    device_id : int
        Number of device in analyze.
    IP : str
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
    arguments : argparse
        Setted arguments of the script.
    sample : opened file
        Output file.    
    """
    # ==================================================================
    device_json = {
        "DeviceID": 0,
        "LastCom": 0,
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
    # ==================================================================
    device_json["DeviceID"] = device_id
    # ==================================================================
    IPAddress(IP, cursor, device_json)
    # ==================================================================
    device_json["LastCom"] = float(TIME)
    DeviceIP = ipaddress.ip_address(IP)
    # ==================================================================
    add_mac_address(device_id, IP, cursor, sqlite_connection, device_json)
    # ==================================================================
    find_labels(device_id, IP, cursor, sqlite_connection, device_json, json_output, gl)
    # ==================================================================
    add_dhcp_records_for_device(device_id, IP, cursor, sqlite_connection, device_json)
    # ==================================================================
    local_services_statistic = {}
    LOCALDEPENDENCIES(
        device_id,
        IP,
        DeviceIP,
        local_services_statistic,
        ip_address_statistics,
        cursor,
        sqlite_connection,
        device_json,
        arguments,
        json_output,
    )
    StatPercent(local_services_statistic, device_json, 0)
    # ==================================================================
    if arguments.onlylocal == False:
        GlobalStatistic = {}
        GLOBALDEPENDENCIES(
            device_id,
            IP,
            DeviceIP,
            GlobalStatistic,
            ip_address_statistics,
            cursor,
            sqlite_connection,
            device_json,
            arguments,
            json_output,
        )
        StatPercent(GlobalStatistic, device_json, 1)
    # ==================================================================
    if arguments.print == True:
        PrintDeviceFromJSON(device_json, arguments)
    if arguments.file != "":
        print("Output for device ", IP, " printed to file: ", arguments.file)
        PrintDeviceToFileFromJSON(device_json, arguments, sample)
    if arguments.activity == True:
        graph_activity_of_device(IP, cursor, json_output)
    # ==================================================================
    json_output["Devices"].append(device_json)


def AnalyzeNetwork(sqlite_connection, arguments):
    """Analyze network subnet from arguments.

    Parameters
    -----------
    sqlite_connection : sqlite3
        Connection to sqlite3 database.
    arguments : argparse
        Setted arguments of the script.
    """
    # ==================================================================
    json_output = {
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
    write_json(json_output, arguments.json)
    json_output = read_json(arguments.json)
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
    if arguments.file != "":
        if check_str(arguments.file, ".txt") == True:
            FILE = arguments.file
        else:
            FILE = arguments.file + ".txt"
        sample = open(FILE, "w")
    else:
        sample = ""
    NET = ipaddress.ip_network(arguments.network)
    cursor.execute("SELECT * FROM LocalDevice")
    LocalDevices = cursor.fetchall()
    for LocalDevice in LocalDevices:
        if LocalDevice[0] == "255.255.255.255" or LocalDevice[0] == "0.0.0.0":
            continue
        IP = ipaddress.ip_address(LocalDevice[0])
        if IP in NET:
            AnalyzeLocalDevice(
                device_id,
                LocalDevice[0],
                LocalDevice[1],
                cursor,
                sqlite_connection,
                json_output,
                ip_address_statistics,
                gl,
                arguments,
                sample,
            )
            device_id = device_id + 1
    # ==================================================================
    if arguments.localgraph == True:
        graph_of_local_dependencies(cursor, sqlite_connection, json_output)
    if arguments.globalgraph == True:
        graph_of_global_dependencies(cursor, sqlite_connection, json_output)
    if arguments.bipartite == True:
        graph_of_dependencies_between_local_and_global_devices(
            cursor, sqlite_connection, json_output
        )
    # ==================================================================
    StatPercent(ip_address_statistics, json_output, 3)
    if arguments.file != "":
        print(
            "######################################################################",
            file=sample,
        )
        print("  Print Statistic of using network by devices in %:", file=sample)
        for i, j in ip_address_statistics.items():
            print("    ", i, "\t\t\t", j, "%", file=sample)
    if arguments.print == True:
        print("######################################################################")
        print("  Print Statistic of using network by devices in %:")
        StatPercent(ip_address_statistics, json_output, 2)
    # ==================================================================
    if arguments.file != "":
        sample.close()
    x = datetime.datetime.now()
    json_output["Network"] = arguments.network
    json_output["DateAnalyze"] = str(x)
    json_output["NumberDevice"] = device_id - 1
    write_json(json_output, arguments.json)
    print("Output json_output: ", arguments.json)


def AnalyzeSingleDevice(sqlite_connection, arguments):
    """Analyze single device from arguments. If isn't in database print error and end. Else analyze it.

    Parameters
    -----------
    sqlite_connection : sqlite3
        Connection to sqlite3 database.
    arguments : argparse
        Setted arguments of the script.
    """
    try:
        IP = ipaddress.ip_address(arguments.device)
    except:
        print("ERROR: Entered value isn't IP address")
        sys.exit()
    cursor = sqlite_connection.cursor()
    cursor.execute(
        "SELECT * FROM LocalDevice WHERE IP='{ip}'".format(ip=arguments.device)
    )
    device = cursor.fetchone()
    if not device:
        print("ERROR: Entered IP address isn't in database")
        sys.exit()
    json_output = {
        "Name": "AnalyzeSingleDevice",
        "DateAnalyze": "",
        "Routers": [],
        "Services": [],
        "ip_address_statistics": [],
        "Devices": [],
        "Files": [],
    }
    write_json(json_output, arguments.json)
    json_output = read_json(arguments.json)
    ip_address_statistics = {}
    if arguments.file != "":
        if check_str(arguments.file, ".txt") == True:
            FILE = arguments.file
        else:
            FILE = arguments.file + ".txt"
        sample = open(FILE, "w")
    else:
        sample = ""
    AnalyzeLocalDevice(
        "XXX",
        device[0],
        device[1],
        cursor,
        sqlite_connection,
        json_output,
        ip_address_statistics,
        True,
        arguments,
        sample,
    )
    StatPercent(ip_address_statistics, json_output, 3)
    if arguments.file != "":
        print(
            "######################################################################",
            file=sample,
        )
        print("  Print Statistic of using network by devices in %:", file=sample)
        for i, j in ip_address_statistics.items():
            print("    ", i, "\t\t\t", j, "%", file=sample)
    if arguments.print == True:
        print("######################################################################")
        print("  Print Statistic of using network by devices in %:")
        StatPercent(ip_address_statistics, json_output, 2)
    if arguments.file != "":
        sample.close()
    x = datetime.datetime.now()
    json_output["DateAnalyze"] = str(x)
    write_json(json_output, arguments.json)
    print("Output json_output: ", arguments.json)


def DoAnalyze(sqlite_connection, arguments):
    """Analyze all "local" devices from database table LocalDevice.

    Parameters
    -----------
    sqlite_connection : sqlite3
        Connection to sqlite3 database.
    arguments : argparse
        Setted arguments of the script.
    """
    # ==================================================================
    json_output = {
        "Name": "PassiveAutodiscovery",
        "DateAnalyze": "",
        "NumberDevice": 0,
        "Routers": [],
        "Services": [],
        "ip_address_statistics": [],
        "Devices": [],
        "Files": [],
    }
    write_json(json_output, arguments.json)
    json_output = read_json(arguments.json)
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
    if arguments.file != "":
        if check_str(arguments.file, ".txt") == True:
            FILE = arguments.file
        else:
            FILE = arguments.file + ".txt"
        sample = open(FILE, "w")
    else:
        sample = ""
    cursor.execute("SELECT * FROM LocalDevice")
    LocalDevices = cursor.fetchall()
    for LocalDevice in LocalDevices:
        if LocalDevice[0] == "255.255.255.255" or LocalDevice[0] == "0.0.0.0":
            continue
        AnalyzeLocalDevice(
            device_id,
            LocalDevice[0],
            LocalDevice[1],
            cursor,
            sqlite_connection,
            json_output,
            ip_address_statistics,
            gl,
            arguments,
            sample,
        )
        device_id = device_id + 1
    # ==================================================================
    if arguments.localgraph == True:
        graph_of_local_dependencies(cursor, sqlite_connection, json_output)
    if arguments.globalgraph == True:
        graph_of_global_dependencies(cursor, sqlite_connection, json_output)
    if arguments.bipartite == True:
        graph_of_dependencies_between_local_and_global_devices(
            cursor, sqlite_connection, json_output
        )
    # ==================================================================
    StatPercent(ip_address_statistics, json_output, 3)
    if arguments.file != "":
        print(
            "######################################################################",
            file=sample,
        )
        print("  Print Statistic of using network by devices in %:", file=sample)
        for i, j in ip_address_statistics.items():
            print("    ", i, "\t\t\t", j, "%", file=sample)
    if arguments.print == True:
        print("######################################################################")
        print("  Print Statistic of using network by devices in %:")
        StatPercent(ip_address_statistics, json_output, 3)
    # ==================================================================
    if arguments.file != "":
        sample.close()
    x = datetime.datetime.now()
    json_output["DateAnalyze"] = str(x)
    json_output["NumberDevice"] = device_id - 1
    write_json(json_output, arguments.json)
    print("Output json_output: ", arguments.json)


def Arguments():
    """Arguments of the DeviceAnalyzer script.

    Returns
    --------
    arguments : argparse
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
    arguments = parser.parse_args()
    if arguments.device != "" and arguments.network != "":
        print("Parameters -D and -N can't be combinated. Choose only one")
        sys.exit()
    if arguments.network != "":
        try:
            NET = ipaddress.ip_network(arguments.network)
        except:
            print("Badly inserted ip address of network ", arguments.network)
            sys.exit()
    return arguments


def ConnectToDatabase(arguments):
    """Connect to sqlite3 database which analyze.

    Parameters
    -----------
    arguments : argparse
        Setted arguments of the script.
    Returns
    --------
    sqlite_connection : sqlite3
        Connection to sqlite3 database with name from arguments.
    """
    try:  # connect to a database
        print("Connecting to a database....", end="")
        if check_str(arguments.database, ".db") == True:
            FILE = arguments.database
        else:
            FILE = arguments.database + ".db"
        if not os.path.exists(FILE):
            print("")
            print("can't connect to ", FILE)
            sys.exit()
        sqlite_connection = sqlite3.connect(FILE)
        print("done")
    except sqlite3.Error as error:
        print("Can't connect to a database:  ", error)
    return sqlite_connection


def Main():
    """Main function call one of three function by arguments where it is set.

    """
    arguments = Arguments()
    if arguments.printJSON != "":
        if arguments.print == False and arguments.file == "":
            print(
                "Need define output method (print to command line or file [-p], [-f])"
            )
            sys.exit()
        json_output = read_json(arguments.json)
        PrintJSON(json_output, arguments)
        sys.exit()
    sqlite_connection = ConnectToDatabase(arguments)
    if arguments.device != "":
        AnalyzeSingleDevice(sqlite_connection, arguments)
    elif arguments.network != "":
        AnalyzeNetwork(sqlite_connection, arguments)
    else:
        DoAnalyze(sqlite_connection, arguments)
    # =====================================================
    # Close database connection
    if sqlite_connection:
        sqlite_connection.close()


if __name__ == "__main__":
    Main()

