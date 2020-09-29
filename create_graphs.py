#!/usr/bin/python3.6
"""create_graph module contains fuction that create graphs output of device_analyzer module.

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
import tempfile
import ipaddress

# Third Part Imports
import pandas
import numpy
import networkx
import matplotlib.pyplot as plt
import matplotlib.ticker as plticker


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
        f"SELECT * FROM LocalDependencies WHERE (IP_origin='{device}' OR IP_target='{device}')"
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
        Name of table where is record of dependency safed (LocalDependencies or Global).
    cursor : sqlite3
        Cursor to sqlite3 database for execute SQL queries.
    device_json : JSON  
        JSON file loaded in python.    
    """
    if table is True:
        cursor.execute(
            f"SELECT * FROM DependenciesTime WHERE DependenciesID='{dependency[0]}'"
        )
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
    cursor.execute("SELECT * FROM LocalDependencies")
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
    ip_address = cursor.fetchall()
    bipartite_graph = networkx.Graph()
    graph_number = 0
    for i in ip_address:
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
