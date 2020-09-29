#!/usr/bin/python3.6
"""print_analyze module contains function that print output of device_analyzer module.


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
import sys
from termgraph import termgraph


def stats_of_services(
    services_statistic, dependency, num_packets, cursor, sqlite_connection
):
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
            services_statistic[st] = services_statistic[st] + num_packets
        else:
            services_statistic[st] = num_packets

    cursor.execute(
        "SELECT * FROM Services WHERE PortNumber={pt}".format(pt=dependency[4])
    )
    servicestat = cursor.fetchone()
    if servicestat:
        st = servicestat[2].replace(" ", "_")
        if st in services_statistic:
            services_statistic[st] = services_statistic[st] + num_packets
        else:
            services_statistic[st] = num_packets


def add_or_update_statistic_of_device(
    dependency, num_packets, ip_address, ip_address_statistics
):
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
                ip_address_statistics[dependency[1]] + num_packets
            )
        else:
            ip_address_statistics[dependency[1]] = num_packets
    if dependency[2] == ip_address:
        if dependency[2] in ip_address_statistics:
            ip_address_statistics[dependency[2]] = (
                ip_address_statistics[dependency[2]] + num_packets
            )
        else:
            ip_address_statistics[dependency[2]] = num_packets


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
        plot_statistics(statistic.items())
