#!/usr/bin/python3.6
"""Collector script:

    Collector script analyze IP flow that get from PassiveAutodiscovery module. 

    Collector get database connection, arguments and IP flow.
    IP flow si analyzed and arguemnts specificate how to do it.
    The analyze get information from IP flow and add them to sqlite3 database. 

    Collector function collector is call from PassiveAutodiscovery module.

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


def service_label(ip, port, table, cursor, sglite_connection, arguments):
    """Check if port in IP flow is used by some role of device (services), if yes and if it is NOT in database, put record to sqlite3 database.
    
    Parameters
    -----------
    ip : str
        IP address of device that comunicate on protocol with port number port.
    port : int
        Port number of used protocol.
    table : str
        Name of the table to safe potencial record (if device is  "local": table == LocalServices, if device is "global": table == GlobalServices).
    cursor : sqlite3
        Cursor to sqlite3 database for execute SQL queries.
    sglite_connection : sqlite3
        Connection to sqlite3 database.
    arguments : argparse   
        Setted argument of the PassiveAutodiscovery module.
    """
    cursor.execute(f"SELECT * FROM Services WHERE PortNumber={port}")
    row = cursor.fetchone()
    if row:  # if port is services (role of device)
        cursor.execute(f"SELECT * FROM {table} WHERE IP='{ip}' AND PortNumber={port}")
        rows = cursor.fetchall()
        if rows:  # if port and IP is in database, do nothing (record exists)
            return
        else:  # else push new record to db
            if arguments.localserv and table == "LocalServices":
                print(f"New local services: {ip} -> {row[1]}")
            if arguments.globalserv and table == "GlobalServices":
                print(f"New global services: {ip} -> {row[1]}")
            try:
                cursor.execute(
                    f"INSERT INTO {table} (PortNumber, IP) VALUES ('{port}', '{ip}')"
                )
                sglite_connection.commit()
            except sqlite3.IntegrityError:
                print(f"Error with inserting into table {table}")
    else:
        return


def insert_time(table, cursor, sglite_connection, rows, time, num_packets):
    """Insert data to table DependeciesTime or GlobalTime
    
    Parameters
    -----------
    table : str
        Table where record about dependency may be safed. ("LocalDependencies" - for dependencies between "local" devices, "Global" - for dependencies between "local" device and global device)    
    cursor : sqlite3
        Cursor to sqlite3 database for execute SQL queries.
    sglite_connection : sqlite3
        Connection to sqlite3 database.
    time : str
        Time of IP flow.
    num_packets : int
        Number of packet carryed in dependency(single IP flow).
    """
    try:
        if table == "LocalDependencies":
            cursor.execute(
                f"INSERT INTO DependenciesTime (DependenciesID, Time, NumPackets) "
                f"VALUES ('{rows[0]}', '{time}', '{num_packets}')"
            )
        else:
            cursor.execute(
                f"INSERT INTO GlobalTime (GlobalID, Time, NumPackets) "
                f"VALUES ('{rows[0]}', '{time}', '{num_packets}')"
            )
            sglite_connection.commit()
    except sqlite3.IntegrityError:
        print(f"Error with inserting with error {sqlite3.IntegrityError}")


def new_dependency(
    table,
    src_ip,
    dst_ip,
    src_port,
    dst_port,
    time,
    num_packets,
    cursor,
    sglite_connection,
    arguments,
):
    """If dependency (local or global) doesn't exist, function will add record about it to database. Else function will find the record and update packet number on this dependency.
    
    Parameters
    -----------
    table : str
        Table where record about dependency may be safed. ("LocalDependencies" - for dependencies between "local" devices, "GlobalDependencies" - for dependencies between "local" device and global device)    
    src_ip : str
        Source IP address of dependency.
    dst_ip : str
        Destination IP address of dependency.
    src_port : int
        Source port number of dependency.
    dst_port : int
        Destination prot of dependency.
    time : str
        Time of IP flow.
    num_packets : int
        Number of packet carryed in dependency(single IP flow).
    cursor : sqlite3
        Cursor to sqlite3 database for execute SQL queries.
    sglite_connection : sqlite3
        Connection to sqlite3 database.
    arguments : argparse   
        Setted argument of the PassiveAutodiscovery module.
    """
    if arguments.UsualyPorts:
        # if analyze only "usualy" protocols (protocols in table Services), than check if PORT is one of these protocols
        try:
            cursor.execute(
                f"SELECT * FROM Services WHERE PortNumber={src_port} OR PortNumber={dst_port}"
            )
            row = cursor.fetchone()
            if row is None:
                return
        except sqlite3.IntegrityError:
            print(f"Error while SELECT {sqlite3.IntegrityError}")
            return
    # =================================================================================================================================================================
    try:
        cursor.execute(
            f"SELECT * FROM {table} "
            f"WHERE IP_origin='{src_ip}' "
            f"AND IP_target='{dst_ip}' "
            f"AND (Port_target={dst_port} OR Port_origin={dst_port} OR Port_target={src_port} OR Port_origin={src_port})"
        )
        rows = cursor.fetchone()
    except sqlite3.IntegrityError:
        print(f"Error in SELECT {sqlite3.IntegrityError}")
        return
    # =================================================================================================================================================================
    if rows:  # if record rows1 is in database, then update PACKETS
        try:
            cursor.execute(
                f"UPDATE {table} SET NumPackets={(rows[5] + num_packets)} "
                f"WHERE IP_origin='{src_ip}' "
                f"AND IP_target='{dst_ip}' "
                f"AND (Port_target='{dst_port}' OR Port_origin='{dst_port}' OR Port_target='{src_port}' OR Port_origin='{src_port}')"
            )
            sglite_connection.commit()
        except sqlite3.IntegrityError:
            print(
                f"Error with updating record in table {table} with error {sqlite3.IntegrityError}"
            )
        if arguments.time:
            insert_time(table, cursor, sglite_connection, rows, time, num_packets)
        return
    # =================================================================================================================================================================
    cursor.execute(
        f"SELECT * FROM {table} "
        f"WHERE IP_origin='{dst_ip}' "
        f"AND IP_target='{src_ip}' "
        f"AND (Port_target={dst_port} OR Port_origin={dst_port} OR Port_target={src_port} OR Port_origin={src_port})"
    )
    rows = cursor.fetchone()
    # =================================================================================================================================================================
    if rows:  # if record rows2 is in database, then update PACKETS
        try:
            cursor.execute(
                f"UPDATE {table} SET NumPackets={(rows[5] + num_packets)} "
                f"WHERE IP_origin='{dst_ip}' "
                f"AND IP_target='{src_ip}' "
                f"AND (Port_target='{dst_port}' OR Port_origin='{dst_port}' OR Port_target='{src_port}' OR Port_origin='{src_port}')"
            )
            sglite_connection.commit()
        except sqlite3.IntegrityError:
            print(
                f"Error with updating record in table {table} with error {sqlite3.IntegrityError}"
            )
        if arguments.time:
            insert_time(table, cursor, sglite_connection, rows, time, num_packets)
        return
    # =================================================================================================================================================================
    else:  # else found a new local or global dependencies
        if arguments.localdependencies and table == "LocalDependencies":
            print(f"new local dependencies: {src_ip} -> {dst_ip}")
        if arguments.globaldependencies and table == "Global":
            print(f"new global dependencies: {src_ip} -> {dst_ip}")
        try:
            empty_str = ""
            cursor.execute(
                f"INSERT INTO {table} (IP_origin, IP_target, Port_origin, Port_target, NumPackets, NumBytes) "
                f"VALUES ('{src_ip}', '{dst_ip}', '{src_port}', '{dst_port}', '{num_packets}', '{empty_str}')"
            )
            sglite_connection.commit()
        except sqlite3.IntegrityError:
            print(f"Error with inserting with error {sqlite3.IntegrityError}")
        if arguments.time:
            cursor.execute(
                f"SELECT * FROM {table} "
                f"WHERE IP_origin='{src_ip}' "
                f"AND IP_target='{dst_ip}' "
                f"AND Port_origin='{src_port}' "
                f"AND Port_target='{dst_port}'"
            )
            rows = cursor.fetchone()
            insert_time(table, cursor, sglite_connection, rows, time, num_packets)


def dhcp(src_ip, dst_ip, src_port, dst_port, time, cursor, sglite_connection):
    """If IP flow is DHCP traffic, then safe record of it to table DHCP.
    
    Parameters
    -----------
    src_ip : str
        Source IP address of dependency.
    dst_ip : str
        Destination IP address of dependency.
    src_port : int
        Source port number of dependency.
    dst_port : int
        Destination prot of dependency.
    time : int
        Unix time of IP flow.
    cursor : sqlite3
        Cursor to sqlite3 database for execute SQL queries.
    sglite_connection : sqlite3
        Connection to sqlite3 database.
    """
    if (src_port == 68 and dst_port == 67) or (src_port == 546 and dst_port == 547):
        try:
            cursor.execute(
                f"INSERT INTO DHCP (DeviceIP, ServerIP, Time) "
                f"VALUES ('{src_ip}', '{dst_ip}', '{time}')"
            )
            sglite_connection.commit()
        except sqlite3.IntegrityError:
            print(f"Error with inserting into table DHCP: {sqlite3.IntegrityError}")
    elif (src_port == 67 and dst_port == 68) or (src_port == 547 and dst_port == 546):
        try:
            cursor.execute(
                f"INSERT INTO DHCP (DeviceIP, ServerIP, Time) "
                f"VALUES ('{dst_ip}', 'src_ip', 'time')"
            )
            sglite_connection.commit()
        except sqlite3.IntegrityError:
            print(f"Error with inserting into table DHCP: {sqlite3.IntegrityError}")
    else:
        return


def add_router(ip, mac, cursor, sglite_connection):
    """Function for adding record to table Routers. The record is MAC address of router and Ip address of device behind him or router himself.
    
    Parameters
    -----------
    ip : str
        IP address of device behind router (or IP address of the router).
    mac : str
        MAC address of router.
    cursor : sqlite3
        Cursor to sqlite3 database for execute SQL queries.
    sglite_connection : sqlite3
        Connection to sqlite3 database.
    """
    cursor.execute(f"SELECT * FROM Routers WHERE MAC='{mac}' AND IP='{ip}'")
    row = cursor.fetchone()
    if row:
        return
    else:
        try:
            cursor.execute(f"INSERT INTO Routers (MAC, IP) VALUES ('{mac}', '{ip}')")
            sglite_connection.commit()
        except sqlite3.IntegrityError:
            print(f"Error with inserting into table Routers: {sqlite3.IntegrityError}")


def add_mac(ip, mac, time, cursor, sglite_connection, arguments):
    """
    
    Parameters
    -----------
    IP : str
        IP address of device.
    MAC : str
        MAC address of device.
    TIME : int
        Unix time of IP flow where was combiantion IP and MAC used.
    cursor : sqlite3
        Cursor to sqlite3 database for execute SQL queries.
    sglite_connection : sqlite3
        Connection to sqlite3 database.
    arguments : argparse   
        Setted argument of the PassiveAutodiscovery module.
    """
    if arguments.macdev:
        print(f"New MAC address: {ip} -> {mac}")
    try:
        empty_string = ""
        cursor.execute(
            f"INSERT INTO MAC (IP, MAC, FirstUse, LastUse) "
            f"VALUES ('{ip}', '{mac}', '{time}', '{empty_string}')"
        )
        sglite_connection.commit()
    except sqlite3.IntegrityError:
        print(f"Error with inserting into table MAC: {sqlite3.IntegrityError}")


def mac(ip, mac, time, cursor, sglite_connection, arguments):
    """If device is is in local segemnt, the module can rosolve his MAC address and add record of it to table MAC. If it's router and behind it is local subnet (2 or more local device or one global device on this mac address (the same IP version)) add all record of this mac address from table MAC to table Router and add new record from this IP flow.
    
    Parameters
    -----------
    ip : str
        IP address of the device.
    mac : str
        MAC address of the device.
    time : int
        Unix time of the IP flow.
    cursor : sqlite3
        Cursor to sqlite3 database for execute SQL queries.
    sglite_connection : sqlite3
        Connection to sqlite3 database.
    arguments : argparse   
        Setted argument of the PassiveAutodiscovery module.
    """
    # =======If device mac is router, do not continue in MAC code=======
    cursor.execute("SELECT * FROM Routers WHERE MAC='%s'" % mac)
    routers = cursor.fetchall()
    if routers:
        add_router(ip, mac, cursor, sglite_connection)
        return
    # ==================================================================
    cursor.execute("SELECT * FROM MAC WHERE MAC.MAC='%s'" % mac)
    rows = cursor.fetchall()
    if rows:
        tmp = 0
        for row in rows:
            if (
                row[4] != ""
            ):  # check if it currect recod of MAC address (the old one have in row[4] time of end using)
                continue
            newip = ipaddress.ip_address(ip)
            oldip = ipaddress.ip_address(row[1])
            if newip == oldip:  # if ip match, end it
                return
            elif (
                newip.version == oldip.version
            ):  # if not and have same version (one MAC can have both of IPv4 and IPv6 addresses)
                if newip.is_link_local == True or oldip.is_link_local == True:
                    tmp = 1
                    continue
                # TODO TEST THIS!!!
                # Until I will have change test this on real local network with more local segments, will be this comment (SARS-CoV-2 is responsible for this)
                # Think of this commented code:
                tmp = 2
            #                cursor.execute("SELECT * FROM DHCP WHERE DeviceIP='%s'" % ip)
            #                DHCProws = cursor.fetchall()
            #                if DHCProws:
            #                    lastrow = DHCProws[0]
            #                    for DHCProw in DHCProws:
            #                        if DHCProw[3] > lastrow[3]:    #if DHCP com. for IP was after MAC use and
            #                            lastrow = DHCProw
            #                        else:
            #                            None
            #                    if float(time) > float(DHCProw[3]) and float(row[3]) < float(DHCProw[3]):
            #                        try:
            #                            cursor.execute("UPDATE MAC SET LastUse='%s' WHERE MAC.IP='%s' AND MAC.MAC='%s' AND MAC.FirstUse='%s'" % (time, row[1], row[2], row[3]) )
            #                            sglite_connection.commit()
            #                        except sqlite3.IntegrityError:
            #                            None
            #                        add_mac(ip, mac, time, cursor, sglite_connection, arguments)
            #                        return
            #                    elif float(time) > float(DHCProw[3]) and float(row[3]) > float(DHCProw[3]):
            #                        add_router(ip, mac, cursor, sglite_connection)
            #                        add_router(row[1], mac, cursor, sglite_connection)
            #                        try:
            #                            cursor.execute("DELETE FROM MAC WHERE MAC.IP='%s' AND MAC.MAC='%s' AND MAC.FirstUse='%s'" % (row[1], row[2], row[3]) )
            #                            sglite_connection.commit()
            #                        except sqlite3.IntegrityError:
            #                            None
            #                        return
            #                    else:
            #                        continue
            #                else:
            #                    tmp = 1
            else:
                if tmp == 2:
                    continue
                else:
                    tmp = 1
        if tmp == 1:
            add_mac(ip, mac, time, cursor, sglite_connection, arguments)
            return
    else:
        add_mac(ip, mac, time, cursor, sglite_connection, arguments)


def new_device(ip, time, cursor, sglite_connection, arguments):
    """This funcion check if "local" device is in sqlite3 database table LocalDevice. If isn't, add it to table. If is, update last comunication in record of it.
    
    Parameters
    -----------
    ip : str
        IP address of the local device.
    time : int
        Unix time of the IP flow.    
    cursor : sqlite3
        Cursor to sqlite3 database for execute SQL queries.
    sglite_connection : sqlite3
        Connection to sqlite3 database.
    arguments : argparse   
        Setted argument of the PassiveAutodiscovery module.
    """
    cursor.execute(f"SELECT * FROM LocalDevice WHERE LocalDevice.IP='{ip}'")
    row = cursor.fetchone()
    if row:  # if device exists
        return
    else:  # add new record
        if arguments.localdev:
            print(f"New local device: {ip}")
        try:
            cursor.execute(f"INSERT INTO LocalDevice (IP) VALUES ('{ip}')")
            sglite_connection.commit()
        except sqlite3.IntegrityError:
            print(
                f"Error with inserting into table LocalDevice with error: {sqlite3.IntegrityError}"
            )


def delete_unnecessary_global_dependencies(sglite_connection, num_packets):
    """Delete global dependencies from table Global that have number of packer smaller then number num_packets
    
    Parameters
    -----------
    sglite_connection : sqlite3
        Connection to sqlite3 database.
    num_packets : int
        Number of packet that is line for delete.
    """
    cursor = sglite_connection.cursor()
    try:
        cursor.execute(
            f"DELETE FROM Global "
            f"WHERE NumPackets < {num_packets} "
            f"AND (Port_origin != 53 OR Port_target != 53 OR Port_origin != 68 OR Port_target != 68 OR Port_origin != 67 OR Port_target != 67)"
        )
        sglite_connection.commit()
    except sqlite3.IntegrityError:
        print(
            f"Error in deleting rows from Global with error: {sqlite3.IntegrityError}"
        )


def collect_flow_data(rec, sglite_connection, cursor, arguments, biflow):
    """Main function of this script. This function receive IP flow, database proms and arguments. Then work with received IP flow to get information from it and record of it safe (update) in sqlite3 database that received.
    
    Parameters
    -----------
    rec : pytrap
        Received IP flow to analyze.
    cursor : sqlite3
        Cursor to sqlite3 database for execute SQL queries.
    sglite_connection : sqlite3
        Connection to sqlite3 database.
    arguments : argparse   
        Setted argument of the PassiveAutodiscovery module.
    """
    # ===============================================================================
    # if mac address is broadcast then ignore this IP flow, also this check if MAC address is in record of IP flows, if isn't this will set not working with it.
    mac_template = True
    try:
        if rec.DST_MAC == "ff:ff:ff:ff:ff:ff" or rec.SRC_MAC == "ff:ff:ff:ff:ff:ff":
            return
    except:
        mac_template = False
    # ===============================================================================
    # IP address from IP flow to format where can be ease work with
    src_ipaddress = ipaddress.ip_address(rec.SRC_IP)
    dst_ipaddress = ipaddress.ip_address(rec.DST_IP)
    # ===============================================================================
    # banned Ip address (broadcast,...)
    ban_ipaddress_1 = ipaddress.ip_address("0.0.0.0")
    ban_ipaddress_2 = ipaddress.ip_address("255.255.255.255")
    # ===============================================================================
    # check if IP address isn't banned (multicasts,broadcasts), if yes return
    if src_ipaddress.is_multicast or dst_ipaddress.is_multicast:
        return
    if rec.SRC_IP == ban_ipaddress_1 or rec.DST_IP == ban_ipaddress_1:
        return
    if rec.SRC_IP == ban_ipaddress_2 or rec.DST_IP == ban_ipaddress_2:
        return
    # ===============================================================================
    src = False  # src is boolean - True if SRC_IP is from setted networks
    dst = False  # dst is boolean - True if SRC_IP is from setted networks
    # chceck if IP addresses isn't broadcasts of setted networks, if yes return
    for network_ip in arguments.networks:
        # network_ip is string IP address of network
        network_ipaddress = ipaddress.ip_network(network_ip)
        # network_ipaddress is object of ipaddress from python library
        if src_ipaddress in network_ipaddress:
            if network_ipaddress.version == 4:
                network_ipaddress_v4 = ipaddress.IPv4Network(network_ip)
                if src_ipaddress == network_ipaddress_v4.broadcast_address:
                    return
            src = True
            break
        elif dst_ipaddress in network_ipaddress:
            if network_ipaddress.version == 4:
                network_ipaddress_v4 = ipaddress.IPv4Network(network_ip)
                if dst_ipaddress == network_ipaddress_v4.broadcast_address:
                    return
            dst = True
            break
        else:
            continue
    # ===============================================================================
    # prepare packet numbers
    if biflow is True:
        num_packets = rec.PACKETS + rec.PACKETS_REV
    else:
        num_packets = rec.PACKETS
    # ===============================================================================
    # Main funciton which call function for safing data to sqlite3 database
    if (
        src_ipaddress.is_private and arguments.OnlySetNetworks == False
    ) or src:  # Source Device is in local network
        new_device(rec.SRC_IP, rec.TIME_LAST, cursor, sglite_connection, arguments)
        if mac_template == True:
            mac(
                rec.SRC_IP,
                rec.SRC_MAC,
                rec.TIME_LAST,
                cursor,
                sglite_connection,
                arguments,
            )
        if (
            dst_ipaddress.is_private and arguments.OnlySetNetworks == False
        ) or dst:  # Destination Device is in local network
            new_device(rec.DST_IP, rec.TIME_LAST, cursor, sglite_connection, arguments)
            if mac_template == True:
                mac(
                    rec.DST_IP,
                    rec.DST_MAC,
                    rec.TIME_LAST,
                    cursor,
                    sglite_connection,
                    arguments,
                )
            # =====================================================================================
            new_dependency(
                "LocalDependencies",
                rec.SRC_IP,
                rec.DST_IP,
                rec.SRC_PORT,
                rec.DST_PORT,
                rec.TIME_LAST,
                num_packets,
                cursor,
                sglite_connection,
                arguments,
            )
            service_label(
                rec.SRC_IP,
                rec.SRC_PORT,
                "LocalServices",
                cursor,
                sglite_connection,
                arguments,
            )
            service_label(
                rec.DST_IP,
                rec.DST_PORT,
                "LocalServices",
                cursor,
                sglite_connection,
                arguments,
            )
            dhcp(
                rec.SRC_IP,
                rec.DST_IP,
                rec.SRC_PORT,
                rec.DST_PORT,
                rec.TIME_LAST,
                cursor,
                sglite_connection,
            )
        else:  # Destination Device is in global network
            service_label(
                rec.SRC_IP,
                rec.SRC_PORT,
                "LocalServices",
                cursor,
                sglite_connection,
                arguments,
            )
            if arguments.GlobalDependencies == True:
                new_dependency(
                    "Global",
                    rec.SRC_IP,
                    rec.DST_IP,
                    rec.SRC_PORT,
                    rec.DST_PORT,
                    rec.TIME_LAST,
                    num_packets,
                    cursor,
                    sglite_connection,
                    arguments,
                )
                service_label(
                    rec.DST_IP,
                    rec.DST_PORT,
                    "GlobalServices",
                    cursor,
                    sglite_connection,
                    arguments,
                )
            if mac_template == True:
                add_router(rec.DST_IP, rec.DST_MAC, cursor, sglite_connection)
    else:  # Source Device is in global network
        if (dst_ipaddress.is_private and arguments.OnlySetNetworks == False) or dst:
            new_device(rec.DST_IP, rec.TIME_LAST, cursor, sglite_connection, arguments)
            # =====================================================================================
            service_label(
                rec.DST_IP,
                rec.DST_PORT,
                "LocalServices",
                cursor,
                sglite_connection,
                arguments,
            )
            if arguments.GlobalDependencies == True:
                new_dependency(
                    "Global",
                    rec.SRC_IP,
                    rec.DST_IP,
                    rec.SRC_PORT,
                    rec.DST_PORT,
                    rec.TIME_LAST,
                    num_packets,
                    cursor,
                    sglite_connection,
                    arguments,
                )
                service_label(
                    rec.SRC_IP,
                    rec.SRC_PORT,
                    "GlobalServices",
                    cursor,
                    sglite_connection,
                    arguments,
                )
            if mac_template == True:
                mac(
                    rec.DST_IP,
                    rec.DST_MAC,
                    rec.TIME_LAST,
                    cursor,
                    sglite_connection,
                    arguments,
                )
                add_router(rec.SRC_IP, rec.SRC_MAC, cursor, sglite_connection)
        else:
            return
