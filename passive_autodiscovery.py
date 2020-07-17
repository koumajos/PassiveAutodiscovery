#!/usr/bin/python3.6
"""PassiveAutodiscovery module:
    
    This is module for modular monitoring system NEMEA (Network Measurement Analysis).
    
    Module main funkcionality is Autodiscovery, Device Recognition and Deppendency mapping.For this funkcionalities module use passive analyze. That mean that module take IP flows from IFC interface, that is always filled by flow_meter, and analyze them. Flow_meter capture packets on network interface and create from it IP flows. (Module can also use files of IP flows as IFC interface)
    Module use sqlite3 database for safing data from IP flows.     
    --------------
    Autodiscovery:
        Finds "local" device from network traffic. (local device = device that is from private subnet 10.0.0.0/8 or 172.16.0.0/16 or 192.168.0.0/24 OR device from subnet that was inserted by user with parameter -N)
    Device Recognition:
        Module recognize the roles of device in network and set to the device labels. This labels marks the roles of device. In the example for device that has role dhcp server fro the network, will module set to device label [DHCP Server].
    Dependency mapping:
        Module safe all dependencies between "local" devices. Can also safe dependencies between "local" device and "global" devices(devices that aren't "local").

    Module is coaporate with collector.py script that fill sqlite3 database. 
    The output from the database (entire analyze) is created by DeviceAnalyzer.py script.   


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
import sqlite3
import csv
import time
from datetime import datetime
import ipaddress
import argparse
from argparse import RawTextHelpFormatter

# Third Part Imports
import pytrap
import colorama

# Local Application Imports
import collector
from create_script import check_str


def move_cursor(x, y):
    """Move cursor in actualization prints to X, Y coordinates.
        
    Parameters
    -----------
    x : int
        coordinate X
    y : int
        coordinate Y
    """
    print("\x1b[{};{}H".format(y + 1, x + 1))


def clear():
    """Clear command line for actualization prints."""
    print("\x1b[2J")


def print_act_inf(old_time, start_time, arg, num_flows, cursor):
    """Prints actualication information about running the module. Enable with parameter -P.
        
    Parameters
    -----------
    old_time : int
        UNIX time of last print.
    start_time : int
        UNIX time of start the module.
    arg : argparse
        Setted arguments of module.
    num_flows : int
        Number of IP flows that bean analyze by module.
    cursor : sqlite3
        Cursor to sqlite3 database for execute SQL queries.
    Returns
    --------
    old_time : int
        UNIX time of this print.
    """
    move_cursor(0, 0)  # move cursor at the start of command line

    print("PassiveAutodiscovery modul")

    if check_str(arg.database, ".db"):
        print(f"from: {arg.i}      to: {arg.database}")
    else:
        print(f"from: {arg.i}      to: {arg.database}.db")

    print("Networks: ", end="")  # print analyzed networks
    if arg.networks != "" and arg.OnlySetNetworks == True:
        for i in arg.networks:
            if i != arg.networks[-1]:
                print(f"{i}, ", end="")
            else:
                print(i)
    elif arg.networks != "":
        for i in arg.networks:
            print(f"{i}, ", end="")
        print("Private networks")
    else:
        print("Private subnets")
    print("")

    print(f"Started time: {datetime.fromtimestamp(start_time)}")
    print("")

    old_time = time.time()
    print(
        f"Time: {str(int((old_time - start_time) / 60))} min      IP flows: {str(num_flows)}"
    )  # print time of running module and number of analyzed ip flows

    cursor.execute("SELECT COUNT(*) FROM LocalDevice")
    devices = cursor.fetchone()
    cursor.execute("SELECT COUNT(*) FROM LocalServices")
    services = cursor.fetchone()
    print(
        f"Find Devices: {str(devices[0])}      Find Services: {str(services[0])}"
    )  # print number of findend "local" devices and their services

    cursor.execute("SELECT COUNT(*) FROM Dependencies")
    dependencies = cursor.fetchone()
    cursor.execute("SELECT COUNT(*) FROM Global")
    count_global = cursor.fetchone()
    print(
        f"Local Dependencies: {str(dependencies[0])}      Global Dependencies: {str(count_global[0])}"
    )  # pritn number of dependencies
    return old_time


def arguments():
    """Arguemtns of the module.
        
    Returns
    --------
    arg : argparse
        Setted arguemnts of the module.
    """
    parser = argparse.ArgumentParser(
        description="""Collect flow from network interface and output to database

    Database is created by CreateScript.py.
    Then analyze with DeviceAnalyzer.py.

    Usage:""",
        formatter_class=RawTextHelpFormatter,
    )

    parser.add_argument(
        "-i",
        help='Specification of interface types and their parameters, see "-h trap" (mandatory parameter).',
        type=str,
        metavar="IFC_SPEC",
    )

    parser.add_argument("-v", help="Be verbose.", action="store_true")

    parser.add_argument("-vv", help="Be more verbose.", action="store_true")

    parser.add_argument("-vvv", help="Be even more verbose.", action="store_true")

    parser.add_argument(
        "-d",
        "--database",
        help="Set name of the database without . part,  default is Database",
        type=str,
        metavar="NAME",
        default="Database",
    )

    parser.add_argument(
        "-N",
        "--networks",
        help="IP addresses and mask (IPaddress/MASK - 192.168.1.0/24) of networks to monitor",
        type=str,
        nargs="+",
        metavar="IPs",
        default="",
    )

    parser.add_argument(
        "-!",
        "--OnlySetNetworks",
        help="Only monitor entered networks via parameter N (ussage: -N ... -! )",
        action="store_true",
    )

    parser.add_argument(
        "-U",
        "--UsualyPorts",
        help='Map only "usualy" transport layer ports',
        action="store_true",
    )

    parser.add_argument(
        "-F",
        "--FilterIPFlows",
        help="Filter incompletely conection",
        action="store_true",
    )

    parser.add_argument(
        "-G",
        "--GlobalDependencies",
        help="Mapping the dependencies to global subnets",
        action="store_true",
    )

    parser.add_argument(
        "-D",
        "--DeleteGlobal",
        help="Delete periodicly dependencies that have setted amount of packets from global dependencies",
        type=int,
        metavar="NUMBER",
        default=0,
    )

    parser.add_argument(
        "-RAM",
        "--RAM",
        help="Safe database in RAM memory and safe to file after modul end",
        action="store_true",
    )

    parser.add_argument(
        "-T",
        "--time",
        help="Safe to database also time records of lcoal and global dependencies",
        action="store_true",
    )

    parser.add_argument("-P", help="Printing information in menu", action="store_true")

    parser.add_argument(
        "-l",
        "--localdev",
        help="Print if modul find new local device(print will slow program)",
        action="store_true",
    )

    parser.add_argument(
        "-s",
        "--localserv",
        help="Print if modul find new local services(print will slow program)",
        action="store_true",
    )

    parser.add_argument(
        "-L",
        "--localdependencies",
        help='Print if modul find new dependencies between two "local" device(print will slow program)',
        action="store_true",
    )

    parser.add_argument(
        "-m",
        "--macdev",
        help='Print if found MAC adress for "local" device(print will slow program)',
        action="store_true",
    )

    parser.add_argument(
        "-S",
        "--globalserv",
        help="Print if modul find new global service(print will slow program)",
        action="store_true",
    )

    parser.add_argument(
        "-g",
        "--globaldependencies",
        help='Print if modul find new dependency between "local" device and global device(print will slow program)',
        action="store_true",
    )

    arg = parser.parse_args()

    if arg.P and (
        arg.localdev
        or arg.localserv
        or arg.globalserv
        or arg.localdependencies
        or arg.globaldependencies
        or arg.macdev
    ):
        print("Parameters -P and (-l or -s or -L -g -S -m) can't be combinated")
        sys.exit()
    if arg.networks != "":
        for net in arg.networks:
            try:
                NET = ipaddress.ip_network(net)
            except:
                print(f"Badly inserted ip address of network {net}")
                sys.exit()
    if arg.P == True:
        colorama.init()
        clear()
    return arg


def load_pytrap():
    """Init nemea libraries and set format of IP flows.
        
    Returns
    --------
    rec : pytrap
        Templete of IP flows.
    trap : pytrap
        Init pytrap NEMEA library, for capture IP flows from IFC interface setted in paramater -i.
    """
    trap = pytrap.TrapCtx()
    trap.init(sys.argv)
    # Set the list of required fields in received messages.
    # This list is an output of e.g. flow_meter - basic flow.
    input_spec = "ipaddr DST_IP,ipaddr SRC_IP,uint64 BYTES,uint64 LINK_BIT_FIELD,time TIME_FIRST,time TIME_LAST,uint32 PACKETS,uint16 DST_PORT,uint16 SRC_PORT,uint8 DIR_BIT_FIELD,uint8 PROTOCOL,uint8 TCP_FLAGS,uint8 TOS,uint8 TTL"
    trap.setRequiredFmt(0, pytrap.FMT_UNIREC, input_spec)
    rec = pytrap.UnirecTemplate(input_spec)
    return rec, trap


def ram_database():
    """Create sqlite3 database in RAM memory, create schema of it and fill the database with initial data for tables Ports, VendorsMAC and Services.
        
    Returns
    --------
    sqlite_connection : sqlite3
        The connection to the created sqlite3 database.
    cursor : sqlite3
        The cursor to the created database to execute SQL queries.
    """
    try:
        sqlite_connection = sqlite3.connect(":memory:")  # create database in RAM memory
        cursor = sqlite_connection.cursor()
    except sqlite3.Error as error:
        print(f"Can't create database in RAM memory: {error}")
    try:
        qry = open("Database_sqlite_create.sql", "r").read()
        sqlite3.complete_statement(qry)
        cursor.executescript(qry)  # create schema of the database
    except sqlite3.Error as error:
        print(f"Can't create schema database in RAM memory: {error}")

    try:  # fill database with intial data
        try:
            reader = csv.reader(open("Ports_url.csv", "r"), delimiter=",")
        except:
            reader = csv.reader(open("Ports.csv", "r"), delimiter=",")
        for row in reader:
            to_db = [row[0], row[1], row[2], row[3]]
            cursor.execute(
                "INSERT INTO Ports (ServiceName, PortNumber, TransportProtocol, Description) VALUES (?, ?, ?, ?);",
                to_db,
            )

        try:
            reader = csv.reader(open("VendorsMAC_url.csv", "r"), delimiter=",")
        except:
            reader = csv.reader(open("VendorsMAC.csv", "r"), delimiter=",")
        for row in reader:
            to_db = [row[0], row[1], row[2], row[4], row[5]]
            cursor.execute(
                "INSERT INTO VendorsMAC (VendorMAC, IsPrivate, CompanyName, CountryCode, AssignmentBlockSize) VALUES (?, ?, ?, ?, ?);",
                to_db,
            )

        reader = csv.reader(open("Services.csv", "r"), delimiter=",")
        for row in reader:
            to_db = [row[0], row[1], row[2], row[3]]
            cursor.execute(
                "INSERT INTO Services (PortNumber, DeviceType, Shortcut, Description) VALUES (?, ?, ?, ?);",
                to_db,
            )
        sqlite_connection.commit()

        reader = csv.reader(open("Filter.csv", "r"), delimiter=",")
        for row in reader:
            to_db = [row[0], row[1], row[2], row[3]]
            cursor.execute(
                "INSERT INTO Filter (ID_Filter, PortNumber, Protocol, MinPackets) VALUES (?, ?, ?, ?);",
                to_db,
            )
        sqlite_connection.commit()
    except sqlite3.Error as error:
        print(f"Can't fill the database in RAM memory with initial data: {error}")
    return sqlite_connection, cursor


def safe_ram_database_to_file(sqlite_connection, arg):
    """Safe the RAM menory based sqlite3 database to output sqlite3 database file (.db) with selected name from parameter -d.
    
    Parameters
    -----------
    sqlite_connection : sqlite3
        The connection to the created sqlite3 database.
    arg : argparse
        Setted arg of module.    
    """
    try:  # connect to a database
        if check_str(arg.database, ".db"):
            file = arg.database
        else:
            file = arg.database + ".db"
        if os.path.exists(file):
            os.remove(file)
        sqlite_connection_backup = sqlite3.connect(file)

        print(f"Exporting data from RAM memory to file {file}...", end="")
        with sqlite_connection_backup:
            for line in sqlite_connection.iterdump():
                if line not in ("BEGIN;", "COMMIT;"):
                    sqlite_connection_backup.execute(line)
        sqlite_connection_backup.commit()
        print("done")
    except sqlite3.Error as error:
        print(f"Can't connect to a database:  {error}")


def connect_to_database(arg):
    """Connect to sqlite3 databased based in file (.db) with name setted in parameter -d.
    
    Parameters
    -----------
    arg : argparse
        Setted arg of module.    
        
    Returns
    --------
    sqlite_connection : sqlite3
        The connection to the created sqlite3 database.
    cursor : sqlite3
        The cursor to the created database to execute SQL queries.
    """
    try:
        if check_str(arg.database, ".db") == True:
            file = arg.database
        else:
            file = arg.database + ".db"
        if not os.path.exists(file):
            print(f"can't connect to {file}")
            sys.exit()
        sqlite_connection = sqlite3.connect(file)
        cursor = sqlite_connection.cursor()
    except sqlite3.Error as error:
        print(f"Can't connect to a database:  {error}")
    return sqlite_connection, cursor


def filter_incomplete_traffic(cursor, arg, rec):
    """Filter incomplete IP flows. For TCP: check if tcp handshake was complete (3 packets). For UDP: check packet number with complete connection via protocol in table Filter.
        
    Parameters
    -----------
    arg : argparse
        Setted arg of module.
    rec : pytrap    
        Analyzed IP flow.
    Returns
    --------
    boolean
        True if IP flows is incomplete.         
        False if Ip flows isn't incomplete.
    """
    if arg.FilterIPFlows is False:
        return False
    # ===========================================
    if rec.PROTOCOL == 6 and rec.PACKETS < 3:  # 6 is TCP
        return True
    if rec.PROTOCOL == 17:  # 17 is UDP
        cursor.execute(
            "SELECT * FROM Filter WHERE ( PortNumber='{ps}' AND Protocol='{udp}' ) OR ( PortNumber='{pt}' AND Protocol='{udp}')".format(
                ps=rec.SRC_PORT, pt=rec.DST_PORT, udp="UDP"
            )
        )
        row = cursor.fetchone()
        if row:  # if known minimum exists
            if rec.PACKETS < row[3]:
                return True
        else:
            if rec.PACKETS < 2:
                return True
    return False


def main():
    """Main function of module. First set initial things (arguemnts, pytrap library, database), 
    then waiting for IP flows on selected IFC interface and call for them collector.py script to add it to database.   
    """
    arg = arguments()
    rec, trap = load_pytrap()
    if arg.RAM:
        sqlite_connection, cursor = ram_database()
    else:
        sqlite_connection, cursor = connect_to_database(arg)
    if arg.P:
        start_time = time.time()
        old_time = print_act_inf(start_time, start_time, arg, 0, cursor)
    else:
        print("Script is running...")

    db_flows = 0  # counter of IP flows that is subdued to database
    filtered_flows = 0  # counter of IP flows that isn't subdueded to database
    # db_flows + filtered_flows == all IP flows captured

    while True:  # main loop for load ip-flows from interfaces
        try:  # load IP flow from IFC interface
            data = trap.recv()
        except pytrap.FormatChanged as e:
            fmttype, inputspec = trap.getDataFmt(0)
            rec = pytrap.UnirecTemplate(inputspec)
            data = e.data
        if len(data) <= 1:
            break
        rec.setData(data)  # set the IP flow to created tempalte

        if filter_incomplete_traffic(cursor, arg, rec):
            filtered_flows = filtered_flows + 1
            continue

        if arg.P:  # if prints actualizate information enable, print it every minute
            if old_time + 60 < time.time():
                old_time = print_act_inf(
                    old_time, start_time, arg, db_flows + filtered_flows, cursor
                )

        collector.collect_flow_data(rec, sqlite_connection, cursor, arg)

        db_flows = db_flows + 1
        if arg.DeleteGlobal != 0 and db_flows % 10000 == 0:
            collector.delete_unnecessary_global_dependencies(
                sqlite_connection, arg.DeleteGlobal
            )

    if arg.DeleteGlobal != 0:
        collector.delete_unnecessary_global_dependencies(
            sqlite_connection, arg.DeleteGlobal
        )

    if arg.P:
        old_time = print_act_inf(
            old_time, start_time, arg, db_flows + filtered_flows, cursor
        )

    # Free allocated TRAP IFCs
    trap.finalize()
    if arg.RAM:  # if database was safed in RAM memory, safed it to file
        safe_ram_database_to_file(sqlite_connection, arg)
    # Close database connection
    if sqlite_connection:
        sqlite_connection.close()


if __name__ == "__main__":
    main()

