#!/usr/bin/python3.6
"""PassiveAutodiscovery module 
    
    This is module for modular monitoring system NEMEA (Network Measurement Analysis).
    
    Module main funkcionality is Autodiscovery, Device Recognition and Deppendency mapping.
    For this funkcionalities module use passive analyze. That mean that module take IP flows
    from IFC interface, that is always filled by flow_meter, and analyze them. Flow_meter 
    capture packets on network interface and create from it IP flows. 
    (Module can also use files of IP flows as IFC interface)
    Module use sqlite3 database for safing data from IP flows.     
    --------------
    Autodiscovery:
        Finds "local" device from network traffic. (local device = device that is from 
        private subnet 10.0.0.0/8 or 172.16.0.0/16 or 192.168.0.0/24 OR device from 
        subnet that was inserted by user with parameter -N)
    Device Recognition:
        Module recognize the roles of device in network and set to the device labels. This labels
        marks the roles of device. In the example for device that has role dhcp server fro the 
        network, will module set to device label [DHCP Server].
    Deppendency mapping:
        Module safe all dependencies between "local" devices. Can also safe dependencies
        between "local" device and "global" devices(devices that aren't "local").

    Module is coaporate with Collector.py script that fill sqlite3 database. 
    The output from the database (entire analyze) is created by DeviceAnalyzer.py script.   
"""
#=================================================================================================================================
#NEMEA system library for 
import pytrap
#libraries for working with OS UNIX files and system
import sys
import os
#libraries for working with sqlite3 database
import sqlite3
import csv
#library for work with IP addresses
import ipaddress
#library for work with UNIX time
import time
from datetime import datetime
#library for print actualizate statistics 
import colorama
#libraries for arguments of module
import argparse
from argparse import RawTextHelpFormatter
#cooperate python script
import Collector
#=================================================================================================================================
#=================================================================================================================================
def move_cursor(x,y):
    """Move cursor in actualization prints to X, Y coordinates.
        
    Parameters:
    -----------
    x : int
        coordinate X
    y : int
        coordinate Y
    """
    print ("\x1b[{};{}H".format(y+1,x+1))
#=================================================================================================================================
#=================================================================================================================================
def clear():
    """Clear command line for actualization prints.
    
    """
    print ("\x1b[2J")
#=================================================================================================================================
#=================================================================================================================================
def PRINT(oldT, startT, arguments, NumFlows, cursor):
    """Prints actualication information about running the module. Enable with parameter -P.
        
    Parameters:
    -----------
    oldT : int
        UNIX time of last print.
    startT : int
        UNIX time of start the module.
    arguments : argparse
        Setted arguments of module.
    NumFlows : int
        Number of IP flows that bean analyze by module.
    cursor : sqlite3
        Cursor to sqlite3 database for execute SQL queries.
    Returns:
    --------
    oldT : int
        UNIX time of this print.
    """
    move_cursor(0,0)    #move cursor at the start of command line
    print("PassiveAutodiscovery modul")
    print("from: ", arguments.i, "      to: ", arguments.database, ".db")
    print("Networks: ", end='')         #print analyzed networks
    if arguments.networks != "" and arguments.OnlySetNetworks == True:
        for i in arguments.networks:        
            if i != arguments.networks[-1]:            
                print(i, ", ", end='')
            else:
                print(i)
    elif arguments.networks != "":
        for i in arguments.networks:        
            print(i, ", ", end='')
        print("Private networks")
    else:
        print("Private subnets")
    print("")        
    print("Started time: ", datetime.fromtimestamp(startT))     #print when module started       
    print("")
    oldT = time.time()
    print("Time: " + str(int((oldT - startT)/60)) + " min" + "      " + "IP flows: " + str(NumFlows))   #print time of running module and number of analyzed ip flows
    cursor.execute("SELECT COUNT(*) FROM LocalDevice")
    devices = cursor.fetchone()
    cursor.execute("SELECT COUNT(*) FROM LocalServices")
    services = cursor.fetchone()
    print("Find Devices: " + str(devices[0]) + "      " + "Find Services: " +  str(services[0]))    #print number of findend "local" devices and their services 
    cursor.execute("SELECT COUNT(*) FROM Dependencies")
    Dependencies = cursor.fetchone()
    cursor.execute("SELECT COUNT(*) FROM Global")
    Global = cursor.fetchone()
    print("Local Dependencies: " + str(Dependencies[0]) + "      " + "Global Dependencies: " + str(Global[0]))  #pritn number of dependencies
    return oldT
#=================================================================================================================================
#=================================================================================================================================
def Arguments():
    """Arguemtns of the module.
        
    Returns:
    --------
    arguments : argparse
        Setted arguemnts of the module.
    """
    parser = argparse.ArgumentParser( description="""Collect flow from network interface and output to database

    Database is created by CreateScript.py.
    Then analyze with DeviceAnalyzer.py.

    Usage:""", formatter_class=RawTextHelpFormatter)
    #=====================================================
    parser.add_argument(
        '-i',
        help="Specification of interface types and their parameters, see \"-h trap\" (mandatory parameter).",
        type=str,
        metavar='IFC_SPEC',
    )
    #=====================================================
    parser.add_argument(
        '-v',
        help="Be verbose.",
        action="store_true"
    )
    #=====================================================
    parser.add_argument(
        '-vv',
        help="Be more verbose.",
        action="store_true"
    )
    #=====================================================
    parser.add_argument(
        '-vvv',
        help="Be even more verbose.",
        action="store_true"
    )
    #=====================================================
    parser.add_argument(
        '-d', '--database',
        help="Set name of the database without . part,  default is Database",
        type=str,
        metavar='NAME',
        default="Database"
    )
    #=====================================================
    parser.add_argument(
        '-N', '--networks',
        help="IP addresses and mask (IPaddress/MASK - 192.168.1.0/24) of networks to monitor",
        type=str,
        nargs='+',
        metavar='IPs',
        default=""
    )
    #=====================================================
    parser.add_argument(
        '-!', '--OnlySetNetworks',
        help="Only monitor entered networks via parameter N (ussage: -N ... -! )",
        action="store_true"
    )
    #=====================================================
    parser.add_argument(
        '-U', '--UsualyPorts',
        help="Map only \"usualy\" transport layer ports",
        action="store_true"
    )
    #=====================================================
    parser.add_argument(
        '-F', '--FilterIPFlows',
        help="Filter incompletely conection",
        action="store_true"
    )
    #=====================================================
    parser.add_argument(
        '-G', '--GlobalDependencies',
        help="Mapping the dependencies to global subnets",
        action="store_true"
    )
    #=====================================================
    parser.add_argument(
        '-D', '--DeleteGlobal',
        help="Delete periodicly dependencies that have setted amount of packets from global dependencies",
        type=int,
        metavar='NUMBER',
        default=0
    )
    #=====================================================
    parser.add_argument(
        '-RAM', '--RAM',
        help="Safe database in RAM memory and safe to file after modul end",
        action="store_true"
    )
    #=====================================================
    parser.add_argument(
        '-P', '--PRINT',
        help="Printing information in menu",
        action="store_true"
    )
    #=====================================================
    parser.add_argument(
        '-l', '--localdev',
        help="Print if modul find new local device(print will slow program)",
        action="store_true"
    )
    #=====================================================
    parser.add_argument(
        '-s', '--localserv',
        help="Print if modul find new local services(print will slow program)",
        action="store_true"
    )
    #=====================================================
    parser.add_argument(
        '-L', '--localdependencies',
        help="Print if modul find new dependencies between two \"local\" device(print will slow program)",
        action="store_true"
    )
    #=====================================================
    parser.add_argument(
        '-m', '--macdev',
        help="Print if found MAC adress for \"local\" device(print will slow program)",
        action="store_true"
    )
    #=====================================================
    parser.add_argument(
        '-S', '--globalserv',
        help="Print if modul find new global service(print will slow program)",
        action="store_true"
    )
    #=====================================================
    parser.add_argument(
        '-g', '--globaldependencies',
        help="Print if modul find new dependency between \"local\" device and global device(print will slow program)",
        action="store_true"
    )
    #=====================================================
    arguments = parser.parse_args()
    #=====================================================
    if arguments.PRINT == True and (arguments.localdev == True or arguments.localserv == True or arguments.globalserv == True or arguments.localdependencies == True or arguments.globaldependencies == True or arguments.macdev == True):
        print("Parameters -P and (-l or -s or -L -g -S -m) can't be combinated")
        sys.exit()
    if arguments.PRINT == True:
        colorama.init()
        clear()
    return arguments
#=================================================================================================================================
#=================================================================================================================================
def PYTRAP():
    """Init nemea libraries and set format of IP flows.
        
    Returns:
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
    inputspec = "ipaddr DST_IP,ipaddr SRC_IP,uint64 BYTES,uint64 LINK_BIT_FIELD,time TIME_FIRST,time TIME_LAST,uint32 PACKETS,uint16 DST_PORT,uint16 SRC_PORT,uint8 DIR_BIT_FIELD,uint8 PROTOCOL,uint8 TCP_FLAGS,uint8 TOS,uint8 TTL"
    trap.setRequiredFmt(0, pytrap.FMT_UNIREC, inputspec)
    rec = pytrap.UnirecTemplate(inputspec)
    return rec, trap
#=================================================================================================================================
#=================================================================================================================================
def RAMDatabase():
    """Create sqlite3 database in RAM memory, create schema of it and fill the database with initial data for tables Ports, VendorsMAC and Services.
        
    Returns:
    --------
    SQLiteConnection : sqlite3
        The connection to the created sqlite3 database.
    cursor : sqlite3
        The cursor to the created database to execute SQL queries.
    """
    try:
        SQLiteConnection = sqlite3.connect(":memory:")      #create database in RAM memory
        cursor = SQLiteConnection.cursor()
    except sqlite3.Error as error:
        print("Can't create database in RAM memory: ", error)
    try:
        qry = open('Database_sqlite_create.sql', 'r').read()
        sqlite3.complete_statement(qry)     
        cursor.executescript(qry)           #create schema of the database
    except sqlite3.Error as error:
        print("Can't create schema database in RAM memory: ", error)
    try:        #fill database with intial data
        try:
            reader = csv.reader(open('Ports_url.csv','r'), delimiter=',')
        except:
            reader = csv.reader(open('Ports.csv','r'), delimiter=',')
        for row in reader:
            to_db = [row[0], row[1], row[2], row[3]]
            cursor.execute("INSERT INTO Ports (ServiceName, PortNumber, TransportProtocol, Description) VALUES (?, ?, ?, ?);", to_db)
        #===============================================================================================
        try:    
            reader = csv.reader(open('VendorsMAC_url.csv','r'), delimiter=',')
        except:
            reader = csv.reader(open('VendorsMAC.csv','r'), delimiter=',')    
        for row in reader:
            to_db = [row[0], row[1], row[2], row[4], row[5]]
            cursor.execute("INSERT INTO VendorsMAC (VendorMAC, IsPrivate, CompanyName, CountryCode, AssignmentBlockSize) VALUES (?, ?, ?, ?, ?);", to_db)
        #===============================================================================================
        reader = csv.reader(open('Services.csv','r'), delimiter=',')    
        for row in reader:
            to_db = [row[0], row[1], row[2], row[3]]
            cursor.execute("INSERT INTO Services (PortNumber, DeviceType, Shortcut, Description) VALUES (?, ?, ?, ?);", to_db)
        SQLiteConnection.commit()
    except sqlite3.Error as error:
        print("Can't fill the database in RAM memory with initial data: ", error)
    return SQLiteConnection, cursor
#=================================================================================================================================
#=================================================================================================================================
def SafeRAMDatabase(SQLiteConnection, arguments):
    """Safe the RAM menory based sqlite3 database to output sqlite3 database file (.db) with selected name from parameter -d.
    
    Parameters:
    -----------
    SQLiteConnection : sqlite3
        The connection to the created sqlite3 database.
    arguments : argparse
        Setted arguments of module.    
    """
    try:    #connect to a database
        if os.path.exists(arguments.database + ".db"):
            os.remove(arguments.database + ".db")        
        SQLiteConnectionBackUP = sqlite3.connect(arguments.database + ".db")
        print("Exporting data from RAM memory to file", arguments.database, ".db...", end='')    
        with SQLiteConnectionBackUP:
            for line in SQLiteConnection.iterdump():
                if line not in ('BEGIN;', 'COMMIT;'):
                    SQLiteConnectionBackUP.execute(line)
        SQLiteConnectionBackUP.commit()
        print("done")        
    except sqlite3.Error as error:
        print("Can't connect to a database:  ", error)
#=================================================================================================================================
#=================================================================================================================================
def ConnectToDatabase(arguments):
    """Connect to sqlite3 databased based in file (.db) with name setted in parameter -d.
    
    Parameters:
    -----------
    arguments : argparse
        Setted arguments of module.    
        
    Returns:
    --------
    SQLiteConnection : sqlite3
        The connection to the created sqlite3 database.
    cursor : sqlite3
        The cursor to the created database to execute SQL queries.
    """
    try:    #connect to a database
        if not os.path.exists(arguments.database + ".db"):
            print("can't connect to ", arguments.database + ".db")
            sys.exit()      #if file not exists end the entire module
        SQLiteConnection = sqlite3.connect(arguments.database + ".db")
        cursor = SQLiteConnection.cursor()
    except sqlite3.Error as error:
        print("Can't connect to a database:  ", error)
    return SQLiteConnection, cursor
#=================================================================================================================================
#=================================================================================================================================
def IncompleteTraffic(arguments, rec):
    """Filter incomplete IP flows.
        
    Parameters:
    -----------
    arguments : argparse
        Setted arguments of module.
    rec : pytrap    
        Analyzed IP flow.
    Returns:
    --------
    boolean
        True if IP flows is incomplete.         
        False if Ip flows isn't incomplete.
        
    """
    if arguments.FilterIPFlows == False:
        return False
    #===========================================
    if rec.PROTOCOL == 6 and rec.PACKETS < 3:      #6 is TCP, https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
        return True
    #TODO: Try fillter incomplete traffic using UDP protocol (??or other protocol??)
    return False    
#=================================================================================================================================
#=================================================================================================================================
# Main function
def Main():
    """Main function of module. First set initial things (arguemnts, pytrap library, database), then waiting for IP flows on selected IFC interface and call for them Collector.py script to add it to database.
        
    """
    arguments = Arguments()
    rec, trap = PYTRAP()
    #====================================================
    if arguments.RAM == True:
        SQLiteConnection, cursor = RAMDatabase()
    else:
        SQLiteConnection, cursor = ConnectToDatabase(arguments)
    #====================================================
    if arguments.PRINT == True:
        startT = time.time()
        oldT = PRINT(startT, startT, arguments, 0, cursor)
    else:
        print("Script is running...")                       
    #====================================================
    Dtmp = 0        #counter of IP flows that is subdued to database
    Rtmp = 0        #counter of IP flows that isn't subdueded to database
    # Dtmp + Rtmp == all IP flows captured 
    #====================================================
    while True:     #main loop for load ip-flows from interfaces
        try:    #load IP flow from IFC interface
            data = trap.recv()
        except pytrap.FormatChanged as e:
            fmttype, inputspec = trap.getDataFmt(0)
            rec = pytrap.UnirecTemplate(inputspec)
            data = e.data
        if len(data) <= 1:
            break
        rec.setData(data)   # set the IP flow to created tempalte
        #====================================================
        if IncompleteTraffic(arguments, rec) == True:   #fillter incomplete IP flow
            Rtmp = Rtmp + 1            
            continue
        #====================================================
        if arguments.PRINT == True:    #if prints actualizate information enable, print it every minute
            if oldT + 60 < time.time():
                oldT = PRINT(oldT, startT, arguments, Dtmp + Rtmp, cursor)
        #====================================================
        Collector.collector(rec, SQLiteConnection, cursor, arguments)   #analyze te IP flow and data from it get to database
        #====================================================
        Dtmp = Dtmp + 1
        if arguments.DeleteGlobal != 0 and Dtmp % 10000 == 0:       # if delete some dependencies enabled and is time for periodic delete do it
            Collector.DeleteGlobalDependencies(SQLiteConnection, arguments.DeleteGlobal)
    #====================================================
    # if delete dependencies from table Global, must delete in end of the script    
    if arguments.DeleteGlobal != 0:
        Collector.DeleteGlobalDependencies(SQLiteConnection, arguments.DeleteGlobal)
    if arguments.PRINT == True:    #if prints actualizate information enable, print it every minute
        oldT = PRINT(oldT, startT, arguments, Dtmp + Rtmp, cursor)
    # Free allocated TRAP IFCs
    trap.finalize()
    if arguments.RAM == True:       #if database was safed in RAM memory, safed it to file
        SafeRAMDatabase(SQLiteConnection, arguments)
    # Close database connection
    if(SQLiteConnection):
        SQLiteConnection.close()
#===============================================================================================
#===============================================================================================
if __name__ == "__main__":
    Main()
#===============================================================================================
#===============================================================================================
