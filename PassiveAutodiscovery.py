#!/usr/bin/python3.6
#libraries:
import pytrap
import sys
import os
import sqlite3
import csv
import ipaddress
import re
#=======================
import time
import colorama
from datetime import datetime
#=======================
import argparse
from argparse import RawTextHelpFormatter
#python modules:
import Collector
#=================================================================================================================================
# Main loop
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
    '-I', '--ignoreIncompletelyTCP',
    help="Ignore incompletely TCP conection (2 or less packet)",
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
#=================================================================================================================================
trap = pytrap.TrapCtx()
trap.init(sys.argv)
# Set the list of required fields in received messages.
# This list is an output of e.g. flow_meter - basic flow.
inputspec = "ipaddr DST_IP,ipaddr SRC_IP,uint64 BYTES,uint64 LINK_BIT_FIELD,time TIME_FIRST,time TIME_LAST,uint32 PACKETS,uint16 DST_PORT,uint16 SRC_PORT,uint8 DIR_BIT_FIELD,uint8 PROTOCOL,uint8 TCP_FLAGS,uint8 TOS,uint8 TTL"
trap.setRequiredFmt(0, pytrap.FMT_UNIREC, inputspec)
rec = pytrap.UnirecTemplate(inputspec)
#=================================================================================================================================
#=================================================================================================================================
#=================================================================================================================================
colorama.init()
def move_cursor(x,y):
    print ("\x1b[{};{}H".format(y+1,x+1))
def clear():
    print ("\x1b[2J")
clear()

def PRINT(oldT, startT, arguments, tmp):
    move_cursor(0,0)
    print("PassiveAutodiscovery modul")
    print("from: ", arguments.i, "      to: ", arguments.database, ".db")
    print("Networks: ", end='')
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
    print("Started time: ", datetime.fromtimestamp(startT))            
    print("")
    oldT = time.time()
    print("Time: " + str(int((oldT - startT)/60)) + " min" + "      " + "IP flows: " + str(tmp))
    cursor.execute("SELECT COUNT(*) FROM LocalDevice")
    devices = cursor.fetchone()
    cursor.execute("SELECT COUNT(*) FROM LocalServices")
    services = cursor.fetchone()
    print("Find Devices: " + str(devices[0]) + "      " + "Find Services: " +  str(services[0]))
    cursor.execute("SELECT COUNT(*) FROM Dependencies")
    Dependencies = cursor.fetchone()
    cursor.execute("SELECT COUNT(*) FROM Global")
    Global = cursor.fetchone()
    print("Local Dependencies: " + str(Dependencies[0]) + "      " + "Global Dependencies: " + str(Global[0]))
    return oldT
#=================================================================================================================================
if arguments.RAM == True:
    try:
        #print("Creating database in RAM memory....", end='')
        SQLiteConnection = sqlite3.connect(":memory:")
        cursor = SQLiteConnection.cursor()
        #print("done")
    except sqlite3.Error as error:
        print("Cant delete database in RAM memory: ", error)
    try:
        #print("Create schema of database in memory...", end='')        
        qry = open('Database_sqlite_create.sql', 'r').read()
        sqlite3.complete_statement(qry)
        cursor.executescript(qry)
        #print("done")
    except sqlite3.Error as error:
        print("Cant create database in RAM memory: ", error)
    try:
        try:
            reader = csv.reader(open('Ports_url.csv','r'), delimiter=',')
         #   print("Inserting data to table Ports....", end='')
        except:
            reader = csv.reader(open('Ports.csv','r'), delimiter=',')
        #    print("Inserting data to table Ports....", end='')
        for row in reader:
            to_db = [row[0], row[1], row[2], row[3]]
            cursor.execute("INSERT INTO Ports (ServiceName, PortNumber, TransportProtocol, Description) VALUES (?, ?, ?, ?);", to_db)
        #print("done")
        #===============================================================================================
        try:    
            reader = csv.reader(open('VendorsMAC_url.csv','r'), delimiter=',')
        #    print("Inserting data to table VendorsMAC....", end='')
        except:
            reader = csv.reader(open('VendorsMAC.csv','r'), delimiter=',')    
        #    print("Inserting data to table VendorsMAC....", end='')
        for row in reader:
            to_db = [row[0], row[1], row[2], row[4], row[5]]
            cursor.execute("INSERT INTO VendorsMAC (VendorMAC, IsPrivate, CompanyName, CountryCode, AssignmentBlockSize) VALUES (?, ?, ?, ?, ?);", to_db)
        #print("done")
        #===============================================================================================
        #print("Inserting Services data to table....", end='')
        reader = csv.reader(open('Services.csv','r'), delimiter=',')    
        for row in reader:
            to_db = [row[0], row[1], row[2], row[3]]
            cursor.execute("INSERT INTO Services (PortNumber, DeviceType, Shortcut, Description) VALUES (?, ?, ?, ?);", to_db)
        SQLiteConnection.commit()
        #print("done")
    except sqlite3.Error as error:
        print("Cant create database in RAM memory: ", error)
else:
    try:    #connect to a database
        #print("Connecting to a database....", end='')
        if not os.path.exists(arguments.database + ".db"):
        #    print("")
            print("can't connect to ", arguments.database + ".db")
            sys.exit()
        SQLiteConnection = sqlite3.connect(arguments.database + ".db")
        cursor = SQLiteConnection.cursor()
        #print("done")
    except sqlite3.Error as error:
        print("Can't connect to a database:  ", error)
if arguments.PRINT == True:
    startT = time.time()
    oldT  = time.time()
    oldT = PRINT(oldT, startT, arguments, 0)
else:
    print("Running script:")                       
tmp = 0
while True:     #main loop for load ip-flows from interfaces
    try:
        data = trap.recv()
    except pytrap.FormatChanged as e:
        fmttype, inputspec = trap.getDataFmt(0)
        rec = pytrap.UnirecTemplate(inputspec)
        data = e.data
    if len(data) <= 1:
        break
    rec.setData(data)
    #====================================================
    if arguments.ignoreIncompletelyTCP == True:
        if rec.PROTOCOL == 6 and rec.PACKETS < 3:      #6 is TCP, https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
            continue      
    #====================================================
    if arguments.PRINT == True:    
        if oldT + 60 < time.time():
            oldT = PRINT(oldT, startT, arguments, tmp)
    #====================================================
    Collector.collector(rec, SQLiteConnection, cursor, arguments)
    #====================================================
    tmp = tmp + 1
    if arguments.DeleteGlobal != 0 and tmp % 10000 == 0:
        Collector.DeleteGlobalDependencies(SQLiteConnection, arguments.DeleteGlobal)
if arguments.DeleteGlobal != 0:
    Collector.DeleteGlobalDependencies(SQLiteConnection, arguments.DeleteGlobal)
#=================================================================================================================================
# Free allocated TRAP IFCs
trap.finalize()
# Close database connection
if arguments.RAM == True:
    try:    #connect to a database
        print("Connecting to a database....", end='')
        if os.path.exists(arguments.database + ".db"):
            os.remove(arguments.database + ".db")        
        SQLiteConnectionBackUP = sqlite3.connect(arguments.database + ".db")
        print("done")
        print("Exporting data from RAM memory to file", arguments.database, ".db...", end='')    
        with SQLiteConnectionBackUP:
            for line in SQLiteConnection.iterdump():
                if line not in ('BEGIN;', 'COMMIT;'):
                    SQLiteConnectionBackUP.execute(line)
        SQLiteConnectionBackUP.commit()
        print("done")        
    except sqlite3.Error as error:
        print("Can't connect to a database:  ", error)

if(SQLiteConnection):
    SQLiteConnection.close()
#=================================================================================================================================
#=================================================================================================================================
#=================================================================================================================================
