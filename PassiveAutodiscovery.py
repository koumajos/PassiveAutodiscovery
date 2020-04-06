#!/usr/bin/python3.6
#libraries:
import pytrap
import sys
import os
import sqlite3
import ipaddress
import re
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
try:    #connect to a database
    print("Connecting to a database....", end='')
    if not os.path.exists(arguments.database + ".db"):
        print("")
        print("can't connect to ", arguments.database + ".db")
        sys.exit()
    SQLiteConnection = sqlite3.connect(arguments.database + ".db")
    print("done")
except sqlite3.Error as error:
    print("Can't connect to a database:  ", error)
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
    Collector.collector(rec, SQLiteConnection, arguments)
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
if(SQLiteConnection):
    SQLiteConnection.close()
#=================================================================================================================================
#=================================================================================================================================
#=================================================================================================================================
