#!/usr/bin/python3.6
#libraries:
import pytrap
import sys
import os
import sqlite3
import ipaddress
import re
#python modules:
import Collector
#=================================================================================================================================
trap = pytrap.TrapCtx()
trap.init(sys.argv)
# Set the list of required fields in received messages.
# This list is an output of e.g. flow_meter - basic flow.
inputspec = "ipaddr DST_IP,ipaddr SRC_IP,uint64 BYTES,uint64 LINK_BIT_FIELD,time TIME_FIRST,time TIME_LAST,uint32 PACKETS,uint16 DST_PORT,uint16 SRC_PORT,uint8 DIR_BIT_FIELD,uint8 PROTOCOL,uint8 TCP_FLAGS,uint8 TOS,uint8 TTL"
trap.setRequiredFmt(0, pytrap.FMT_UNIREC, inputspec)
rec = pytrap.UnirecTemplate(inputspec)
#=================================================================================================================================
# Main loop
print("You can input network addresses... (end input by: end )")
NetworkLocalAddresses = []
while True:
    tmp = input()
    if tmp == "end":
        break
    try:
        ip = ipaddress.ip_network(tmp)
        NetworkLocalAddresses.append(tmp)
        print("Add new netwrok ip address: ", tmp)    
    except:
        print("Bad network address entered!")
#==========================================================
print("Only mapping entered networks? [yes]: ")    
tmp = input()
if tmp == "yes" or tmp == "YES" or tmp == "Yes":
    Networks = True
else:
    Networks = False
#==========================================================
print("Mapping only \"usualy\" transport layer port(no - will map all ports)? [yes]: ")    
tmp = input()
if tmp == "yes" or tmp == "YES" or tmp == "Yes":
    MappPorts = True
else:
    MappPorts = False
#==========================================================
print("Mapping the dependencies to global subnets(no private and entered network)? [yes]: ")    
tmp = input()
if tmp == "yes" or tmp == "YES" or tmp == "Yes":
    GlobalMapping = True
else:
    GlobalMapping = False
#==========================================================
DeleteGlobal = False
if GlobalMapping == True:
    print("Delete periodicly dependencies that have small amount of packets(you will set the number) from global dependencies? [yes]: ")    
    tmp = input()
    if tmp == "yes" or tmp == "YES" or tmp == "Yes":
        DeleteGlobal = True
    else:
        DeleteGlobal = False
    if DeleteGlobal == True:
        print("Set number of packets:")
        tmp = input()        
        PacketNumber = int(tmp)
#==========================================================
print("Would you like print some information while capturing data on netwrok? [yes]")
tmp = input()
if tmp == "yes":
    #==========================================================
    print("Print if modul find new local device(print will slow program) [yes]: ")    
    tmp = input()
    if tmp == "yes" or tmp == "YES" or tmp == "Yes":
        PrintLocalDevice = True
    else:
        PrintLocalDevice = False
    #==========================================================
    print("Print if modul find new local services(print will slow program) [yes]: ")    
    tmp = input()
    if tmp == "yes" or tmp == "YES" or tmp == "Yes":
        PrintLocalServices = True
    else:
        PrintLocalServices = False
    #==========================================================
    print("Print if modul find new local dependency(print will slow program) [yes]: ")    
    tmp = input()
    if tmp == "yes" or tmp == "YES" or tmp == "Yes":
        PrintLocalDependency = True
    else:
        PrintLocalDependency = False
    #==========================================================
    print("Print if found MAC adress for device? [yes]: ")    
    tmp = input()
    if tmp == "yes" or tmp == "YES" or tmp == "Yes":
        PrintMAC = True
    else:
        PrintMAC = False
    #==========================================================
    PrintGlobalService = False
    PrintGlobalDependency = False
    if GlobalMapping == True:
        print("Print if modul find new global service(print will slow program): ")   
        tmp = input()
        if tmp == "yes" or tmp == "YES" or tmp == "Yes":
            PrintGlobalService = True
        else:
            PrintGlobalService = False
        #==========================================================
        print("Print if modul find new global dependency(print will slow program): ")    
        tmp = input()
        if tmp == "yes" or tmp == "YES" or tmp == "Yes":
            PrintGlobalDependency = True
        else:
            PrintGlobalDependency = False
    #==========================================================
else:
    PrintLocalDevice = False
    PrintLocalServices = False
    PrintLocalDependency = False
    PrintMAC = False
    PrintGlobalService = False
    PrintGlobalDependency = False
#==========================================================
try:    #connect to a database
    print("Connecting to a database....", end='')
    if not os.path.exists('Database.db'):
        print("")
        print("can't connect to Database.db")
        sys.exit()
    SQLiteConnection = sqlite3.connect('Database.db')
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
    #===============================
    Collector.collector(rec, SQLiteConnection, NetworkLocalAddresses, Networks, GlobalMapping, PrintLocalDevice, PrintLocalServices,PrintLocalDependency, PrintGlobalService,PrintGlobalDependency, MappPorts,PrintMAC)
    #===============================
    tmp = tmp + 1
    if DeleteGlobal == True and tmp % 10000 == 0:
        Collector.DeleteGlobalDependencies(SQLiteConnection, PacketNumber)
if DeleteGlobal == True:
    Collector.DeleteGlobalDependencies(SQLiteConnection, PacketNumber)
# Free allocated TRAP IFCs
trap.finalize()
# Close database connection
if(SQLiteConnection):
    SQLiteConnection.close()
#=================================================================================================================================
