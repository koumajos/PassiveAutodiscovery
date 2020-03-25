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
print("")
print("Only mapping entered networks? [yes]: ", tmp)    
tmp = input()
if tmp == "yes" or tmp == "YES" or tmp == "Yes":
    Networks = True
else:
    Networks = False
#==========================================================
print("")
print("Mapping only \"usualy\" transport layer port(no - will map all ports)? [yes]: ", tmp)    
tmp = input()
if tmp == "yes" or tmp == "YES" or tmp == "Yes":
    MappPorts = True
else:
    MappPorts = False
#==========================================================
print("")
print("Mapping the dependencies to global subnets(no private and entered network)? [yes]: ", tmp)    
tmp = input()
if tmp == "yes" or tmp == "YES" or tmp == "Yes":
    GlobalMapping = True
else:
    GlobalMapping = False
#==========================================================
print("")
print("Print if modul find new local device(print will slow program) [yes]: ", tmp)    
tmp = input()
if tmp == "yes" or tmp == "YES" or tmp == "Yes":
    PrintLocalDevice = True
else:
    PrintLocalDevice = False
#==========================================================
print("")
print("Print if modul find new local services(print will slow program) [yes]: ", tmp)    
tmp = input()
if tmp == "yes" or tmp == "YES" or tmp == "Yes":
    PrintLocalServices = True
else:
    PrintLocalServices = False
#==========================================================
print("")
print("Print if modul find new local dependency(print will slow program) [yes]: ", tmp)    
tmp = input()
if tmp == "yes" or tmp == "YES" or tmp == "Yes":
    PrintLocalDependency = True
else:
    PrintLocalDependency = False
#==========================================================
print("")
print("Print if found MAC adress for device? [yes]: ", tmp)    
tmp = input()
if tmp == "yes" or tmp == "YES" or tmp == "Yes":
    PrintMAC = True
else:
    PrintMAC = False
#==========================================================
PrintGlobalService = False
PrintGlobalDependency = False
if GlobalMapping == True:
    print("")
    print("Print if modul find new global service(print will slow program): ", tmp)    
    tmp = input()
    if tmp == "yes" or tmp == "YES" or tmp == "Yes":
        PrintGlobalService = True
    else:
        PrintGlobalService = False
    #==========================================================
    print("")
    print("Print if modul find new global dependency(print will slow program): ", tmp)    
    tmp = input()
    if tmp == "yes" or tmp == "YES" or tmp == "Yes":
        PrintGlobalDependency = True
    else:
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
# Free allocated TRAP IFCs
trap.finalize()
# Close database connection
if(SQLiteConnection):
    SQLiteConnection.close()
#=================================================================================================================================
