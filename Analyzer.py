#!/usr/bin/python3.6
import sys
import os
import ipaddress
import sqlite3
import json
#=======================================================================================================================================
#=======================================================================================================================================
#=======================================================================================================================================
#Create graph of local to local dependencies
def GraphLocalDependencies(cursor, SQLiteConnection):
    None
#=======================================================================================================================================
#Create graph of global to local dependencies
def GraphGlobalDependencies(cursor, SQLiteConnection):
    None
#=======================================================================================================================================
#Analyze single device   
def AnalyzeLocalDevice(DeviceID, IP, TIME, cursor, SQLiteConnection):    
    print("######################################################################") 
    print("DeviceID: ", DeviceID)
    print("  IP: ", IP)
    #==================================================================
    createJson = {  "IP": "", 
                    "MAC": "", 
                    "Vendor": "", 
                    "Labels": None, 
                    "DHCP": None, 
                    "LocalDependencies": None, 
                    "LocalProcent": None, 
                    "GlobalDependencies": None, 
                    "GlobalProcent": None
                  }
    #==================================================================
    cursor.execute("SELECT * FROM MAC WHERE IP='{ip}' AND LastUse='{lu}'".format(ip=IP, lu=""))
    row = cursor.fetchone()
    if row:
        print("  MAC: ", row[2], end="")
        mac = map(''.join, zip(*[iter(row[2])]*8))
        cursor.execute("SELECT * FROM VendorsMAC WHERE VendorMAC='{m}'".format(m=list(mac)[0].upper()))
        row = cursor.fetchone()
        print(" | Vendor: ", row[3], ", ", row[4])
    else:
        print("  MAC: ---")
    
#    print("")
#=======================================================================================================================================
#Main function of Analyzer
def DoAnalyze(SQLiteConnection):
    #==================================================================
    creteJSON = {   "Name": "DeppendencyMapping", 
                    "DateAnalyze": "", 
                    "NumberDevice": 0
                    "Routers": None
                }    
    #==================================================================
    cursor = SQLiteConnection.cursor()
    DeviceID = 1
    #==================================================================
    cursor.execute("SELECT * FROM LocalDevice")
    LocalDevices = cursor.fetchall()
    for LocalDevice in LocalDevices:
        AnalyzeLocalDevice(DeviceID, LocalDevice[0], LocalDevice[1], cursor, SQLiteConnection)
        DeviceID = DeviceID + 1
    GraphLocalDependencies(cursor, SQLiteConnection)
    GraphGlobalDependencies(cursor, SQLiteConnection)
#=======================================================================================================================================
# Main loop
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
#=====================================================
DoAnalyze(SQLiteConnection)
#=====================================================
# Close database connection
if(SQLiteConnection):
    SQLiteConnection.close()

