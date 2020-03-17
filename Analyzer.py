#!/usr/bin/python3.6
import sys
import os
import ipaddress
import sqlite3
import time
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
#MAC address and vendor adding
def MAC(DeviceID, IP, cursor, SQLiteConnection):
    cursor.execute("SELECT * FROM MAC WHERE IP='{ip}' AND LastUse='{lu}'".format(ip=IP, lu=""))
    row = cursor.fetchone()
    cursor.execute("SELECT * FROM Routers WHERE IP='{ip}'".format(ip=IP) )
    Router = cursor.fetchone()
    mac = ""    
    if row:
        print("  MAC: ", row[2], end="")
        mac = map(''.join, zip(*[iter(row[2])]*8))
    elif Router:
        print("  MAC: ", Router[1], end="")
        mac = map(''.join, zip(*[iter(Router[1])]*8))    
    else:
        print("  MAC: ---")
    if mac != "":
        cursor.execute("SELECT * FROM VendorsMAC WHERE VendorMAC='{m}'".format(m=list(mac)[0].upper()))
        row = cursor.fetchone()
        print(" | Vendor: ", row[3], ",", row[4])
#=======================================================================================================================================
#Labels adding   
def LABELS(DeviceID, IP, cursor, SQLiteConnection):
    print("Labels:")
    cursor.execute("SELECT * FROM LocalServices WHERE IP='{ip}'".format(ip=IP) )
    Labels = cursor.fetchall()
    tmp = 0    
    if Labels:
        tmp = 1        
        for Label in Labels:
            cursor.execute("SELECT * FROM Services WHERE PortNumber='{port}'".format(port=Label[0]) )
            Service = cursor.fetchone()            
            print(" [", Service[1], "]  - ", Service[3])
    cursor.execute("SELECT * FROM Global G JOIN GlobalServices GS ON G.IP_target=GS.IP JOIN Services S ON S.PortNumber=GS.PortNumber WHERE G.IP_origin='{ipo}' AND S.DeviceType='{t}'".format(ipo=IP, t="WEB SERVER") )
    WebServer = cursor.fetchone()
    if WebServer:
        tmp = 1
        print(" [ End Device ]  - PC, Mobile Phone, Server, ... (everything with web browser)")
    cursor.execute("SELECT * FROM Routers WHERE IP='{ip}'".format(ip=IP) )
    Router = cursor.fetchone()
    if Router:
        tmp = 1
        print(" [ Router ]")    
    if tmp == 0:
        print("  ---")    
#=======================================================================================================================================
#DHCP records adding   
def DHCP(DeviceID, IP, cursor, SQLiteConnection):
    print("DHCP:")
    cursor.execute("SELECT * FROM DHCP WHERE DeviceIP='{ip}' ORDER BY Time DESC".format(ip=IP) )
    DHCPs = cursor.fetchall()    
    if DHCPs:
        for DHCP in DHCPs:
            print("  Server: ", DHCP[2], " Time:", time.ctime(float(DHCP[3])) )
    else:
        print("  ---")    
#=======================================================================================================================================
#LocalDependencies records adding  
def LOCALDEPENDENCIES(DeviceID, IP, DeviceIP, cursor, SQLiteConnection):
    print("Local Dependencies:")    
    cursor.execute("SELECT * FROM Dependencies WHERE IP_origin='{ipo}' OR IP_target='{ipt}' ORDER BY NumBytes DESC".format(ipo=IP, ipt=IP) )
    Dependencies = cursor.fetchall()    
    if Dependencies:    
        for Dependency in Dependencies:
            SrcIP = ipaddress.ip_address(Dependency[1])
            cursor.execute("SELECT * FROM Services WHERE PortNumber='{portS}'".format(portS=Dependency[3]) )
            ServiceS = cursor.fetchone()                
            cursor.execute("SELECT * FROM Services WHERE PortNumber='{portD}'".format(portD=Dependency[4]) )
            ServiceD = cursor.fetchone()    
            if ServiceS:
                if SrcIP == DeviceIP:
                    print("  -> ", Dependency[2], end='')
                    if ServiceS[1] == "DHCP Client":
                        print("  is [ DHCP Server ]  -  Number of packets: ", Dependency[5])
                        continue
                    else:
                        print(" need", end='')
                else:               
                    print("  -> ", Dependency[1], " is", end='')
                print(" [", ServiceS[1], "]  -  Number of packets: ", Dependency[5])            
            elif ServiceD:
                if SrcIP == DeviceIP:
                    print("  -> ", Dependency[2], " is", end='')
                else:               
                    print("  -> ", Dependency[1], " need", end='')
                print(" [", ServiceD[1], "]  -  Number of packets: ", Dependency[5])                        
            else:
                if SrcIP == DeviceIP:
                    print("  -> ", Dependency[2], " is", end='')
                    cursor.execute("SELECT * FROM Ports WHERE PortNumber='{portD}'".format(portD=Dependency[4]) )
                    PortD = cursor.fetchone()                    
                    if PortD:
                        print("  -  ", PortD[1], "  -  Number of packets: ", Dependency[5])
                    else:
                        print("  -  ", Dependency[4], "  -  Number of packets: ", Dependency[5])
                else:               
                    print("  -> ", Dependency[1], " need", end='')
                    cursor.execute("SELECT * FROM Ports WHERE PortNumber='{portS}'".format(portS=Dependency[3]) )
                    PortS = cursor.fetchone()    
                    if PortS:
                        print("  -  ", PortS[1], "  -  Number of packets: ", Dependency[5])
                    else:
                        print("  -  ", Dependency[3], "  -  Number of packets: ", Dependency[5])
            #print("  ",Dependency)
    else:
        print("  ---")    
#=======================================================================================================================================
#GlobalDependencies records adding  
def GLOBALDEPENDENCIES(DeviceID, IP, DeviceIP, cursor, SQLiteConnection):
    print("Global Dependencies:")    
    cursor.execute("SELECT * FROM Global WHERE IP_origin='{ipo}' OR IP_target='{ipt}' ORDER BY NumBytes DESC".format(ipo=IP, ipt=IP) )
    GlobalDependencies = cursor.fetchall()
    if GlobalDependencies:    
        for GlobalDependency in GlobalDependencies:
            SrcIP = ipaddress.ip_address(GlobalDependency[1])
            cursor.execute("SELECT * FROM Services WHERE PortNumber='{portS}'".format(portS=GlobalDependency[3]) )
            ServiceS = cursor.fetchone()                
            cursor.execute("SELECT * FROM Services WHERE PortNumber='{portD}'".format(portD=GlobalDependency[4]) )
            ServiceD = cursor.fetchone()    
            if ServiceS:
                if SrcIP == DeviceIP:
                    print("  -> ", GlobalDependency[2], end='')
                    if ServiceS[1] == "DHCP Client":
                        print("  is [ DHCP Server ]  -  Number of packets: ", GlobalDependency[5])
                        continue
                    else:
                        print(" need", end='')
                else:               
                    print("  -> ", GlobalDependency[1], " is", end='')
                print(" [", ServiceS[1], "]  -  Number of packets: ", GlobalDependency[5])            
            elif ServiceD:
                if SrcIP == DeviceIP:
                    print("  -> ", GlobalDependency[2], " is", end='')
                else:               
                    print("  -> ", GlobalDependency[1], " need", end='')
                print(" [", ServiceD[1], "]  -  Number of packets: ", GlobalDependency[5])                        
            else:
                if SrcIP == DeviceIP:
                    print("  -> ", GlobalDependency[2], " is", end='')
                    cursor.execute("SELECT * FROM Ports WHERE PortNumber='{portD}'".format(portD=GlobalDependency[4]) )
                    PortD = cursor.fetchone()                    
                    if PortD:
                        print("  -  ", PortD[1], "  -  Number of packets: ", GlobalDependency[5])
                    else:
                        print("  -  ", GlobalDependency[4], "  -  Number of packets: ", GlobalDependency[5])
                else:               
                    print("  -> ", GlobalDependency[1], " need", end='')
                    cursor.execute("SELECT * FROM Ports WHERE PortNumber='{portS}'".format(portS=GlobalDependency[3]) )
                    PortS = cursor.fetchone()    
                    if PortS:
                        print("  -  ", PortS[1], "  -  Number of packets: ", GlobalDependency[5])
                    else:
                        print("  -  ", GlobalDependency[3], "  -  Number of packets: ", GlobalDependency[5])
            #print("  ", GlobalDependency)
    else:
        print("  ---")
#=======================================================================================================================================
#Analyze single device   
def AnalyzeLocalDevice(DeviceID, IP, TIME, cursor, SQLiteConnection):    
    print("######################################################################") 
    print("DeviceID: ", DeviceID)
    print("  IP: ", IP)
    DeviceIP = ipaddress.ip_address(IP)
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
    MAC(DeviceID, IP, cursor, SQLiteConnection)
    #==================================================================
    LABELS(DeviceID, IP, cursor, SQLiteConnection)
    #==================================================================
    DHCP(DeviceID, IP, cursor, SQLiteConnection)
    #==================================================================    
    LOCALDEPENDENCIES(DeviceID, IP, DeviceIP, cursor, SQLiteConnection)
    #==================================================================
    GLOBALDEPENDENCIES(DeviceID, IP, DeviceIP, cursor, SQLiteConnection)    
    #==================================================================
    
#    print("")
#=======================================================================================================================================
#Main function of Analyzer
def DoAnalyze(SQLiteConnection):
    #==================================================================
    creteJSON = {   "Name": "DeppendencyMapping", 
                    "DateAnalyze": "", 
                    "NumberDevice": 0,
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

