#!/usr/bin/python3.6
import sys
import os
import ipaddress
import sqlite3
import time
import json
import math
import socket
#=======================
from termgraph import termgraph
import tempfile
#=======================
import pandas
import numpy
import networkx
import matplotlib.pyplot as plt
#=======================================================================================================================================
#plot percent graph
def plot(data):
    with tempfile.NamedTemporaryFile(mode='a+') as f:
        # Save data in temporary file
        for row in data:
            f.write('\t'.join(map(str, row)) + '\n')
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
#=======================================================================================================================================
#Write json to json file
def write_json(data, filename): 
    with open(filename,'w') as f: 
        json.dump(data, f, indent=4) 
#=======================================================================================================================================
#Create graph of local to local dependencies
def GraphLocalDependencies(cursor, SQLiteConnection):
    print("  Graph of local dependencies:")    
    cursor.execute("SELECT * FROM Dependencies")
    rows = cursor.fetchall()
    #=================================
    plt.figure("Map of Local Dependencies", figsize=(20, 10), dpi=80, facecolor='w', edgecolor='k')    
    G = networkx.Graph()        
    for row in rows:
        G.add_node(row[1])
        G.add_node(row[2])
        G.add_weighted_edges_from([(row[1], row[2], row[4])])
#    print(G.nodes())
#    print(G.edges())
    networkx.draw(G, with_labels=True)
    plt.show()    
#    plt.savefig("Graph_Local.png")
#    plt.show()   
#=======================================================================================================================================
#Create graph of global to local dependencies
def GraphGlobalDependencies(cursor, SQLiteConnection):
    print("  Graph of global dependencies:")    
    cursor.execute("SELECT * FROM Global")
    rows = cursor.fetchall()
    #=================================
    plt.figure("Map of Global Dependencies", figsize=(20, 10), dpi=80, facecolor='w', edgecolor='k')    
    H = networkx.Graph()        
    for row in rows:
        if not H.has_node(row[1]):
            H.add_node(row[1])
        if not H.has_node(row[2]):        
            H.add_node(row[2])
        if not H.has_edge(row[1], row[2]):        
            H.add_weighted_edges_from([(row[1], row[2], row[4])])
#    print(H.nodes())
#    print(H.edges())
    pos = networkx.spring_layout(H,k=5/math.sqrt(H.order()),iterations=20)
    networkx.draw(H, with_labels=True)
    #ax = plt.gca()
    #ax.collections[0].set_edgecolor("#555555") 
    plt.show()       
#   plt.savefig("Graph_Global.png")
#    plt.show()
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
    print("  Labels:")
    cursor.execute("SELECT * FROM LocalServices WHERE IP='{ip}'".format(ip=IP) )
    Labels = cursor.fetchall()
    tmp = 0    
    if Labels:
        tmp = 1        
        for Label in Labels:
            cursor.execute("SELECT * FROM Services WHERE PortNumber='{port}'".format(port=Label[0]) )
            Service = cursor.fetchone()            
            print("   [", Service[1], "]  - ", Service[3])
    cursor.execute("SELECT * FROM Global G JOIN GlobalServices GS ON G.IP_target=GS.IP JOIN Services S ON S.PortNumber=GS.PortNumber WHERE G.IP_origin='{ipo}' AND S.DeviceType='{t}'".format(ipo=IP, t="WEB SERVER") )
    WebServer = cursor.fetchone()
    if WebServer:
        tmp = 1
        print("   [ End Device ]  - PC, Mobile Phone, Server, ... (everything with web browser)")
    cursor.execute("SELECT * FROM Routers WHERE IP='{ip}'".format(ip=IP) )
    Router = cursor.fetchone()
    if Router:
        tmp = 1
        print("   [ Router ]")    
    if tmp == 0:
        print("    ---")    
#=======================================================================================================================================
#DHCP records adding   
def DHCP(DeviceID, IP, cursor, SQLiteConnection):
    print("  DHCP:")
    cursor.execute("SELECT * FROM DHCP WHERE DeviceIP='{ip}' ORDER BY Time DESC".format(ip=IP) )
    DHCPs = cursor.fetchall()    
    if DHCPs:
        for DHCP in DHCPs:
            print("    Server: ", DHCP[2], " Time:", time.ctime(float(DHCP[3])) )
    else:
        print("    ---")
#====================================================================================================================================== 
#Stats
def Stats(LocalStatistic, Dependency, cursor, SQLiteConnection):
    cursor.execute("SELECT * FROM Ports WHERE PortNumber='{po}'".format(po=Dependency[3]) )
    stats = cursor.fetchall()    
    for stat in stats:
        if stat[1] == '':            
            return    
    #=========================================================================================    
    cursor.execute("SELECT * FROM Services WHERE PortNumber={po}".format(po=Dependency[3]) )
    servicestat = cursor.fetchone()    
    if servicestat:
        if servicestat[2] in LocalStatistic:
            LocalStatistic[servicestat[2]] = LocalStatistic[servicestat[2]] + Dependency[5]
        else:
            LocalStatistic[servicestat[2]] = Dependency[5]
    else:               
        cursor.execute("SELECT * FROM Ports WHERE PortNumber='{po}'".format(po=Dependency[3]) )
        stats = cursor.fetchall()    
        if stats:        
            for stat in stats:
                if stat[1] in LocalStatistic:
                    LocalStatistic[stat[1]] = LocalStatistic[stat[1]] + Dependency[5]
                else:
                    LocalStatistic[stat[1]] = Dependency[5]    
                break
    #==========================================
    cursor.execute("SELECT * FROM Services WHERE PortNumber={pt}".format(pt=Dependency[4]) )
    servicestat = cursor.fetchone()    
    if servicestat:
        if servicestat[2] in LocalStatistic:
            LocalStatistic[servicestat[2]] = LocalStatistic[servicestat[2]] + Dependency[5]
        else:
            LocalStatistic[servicestat[2]] = Dependency[5]        
    else:               
        cursor.execute("SELECT * FROM Ports WHERE PortNumber='{pt}'".format(pt=Dependency[4]) )
        stats = cursor.fetchall()    
        if stats:        
            for stat in stats:
                if stat[1] in LocalStatistic:
                    LocalStatistic[stat[1]] = LocalStatistic[stat[1]] + Dependency[5]
                else:
                    LocalStatistic[stat[1]] = Dependency[5]
                break    
#=======================================================================================================================================
#LocalDependencies records adding  
def LOCALDEPENDENCIES(DeviceID, IP, DeviceIP, LocalStatistic, cursor, SQLiteConnection):
    print("  Local Dependencies:")    
    cursor.execute("SELECT * FROM Dependencies WHERE IP_origin='{ipo}' OR IP_target='{ipt}' ORDER BY NumBytes DESC".format(ipo=IP, ipt=IP) )
    Dependencies = cursor.fetchall()    
    if Dependencies:    
        for Dependency in Dependencies:
            Stats(LocalStatistic, Dependency, cursor, SQLiteConnection)
            #==========================================
            SrcIP = ipaddress.ip_address(Dependency[1])
            cursor.execute("SELECT * FROM Services WHERE PortNumber='{portS}'".format(portS=Dependency[3]) )
            ServiceS = cursor.fetchone()                
            cursor.execute("SELECT * FROM Services WHERE PortNumber='{portD}'".format(portD=Dependency[4]) )
            ServiceD = cursor.fetchone()    
            if ServiceS:
                if SrcIP == DeviceIP:
                    print("    -> ", Dependency[2].ljust(20, ' '), end='')
                    if ServiceS[1] == "DHCP Client":
                        print("  is [ DHCP Server ]  -  Number of packets: ", Dependency[5])
                        continue
                    else:
                        print(" need", end='')
                else:               
                    print("    -> ", Dependency[1].ljust(20, ' '), " is", end='')
                print(" [", ServiceS[1], "]  -  Number of packets: ", Dependency[5])            
            elif ServiceD:
                if SrcIP == DeviceIP:
                    print("    -> ", Dependency[2].ljust(20, ' '), " is", end='')
                else:               
                    print("    -> ", Dependency[1].ljust(20, ' '), " need", end='')
                print(" [", ServiceD[1], "]  -  Number of packets: ", Dependency[5])                        
            else:
                if SrcIP == DeviceIP:
                    print("    -> ", Dependency[2].ljust(20, ' '), " is", end='')
                    cursor.execute("SELECT * FROM Ports WHERE PortNumber='{portD}'".format(portD=Dependency[4]) )
                    PortD = cursor.fetchone()                    
                    if PortD:
                        print("  -  ", PortD[1], "  -  Number of packets: ", Dependency[5])
                    else:
                        print("  -  ", Dependency[4], "  -  Number of packets: ", Dependency[5])
                else:               
                    print("    -> ", Dependency[1].ljust(20, ' '), " need", end='')
                    cursor.execute("SELECT * FROM Ports WHERE PortNumber='{portS}'".format(portS=Dependency[3]) )
                    PortS = cursor.fetchone()    
                    if PortS:
                        print("  -  ", PortS[1], "  -  Number of packets: ", Dependency[5])
                    else:
                        print("  -  ", Dependency[3], "  -  Number of packets: ", Dependency[5])
            #print("  ",Dependency)
    else:
        print("    ---")    
#=======================================================================================================================================
#GlobalDependencies records adding  
def GLOBALDEPENDENCIES(DeviceID, IP, DeviceIP, GlobalStatistic, cursor, SQLiteConnection):
    print("  Global Dependencies:")    
    cursor.execute("SELECT * FROM Global WHERE IP_origin='{ipo}' OR IP_target='{ipt}' ORDER BY NumBytes DESC".format(ipo=IP, ipt=IP) )
    GlobalDependencies = cursor.fetchall()
    if GlobalDependencies:    
        for GlobalDependency in GlobalDependencies:
            Stats(GlobalStatistic, GlobalDependency, cursor, SQLiteConnection)
            #==========================================
            SrcIP = ipaddress.ip_address(GlobalDependency[1])
            cursor.execute("SELECT * FROM Services WHERE PortNumber='{portS}'".format(portS=GlobalDependency[3]) )
            ServiceS = cursor.fetchone()                
            cursor.execute("SELECT * FROM Services WHERE PortNumber='{portD}'".format(portD=GlobalDependency[4]) )
            ServiceD = cursor.fetchone()    
            if ServiceS:
                if SrcIP == DeviceIP:
                    print("    -> ", GlobalDependency[2].ljust(20, ' '), end='')
                    if ServiceS[1] == "DHCP Client":
                        print("  is [ DHCP Server ]  -  Number of packets: ", GlobalDependency[5])
                        continue
                    else:
                        print(" need", end='')
                else:               
                    print("    -> ", GlobalDependency[1].ljust(20, ' '), " is", end='')
                if ServiceS[1] == "WEB Server" and SrcIP == DeviceIP:
                    try:               
                        sck = socket.gethostbyaddr(GlobalDependency[2])
                        print(" [", ServiceS[1], "] (Domain:", sck[0] , ") -  Number of packets: ", GlobalDependency[5])            
                    except:
                        print(" [", ServiceS[1], "]  -  Number of packets: ", GlobalDependency[5])                                                    
                elif ServiceS[1] == "WEB Server":
                    try:               
                        sck = socket.gethostbyaddr(GlobalDependency[1])
                        print(" [", ServiceS[1], "] (Domain:", sck[0] , ") -  Number of packets: ", GlobalDependency[5])            
                    except:
                        print(" [", ServiceS[1], "]  -  Number of packets: ", GlobalDependency[5])                                                    
                else:
                    print(" [", ServiceS[1], "]  -  Number of packets: ", GlobalDependency[5])            
            elif ServiceD:
                if SrcIP == DeviceIP:
                    print("    -> ", GlobalDependency[2].ljust(20, ' '), " is", end='')
                else:               
                    print("    -> ", GlobalDependency[1].ljust(20, ' '), " need", end='')
                if ServiceD[1] == "WEB Server" and SrcIP == DeviceIP:
                    try:                    
                        sck = socket.gethostbyaddr(GlobalDependency[2])
                        print(" [", ServiceD[1], "] (Domain:", sck[0] , ") -  Number of packets: ", GlobalDependency[5])
                    except:
                        print(" [", ServiceD[1], "]  -  Number of packets: ", GlobalDependency[5])           
                elif ServiceD[1] == "WEB Server":
                    try:                    
                        sck = socket.gethostbyaddr(GlobalDependency[1])
                        print(" [", ServiceD[1], "] (Domain:", sck[0] , ") -  Number of packets: ", GlobalDependency[5])
                    except:
                        print(" [", ServiceD[1], "]  -  Number of packets: ", GlobalDependency[5])           
                else:
                    print(" [", ServiceD[1], "]  -  Number of packets: ", GlobalDependency[5])                        
            else:
                if SrcIP == DeviceIP:
                    print("    -> ", GlobalDependency[2].ljust(20, ' '), " is", end='')
                    cursor.execute("SELECT * FROM Ports WHERE PortNumber='{portD}'".format(portD=GlobalDependency[4]) )
                    PortD = cursor.fetchone()                    
                    if PortD:
                        print("  -  ", PortD[1], "  -  Number of packets: ", GlobalDependency[5])
                    else:
                        print("  -  ", GlobalDependency[4], "  -  Number of packets: ", GlobalDependency[5])
                else:               
                    print("    -> ", GlobalDependency[1].ljust(20, ' '), " need", end='')
                    cursor.execute("SELECT * FROM Ports WHERE PortNumber='{portS}'".format(portS=GlobalDependency[3]) )
                    PortS = cursor.fetchone()    
                    if PortS:
                        print("  -  ", PortS[1], "  -  Number of packets: ", GlobalDependency[5])
                    else:
                        print("  -  ", GlobalDependency[3], "  -  Number of packets: ", GlobalDependency[5])
            #print("  ", GlobalDependency)
    else:
        print("    ---")
#=======================================================================================================================================
#Analyze single device   
def StatProcent(Statistic):    
    if Statistic == {}:
        return
    tmp = 0    
    for i, j in Statistic.items():
        tmp = tmp + j
    #==========================
    Statistic = {r: Statistic[r] for r in sorted(Statistic, key=Statistic.get, reverse=True)}
    print("  Statistical of Local Dependencies:  (in %)")
    for i, j in Statistic.items():
        Statistic[i] = float(j/tmp*100)
    #    print("    ", i, "     ", Statistic[i], "%")
    plot(Statistic.items())
#=======================================================================================================================================
#IP_print
def IPAddress(IP, cursor):   
    print("  IP: ", IP, end='')
    cursor.execute("SELECT * FROM Routers WHERE IP='{ip}'".format(ip=IP) )
    Router = cursor.fetchone()
    if not Router:
        cursor.execute("SELECT * FROM MAC WHERE IP='{ip}' AND LastUse='{lu}'".format(ip=IP, lu='') )
        IPs = cursor.fetchone()
        for ip in IPS:
            if not ip == IP:
                print(" <", ip, "> ", end='')
        print("")  
    else:
        cursor.execute("SELECT * FROM Routers WHERE MAC='{mac}'".format(mac=Router[1]) )
        Routers = cursor.fetchall()
        for ip in Routers:
            ipd = ipaddress.ip_address(ip[2])        
            if ipd.is_private and ip[2] != IP:
                print(" <", ip[2], "> ", end='')
        print("")
#=======================================================================================================================================
#Analyze single device   
def AnalyzeLocalDevice(DeviceID, IP, TIME, cursor, SQLiteConnection):    
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
    print("######################################################################") 
    print("DeviceID: ", DeviceID)
    #==================================================================
    IPAddress(IP, cursor)
    #==================================================================
    print("  Last communication: ", TIME)    
    DeviceIP = ipaddress.ip_address(IP)
    #==================================================================
    MAC(DeviceID, IP, cursor, SQLiteConnection)
    #==================================================================
    LABELS(DeviceID, IP, cursor, SQLiteConnection)
    #==================================================================
    DHCP(DeviceID, IP, cursor, SQLiteConnection)
    #==================================================================    
    LocalStatistic = {}    
    LOCALDEPENDENCIES(DeviceID, IP, DeviceIP, LocalStatistic, cursor, SQLiteConnection)
    StatProcent(LocalStatistic)
    #==================================================================
    GlobalStatistic = {}    
    GLOBALDEPENDENCIES(DeviceID, IP, DeviceIP, GlobalStatistic, cursor, SQLiteConnection)    
    StatProcent(GlobalStatistic)    
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

