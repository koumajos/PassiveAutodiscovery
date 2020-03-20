#!/usr/bin/python3.6
import sys
import os
import ipaddress
import sqlite3
import time
import json
import math
import socket
import datetime
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
#Open json file
def read_json(data, filename):
    with open("%s.json" % filename, "r") as jsonFile:
        data = json.load(jsonFile)
#=======================================================================================================================================
#Write json to json file
def write_json(data, filename): 
    with open("%s.json" % filename,'w') as f: 
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
    networkx.draw(G, with_labels=True)
    plt.savefig("Graph_Local.png")
    plt.show()    
#=======================================================================================================================================
#Create graph of global to local dependencies
def GraphGlobalDependencies(cursor, SQLiteConnection):
    cursor.execute("SELECT * FROM LocalDevice")
    LocalDevices = cursor.fetchall()
    for device in LocalDevices:
        cursor.execute("SELECT * FROM Global WHERE IP_origin='{ip}'".format(ip=device[0]))
        GlobalDependencies = cursor.fetchall()
        if not GlobalDependencies:
            return        
        print("Global Dependencies for device %s" % device[0])        
        plt.figure("Map of Global Dependencies for device: %s" % device[0], figsize=(20, 10), dpi=80, facecolor='w', edgecolor='k')
        H = networkx.Graph()
        for GlobalDependency in GlobalDependencies:
            if not H.has_node(GlobalDependency[1]):
                H.add_node(GlobalDependency[1])
            if not H.has_node(GlobalDependency[2]):        
                H.add_node(GlobalDependency[2])
            if not H.has_edge(GlobalDependency[1], GlobalDependency[2]):        
                H.add_weighted_edges_from([(GlobalDependency[1], GlobalDependency[2], GlobalDependency[4])])
        pos = networkx.spring_layout(H,k=5/math.sqrt(H.order()),iterations=20)
        networkx.draw(H, with_labels=True)
        plt.savefig("Graph_Global_%s.png" % device[0])
        plt.show()
#=======================================================================================================================================
#MAC address and vendor adding
def MAC(DeviceID, IP, cursor, SQLiteConnection, createJSON):
    cursor.execute("SELECT * FROM MAC WHERE IP='{ip}' AND LastUse='{lu}'".format(ip=IP, lu=""))
    row = cursor.fetchone()
    cursor.execute("SELECT * FROM Routers WHERE IP='{ip}'".format(ip=IP) )
    Router = cursor.fetchone()
    mac = ""    
    if row:
        print("  MAC: ", row[2], end="")
        createJSON["MAC"] = row[2]
        mac = map(''.join, zip(*[iter(row[2])]*8))
    elif Router:
        print("  MAC: ", Router[1], end="")
        mac = map(''.join, zip(*[iter(Router[1])]*8))    
    else:
        print("  MAC: ---")
    if mac != "":
        cursor.execute("SELECT * FROM VendorsMAC WHERE VendorMAC='{m}'".format(m=list(mac)[0].upper()))
        row = cursor.fetchone()
        createJSON["Vendor"] = row[3]
        createJSON["Country"] = row[4]
        print(" | Vendor: ", row[3], ",", row[4])
#=======================================================================================================================================
#Labels adding   
def LABELS(DeviceID, IP, cursor, SQLiteConnection, createJSON):
    print("  Labels:")
    cursor.execute("SELECT * FROM LocalServices WHERE IP='{ip}'".format(ip=IP) )
    Labels = cursor.fetchall()
    tmp = 0    
    if Labels:
        tmp = 1        
        for Label in Labels:
            cursor.execute("SELECT * FROM Services WHERE PortNumber='{port}'".format(port=Label[0]) )
            Service = cursor.fetchone()
            createJSON["Labels"].append(Service[1])
            createJSON["LabelsDescription"].append(Service[3])
            print("   [", Service[1], "]  - ", Service[3])
    cursor.execute("SELECT * FROM Global G JOIN GlobalServices GS ON G.IP_target=GS.IP JOIN Services S ON S.PortNumber=GS.PortNumber WHERE G.IP_origin='{ipo}' AND S.DeviceType='{t}'".format(ipo=IP, t="WEB SERVER") )
    WebServer = cursor.fetchone()
    if WebServer:
        tmp = 1
        createJSON["Labels"].append("End Device")
        createJSON["LabelsDescription"].append("PC, Mobile Phone, Server, ... (everything with web browser)")
        print("   [ End Device ]  - PC, Mobile Phone, Server, ... (everything with web browser)")
    cursor.execute("SELECT * FROM Routers WHERE IP='{ip}'".format(ip=IP) )
    Router = cursor.fetchone()
    if Router:
        tmp = 1
        createJSON["Labels"].append("Router")
        createJSON["LabelsDescription"].append("Routing network device")
        print("   [ Router ]  - Routing network device")    
    if tmp == 0:
        print("    ---")    
#=======================================================================================================================================
#DHCP records adding   
def DHCP(DeviceID, IP, cursor, SQLiteConnection, createJSON):
    print("  DHCP:")
    cursor.execute("SELECT * FROM DHCP WHERE DeviceIP='{ip}' ORDER BY Time DESC".format(ip=IP) )
    DHCPs = cursor.fetchall()    
    if DHCPs:
        for DHCP in DHCPs:
            createJSON["DHCPServ"].append(DHCP[2])
            createJSON["DHCPTime"].append(time.ctime(float(DHCP[3])))
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
def LOCALDEPENDENCIES(DeviceID, IP, DeviceIP, LocalStatistic, cursor, SQLiteConnection, createJSON):
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
            #==========================================
            IPs = ""
            Verbs = "provides"
            Services = ""            
            Packets = Dependency[5]            
            #==========================================
            if ServiceS:
                if SrcIP == DeviceIP:
                    IPs = Dependency[2]                    
                    if ServiceS[1] == "DHCP Client":
                        Services = "DHCP Server"
                    else:
                        Verbs = "requires"
                        Services = ServiceS[1]
                else:               
                    IPs = Dependency[1]                    
                    Services = ServiceS[1]
            elif ServiceD:
                if SrcIP == DeviceIP:
                    IPs = Dependency[2]                    
                else:               
                    IPs = Dependency[1]                    
                    Verbs = "requires"
                Services = ServiceD[1]
            else:
                if SrcIP == DeviceIP:
                    IPs = Dependency[2]                    
                    cursor.execute("SELECT * FROM Ports WHERE PortNumber='{portD}'".format(portD=Dependency[4]) )
                    PortD = cursor.fetchone()                    
                    if PortD:
                        if not PortD[1] == '': 
                            Services = PortD[1]
                        else:
                            Services = PortD[2]
                    else:
                        Services = Dependency[4]
                else:               
                    IPs = Dependency[1]                    
                    Verbs = "requires"
                    cursor.execute("SELECT * FROM Ports WHERE PortNumber='{portS}'".format(portS=Dependency[3]) )
                    PortS = cursor.fetchone()
                    if PortS:
                        if not PortS[1] == '': 
                            Services = PortS[1]
                        else:
                            Services = PortS[2]
                    else:
                        Services = Dependency[3]
            #========================================================
            print("    -> ", IPs.ljust(20, ' '), " ", Verbs, "  -  [", Services, "]  -  Number of packets: ", Packets)            
            #========================================================
            createJSON["LocalDependencies"].append({"IP": "%s" % IPs, "Verb": "%s" % Verbs, "Service": "%s" % Services, "Packets": "%s" % Packets})
    else:
        print("    ---")    
#=======================================================================================================================================
#GlobalDependencies records adding  
def GLOBALDEPENDENCIES(DeviceID, IP, DeviceIP, GlobalStatistic, cursor, SQLiteConnection, createJSON):
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
            #========================================================
            IPs = ""
            Verbs = "provides"
            Services = ""            
            Packets = GlobalDependency[5]
            Domain = ""            
            #========================================================
            if ServiceS:
                if SrcIP == DeviceIP:
                    IPs = GlobalDependency[2]                    
                    if ServiceS[1] == "DHCP Client":
                        Services = "DHCP Server"            
                    else:
                        Verbs = "requires"
                else:               
                    IPs = GlobalDependency[1]
                if ServiceS[1] == "WEB Server" and SrcIP == DeviceIP:
                    Services = ServiceS[1]            
                    try:               
                        sck = socket.gethostbyaddr(GlobalDependency[2])
                        Domain = "(Domain:" + sck[0] + ")"
                    except:
                        None
                elif ServiceS[1] == "WEB Server":
                    Services = ServiceS[1]            
                    try:               
                        sck = socket.gethostbyaddr(GlobalDependency[1])
                        Domain = "(Domain:" + sck[0] + ")"
                    except:
                        None
                else:
                    Services = ServiceS[1]            
            elif ServiceD:
                if SrcIP == DeviceIP:
                    IPs = GlobalDependency[2]
                else:               
                    IPs = GlobalDependency[1]
                    Verbs = "requires"
                if ServiceD[1] == "WEB Server" and SrcIP == DeviceIP:
                    Services = ServiceD[1]            
                    try:                    
                        sck = socket.gethostbyaddr(GlobalDependency[2])
                        Domain = "(Domain:" + sck[0] + ")"
                    except:
                        None           
                elif ServiceD[1] == "WEB Server":
                    Services = ServiceD[1]            
                    try:                    
                        sck = socket.gethostbyaddr(GlobalDependency[1])
                        Domain = "(Domain:" + sck[0] + ")"
                    except:
                        None           
                else:
                    Services = ServiceD[1]
            else:
                if SrcIP == DeviceIP:
                    IPs = GlobalDependency[2]       
                    cursor.execute("SELECT * FROM Ports WHERE PortNumber='{portD}'".format(portD=GlobalDependency[4]) )
                    PortD = cursor.fetchone()                    
                    if PortD:
                        Services = PortD[1]                       
                    else:
                        Services = GlobalDependency[4]
                else:               
                    IPs = GlobalDependency[1]       
                    Verbs = "requires"
                    cursor.execute("SELECT * FROM Ports WHERE PortNumber='{portS}'".format(portS=GlobalDependency[3]) )
                    PortS = cursor.fetchone()    
                    if PortS:
                        Services = PortS[1]
                    else:
                        Services = GlobalDependency[3]
            #========================================================
            print("    -> ", IPs.ljust(20, ' '), " ", Verbs, "  -  [", Services, "] ", Domain," -  Number of packets: ", Packets)            
            #========================================================
            createJSON["GlobalDependencies"].append({"IP": "%s" % IPs, "Verb": "%s" % Verbs, "Service": "%s" % Services, "Packets": "%s" % Packets})
    else:
        print("    ---")
#=======================================================================================================================================
#Analyze single device   
def StatProcent(Statistic, createJSON, TMP):    
    if Statistic == {}:
        return
    tmp = 0    
    for i, j in Statistic.items():
        tmp = tmp + j
    #==========================
    Statistic = {r: Statistic[r] for r in sorted(Statistic, key=Statistic.get, reverse=True)}
    if TMP == True:    
        print("  Statistical of Local Dependencies:  (in %)")
    else:
        print("  Statistical of Global Dependencies:  (in %)")        
    for i, j in Statistic.items():
        Statistic[i] = float(j/tmp*100)
        if TMP == True:
            createJSON["LocalStatistic"].append({"Service": "%s" % i, "Procents": "%s" % Statistic[i]})
        else:
            createJSON["GlobalStatistic"].append({"Service": "%s" % i, "Procents": "%s" % Statistic[i]})
    #    print("    ", i, "     ", Statistic[i], "%")
    plot(Statistic.items())
#=======================================================================================================================================
#IP_print
def IPAddress(IP, cursor, createJSON):   
    print("  IP: ", IP, end='')
    createJSON["IP"].append(IP)
    cursor.execute("SELECT * FROM Routers WHERE IP='{ip}'".format(ip=IP) )
    Router = cursor.fetchone()
    if not Router:
        cursor.execute("SELECT * FROM MAC WHERE IP='{ip}' AND LastUse='{lu}'".format(ip=IP, lu='') )
        IPs = cursor.fetchone()
        for ip in IPS:
            if not ip[2] == IP:
                print(" <", ip[2], "> ", end='')
                createJSON["IP"].append(ip[2])
        print("")  
    else:
        cursor.execute("SELECT * FROM Routers WHERE MAC='{mac}'".format(mac=Router[1]) )
        Routers = cursor.fetchall()
        for ip in Routers:
            ipd = ipaddress.ip_address(ip[2])        
            if ipd.is_private and ip[2] != IP:
                print(" <", ip[2], "> ", end='')
                createJSON["IP"].append(ip[2])
        print("")
#=======================================================================================================================================
#Analyze single device   
def AnalyzeLocalDevice(DeviceID, IP, TIME, cursor, SQLiteConnection, JSON):    
    #==================================================================
    createJSON = {  "DeviceID":0,
                    "IP": [], 
                    "MAC": "", 
                    "Vendor": "",
                    "Country": "", 
                    "Labels": [],
                    "LabelsDescription": [], 
                    "DHCPServ": [], 
                    "DHCPTime": [], 
                    "LocalDependencies": [],                    
                    "LocalStatistic": [], 
                    "GlobalDependencies": [],                    
                    "GlobalStatistic": [], 
                  }
    #==================================================================
    print("######################################################################") 
    print("DeviceID: ", DeviceID)
    createJSON["DeviceID"] = DeviceID
    #==================================================================
    IPAddress(IP, cursor, createJSON)
    #==================================================================
    print("  Last communication: ", TIME)    
    DeviceIP = ipaddress.ip_address(IP)
    #==================================================================
    MAC(DeviceID, IP, cursor, SQLiteConnection, createJSON)
    #==================================================================
    LABELS(DeviceID, IP, cursor, SQLiteConnection, createJSON)
    #==================================================================
    DHCP(DeviceID, IP, cursor, SQLiteConnection, createJSON)
    #==================================================================    
    LocalStatistic = {}    
    LOCALDEPENDENCIES(DeviceID, IP, DeviceIP, LocalStatistic, cursor, SQLiteConnection, createJSON)
    StatProcent(LocalStatistic, createJSON, True)
    #==================================================================
    GlobalStatistic = {}    
    GLOBALDEPENDENCIES(DeviceID, IP, DeviceIP, GlobalStatistic, cursor, SQLiteConnection, createJSON)    
    StatProcent(GlobalStatistic, createJSON, False)    
    #==================================================================
    JSON["Devices"].append(createJSON)
#=======================================================================================================================================
#Main function of Analyzer
def DoAnalyze(SQLiteConnection):
    #==================================================================
    JSON = {   "Name": "DeppendencyMapping", 
                    "DateAnalyze": "", 
                    "NumberDevice": 0,
                    "Devices": []
                }    
    write_json(JSON, "DependencyMapping")
    read_json(JSON, "DependencyMapping")
    #==================================================================
    cursor = SQLiteConnection.cursor()
    DeviceID = 1
    #==================================================================
    cursor.execute("SELECT * FROM LocalDevice")
    LocalDevices = cursor.fetchall()
    for LocalDevice in LocalDevices:
        AnalyzeLocalDevice(DeviceID, LocalDevice[0], LocalDevice[1], cursor, SQLiteConnection, JSON)
        DeviceID = DeviceID + 1
    #==================================================================
    x = datetime.datetime.now()
    JSON["DateAnalyze"] = str(x)
    JSON["NumberDevice"] = DeviceID - 1
    write_json(JSON, "DependencyMapping")
    #==================================================================
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

