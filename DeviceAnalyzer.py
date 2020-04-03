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
    cursor.execute("SELECT * FROM Dependencies")
    rows = cursor.fetchall()
    if not rows:
        return
    print("######################################################################") 
    print("Graph of local dependencies is safed in file:\tGraph_Local.png")    
    #=================================
    plt.figure("Map of Local Dependencies IPv4", figsize=(20, 10), dpi=80, facecolor='w', edgecolor='k')    
    G = networkx.Graph()        
    for row in rows:
        if row[1] == '255.255.255.255' or row[1] == '0.0.0.0' or row[2] == '255.255.255.255' or row[2] == '0.0.0.0': 
            continue
        ipa = ipaddress.ip_address(row[1])
        if ipa.version == 4:
            G.add_edge(row[1], row[2])
    pos = networkx.spring_layout(G)    
    networkx.draw(G, pos, with_labels=True)
    plt.axis('off')
    plt.savefig("Graph_Local_IPv4.png")    
    plt.show()
    #=================================
    plt.figure("Map of Local Dependencies IPv6", figsize=(20, 10), dpi=80, facecolor='w', edgecolor='k')    
    H = networkx.Graph()        
    for row in rows:
        if row[1] == '255.255.255.255' or row[1] == '0.0.0.0' or row[2] == '255.255.255.255' or row[2] == '0.0.0.0': 
            continue
        ipa = ipaddress.ip_address(row[1])
        if ipa.version == 6:
            H.add_edge(row[1], row[2])
    pos = networkx.spring_layout(H)    
    networkx.draw(H, pos, with_labels=True)
    plt.axis('off')
    plt.savefig("Graph_Local_IPv6.png")    
    plt.show()    
#=======================================================================================================================================
#Create graph of global to local dependencies
def GraphGlobalDependencies(cursor, SQLiteConnection):
    print("######################################################################") 
    cursor.execute("SELECT * FROM LocalDevice")
    LocalDevices = cursor.fetchall()
    for device in LocalDevices:
        cursor.execute("SELECT * FROM Global WHERE IP_origin='{ip}'".format(ip=device[0]))
        GlobalDependencies = cursor.fetchall()
        if not GlobalDependencies:
            return        
        print("Global Dependencies for device %s is safed in file:\t%s.png" % (device[0],device[0]))        
        plt.figure("Map of Global Dependencies for device: %s" % device[0], figsize=(20, 10), dpi=80, facecolor='w', edgecolor='k')
        H = networkx.Graph()
        for GlobalDependency in GlobalDependencies:
            H.add_edge(GlobalDependency[1], GlobalDependency[2])
        pos = networkx.spring_layout(H)    
        networkx.draw(H, pos, with_labels=True)
        plt.axis('off')
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
        createJSON["MAC"] = row[2]
        mac = map(''.join, zip(*[iter(row[2])]*8))
    elif Router:
        mac = map(''.join, zip(*[iter(Router[1])]*8))    
    else:
        None
    if mac != "":
        cursor.execute("SELECT * FROM VendorsMAC WHERE VendorMAC='{m}'".format(m=list(mac)[0].upper()))
        row = cursor.fetchone()
        if row:        
            createJSON["Vendor"] = row[3]
            createJSON["Country"] = row[4]
        else:
            None
#=======================================================================================================================================
#Labels adding   
def LABELS(DeviceID, IP, cursor, SQLiteConnection, createJSON, JSON, GL):
    cursor.execute("SELECT * FROM LocalServices WHERE IP='{ip}'".format(ip=IP) )
    Labels = cursor.fetchall()
    tmp = 0    
    if Labels:
        for Label in Labels:
            #==========TEST THIS====================================================================================================================
            if GL == True:
                cursor.execute("SELECT * FROM Global WHERE (IP_origin='{ip}' AND Port_origin='{port}') OR (IP_target='{ip}' AND Port_target='{port}')".format(port=Label[0], ip=IP) )
                Global = cursor.fetchone()
                cursor.execute("SELECT * FROM Dependencies WHERE (IP_origin='{ip}' AND Port_origin='{port}') OR (IP_target='{ip}' AND Port_target='{port}') ".format(port=Label[0], ip=IP) )
                Local = cursor.fetchone()
                if not Global and not Local:
                    continue            
            #==============================================================================================================================
            tmp = 1        
            cursor.execute("SELECT * FROM Services WHERE PortNumber='{port}'".format(port=Label[0]) )
            Service = cursor.fetchone()
            if Label[1] == "Router" and not IP in JSON["Routers"]:
                JSON["Routers"].append(IP)
            if not Service[1] in JSON["Services"]:
                JSON["Services"].append(Service[1])
            #if Service[1] == "DHCP Client":
            #    createJSON["Labels"].append({"Label": "End Device", "Description": "PC, Mobile Phone,... (everything that can take IP address from DHCP)"})
            createJSON["Labels"].append({"Label": "%s" % Service[1], "Description": "%s" % Service[3]})
    cursor.execute("SELECT * FROM Global G JOIN GlobalServices GS ON G.IP_target=GS.IP JOIN Services S ON S.PortNumber=GS.PortNumber WHERE G.IP_origin='{ipo}' AND S.DeviceType='{t}'".format(ipo=IP, t="WEB Server") )
    WebServer = cursor.fetchone()
    if WebServer:
        tmp = 1
        if not "End Device" in JSON["Services"]:
            JSON["Services"].append("End Device")
        createJSON["Labels"].append({"Label": "End Device", "Description": "PC, Mobile Phone,... (everything that can access web services)"})
    cursor.execute("SELECT * FROM Global G JOIN GlobalServices GS ON G.IP_target=GS.IP JOIN Services S ON S.PortNumber=GS.PortNumber WHERE G.IP_origin='{ipo}' AND S.DeviceType='{t}'".format(ipo=IP, t="Mail Server") )
    MailServer = cursor.fetchone()
    if MailServer:
        tmp = 1
        if not "End Device" in JSON["Services"]:
            JSON["Services"].append("End Device")
        createJSON["Labels"].append({"Label": "End Device", "Description": "PC, Mobile Phone,... (everything that can send emails)"})
    cursor.execute("SELECT * FROM Routers WHERE IP='{ip}'".format(ip=IP) )
    Router = cursor.fetchone()
    if Router:
        tmp = 1
        if not "Router" in JSON["Services"]:
            JSON["Services"].append("Router")
        createJSON["Labels"].append({"Label": "Router", "Description": "Routing network device"})
        if not IP in JSON["Routers"]:
            JSON["Routers"].append(IP)
    if tmp == 0:
        if not "Unknown" in JSON["Services"]:
            JSON["Services"].append("Unknown")
        createJSON["Labels"].append({"Label": "Unknows", "Description": ""})
#=======================================================================================================================================
#DHCP records adding   
def DHCP(DeviceID, IP, cursor, SQLiteConnection, createJSON):
    cursor.execute("SELECT * FROM DHCP WHERE DeviceIP='{ip}' ORDER BY Time DESC".format(ip=IP) )
    DHCPs = cursor.fetchall()    
    if DHCPs:
        for DHCP in DHCPs:
            createJSON["DHCP"].append({"DHCPServ": "%s" % DHCP[2], "DHCPTime": "%s" % time.ctime(float(DHCP[3]))})
#====================================================================================================================================== 
#Stats
def Stats(LocalStatistic, Dependency, cursor, SQLiteConnection):
    cursor.execute("SELECT * FROM Services WHERE PortNumber={po}".format(po=Dependency[3]) )
    servicestat = cursor.fetchone()    
    if servicestat:
        st = servicestat[2].replace(" ", "_")
        if st in LocalStatistic:
            LocalStatistic[st] = LocalStatistic[st] + Dependency[5]
        else:
            LocalStatistic[st] = Dependency[5]
    #==========================================
    cursor.execute("SELECT * FROM Services WHERE PortNumber={pt}".format(pt=Dependency[4]) )
    servicestat = cursor.fetchone()    
    if servicestat:
        st = servicestat[2].replace(" ", "_")
        if st in LocalStatistic:
            LocalStatistic[st] = LocalStatistic[st] + Dependency[5]
        else:
            LocalStatistic[st] = Dependency[5]        
#=======================================================================================================================================
#LocalDependencies records adding  
def LOCALDEPENDENCIES(DeviceID, IP, DeviceIP, LocalStatistic, IPStatistic, cursor, SQLiteConnection, createJSON):
    cursor.execute("SELECT * FROM Dependencies WHERE IP_origin='{ipo}' OR IP_target='{ipt}' ORDER BY NumBytes DESC".format(ipo=IP, ipt=IP) )
    Dependencies = cursor.fetchall()    
    if Dependencies:    
        for Dependency in Dependencies:
            Stats(LocalStatistic, Dependency, cursor, SQLiteConnection)
            #==========================================
            if Dependency[1] == IP:            
                if Dependency[1] in IPStatistic:
                    IPStatistic[Dependency[1]] = IPStatistic[Dependency[1]] + Dependency[5]
                else:
                    IPStatistic[Dependency[1]] = Dependency[5]            
            if Dependency[2] == IP:           
                if Dependency[2] in IPStatistic:
                    IPStatistic[Dependency[2]] = IPStatistic[Dependency[2]] + Dependency[5]
                else:
                    IPStatistic[Dependency[2]] = Dependency[5]            
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
            createJSON["LocalDependencies"].append({"IP": "%s" % IPs, "Verb": "%s" % Verbs, "Service": "%s" % Services, "Packets": "%s" % Packets})
#=======================================================================================================================================
#GlobalDependencies records adding  
def GLOBALDEPENDENCIES(DeviceID, IP, DeviceIP, GlobalStatistic, IPStatistic, cursor, SQLiteConnection, createJSON):
    cursor.execute("SELECT * FROM Global WHERE IP_origin='{ipo}' OR IP_target='{ipt}' ORDER BY NumPackets DESC".format(ipo=IP, ipt=IP) )
    GlobalDependencies = cursor.fetchall()
    if GlobalDependencies:
        promtp = 0    
        for GlobalDependency in GlobalDependencies:
            Stats(GlobalStatistic, GlobalDependency, cursor, SQLiteConnection)
            #==========================================
            SrcIP = ipaddress.ip_address(GlobalDependency[1])
            #==========================================
            if GlobalDependency[1] == IP:            
                if GlobalDependency[1] in IPStatistic:
                    IPStatistic[GlobalDependency[1]] = IPStatistic[GlobalDependency[1]] + GlobalDependency[5]
                else:
                    IPStatistic[GlobalDependency[1]] = GlobalDependency[5]            
            else:
                if GlobalDependency[2] in IPStatistic:
                    IPStatistic[GlobalDependency[2]] = IPStatistic[GlobalDependency[2]] + GlobalDependency[5]
                else:
                    IPStatistic[GlobalDependency[2]] = GlobalDependency[5]                            
            #==========================================
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
                if promtp < 15:
                    Services = ServiceS[1]            
                    if ServiceS[1] == "WEB Server" and SrcIP == DeviceIP:
                        try:               
                            sck = socket.gethostbyaddr(GlobalDependency[2])
                            Domain = "(Domain:" + sck[0] + ")"
                        except:
                            None
                    elif ServiceS[1] == "WEB Server":
                        try:               
                            sck = socket.gethostbyaddr(GlobalDependency[1])
                            Domain = "(Domain:" + sck[0] + ")"
                        except:
                            None
                    else:
                        None
                else:
                    Services = ServiceS[1]
            elif ServiceD:
                if SrcIP == DeviceIP:
                    IPs = GlobalDependency[2]
                else:               
                    IPs = GlobalDependency[1]
                    Verbs = "requires"
                if promtp < 15:
                    Services = ServiceD[1]
                    if ServiceD[1] == "WEB Server" and SrcIP == DeviceIP:
                        try:                    
                            sck = socket.gethostbyaddr(GlobalDependency[2])
                            Domain = "(Domain:" + sck[0] + ")"
                        except:
                            None           
                    elif ServiceD[1] == "WEB Server":
                        try:                    
                            sck = socket.gethostbyaddr(GlobalDependency[1])
                            Domain = "(Domain:" + sck[0] + ")"
                        except:
                            None           
                    else:
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
            createJSON["GlobalDependencies"].append({"IP": "%s" % IPs, "Verb": "%s" % Verbs, "Service": "%s" % Services, "Packets": "%s" % Packets})
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
    for i, j in Statistic.items():
        Statistic[i] = float(j/tmp*100)
        if TMP == 0:
            createJSON["LocalStatistic"].append({"Service": "%s" % i, "Procents": "%s" % Statistic[i]})
        elif TMP == 1:
            createJSON["GlobalStatistic"].append({"Service": "%s" % i, "Procents": "%s" % Statistic[i]})
        else:
            createJSON["IPStatistic"].append({"IP": "%s" % i, "Procents": "%s" % Statistic[i]})
    if TMP == 2:
        plot(Statistic.items())
#=======================================================================================================================================
#IP_print
def IPAddress(IP, cursor, createJSON):   
    createJSON["IP"].append(IP)
    cursor.execute("SELECT * FROM Routers WHERE IP='{ip}'".format(ip=IP) )
    Router = cursor.fetchone()
    if not Router:
        cursor.execute("SELECT * FROM MAC WHERE IP='{ip}' AND LastUse='{lu}'".format(ip=IP, lu='') )
        IPs = cursor.fetchall()
        for ip in IPs:
            if not ip[1] == IP:
                createJSON["IP"].append(ip[1])
    else:
        cursor.execute("SELECT * FROM Routers WHERE MAC='{mac}'".format(mac=Router[1]) )
        Routers = cursor.fetchall()
        for ip in Routers:
            ipd = ipaddress.ip_address(ip[2])        
            if ipd.is_private and ip[2] != IP:
                createJSON["IP"].append(ip[2])
#=======================================================================================================================================
#PrintDevice from JSON files   
def PrintDeviceFromJSON(JSON):
    if not JSON["LocalDependencies"] and not JSON["GlobalDependencies"]:
        return
    print("######################################################################") 
    print("Device ID: ", JSON["DeviceID"])
    #=================================================================================    
    print("  IP: ", end='')
    tmp = 0
    for i in JSON["IP"]:
        if tmp == 0:
            print(i, end='')
            tmp = 1
        else:
            print(" <", i, ">", end='')
    print("")
    #=================================================================================    
    print("  Last communication: ", time.ctime(float(JSON["LastCom"])) )
    #=================================================================================    
    print("  MAC: ", end='')
    if JSON["MAC"] == "":
        print("---")
    else:
        print(JSON["MAC"], end='')
        if JSON["Vendor"] == "":
            print(", ", JSON["Vendor"], ", ", JSON["Country"])
    #=================================================================================    
    print("  Labels:")
    if not JSON["Labels"]:
        print("    ---")
    for i in JSON["Labels"]:
        print("    [", i["Label"], "] - ", i["Description"])  
    #=================================================================================    
    print("  DHCP:")
    if not JSON["DHCP"]:
        print("    ---")
    for i in JSON["DHCP"]:
        print("    ", i["DHCPServ"], " in ", i["DHCPTime"])
    #=================================================================================    
    print("  Local Dependencies:")
    if not JSON["LocalDependencies"]:
        print("    ---")
    for i in JSON["LocalDependencies"]:
        print("    -> ", i["IP"], " ", i["Verb"], " [", i["Service"], "] - number of packets: ", i["Packets"])    
    #=================================================================================    
    if not JSON["LocalStatistic"]:
        print("")    
    else:    
        IPStatistic = {} 
        for i in JSON["LocalStatistic"]:
            IPStatistic[i["Service"]] = i["Procents"]
        plot(IPStatistic.items())    
    #=================================================================================    
    print("  Global Dependencies:")
    if not JSON["GlobalDependencies"]:
        print("    ---")
    tmp = 0
    for i in JSON["GlobalDependencies"]:
        if tmp < 16:        
            print("    -> ", i["IP"], " ", i["Verb"], " [", i["Service"], "] - number of packets: ", i["Packets"])    
            tmp = tmp + 1
        else:
            break
    #=================================================================================    
    if not JSON["GlobalStatistic"]:
        print("")    
    else:   
        IPStatistic = {} 
        for i in JSON["GlobalStatistic"]:
            IPStatistic[i["Service"]] = i["Procents"]
        plot(IPStatistic.items())
#=======================================================================================================================================
#Analyze single device   
def AnalyzeLocalDevice(DeviceID, IP, TIME, cursor, SQLiteConnection, JSON, IPStatistic, GL):    
    #==================================================================
    createJSON = {  "DeviceID":0,
                    "LastCom": 0,
                    "IP": [], 
                    "MAC": "", 
                    "Vendor": "",
                    "Country": "", 
                    "Labels": [],
                    "DHCP": [], 
                    "LocalDependencies": [],                    
                    "LocalStatistic": [], 
                    "GlobalDependencies": [],                    
                    "GlobalStatistic": [], 
                  }
    #==================================================================
    createJSON["DeviceID"] = DeviceID
    #==================================================================
    IPAddress(IP, cursor, createJSON)
    #==================================================================
    createJSON["LastCom"] = float(TIME)
    DeviceIP = ipaddress.ip_address(IP)
    #==================================================================
    MAC(DeviceID, IP, cursor, SQLiteConnection, createJSON)
    #==================================================================
    LABELS(DeviceID, IP, cursor, SQLiteConnection, createJSON, JSON, GL)
    #==================================================================
    DHCP(DeviceID, IP, cursor, SQLiteConnection, createJSON)
    #==================================================================    
    LocalStatistic = {}    
    LOCALDEPENDENCIES(DeviceID, IP, DeviceIP, LocalStatistic, IPStatistic, cursor, SQLiteConnection, createJSON)
    StatProcent(LocalStatistic, createJSON, 0)
    #==================================================================
    GlobalStatistic = {}    
    GLOBALDEPENDENCIES(DeviceID, IP, DeviceIP, GlobalStatistic, IPStatistic, cursor, SQLiteConnection, createJSON)    
    StatProcent(GlobalStatistic, createJSON, 1)    
    #==================================================================
    PrintDeviceFromJSON(createJSON)
    #==================================================================
    JSON["Devices"].append(createJSON)
#=======================================================================================================================================
#Main function of Analyzer
def DoAnalyze(SQLiteConnection, GraphLocal, GraphGlobal):
    #==================================================================
    JSON = {   "Name": "DeppendencyMapping", 
                    "DateAnalyze": "", 
                    "NumberDevice": 0,
                    "Routers": [],                    
                    "Services": [],                    
                    "IPStatistic": [],
                    "Devices": []
                }    
    write_json(JSON, "PassiveAutodiscovery")
    read_json(JSON, "PassiveAutodiscovery")
    #==================================================================
    IPStatistic = {}    
    cursor = SQLiteConnection.cursor()
    DeviceID = 1
    #==================================================================
    GL = True        
    cursor.execute("SELECT COUNT(*) FROM Global")
    GlobalC = cursor.fetchone()
    if GlobalC[0] == 0:
        GL = False
    #==================================================================    
    cursor.execute("SELECT * FROM LocalDevice")
    LocalDevices = cursor.fetchall()
    for LocalDevice in LocalDevices:
        AnalyzeLocalDevice(DeviceID, LocalDevice[0], LocalDevice[1], cursor, SQLiteConnection, JSON, IPStatistic, GL)
        DeviceID = DeviceID + 1
    #==================================================================
    if GraphLocal == True:    
        GraphLocalDependencies(cursor, SQLiteConnection)
    if GraphGlobal == True:
        GraphGlobalDependencies(cursor, SQLiteConnection)
    #==================================================================
    StatProcent(IPStatistic, JSON, 2)    
    #==================================================================
    x = datetime.datetime.now()
    JSON["DateAnalyze"] = str(x)
    JSON["NumberDevice"] = DeviceID - 1
    write_json(JSON, "PassiveAutodiscovery")    
#=======================================================================================================================================
#=======================================================================================================================================
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
print("Print Graph of local dependencies? [yes]: ")    
tmp = input()
if tmp == "yes" or tmp == "YES" or tmp == "Yes":
    GraphLocal = True
else:
    GraphLocal = False
#=====================================================
print("Print Graph of global dependencies? [yes]: ")    
tmp = input()
if tmp == "yes" or tmp == "YES" or tmp == "Yes":
    GraphGlobal = True
else:
    GraphGlobal = False
#=====================================================
DoAnalyze(SQLiteConnection, GraphLocal, GraphGlobal)
#=====================================================
# Close database connection
if(SQLiteConnection):
    SQLiteConnection.close()
