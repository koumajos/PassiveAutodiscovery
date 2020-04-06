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
#=======================
import argparse
from argparse import RawTextHelpFormatter
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
#    plt.show()
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
#    plt.show()    
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
#        plt.show()
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
    cursor.execute("SELECT S.PortNumber, S.DeviceType, S.Shortcut, S.Description FROM LocalServices LS JOIN Services S ON LS.PortNumber=S.PortNumber WHERE LS.IP='{ip}'".format(ip=IP) )
    Labels = cursor.fetchall()
    tmp = 0    
    if Labels:
        for Service in Labels:
            #==========TEST THIS====================================================================================================================
            if GL == True:
                cursor.execute("SELECT * FROM Global WHERE (IP_origin='{ip}' AND Port_origin='{port}') OR (IP_target='{ip}' AND Port_target='{port}')".format(port=Service[0], ip=IP) )
                Global = cursor.fetchone()
                cursor.execute("SELECT * FROM Dependencies WHERE (IP_origin='{ip}' AND Port_origin='{port}') OR (IP_target='{ip}' AND Port_target='{port}') ".format(port=Service[0], ip=IP) )
                Local = cursor.fetchone()
                if not Global and not Local:
                    continue            
            #==============================================================================================================================
            tmp = 1        
            if Service[1] == "Router" and not IP in JSON["Routers"]:
                JSON["Routers"].append(IP)
            if not Service[1] in JSON["Services"]:
                JSON["Services"].append(Service[1])
            #if Service[1] == "DHCP Client":
            #    createJSON["Labels"].append({"Label": "End Device", "Description": "PC, Mobile Phone,... (everything that can take IP address from DHCP)"})
            createJSON["Labels"].append({"Label": "%s" % Service[1], "Description": "%s" % Service[3]})
    #============================================================================================================================================================
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
    if not JSON["LocalDependencies"] and not JSON["GlobalDependencies"] and not JSON["Labels"]:
        return    
    print("######################################################################") 
    print("Device ID: ", JSON["DeviceID"])
    #=================================================================================    
    print("  IP: ", end='')
    tmp = 0
    for i in JSON["IP"]:
        if tmp == 0:
            print(i, end='')
            tmp = i
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
        if arguments.DNS == True and i["Label"] == "WEB Server":
            try:
                domain = socket.gethostbyaddr(i)
                print("    [", i["Label"], "] - DomainName:", domain)  
            except:
                print("    [", i["Label"], "] - ", i["Description"])  
        else:
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
    if arguments.GlobalNumber == -1:
        for i in JSON["GlobalDependencies"]:
            if arguments.DNS == True and i["Service"] == "WEB Server":
                try:
                    domain = socket.gethostbyaddr(i["IP"])
                    print("    -> ", i["IP"], " ", i["Verb"], " [", i["Service"], "]  Domain: ", domain[0],"  - number of packets: ", i["Packets"] )    
                except:
                    print("    -> ", i["IP"], " ", i["Verb"], " [", i["Service"], "] - number of packets: ", i["Packets"] )    
            else:
                print("    -> ", i["IP"], " ", i["Verb"], " [", i["Service"], "] - number of packets: ", i["Packets"] )    
    else:
        tmp = 0
        for i in JSON["GlobalDependencies"]:
            if tmp < arguments.GlobalNumber:        
                if arguments.DNS == True and i["Service"] == "WEB Server":
                    try:
                        domain = socket.gethostbyaddr(i["IP"])
                        print("    -> ", i["IP"], " ", i["Verb"], " [", i["Service"], "]  Domain: ", domain[0],"  - number of packets: ", i["Packets"] )    
                    except:
                        print("    -> ", i["IP"], " ", i["Verb"], " [", i["Service"], "] - number of packets: ", i["Packets"] )    
                else:
                    print("    -> ", i["IP"], " ", i["Verb"], " [", i["Service"], "] - number of packets: ", i["Packets"] )    
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
#PrintDevice from JSON files   
def PrintDeviceToFileFromJSON(JSON, arguments):
    if not JSON["LocalDependencies"] and not JSON["GlobalDependencies"]:
        return    
    sample = open("%s.txt" % arguments.file, 'w') 
    print("######################################################################", file = sample) 
    print("Device ID: ", JSON["DeviceID"], file = sample)
    #=================================================================================    
    print("  IP: ", end='', file = sample)
    tmp = 0
    for i in JSON["IP"]:
        if tmp == 0:
            print(i, end='', file = sample)
            tmp = i
        else:
            print(" <", i, ">", end='', file = sample)
    print("", file = sample)
    #=================================================================================    
    print("  Last communication: ", time.ctime(float(JSON["LastCom"])), file = sample )
    #=================================================================================    
    print("  MAC: ", end='', file = sample)
    if JSON["MAC"] == "":
        print("---", file = sample)
    else:
        print(JSON["MAC"], end='', file = sample)
        if JSON["Vendor"] == "":
            print(", ", JSON["Vendor"], ", ", JSON["Country"], file = sample)
    #=================================================================================    
    print("  Labels:", file = sample)
    if not JSON["Labels"]:
        print("    ---", file = sample)
    for i in JSON["Labels"]:
        if arguments.DNS == True and i["Label"] == "WEB Server":
            try:
                domain = socket.gethostbyaddr(i)
                print("    [", i["Label"], "] - DomainName:", domain, file = sample)  
            except:
                print("    [", i["Label"], "] - ", i["Description"], file = sample)  
        else:
            print("    [", i["Label"], "] - ", i["Description"], file = sample)  
    #=================================================================================    
    print("  DHCP:", file = sample)
    if not JSON["DHCP"]:
        print("    ---", file = sample)
    for i in JSON["DHCP"]:
        print("    ", i["DHCPServ"], " in ", i["DHCPTime"], file = sample)
    #=================================================================================    
    print("  Local Dependencies:", file = sample)
    if not JSON["LocalDependencies"]:
        print("    ---", file = sample)
    for i in JSON["LocalDependencies"]:
        print("    -> ", i["IP"], " ", i["Verb"], " [", i["Service"], "] - number of packets: ", i["Packets"], file = sample)    
    #=================================================================================    
    if not JSON["LocalStatistic"]:
        print("", file = sample)    
    else:    
        IPStatistic = {} 
        for i in JSON["LocalStatistic"]:
            IPStatistic[i["Service"]] = i["Procents"]
        print("  Print Local Statistic:", file = sample)
        for i, j in IPStatistic.items():
            print("    ", i, "\t\t\t", j, "%", file = sample)    
    #=================================================================================    
    print("  Global Dependencies:", file = sample)
    if not JSON["GlobalDependencies"]:
        print("    ---", file = sample)    
    if arguments.GlobalNumber == -1:
        for i in JSON["GlobalDependencies"]:
            if arguments.DNS == True and i["Service"] == "WEB Server":
                try:
                    domain = socket.gethostbyaddr(i["IP"])
                    print("    -> ", i["IP"], " ", i["Verb"], " [", i["Service"], "]  Domain: ", domain[0],"  - number of packets: ", i["Packets"], file = sample)    
                except:
                    print("    -> ", i["IP"], " ", i["Verb"], " [", i["Service"], "] - number of packets: ", i["Packets"], file = sample)    
            else:
                print("    -> ", i["IP"], " ", i["Verb"], " [", i["Service"], "] - number of packets: ", i["Packets"], file = sample)    
    else:
        tmp = 0
        for i in JSON["GlobalDependencies"]:
            if tmp < arguments.GlobalNumber:        
                if arguments.DNS == True and i["Service"] == "WEB Server":
                    try:
                        domain = socket.gethostbyaddr(i["IP"])
                        print("    -> ", i["IP"], " ", i["Verb"], " [", i["Service"], "]  Domain: ", domain[0],"  - number of packets: ", i["Packets"], file = sample)    
                    except:
                        print("    -> ", i["IP"], " ", i["Verb"], " [", i["Service"], "] - number of packets: ", i["Packets"], file = sample)    
                else:
                    print("    -> ", i["IP"], " ", i["Verb"], " [", i["Service"], "] - number of packets: ", i["Packets"], file = sample)    
                tmp = tmp + 1
            else:
                break
    #=================================================================================    
    if not JSON["GlobalStatistic"]:
        print("", file = sample)    
    else:   
        IPStatistic = {} 
        for i in JSON["GlobalStatistic"]:
            IPStatistic[i["Service"]] = i["Procents"]
        print("  Print Global Statistic:", file = sample)
        for i, j in IPStatistic.items():
            print("    ", i, "\t\t\t", j, "%", file = sample)    
    sample.close() 
#=======================================================================================================================================
#Analyze single device   
def AnalyzeLocalDevice(DeviceID, IP, TIME, cursor, SQLiteConnection, JSON, IPStatistic, GL, arguments):    
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
    if arguments.onlylocal == False:
        GlobalStatistic = {}    
        GLOBALDEPENDENCIES(DeviceID, IP, DeviceIP, GlobalStatistic, IPStatistic, cursor, SQLiteConnection, createJSON)    
        StatProcent(GlobalStatistic, createJSON, 1)    
    #==================================================================
    if arguments.print == True:
        PrintDeviceFromJSON(createJSON)
    if arguments.file != "":
        print("Output printed to file: ", arguments.file)
        PrintDeviceToFileFromJSON(createJSON, arguments)
    #==================================================================
    JSON["Devices"].append(createJSON)
#=======================================================================================================================================
#Analyze single device
def AnalyzeSingleDevice(SQLiteConnection, arguments):
    try:
        IP = ipaddress.ip_address(arguments.device)
    except:
        print("ERROR: Entered value isn't IP address")
        sys.exit()
    cursor = SQLiteConnection.cursor()
    cursor.execute("SELECT * FROM LocalDevice WHERE IP='{ip}'".format(ip=arguments.device) )
    device = cursor.fetchone()
    if not device:
        print("ERROR: Entered IP address isn't in database")
        sys.exit()
    JSON = {   "Name": "AnalyzeSingleDevice", 
                    "DateAnalyze": "", 
                    "Routers": [],                    
                    "Services": [],                    
                    "IPStatistic": [],
                    "Devices": []
                }    
    write_json(JSON, arguments.json)
    read_json(JSON, arguments.json)
    IPStatistic = {}    
    AnalyzeLocalDevice("XXX", device[0], device[1], cursor, SQLiteConnection, JSON, IPStatistic, True, arguments)
    x = datetime.datetime.now()
    JSON["DateAnalyze"] = str(x)
    write_json(JSON, arguments.json)
    print("Output JSON: ", arguments.json)
#=======================================================================================================================================
#Main function of Analyzer
def DoAnalyze(SQLiteConnection, arguments):
    #==================================================================
    JSON = {   "Name": "DeppendencyMapping", 
                    "DateAnalyze": "", 
                    "NumberDevice": 0,
                    "Routers": [],                    
                    "Services": [],                    
                    "IPStatistic": [],
                    "Devices": []
                }    
    write_json(JSON, arguments.json)
    read_json(JSON, arguments.json)
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
        if LocalDevice[0] == "255.255.255.255" or LocalDevice[0] == "0.0.0.0":
            continue
        AnalyzeLocalDevice(DeviceID, LocalDevice[0], LocalDevice[1], cursor, SQLiteConnection, JSON, IPStatistic, GL, arguments)
        DeviceID = DeviceID + 1
    #==================================================================
    if arguments.localgraph == True:    
        GraphLocalDependencies(cursor, SQLiteConnection)
    if arguments.globalgraph == True:
        GraphGlobalDependencies(cursor, SQLiteConnection)
    #==================================================================
    StatProcent(IPStatistic, JSON, 2)    
    #==================================================================
    x = datetime.datetime.now()
    JSON["DateAnalyze"] = str(x)
    JSON["NumberDevice"] = DeviceID - 1
    write_json(JSON, arguments.json)
    print("Output JSON: ", arguments.json)    
#=======================================================================================================================================
#=======================================================================================================================================
#=======================================================================================================================================
# Main loop
parser = argparse.ArgumentParser( description="""Analyze of captured network flow in database. 
Database is created by CreateScript. Filled with PassiveAutodiscovery.py NEMEA modul with coaporate Collector.py.

Usage:""", formatter_class=RawTextHelpFormatter)
#=====================================================
parser.add_argument(
    '-D', '--device',
    help="Analyze single device [DEVICE = IP address of device to analyze]",
    type=str,
    default=""
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
    '-G', '--GlobalNumber',
    help="Number of global dependencies to print, default: all dependencies",
    type=int,
    metavar='NUMBER',
    default=-1
)
#=====================================================
parser.add_argument(
    '-J', '--json',
    help="print to JSON file [NAME = name of the file without . part (file will be automatic set to .json), default = PassiveAutodiscovery ]",
    type=str,
    metavar='NAME',
    default="PassiveAutodiscovery"
)
#=====================================================
parser.add_argument(
    '-f', '--file',
    help="print to file [NAME = name of the file without . part (file will be automatic set to .txt) ]",
    type=str,
    metavar='NAME',
    default=""
)
#=====================================================
parser.add_argument(
    '-p', '--print',
    help="print to command line",
    action="store_true"
)
#=====================================================
parser.add_argument(
    '-DNS', '--DNS',
    help="Transalte [WEB Servers] IP to domain name and show in output",
    action="store_true"
)
#=====================================================
parser.add_argument(
    '-l', '--localgraph',
    help="create graph of dependencies between local devices and safe it to file",
    action="store_true"
)
#=====================================================
parser.add_argument(
    '-g', '--globalgraph',
    help="create graph of dependencies between local devices and safe it to file",
    action="store_true"
)
#=====================================================
parser.add_argument(
    '-o', '--onlylocal',
    help="Analyze only local dependencies",
    action="store_true"
)
#=====================================================
arguments = parser.parse_args()
#=====================================================
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
#=====================================================
if arguments.device != "":
    AnalyzeSingleDevice(SQLiteConnection, arguments)
else:
    DoAnalyze(SQLiteConnection, arguments)
#=====================================================
# Close database connection
if(SQLiteConnection):
    SQLiteConnection.close()
#=======================================================================================================================================
#=======================================================================================================================================
#=======================================================================================================================================
