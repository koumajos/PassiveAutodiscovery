#!/usr/bin/python3.6
"""DeviceAnalyzer script:

    DeviceAnalyzer script connect to sqlite3 database which is created by CreateScript and filled by PassiveAutodiscovery script. After connect to database, script will analyzed database acccording to setted arguments of script. Only one mandatory output of the script is JSON document with default name PassiveAutodiscovery.

    Analyze:
        For all device will script get these information from database:
            IP address of device (if mac address is use more IP address and isn't router, it will be list of IP address where first one is for comunication analyzed in the section)        
            Time of last comunication
            Labels of roles that device is (provides these services for other device on network)
            DHCP records (requests and answers) by time.
            List of local dependencies sorted by number of carryed packet. ()
            Statistic of local dependencies by transport layer protocol.            
            List of global dependencies sorted by number of carryed packet.
            Statistic of global dependencies by transport layer protocol.            
        For database can be created:
            Graph of local dependencies. [-l]
            Graph of local device and global devices, which local device communication with. [-g]
            Graph of local devices and globla devices, where global device is in graph only if two or more local devices had communicate with. It will create bipartite graph. [-b]
            Statistical of using network by devices.
    Setting of the script:
        Outputs:
            JSON document - mandatory output, can be setted name of the document [-J name] (default name is PassiveAutodiscovery)
            Command Line - optinional output [-p]
            File .txt - optinional output, can be setted name of the document (hasn't default value) [-f name]
        Analyze:
            Default state - analyze all database [without -D and -N]
            Device - analyze only one inserted device (if exists in database) [-D]
            Network - analyze only one network subnet [-N]
        Number of dependencies in output to command line or File .txt (JSON document contains all dependencies):
            Set the number of local dependencies. [-L]
            Set the number of global dependencies. [-G]
        Dependencies and device with label [WEB Server] can be translate to domain name:
            The domain name will be in output (command line/file). [-DNS] 
        Can ignored global dependencies:
            In outub will be only local dependencies. [-o]
        Can create graphs of dependencies in time.
            For local dependencies. [-t]
            For local to gloval dependencies. [-T]
"""
#libraries for working with OS UNIX files and system
import sys
import os
#library for working with IP addresses
import ipaddress
#library for working with sqlite3 database
import sqlite3
#library for working with JSON document
import json
#library for math things
import math
#library for create network socket (in this script use for DNS queries)
import socket
#libraries for working with time
import time
import datetime
#library for create statistics graphs
from termgraph import termgraph
import tempfile
#libraries for create network graphs
import pandas
import numpy
import networkx
import matplotlib.pyplot as plt
import matplotlib.ticker as plticker
#library for arguments of script
import argparse
from argparse import RawTextHelpFormatter
#===============================================================================================
#===============================================================================================
def CheckStr(STR, DOT):
    """Function check if string have DOT suffix in end of string. Like suffix .txt in text.txt.

    Parameters
    --------
    STR : str 
        String of file name.
    DOT : str
        String of file suffix.
    Returns
    --------
    Boolean : boolean
        True if STR have suffix DOT.
        False if STR havn't suffix DOT.
    """
    x = STR.split(DOT)
    if x[-1] == '':
        return True
    return False
#=======================================================================================================================================
#=======================================================================================================================================
def TimeGraph(Dependency, table, cursor, createJSON):
    """Plot graph of using dependency in time and safe it to file. Line X is time and line Y is number of packets.

    Parameters
    -----------
    Dependency : sqlite3.fetchone()
        Record of dependency that may be ploted.
    table : str
        Name of table where is record of dependency safed (Dependencies or Global).
    cursor : sqlite3
        Cursor to sqlite3 database for execute SQL queries.
    createJSON : JSON  
        JSON file loaded in python.    
    """
    if table == "Dependencies":
        cursor.execute("SELECT * FROM DependenciesTime WHERE DependenciesID='{ID}'".format(ID=Dependency[0]))
        rows = cursor.fetchall()
    else:
        cursor.execute("SELECT * FROM GlobalTime WHERE GlobalID='{ID}'".format(ID=Dependency[0]))
        rows = cursor.fetchall()
    if not rows:
        return
    X = []
    Y = []
    Time = rows[0][2]
    tmpX = 0
    tmpY = 0
    for row in rows:
        if float(row[2]) <= (float(Time) + 60):
            tmpY = tmpY + row[3]
        else: 
            X.append(time.ctime(float(Time)))            
            Y.append(tmpY)
            while float(row[2]) > (float(Time) + 60):
                Time = str(float(Time) + 60)             
                X.append(time.ctime(float(Time)))            
                Y.append(0)
            tmpY = row[3]            
    plt.rcParams["figure.figsize"] = (20,3)
    plt.plot(X,Y)
    plt.setp(plt.gca().xaxis.get_majorticklabels(),rotation=0)
    loc = plticker.MultipleLocator(base=40) # this locator puts ticks at regular intervals
    plt.gca().xaxis.set_major_locator(loc)    # naming the x axis 
    plt.xlabel('Time (in minutes)') 
    # naming the y axis 
    plt.ylabel('Number of Packets') 
    # giving a title to my graph 
    plt.title("Dependency between " + Dependency[1] + "(" + str(Dependency[3]) + ") and " + Dependency[2] + "(" + str(Dependency[4]) + ")") 
    plt.savefig("TimeGraph_" + Dependency[1] + "(" + str(Dependency[3]) + ")_" + Dependency[2] + "(" + str(Dependency[4]) + ")" + ".png")
    createJSON["Files"].append("TimeGraph_" + Dependency[1] + "(" + str(Dependency[3]) + ")_" + Dependency[2] + "(" + str(Dependency[4]) + ")" + ".png")
    print("Graph of using dependency in time safe in file: TimeGraph_" + Dependency[1] + "(" + str(Dependency[3]) + ")_" + Dependency[2] + "(" + str(Dependency[4]) + ")" + ".png")    
    plt.clf()
#=======================================================================================================================================
#=======================================================================================================================================
def plot(data):
    """Plot the statistical graph of using network (by protocols or devices) in %. Only for output in command line.

    Parameters
    -----------
    data : list
        List of deveces/protocols with procent of use the network.  
    """
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
#=======================================================================================================================================
def read_json(filename):
    """Read JSON document from file to prom data.

    Parameters
    -----------
    filename : str
        Name of the output JSON document file.
    Returns
    --------
    data : JSON
        JSON format in python.
    """
    if CheckStr(filename, ".json") == True:
        FILE = filename
    else:
        FILE = filename + ".json"
    with open(FILE, "r") as jsonFile:
        data = json.load(jsonFile)
    return data
#=======================================================================================================================================
#=======================================================================================================================================
def write_json(data, filename): 
    """Write JSON in python to JSON document file. 

    Parameters
    -----------
    data : JSON
        JSON file loaded in python filled with information.
    filename : str
        Name of the output JSON document file.
    """
    if CheckStr(filename, ".json") == True:
        FILE = filename
    else:
        FILE = filename + ".json"
    with open(FILE,'w') as f: 
        json.dump(data, f, indent=4) 
#=======================================================================================================================================
#=======================================================================================================================================
def GraphLocalDependencies(cursor, SQLiteConnection, JSON):
    """Function create graph of local dependencies for IP address version 4 and IP address version 6. Then safe it to file named Graph_Local_[ip verison].

    Parameters
    -----------
    cursor : sqlite3
        Cursor to sqlite3 database for execute SQL queries.
    SQLiteConnection : sqlite3
        Connection to sqlite3 database.
    JSON : JSON
        JSON file loaded in python.    
    """
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
    createJSON["Files"].append("Graph_Local_IPv4.png")    
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
    createJSON["Files"].append("Graph_Local_IPv6.png")    
#=======================================================================================================================================
#=======================================================================================================================================
def GraphGlobalDependencies(cursor, SQLiteConnection, JSON):
    """Function create graph of global dependencies for each device. Then safe them to files named Graph_Global_[IP address].

    Parameters
    -----------
    cursor : sqlite3
        Cursor to sqlite3 database for execute SQL queries.
    SQLiteConnection : sqlite3
        Connection to sqlite3 database.
    JSON : JSON
        JSON file loaded in python.    
    """
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
        createJSON["Files"].append("Graph_Global_%s.png" % device[0])    
#=======================================================================================================================================
#=======================================================================================================================================
def GraphLocalToGlobal(cursor, SQLiteConnection, JSON):
    """Function create graph of dependencies between local and global device, where global is only if two or more local device have communication with. Then safe them to files named Graph_GlobalsToLocals_[number]. (Graph are for visibility safe to more files by small number of devices)

    Parameters
    -----------
    cursor : sqlite3
        Cursor to sqlite3 database for execute SQL queries.
    SQLiteConnection : sqlite3
        Connection to sqlite3 database.
    JSON : JSON
        JSON file loaded in python.    
    """
    print("######################################################################") 
    cursor.execute("SELECT * FROM (SELECT IP_origin AS IP FROM Global GROUP BY IP_origin HAVING COUNT(*) > 1 UNION ALL SELECT IP_target AS IP FROM Global GROUP BY IP_target HAVING COUNT(*) > 1) GROUP BY IP")
    IP = cursor.fetchall()
    I = networkx.Graph()
    tmp = 0
    for i in IP:
        ip = ipaddress.ip_address(i[0])
        if ip.is_global == True:
            cursor.execute("SELECT * FROM (SELECT IP_target AS IP, IP_origin AS IPM FROM Global WHERE IP_origin='{ipo}' UNION ALL SELECT IP_origin AS IP, IP_target AS IPM FROM Global WHERE IP_target='{ipo}') GROUP BY IP".format(ipo=i[0], ipt=i[0]))
            Dependencies = cursor.fetchall()
            if len(Dependencies) > 1:            
                for j in Dependencies:
                    I.add_node(j[0],  bipartite=0)
                    I.add_node(j[1],  bipartite=1)
                    I.add_edge(j[0], j[1])
                if len(I) > 15:
                    try:                    
                        # Separate by group
                        l, r = networkx.bipartite.sets(I)
                        pos = {}    
                        # Update position for node from each group
                        pos.update((node, (1, index)) for index, node in enumerate(l))
                        pos.update((node, (2, index)) for index, node in enumerate(r))
                        networkx.draw(I, pos, with_labels=True)
                        x_values, y_values = zip(*pos.values())
                        x_max = max(x_values)
                        x_min = min(x_values)
                        x_margin = (x_max - x_min) * 0.25
                        plt.xlim(x_min - x_margin, x_max + x_margin)
                        plt.axis('off')
                        plt.savefig("Graph_GlobalsToLocals_%s.png" % tmp)
                        #plt.show()
                        plt.clf()                        
                        JSON["Files"].append("Graph_GlobalsToLocals_%s.png" % tmp)    
                        tmp = tmp + 1
                        I.clear()
                    except:
                        I.clear()
                        #return
#=======================================================================================================================================
#=======================================================================================================================================
def MAC(DeviceID, IP, cursor, SQLiteConnection, createJSON):
    """Find if for device IP is in database MAC address record in table MAC or table Routers. If in table MAC, the device with IP has this MAC address. If in Router, the device with IP has this MAC address or is behind router with this MAC address (Ussualy cant resolve this by program).

    Parameters
    -----------
    DeviceID : int
        ID of device in analyze.
    IP : str
        IP address of device.
    cursor : sqlite3
        Cursor to sqlite3 database for execute SQL queries.
    SQLiteConnection : sqlite3
        Connection to sqlite3 database.
    createJSON : JSON
        JSON file for device with DeviceID ID loaded in python.    
    """
    cursor.execute("SELECT * FROM MAC WHERE IP='{ip}' AND LastUse='{lu}'".format(ip=IP, lu=""))
    row = cursor.fetchone()
    cursor.execute("SELECT * FROM Routers WHERE IP='{ip}'".format(ip=IP) )
    Router = cursor.fetchone()
    mac = ""    
    if row:
        createJSON["MAC"] = row[2]
        mac = [row[2][i:i+8] for i in range(0, len(row[2]), 8) ][0] 
    elif Router:
        createJSON["RouterMAC"] = Router[1]
        mac = [Router[1][i:i+8] for i in range(0, len(Router[1]), 8) ][0] 
    else:
        None
    if mac != "":
        cursor.execute("SELECT * FROM VendorsMAC WHERE VendorMAC='{m}'".format(m=mac.upper()))
        row = cursor.fetchone()
        if row:        
            createJSON["Vendor"] = row[3]
            createJSON["Country"] = row[4]
        else:
            createJSON["Vendor"] = "Not Find"
#=======================================================================================================================================
#=======================================================================================================================================
def LABELS(DeviceID, IP, cursor, SQLiteConnection, createJSON, JSON, GL):
    """Find all labels (of roles/services) for device in database table LocalServices. Also create new label out of dependencies like [End Device].

    Parameters
    -----------
    DeviceID : int
        ID of device in analyze.
    IP : str
        IP address of device.
    cursor : sqlite3
        Cursor to sqlite3 database for execute SQL queries.
    SQLiteConnection : sqlite3
        Connection to sqlite3 database.
    createJSON : JSON
        JSON file for device with DeviceID ID loaded in python.    
    JSON : JSON
        JSON file for all analyze loaded in python.
    GL : bool
        True if global dependencies exists.
    """
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
            if Service[1] == "WEB Server":      #if device is [WEB Server], try transplate IP address to domain name 
                try:
                    domain = socket.gethostbyaddr(IP)
                    if not {"Label": "%s" % Service[1], "Description": "%s" % domain[0]} in createJSON["Labels"]:
                        createJSON["Labels"].append({"Label": "%s" % Service[1], "Description": "%s" % domain[0]})
                    continue
                except:
                    None
            if not {"Label": "%s" % Service[1], "Description": "%s" % Service[3]} in createJSON["Labels"]:      #add to output only unique labels
                createJSON["Labels"].append({"Label": "%s" % Service[1], "Description": "%s" % Service[3]})
    #============================================================================================================================================================
    #Create new labels from dependencies from access to Web Sevices, Mail Services, or record in table Routers   
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
        cursor.execute("SELECT * FROM Routers WHERE MAC='{mac}'".format(mac=Router[1]) )
        Routers = cursor.fetchall()
        devices4 = 0
        devices6 = 0
        for i in Routers:
            ipd = ipaddress.ip_address(i[2])
            if ipd.is_global == False:            
                if ipd.version == 4:
                    devices4 = devices4 + 1
                else:
                    devices6 = devices6 + 1
            if devices6 > 1 or devices4 > 1:
                break
        if devices6 > 1 or devices4 > 1:
            None
        else:
            tmp = 1
            if not "Router" in JSON["Services"]:
                JSON["Services"].append("Router")
            createJSON["Labels"].append({"Label": "Router", "Description": "Routing network device"})
            if not IP in JSON["Routers"]:
                JSON["Routers"].append(IP)
    if tmp == 0:        #if no label was for device find give it label [Unknown]
        if not "Unknown" in JSON["Services"]:
            JSON["Services"].append("Unknown")
        createJSON["Labels"].append({"Label": "Unknows", "Description": ""})
#=======================================================================================================================================
#=======================================================================================================================================
def DHCP(DeviceID, IP, cursor, SQLiteConnection, createJSON):
    """Funkcion finds for device all record of DHCP comunicationa nd set it to output.

    Parameters
    -----------
    DeviceID : int
        ID of device in analyze.
    IP : str
        IP address of device.
    cursor : sqlite3
        Cursor to sqlite3 database for execute SQL queries.
    SQLiteConnection : sqlite3
        Connection to sqlite3 database.
    createJSON : JSON
        JSON file for device with DeviceID ID loaded in python.        
    """
    cursor.execute("SELECT * FROM DHCP WHERE DeviceIP='{ip}' ORDER BY Time DESC".format(ip=IP) )
    DHCPs = cursor.fetchall()    
    if DHCPs:
        for DHCP in DHCPs:
            createJSON["DHCP"].append({"DHCPServ": "%s" % DHCP[2], "DHCPTime": "%s" % time.ctime(float(DHCP[3]))})
#====================================================================================================================================== 
#=======================================================================================================================================
def Stats(LocalStatistic, Dependency, cursor, SQLiteConnection):
    """Function find if source or destination port of dependency isn't some services in network. If yes, then the packet number carry the dependendy add in LocalStatistic to the services. (this create with cyclus counter of packet by protocol in network) 
    
    Parameters
    -----------
    LocalStatistic : dictionary
        Disctionary of protocols and number packet taht was carry over network by protocols.
    Dependency : array
        The one dependency for count packets and protocols.    
    cursor : sqlite3
        Cursor to sqlite3 database for execute SQL queries.
    SQLiteConnection : sqlite3
        Connection to sqlite3 database.
    """
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
#=======================================================================================================================================
def LOCALDEPENDENCIES(DeviceID, IP, DeviceIP, LocalStatistic, IPStatistic, cursor, SQLiteConnection, createJSON, arguments, JSON):
    """Function for device find in database all local dependencies and set in to output JSON. Also create statistic of local dependencies and statistic of using network by deveices. 

    Parameters
    -----------
    DeviceID : int
        Number of device in analyze.
    IP : str
        Device IP address in format str.
    DeviceIP : ipaddress
        Device IP address in format ipaddress.
    LocalStatistic : dictionary
        Statistic of local dependencies.
    IPStatistic : dictionary
        Statistic of using network by device.
    cursor : sqlite3
        Cursor to sqlite3 database for execute SQL queries.
    SQLiteConnection : sqlite3
        Connection to sqlite3 database.
    createJSON : JSON
        JSON file for device with DeviceID ID loaded in python.        
    """
    cursor.execute("SELECT * FROM Dependencies WHERE IP_origin='{ipo}' OR IP_target='{ipt}' ORDER BY NumPackets DESC".format(ipo=IP, ipt=IP) )
    Dependencies = cursor.fetchall()
    tmp = 0
    if Dependencies:    
        for Dependency in Dependencies:
            if arguments.timeL > tmp:
                TimeGraph( Dependency, "Dependencies", cursor, JSON)
                tmp = tmp + 1
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
                        Services = "DHCP Server(67)"
                    else:
                        Verbs = "requires"
                        Services = ServiceS[1] + "(" + str(Dependency[3]) + ")"
                else:               
                    IPs = Dependency[1]                    
                    Services = ServiceS[1] + "(" + str(Dependency[3]) + ")"
            elif ServiceD:
                if SrcIP == DeviceIP:
                    IPs = Dependency[2]                    
                else:               
                    IPs = Dependency[1]                    
                    Verbs = "requires"
                Services = ServiceD[1] + "(" + str(Dependency[4]) + ")"
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
#=======================================================================================================================================
def GLOBALDEPENDENCIES(DeviceID, IP, DeviceIP, GlobalStatistic, IPStatistic, cursor, SQLiteConnection, createJSON, arguments, JSON):
    """Function for device find in database all global dependencies and set in to output JSON. Also create statistic of global dependencies and statistic of using network by deveices. 

    Parameters
    -----------
    DeviceID : int
        Number of device in analyze.
    IP : str
        Device IP address in format str.
    DeviceIP : ipaddress
        Device IP address in format ipaddress.
    GlobalStatistic : dictionary
        Statistic of local dependencies.
    IPStatistic : dictionary
        Statistic of using network by device.
    cursor : sqlite3
        Cursor to sqlite3 database for execute SQL queries.
    SQLiteConnection : sqlite3
        Connection to sqlite3 database.
    createJSON : JSON
        JSON file for device with DeviceID ID loaded in python.        
    """
    cursor.execute("SELECT * FROM Global WHERE IP_origin='{ipo}' OR IP_target='{ipt}' ORDER BY NumPackets DESC".format(ipo=IP, ipt=IP) )
    GlobalDependencies = cursor.fetchall()
    tmp = 0    
    if GlobalDependencies:
        promtp = 0    
        for GlobalDependency in GlobalDependencies:
            if arguments.timeG > tmp:
                TimeGraph( GlobalDependency, "Global", cursor, JSON)
                tmp = tmp + 1
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
                    Services = ServiceS[1] + "(" + str(GlobalDependency[3]) + ")"            
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
                    Services = ServiceS[1] + "(" + str(GlobalDependency[3]) + ")"
            elif ServiceD:
                if SrcIP == DeviceIP:
                    IPs = GlobalDependency[2]
                else:               
                    IPs = GlobalDependency[1]
                    Verbs = "requires"
                if promtp < 15:
                    Services = ServiceD[1] + "(" + str(GlobalDependency[4]) + ")"
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
                    Services = ServiceD[1] + "(" + str(GlobalDependency[4]) + ")"
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
#=======================================================================================================================================
def StatProcent(Statistic, createJSON, TMP):    
    """Function receive dictionary. The dictionarz number of packets calculate and create from it procents.

    Parameters
    -----------
    Statistic : dictionary
        The dictionary of statistic with protocols/devices and number of packets that was carryed in network by it.
    createJSON : JSON
        JSON file for device with DeviceID ID loaded in python.        
    TMP : int
        Magic value represent the type of statistic (Local statistic == 0, Global statistic == 1, Network use statistic == 2).
    """
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
#=======================================================================================================================================
def IPAddress(IP, cursor, createJSON):   
    """Function finds in database all IP address of the device (more then one only when device used both version of IP address or change IP address while monitoring network (DHCP)).

    Parameters
    -----------
    IP : str
        IP address of analyzed device.
    cursor : sqlite3
        Cursor to sqlite3 database for execute SQL queries.
    createJSON : JSON
        JSON file for device with DeviceID ID loaded in python.            
    """
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
        cursor.execute("SELECT DeviceType FROM LocalServices LS JOIN Services S ON LS.PortNumber=S.PortNumber WHERE LS.IP='{ip}' AND S.DeviceType='{device}'".format(ip=IP, device="Router") )
        Router = cursor.fetchall()
        if Router:
            cursor.execute("SELECT * FROM Routers WHERE MAC='{mac}'".format(mac=Router[1]) )
            Routers = cursor.fetchall()
            IPD = ipaddress.ip_address(IP)        
            for ip in Routers:
                ipd = ipaddress.ip_address(ip[2])        
                if ipd.is_private and ip[2] != IP and IPD.version == ipd.version:
                    createJSON["DeviceBehindRouter"].append(ip[2])
#=======================================================================================================================================
#=======================================================================================================================================
def PrintDeviceFromJSON(JSON, arguments):
    """Print device from output JSON document to command line.

    Parameters
    -----------
    JSON : JSON
        Ouput JSON document.
    arguments : argparse
        Setted arguments of the DeviceAnalyzer script.    
    """
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
    if JSON["MAC"] == "" and JSON["RouterMAC"] == "":
        print("---")
    elif JSON["RouterMAC"] == "":
        print(JSON["MAC"], end='')
        if JSON["Vendor"] != "":
            print(", ", JSON["Vendor"], ", ", JSON["Country"])
    else:
        print(" of router behind this device or this device itself is this router: ", JSON["RouterMAC"], end='')
        if JSON["Vendor"] != "":
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
    if arguments.LocalNumber != -1:
        tmp = 0
        for i in JSON["LocalDependencies"]:
            if tmp < arguments.LocalNumber:
                if i["Verb"] == "provides":
                    print("    -> ", i["IP"], " ", i["Verb"], " [", i["Service"], "] - number of packets: ", i["Packets"])
                else:
                    print("    <- ", i["IP"], " ", i["Verb"], " [", i["Service"], "] - number of packets: ", i["Packets"])        
                tmp = tmp + 1
            else:
                break
    else:
        for i in JSON["LocalDependencies"]:
            if i["Verb"] == "provides":
                print("    -> ", i["IP"], " ", i["Verb"], " [", i["Service"], "] - number of packets: ", i["Packets"])
            else:
                print("    <- ", i["IP"], " ", i["Verb"], " [", i["Service"], "] - number of packets: ", i["Packets"])    
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
                    if i["Verb"] == "provides":
                        print("    -> ", i["IP"], " ", i["Verb"], " [", i["Service"], "]  Domain: ", domain[0],"  - number of packets: ", i["Packets"] )
                    else:
                        print("    <- ", i["IP"], " ", i["Verb"], " [", i["Service"], "]  Domain: ", domain[0],"  - number of packets: ", i["Packets"] )
                except:
                    if i["Verb"] == "provides":
                        print("    -> ", i["IP"], " ", i["Verb"], " [", i["Service"], "] - number of packets: ", i["Packets"] ) 
                    else:
                        print("    <- ", i["IP"], " ", i["Verb"], " [", i["Service"], "] - number of packets: ", i["Packets"] )  
            else:
                print("    -> ", i["IP"], " ", i["Verb"], " [", i["Service"], "] - number of packets: ", i["Packets"] )    
    else:
        tmp = 0
        for i in JSON["GlobalDependencies"]:
            if tmp < arguments.GlobalNumber:        
                if arguments.DNS == True and i["Service"] == "WEB Server":
                    try:
                        domain = socket.gethostbyaddr(i["IP"])
                        if i["Verb"] == "provides":
                            print("    -> ", i["IP"], " ", i["Verb"], " [", i["Service"], "]  Domain: ", domain[0],"  - number of packets: ", i["Packets"] )    
                        else:                    
                            print("    <- ", i["IP"], " ", i["Verb"], " [", i["Service"], "]  Domain: ", domain[0],"  - number of packets: ", i["Packets"] )    
                    except:
                        if i["Verb"] == "provides":
                            print("    -> ", i["IP"], " ", i["Verb"], " [", i["Service"], "] - number of packets: ", i["Packets"] )    
                        else:
                            print("    <- ", i["IP"], " ", i["Verb"], " [", i["Service"], "] - number of packets: ", i["Packets"] )                                        
                else:
                    if i["Verb"] == "provides":
                        print("    -> ", i["IP"], " ", i["Verb"], " [", i["Service"], "] - number of packets: ", i["Packets"] )    
                    else:
                        print("    <- ", i["IP"], " ", i["Verb"], " [", i["Service"], "] - number of packets: ", i["Packets"] )    
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
#=======================================================================================================================================
def PrintDeviceToFileFromJSON(JSON, arguments, sample):
    """Print device from output JSON document to file.

    Parameters
    -----------
    JSON : JSON
        Ouput JSON document.
    arguments : argparse
        Setted arguments of the DeviceAnalyzer script.    
    sample : opened file
        Opened output file.
    """
    if not JSON["LocalDependencies"] and not JSON["GlobalDependencies"]:
        return    
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
    if JSON["MAC"] == "" and JSON["RouterMAC"] == "":
        print("---", file = sample)
    elif JSON["RouterMAC"] == "":
        print(JSON["MAC"], end='', file = sample)
        if JSON["Vendor"] != "":
            print(", ", JSON["Vendor"], ", ", JSON["Country"], file = sample)
    else:
        print(" of router behind this device or this device itself is this router: ", JSON["RouterMAC"], end='', file = sample)
        if JSON["Vendor"] != "":
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
    if arguments.LocalNumber != -1:
        tmp = 0
        for i in JSON["LocalDependencies"]:
            if tmp < arguments.LocalNumber:
                if i["Verb"] == "provides":
                    print("    -> ", i["IP"], " ", i["Verb"], " [", i["Service"], "] - number of packets: ", i["Packets"], file = sample)    
                else:
                    print("    <- ", i["IP"], " ", i["Verb"], " [", i["Service"], "] - number of packets: ", i["Packets"], file = sample)                        
                tmp = tmp + 1
            else:
                break
    else:
        for i in JSON["LocalDependencies"]:
            if i["Verb"] == "provides":
                print("    -> ", i["IP"], " ", i["Verb"], " [", i["Service"], "] - number of packets: ", i["Packets"], file = sample)  
            else:      
                print("    <- ", i["IP"], " ", i["Verb"], " [", i["Service"], "] - number of packets: ", i["Packets"], file = sample)  
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
                        if i["Verb"] == "provides":
                            print("    -> ", i["IP"], " ", i["Verb"], " [", i["Service"], "]  Domain: ", domain[0],"  - number of packets: ", i["Packets"], file = sample)    
                        else:
                            print("    <- ", i["IP"], " ", i["Verb"], " [", i["Service"], "]  Domain: ", domain[0],"  - number of packets: ", i["Packets"], file = sample)                                
                    except:
                        if i["Verb"] == "provides":
                            print("    -> ", i["IP"], " ", i["Verb"], " [", i["Service"], "] - number of packets: ", i["Packets"], file = sample)    
                        else:                
                            print("    <- ", i["IP"], " ", i["Verb"], " [", i["Service"], "] - number of packets: ", i["Packets"], file = sample)    
                else:
                    if i["Verb"] == "provides":
                        print("    -> ", i["IP"], " ", i["Verb"], " [", i["Service"], "] - number of packets: ", i["Packets"], file = sample)    
                    else:                
                        print("    <- ", i["IP"], " ", i["Verb"], " [", i["Service"], "] - number of packets: ", i["Packets"], file = sample)    
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
#=======================================================================================================================================
#=======================================================================================================================================
def PrintJSON(JSON, arguments):
    """Print safed analyze from JSON file. Into file or command line.

    Parameters
    -----------
    JSON : JSON
        JSON file loaded in python.        
    arguments : argparse
        Setted arguments of the script.
    """
    if arguments.print == True:
        for Dev in JSON["Devices"]:
            PrintDeviceFromJSON(Dev, arguments)
    if arguments.file != "":
        if CheckStr(arguments.file, ".txt") == True:
            FILE = arguments.file
        else:
            FILE = arguments.file + ".txt"       
        sample = open(FILE, 'w')
        for Dev in JSON["Devices"]:
            PrintDeviceToFileFromJSON(Dev, arguments, sample) 
#=======================================================================================================================================
#=======================================================================================================================================
def AnalyzeLocalDevice(DeviceID, IP, TIME, cursor, SQLiteConnection, JSON, IPStatistic, GL, arguments, sample):    
    """Analyze a device and output of it add to JSON document.

    Parameters
    -----------
    DeviceID : int
        Number of device in analyze.
    IP : str
        Device IP address.
    TIME : int
        Time of last comunication.
    cursor : sqlite3
        Cursor to sqlite3 database for execute SQL queries.
    SQLiteConnection : sqlite3
        Connection to sqlite3 database.
    JSON : JSON
        JSON file loaded in python.        
    IPStatistic : dictionary
        Dictionary contains statistic of using network by devices.
    GL : bool
        True if global dependencies exists.
    arguments : argparse
        Setted arguments of the script.
    sample : opened file
        Output file.    
    """
    #==================================================================
    createJSON = {  "DeviceID":0,
                    "LastCom": 0,
                    "IP": [], 
                    "MAC": "", 
                    "RouterMAC": "", 
                    "Vendor": "",
                    "Country": "", 
                    "Labels": [],
                    "DHCP": [], 
                    "LocalDependencies": [],                    
                    "LocalStatistic": [], 
                    "GlobalDependencies": [],                    
                    "GlobalStatistic": [] 
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
    LOCALDEPENDENCIES(DeviceID, IP, DeviceIP, LocalStatistic, IPStatistic, cursor, SQLiteConnection, createJSON, arguments, JSON)
    StatProcent(LocalStatistic, createJSON, 0)
    #==================================================================
    if arguments.onlylocal == False:
        GlobalStatistic = {}    
        GLOBALDEPENDENCIES(DeviceID, IP, DeviceIP, GlobalStatistic, IPStatistic, cursor, SQLiteConnection, createJSON, arguments, JSON)    
        StatProcent(GlobalStatistic, createJSON, 1)    
    #==================================================================
    if arguments.print == True:
        PrintDeviceFromJSON(createJSON, arguments)
    if arguments.file != "":
        print("Output for device ", IP," printed to file: ", arguments.file)
        PrintDeviceToFileFromJSON(createJSON, arguments, sample)
    #==================================================================
    JSON["Devices"].append(createJSON)
#=======================================================================================================================================
#=======================================================================================================================================
def AnalyzeNetwork(SQLiteConnection, arguments):
    """Analyze network subnet from arguments.

    Parameters
    -----------
    SQLiteConnection : sqlite3
        Connection to sqlite3 database.
    arguments : argparse
        Setted arguments of the script.
    """
    #==================================================================
    JSON = {        "Name": "AnalyzeNetwork",
                    "Network": "", 
                    "DateAnalyze": "", 
                    "NumberDevice": 0,
                    "Routers": [],                    
                    "Services": [],                    
                    "IPStatistic": [],
                    "Devices": [],
                    "Files": []
                }    
    write_json(JSON, arguments.json)
    JSON = read_json(arguments.json)
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
    if arguments.file != "":
        if CheckStr(arguments.file, ".txt") == True:
            FILE = arguments.file
        else:
            FILE = arguments.file + ".txt"       
        sample = open(FILE, 'w')
    else:
        sample = "" 
    NET = ipaddress.ip_network(arguments.network)
    cursor.execute("SELECT * FROM LocalDevice")
    LocalDevices = cursor.fetchall()
    for LocalDevice in LocalDevices:
        if LocalDevice[0] == "255.255.255.255" or LocalDevice[0] == "0.0.0.0":
            continue
        IP = ipaddress.ip_address(LocalDevice[0])
        if IP in NET:    
            AnalyzeLocalDevice(DeviceID, LocalDevice[0], LocalDevice[1], cursor, SQLiteConnection, JSON, IPStatistic, GL, arguments, sample)
            DeviceID = DeviceID + 1
    #==================================================================
    if arguments.localgraph == True:    
        GraphLocalDependencies(cursor, SQLiteConnection, JSON)
    if arguments.globalgraph == True:
        GraphGlobalDependencies(cursor, SQLiteConnection, JSON)
    if arguments.bipartite == True:        
        GraphLocalToGlobal(cursor, SQLiteConnection, JSON)
    #==================================================================
    if arguments.file != "":
        print("######################################################################", file = sample) 
        print("  Print Statistic of using network by devices in %:", file = sample)
        StatProcent(IPStatistic, JSON, 3)
        for i, j in IPStatistic.items():
            print("    ", i, "\t\t\t", j, "%", file = sample)     
    if arguments.print == True:
        print("######################################################################") 
        print("  Print Statistic of using network by devices in %:")
        StatProcent(IPStatistic, JSON, 2)    
    #==================================================================
    if arguments.file != "":
        sample.close()
    x = datetime.datetime.now()
    JSON["Network"] = arguments.network
    JSON["DateAnalyze"] = str(x)
    JSON["NumberDevice"] = DeviceID - 1
    write_json(JSON, arguments.json)
    print("Output JSON: ", arguments.json)
#=======================================================================================================================================
#=======================================================================================================================================
def AnalyzeSingleDevice(SQLiteConnection, arguments):
    """Analyze single device from arguments. If isn't in database print error and end. Else analyze it.

    Parameters
    -----------
    SQLiteConnection : sqlite3
        Connection to sqlite3 database.
    arguments : argparse
        Setted arguments of the script.
    """
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
                    "Devices": [],
                    "Files": []
                }    
    write_json(JSON, arguments.json)
    JSON = read_json(arguments.json)
    IPStatistic = {}
    if arguments.file != "":
        if CheckStr(arguments.file, ".txt") == True:
            FILE = arguments.file
        else:
            FILE = arguments.file + ".txt"       
        sample = open(FILE, 'w')
    else:
        sample = "" 
    AnalyzeLocalDevice("XXX", device[0], device[1], cursor, SQLiteConnection, JSON, IPStatistic, True, arguments, sample)
    if arguments.file != "":
        sample.close()
    x = datetime.datetime.now()
    JSON["DateAnalyze"] = str(x)
    write_json(JSON, arguments.json)
    print("Output JSON: ", arguments.json)
#=======================================================================================================================================
#=======================================================================================================================================
def DoAnalyze(SQLiteConnection, arguments):
    """Analyze all "local" devices from database table LocalDevice.

    Parameters
    -----------
    SQLiteConnection : sqlite3
        Connection to sqlite3 database.
    arguments : argparse
        Setted arguments of the script.
    """
    #==================================================================
    JSON = {   "Name": "PassiveAutodiscovery", 
                    "DateAnalyze": "", 
                    "NumberDevice": 0,
                    "Routers": [],                    
                    "Services": [],                    
                    "IPStatistic": [],
                    "Devices": [],
                    "Files": []
                }    
    write_json(JSON, arguments.json)
    JSON = read_json(arguments.json)
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
    if arguments.file != "":
        if CheckStr(arguments.file, ".txt") == True:
            FILE = arguments.file
        else:
            FILE = arguments.file + ".txt"       
        sample = open(FILE, 'w')
    else:
        sample = "" 
    cursor.execute("SELECT * FROM LocalDevice")
    LocalDevices = cursor.fetchall()
    for LocalDevice in LocalDevices:
        if LocalDevice[0] == "255.255.255.255" or LocalDevice[0] == "0.0.0.0":
            continue
        AnalyzeLocalDevice(DeviceID, LocalDevice[0], LocalDevice[1], cursor, SQLiteConnection, JSON, IPStatistic, GL, arguments, sample)
        DeviceID = DeviceID + 1
    #==================================================================
    if arguments.localgraph == True:    
        GraphLocalDependencies(cursor, SQLiteConnection, JSON)
    if arguments.globalgraph == True:
        GraphGlobalDependencies(cursor, SQLiteConnection, JSON)
    if arguments.bipartite == True:        
        GraphLocalToGlobal(cursor, SQLiteConnection, JSON)
    #==================================================================
    if arguments.file != "":
        print("######################################################################", file = sample) 
        print("  Print Statistic of using network by devices in %:", file = sample)
        StatProcent(IPStatistic, JSON, 3)
        for i, j in IPStatistic.items():
            print("    ", i, "\t\t\t", j, "%", file = sample)     
    if arguments.print == True:
        print("######################################################################") 
        print("  Print Statistic of using network by devices in %:")
        StatProcent(IPStatistic, JSON, 2)    
    #==================================================================
    if arguments.file != "":
        sample.close()
    x = datetime.datetime.now()
    JSON["DateAnalyze"] = str(x)
    JSON["NumberDevice"] = DeviceID - 1
    write_json(JSON, arguments.json)
    print("Output JSON: ", arguments.json)    
#=======================================================================================================================================
#=======================================================================================================================================
def Arguments():
    """Arguments of the DeviceAnalyzer script.

    Returns
    --------
    arguments : argparse
        Setted arguments of the script.
    """    
    parser = argparse.ArgumentParser( description="""Analyze of captured network flow in database. 
    Database is created by CreateScript. Filled with PassiveAutodiscovery.py NEMEA modul with coaporate Collector.py.

    Usage:""", formatter_class=RawTextHelpFormatter)
    #=====================================================
    parser.add_argument(
        '-D', '--device',
        help="Analyze single device [DEVICE = IP address of device to analyze]",
        type=str,
        metavar='DEVICE',
        default=""
    )
    #=====================================================
    parser.add_argument(
        '-N', '--network',
        help="Analyze single netowkr subnet [NETWORK = IP address of network and mask: 192.168.1.0/24]",
        type=str,
        metavar='NETWORK',
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
        '-L', '--LocalNumber',
        help="Number of local dependencies to print, default: all dependencies",
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
        '-P', '--printJSON',
        help="print from json file that was created by DeviceAnalyzer script. Need define where print output (command line/file) with parameter [-p], [-f].",
        type=str,
        metavar='NAME',
        default=""
    )
    #=====================================================
    parser.add_argument(
        '-DNS', '--DNS',
        help="transalte [WEB Servers] IP to domain name and show in output",
        action="store_true"
    )
    #=====================================================
    parser.add_argument(
        '-t', '--timeL',
        help="Generate graphs of using dependencies in time for setted number of local dependencies from mostly used. (for workign must be run PassiveAutodiscovery.py wiht parameter -T)",
        type=int,
        metavar='NUMBER',
        default=-1
    )
    #=====================================================
    parser.add_argument(
        '-T', '--timeG',
        help="Generate graphs of using dependencies in time for setted number of dependencies of local device with global devices from mostly used. (for workign must be run PassiveAutodiscovery.py wiht parameter -T)",
        type=int,
        metavar='NUMBER',
        default=-1
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
        help="create graph of dependencies between local device and all global devices which was visited by local device, then safe it to file",
        action="store_true"
    )
    #=====================================================
    parser.add_argument(
        '-b', '--bipartite',
        help="create graph of dependencies between local devices and  global devices that was visited by more local devices, then safe it to file",
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
    if arguments.device != "" and arguments.network != "":
        print("Parameters -D and -N can't be combinated. Choose only one")
        sys.exit()
    if arguments.network != "":
        try:
            NET = ipaddress.ip_network(arguments.network)
        except:
            print("Badly inserted ip address of network ", arguments.network)
            sys.exit()    
    return arguments
#=======================================================================================================================================
#=======================================================================================================================================
def ConnectToDatabase(arguments):
    """Connect to sqlite3 database which analyze.

    Parameters
    -----------
    arguments : argparse
        Setted arguments of the script.
    Returns
    --------
    SQLiteConnection : sqlite3
        Connection to sqlite3 database with name from arguments.
    """
    try:    #connect to a database
        print("Connecting to a database....", end='')
        if CheckStr(arguments.database, ".db") == True:
            FILE = arguments.database
        else:
            FILE = arguments.database + ".db"       
        if not os.path.exists(FILE):
            print("")
            print("can't connect to ", FILE)
            sys.exit()
        SQLiteConnection = sqlite3.connect(FILE)
        print("done")
    except sqlite3.Error as error:
        print("Can't connect to a database:  ", error)
    return SQLiteConnection
#=======================================================================================================================================
#=======================================================================================================================================
def Main():
    """Main function call one of three function by arguments where it is set.

    """
    arguments = Arguments()
    if arguments.printJSON != "":
        if arguments.print == False and arguments.file == "":
            print("Need define output method (print to command line or file [-p], [-f])")
            sys.exit() 
        JSON = read_json(arguments.json)
        PrintJSON(JSON, arguments)
        sys.exit()    
    SQLiteConnection = ConnectToDatabase(arguments)
    if arguments.device != "":
        AnalyzeSingleDevice(SQLiteConnection, arguments)
    elif arguments.network != "":
        AnalyzeNetwork(SQLiteConnection, arguments)
    else:
        DoAnalyze(SQLiteConnection, arguments)
    #=====================================================
    # Close database connection
    if(SQLiteConnection):
        SQLiteConnection.close()
#=======================================================================================================================================
#=======================================================================================================================================
if __name__ == "__main__":
    Main()
#=======================================================================================================================================
#=======================================================================================================================================
