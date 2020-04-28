#!/usr/bin/python3.6
"""Collector script:

    Collector script analyze IP flow that get from PassiveAutodiscovery module. 

    Collector get database connection, arguments and IP flow.
    IP flow si analyzed and arguemnts specificate how to do it.
    The analyze get information from IP flow and add them to sqlite3 database. 

    Collector function collector is call from PassiveAutodiscovery module.
"""
#libraries for working with OS UNIX files and system
import sys
import os
#library for working with IP addresses
import ipaddress
#library for working with sqlite3 database
import sqlite3
#=================================================================================================================================
#=================================================================================================================================
#IP = ip address; PORT = transport layer port; table = string of table (local or global services); cursor and SQLiteConnection = sqlite3 database
def Services(IP, PORT, table, cursor, SQLiteConnection, arguments):
    """Check if port in IP flow is used by some role of device (services), if yes and if it is NOT in database, put record to sqlite3 database.
    
    Parameters
    -----------
    IP : str
        IP address of device that comunicate on protocol with port number PORT.
    PORT : int
        Port number of used protocol.
    table : str
        Name of the table to safe potencial record (if device is  "local": table == LocalServices, if device is "global": table == GlobalServices).
    cursor : sqlite3
        Cursor to sqlite3 database for execute SQL queries.
    SQLiteConnection : sqlite3
        Connection to sqlite3 database.
    arguments : argparse   
        Setted argument of the PassiveAutodiscovery module.
    """
    cursor.execute("SELECT * FROM {tb} WHERE PortNumber={pos}".format(tb="Services", pos=PORT ) )
    row = cursor.fetchone()
    if row:     #if port is services (role of device) 
        cursor.execute("SELECT * FROM {tb} WHERE IP='{io}' AND PortNumber={pos}".format(tb=table, io=IP, pos=PORT ) )
        rows = cursor.fetchall()
        if rows:        #if port and IP is in database, do nothing (record exists)
            return
        else:           #else push new record to db
            if  arguments.localserv == True and table == "LocalServices":
                print("New local services: ", IP, " -> ", row[1])
            if arguments.globalserv == True and table == "GlobalServices":
                print("New global services: ", IP, " -> ", row[1])
            try:
                cursor.execute("INSERT INTO {tb} (PortNumber, IP) VALUES ('{port}', '{ip}')".format(tb=table, port=PORT, ip=IP) )
                SQLiteConnection.commit()
            except sqlite3.IntegrityError:
                print("Error with inserting into table ", table)
    else:
        return
#=================================================================================================================================
#=================================================================================================================================
#Dependencies resolved, push into database or update
def NewDependencies(table, SRC_IP, DST_IP, SRC_PORT, DST_PORT, PACKETS, cursor, SQLiteConnection, arguments):
    """If dependency (local or global) doesn't exist, function will add record about it to database. Else function will find the record and update packet number on this dependency.
    
    Parameters
    -----------
    table : str
        Table where record about dependency may be safed. ("Dependencies" - for dependencies between "local" devices, "Global" - for dependencies between "local" device and global device)    
    SRC_IP : str
        Source IP address of dependency.
    DST_IP : str
        Destination IP address of dependency.
    SRC_PORT : int
        Source port number of dependency.
    DST_PORT : int
        Destination prot of dependency.
    PACKETS : int
        Number of packet carryed in dependency(single IP flow).
    cursor : sqlite3
        Cursor to sqlite3 database for execute SQL queries.
    SQLiteConnection : sqlite3
        Connection to sqlite3 database.
    arguments : argparse   
        Setted argument of the PassiveAutodiscovery module.
    """
    if arguments.UsualyPorts == True:   #if analyze only "usualy" protocols (protocols in table Services), than check if PORT is one of these protocols
        try:
            cursor.execute("SELECT * FROM Services WHERE PortNumber={pts} OR PortNumber={pos}".format(pts=SRC_PORT, pos=DST_PORT ) )
            row = cursor.fetchone()
            if not row:
                return  
        except sqlite3.IntegrityError:
            print("Error while SELECT ", sqlite3.IntegrityError)            
            return
    #=================================================================================================================================================================    
    try:    
        cursor.execute("SELECT * FROM {tb} WHERE IP_origin='{io}' AND IP_target='{it}' AND (Port_target={pt} OR Port_origin={po} OR Port_target={pts} OR Port_origin={pos})".format(tb=table, io=SRC_IP, it=DST_IP, pt=DST_PORT, po=DST_PORT, pts=SRC_PORT, pos=SRC_PORT ) )
        rows1 = cursor.fetchone()
    except sqlite3.IntegrityError:
        print("Error in SELECT ", sqlite3.IntegrityError)
        return
    #=================================================================================================================================================================    
    if rows1:   #if record rows1 is in database, then update PACKETS
        NumPackets = rows1[5] + PACKETS
        try:    
            cursor.execute("UPDATE {tb} SET NumPackets={NP} WHERE IP_origin='{io}' AND IP_target='{it}' AND (Port_target='{pt}' OR Port_origin='{po}' OR Port_target='{pts}' OR Port_origin='{pos}')".format(tb=table, io=SRC_IP, it=DST_IP, pt=DST_PORT, po=DST_PORT, pts=SRC_PORT, pos=SRC_PORT, NP=NumPackets ) )
            SQLiteConnection.commit()        
        except sqlite3.IntegrityError:
            print("Error with updating record in table ", table, "with error ", sqlite3.IntegrityError)
        return
    #=================================================================================================================================================================    
    cursor.execute("SELECT * FROM {tb} WHERE IP_origin='{io}' AND IP_target='{it}' AND (Port_target={pt} OR Port_origin={po} OR Port_target={pts} OR Port_origin={pos})".format(tb=table, io=DST_IP, it=SRC_IP, pt=DST_PORT, po=DST_PORT, pts=SRC_PORT, pos=SRC_PORT ) )
    rows2 = cursor.fetchone()
    #=================================================================================================================================================================    
    if rows2: #if record rows2 is in database, then update PACKETS
        NumPackets = rows2[5] + PACKETS
        try:
            cursor.execute("UPDATE {tb} SET NumPackets={NP} WHERE IP_origin='{io}' AND IP_target='{it}' AND (Port_target='{pt}' OR Port_origin='{po}' OR Port_target='{pts}' OR Port_origin='{pos}')".format(tb=table, io=DST_IP, it=SRC_IP, pt=DST_PORT, po=DST_PORT, pts=SRC_PORT, pos=SRC_PORT, NP=NumPackets ) )
            SQLiteConnection.commit()        
        except sqlite3.IntegrityError:
            print("Error with updating record in table ", table, "with error ", sqlite3.IntegrityError)    
    #=================================================================================================================================================================    
    else:   #else found a new local or global dependencies
        if arguments.localdependencies == True and table == "Dependencies":
            print("new local dependencies: ", SRC_IP, " -> ", DST_IP)
        if arguments.globaldependencies == True and table == "Global":
            print("new global dependencies: ", SRC_IP, " -> ", DST_IP)
        try:
            cursor.execute("INSERT INTO {tb} (IP_origin, IP_target, Port_origin, Port_target, NumPackets, NumBytes) VALUES ('%s', '%s', '%s', '%s', '%s', '%s')".format(tb=table) % (SRC_IP, DST_IP, SRC_PORT, DST_PORT, PACKETS, "") )
            SQLiteConnection.commit()
        except sqlite3.IntegrityError:
            print("Error with inserting into table ", table, "with error ", sqlite3.IntegrityError)
#=================================================================================================================================
#=================================================================================================================================
def DHCP(SRC_IP, DST_IP, SRC_PORT, DST_PORT, TIME, cursor, SQLiteConnection):
    """If IP flow is DHCP traffic, then safe record of it to table DHCP.
    
    Parameters
    -----------
    SRC_IP : str
        Source IP address of dependency.
    DST_IP : str
        Destination IP address of dependency.
    SRC_PORT : int
        Source port number of dependency.
    DST_PORT : int
        Destination prot of dependency.
    TIME : int
        Unix time of IP flow.
    cursor : sqlite3
        Cursor to sqlite3 database for execute SQL queries.
    SQLiteConnection : sqlite3
        Connection to sqlite3 database.
    """
    if (SRC_PORT == 68 and DST_PORT == 67) or (SRC_PORT == 546 and DST_PORT == 547):
        try:
            cursor.execute("INSERT INTO DHCP (DeviceIP, ServerIP, Time) VALUES ('%s', '%s', '%s')"% (SRC_IP, DST_IP, TIME) )
            SQLiteConnection.commit()
        except sqlite3.IntegrityError:
            print("Error with inserting into table DHCP")
    elif (SRC_PORT == 67 and DST_PORT == 68) or (SRC_PORT == 547 and DST_PORT == 546):
        try:
            cursor.execute("INSERT INTO DHCP (DeviceIP, ServerIP, Time) VALUES ('%s', '%s', '%s')"% (DST_IP, SRC_IP, TIME) )
            SQLiteConnection.commit()
        except sqlite3.IntegrityError:
            print("Error with inserting into table DHCP")
    else:
        return
#=================================================================================================================================
#=================================================================================================================================
#Add router dependencies to database
#IP = IP address of device behind router; MAC = mac address of router, cursor and SQLiteConnection = database connection
def Routers(IP, MAC, cursor, SQLiteConnection):
    """Function for adding record to table Routers. The record is MAC address of router and Ip address of device behind him or router himself.
    
    Parameters
    -----------
    IP : str
        IP address of device behind router (or IP address of the router).
    MAC : str
        MAC address of router.
    cursor : sqlite3
        Cursor to sqlite3 database for execute SQL queries.
    SQLiteConnection : sqlite3
        Connection to sqlite3 database.
    """
    cursor.execute("SELECT * FROM Routers WHERE MAC='%s' AND IP='%s'" % (MAC, IP))
    row = cursor.fetchone()
    if row:
        return    
    else:
        try:
            cursor.execute("INSERT INTO Routers (MAC, IP) VALUES ('%s', '%s')"% (MAC, IP) )
            SQLiteConnection.commit()
        except sqlite3.IntegrityError:
            print("Error with inserting into table Routers")
#=================================================================================================================================
#=================================================================================================================================
#Add MAC
def MACAdd(IP, MAC, TIME, cursor, SQLiteConnection, arguments):
    """
    
    Parameters
    -----------
    IP : str
        IP address of device.
    MAC : str
        MAC address of device.
    TIME : int
        Unix time of IP flow where was combiantion IP and MAC used.
    cursor : sqlite3
        Cursor to sqlite3 database for execute SQL queries.
    SQLiteConnection : sqlite3
        Connection to sqlite3 database.
    arguments : argparse   
        Setted argument of the PassiveAutodiscovery module.
    """
    if arguments.macdev == True:
        print("New MAC address: ", IP, " -> ", MAC)
    try:
        cursor.execute("INSERT INTO MAC (IP, MAC, FirstUse, LastUse) VALUES ('%s', '%s', '%s', '%s')" % (IP, MAC, TIME, '') )
        SQLiteConnection.commit()
    except sqlite3.IntegrityError:
        print("Error with inserting into table MAC")
#=================================================================================================================================
#Check if MAC address is in database for this IP address and if no add it to database, if yes do stuffs
#=================================================================================================================================
def MAC(IP, MAC, TIME, cursor, SQLiteConnection, arguments):
    """If device is is in local segemnt, the module can rosolve his MAC address and add record of it to table MAC. If it's router and behind it is local subnet (2 or more local device or one global device on this mac address (the same IP version)) add all record of this mac address from table MAC to table Router and add new record from this IP flow.
    
    Parameters
    -----------
    IP : str
        IP address of the device.
    MAC : str
        MAC address of the device.
    TIME : int
        Unix time of the IP flow.
    cursor : sqlite3
        Cursor to sqlite3 database for execute SQL queries.
    SQLiteConnection : sqlite3
        Connection to sqlite3 database.
    arguments : argparse   
        Setted argument of the PassiveAutodiscovery module.
    """
    #=======If device mac is router, do not continue in MAC code=======    
    cursor.execute("SELECT * FROM Routers WHERE MAC='%s'" % MAC )
    routers = cursor.fetchall()
    if routers:
        Routers(IP, MAC, cursor, SQLiteConnection)
        return    
    #==================================================================    
    cursor.execute("SELECT * FROM MAC WHERE MAC.MAC='%s'" % MAC)
    rows = cursor.fetchall()
    if rows:
        tmp = 0
        for row in rows:
            if row[4] != '':    #check if it currect recod of MAC address (the old one have in row[4] time of end using)
                continue            
            newip = ipaddress.ip_address(IP)        
            oldip = ipaddress.ip_address(row[1])        
            if newip == oldip:   #if ip match, end it 
                return           
            elif newip.version == oldip.version:    #if not and have same version (one MAC can have both of IPv4 and IPv6 addresses)
                if newip.is_link_local == True or oldip.is_link_local == True:
                    tmp = 1
                    continue    
                #TODO TEST THIS!!! 
                #Until I will have change test this on real local network with more local segments, will be this comment (SARS-CoV-2 is responsible for this)                
                #Think of this commented code:                 
                tmp = 2                
#                cursor.execute("SELECT * FROM DHCP WHERE DeviceIP='%s'" % IP)
#                DHCProws = cursor.fetchall()
#                if DHCProws:
#                    lastrow = DHCProws[0]                
#                    for DHCProw in DHCProws:
#                        if DHCProw[3] > lastrow[3]:    #if DHCP com. for IP was after MAC use and  
#                            lastrow = DHCProw         
#                        else:
#                            None
#                    if float(TIME) > float(DHCProw[3]) and float(row[3]) < float(DHCProw[3]):
#                        try:
#                            cursor.execute("UPDATE MAC SET LastUse='%s' WHERE MAC.IP='%s' AND MAC.MAC='%s' AND MAC.FirstUse='%s'" % (TIME, row[1], row[2], row[3]) )
#                            SQLiteConnection.commit()                    
#                        except sqlite3.IntegrityError:
#                            None                        
#                        MACAdd(IP, MAC, TIME, cursor, SQLiteConnection, arguments)
#                        return
#                    elif float(TIME) > float(DHCProw[3]) and float(row[3]) > float(DHCProw[3]):
#                        Routers(IP, MAC, cursor, SQLiteConnection)
#                        Routers(row[1], MAC, cursor, SQLiteConnection)
#                        try:                        
#                            cursor.execute("DELETE FROM MAC WHERE MAC.IP='%s' AND MAC.MAC='%s' AND MAC.FirstUse='%s'" % (row[1], row[2], row[3]) )
#                            SQLiteConnection.commit()
#                        except sqlite3.IntegrityError:
#                            None
#                        return                    
#                    else:
#                        continue
#                else:
#                    tmp = 1
            else:           
                if tmp == 2:
                    continue
                else:
                    tmp = 1        
        if tmp == 1:
            MACAdd(IP, MAC, TIME, cursor, SQLiteConnection, arguments)
            return
    else:
        MACAdd(IP, MAC, TIME, cursor, SQLiteConnection, arguments)
#=================================================================================================================================
#=================================================================================================================================
#Check if local IP address is in database, if not push it do table LocalDevice
def NewDevice(IP, TIME, cursor, SQLiteConnection, arguments):
    """This funcion check if "local" device is in sqlite3 database table LocalDevice. If isn't, add it to table. If is, update last comunication in record of it.
    
    Parameters
    -----------
    IP : str
        IP address of the local device.
    TIME : int
        Unix time of the IP flow.    
    cursor : sqlite3
        Cursor to sqlite3 database for execute SQL queries.
    SQLiteConnection : sqlite3
        Connection to sqlite3 database.
    arguments : argparse   
        Setted argument of the PassiveAutodiscovery module.
    """
    cursor.execute("SELECT * FROM LocalDevice WHERE LocalDevice.IP='%s'" % IP)      #check if exists
    row = cursor.fetchone()
    if row:
        try:        #yes - update time
            cursor.execute("UPDATE LocalDevice SET LastCom={LC} WHERE IP='{ip}'".format(LC=TIME, ip=IP) )
            SQLiteConnection.commit()
        except sqlite3.IntegrityError:
            print("Error with updating value in table LocalDevice with error ", sqlite3.IntegrityError)
        return
    else:       #no - add new record
        if arguments.localdev == True:
            print("New local device: ", IP)
        try:
            cursor.execute("INSERT INTO LocalDevice (IP, LastCom) VALUES ('%s', '%s')" % (IP, TIME) )
            SQLiteConnection.commit()
        except sqlite3.IntegrityError:
            print("Error with inserting into table LocalDevice with error ", sqlite3.IntegrityError)
#=================================================================================================================================
#=================================================================================================================================
#deleting small packets dependencies from global
def DeleteGlobalDependencies(SQLiteConnection, PacketNumber):
    """Delete global dependencies from table Global that have number of packer smaller then number PacketNumber.
    
    Parameters
    -----------
    SQLiteConnection : sqlite3
        Connection to sqlite3 database.
    PacketNumber : int
        Number of packet that is line for delete.
    """
    cursor = SQLiteConnection.cursor()
    try:
        cursor.execute("DELETE FROM Global WHERE NumPackets < {number} AND (Port_origin != 53 OR Port_target != 53 OR Port_origin != 68 OR Port_target != 68 OR Port_origin != 67 OR Port_target != 67)".format(number=PacketNumber))
        SQLiteConnection.commit()
    except sqlite3.IntegrityError:
        print("Error in deleting rows from Global")
#=================================================================================================================================
#=================================================================================================================================
#collector collect information from ipflows and push them into database
def collector(rec, SQLiteConnection, cursor, arguments):
    """Main function of this script. This function receive IP flow, database proms and arguments. Then work with received IP flow to get information from it and record of it safe (update) in sqlite3 database that received.
    
    Parameters
    -----------
    rec : pytrap
        Received IP flow to analyze.
    cursor : sqlite3
        Cursor to sqlite3 database for execute SQL queries.
    SQLiteConnection : sqlite3
        Connection to sqlite3 database.
    arguments : argparse   
        Setted argument of the PassiveAutodiscovery module.
    """
    #===============================================================================
    #if mac address is broadcast then ignore this IP flow, also this check if MAC address is in record of IP flows, if isn't this will set not working with it.    
    MACtemplate = True
    try:    
        if rec.DST_MAC == "ff:ff:ff:ff:ff:ff" or rec.SRC_MAC == "ff:ff:ff:ff:ff:ff":
            return
    except:
        MACtemplate = False
    #===============================================================================    
    #IP address from IP flow to format where can be ease work with    
    SrcIP = ipaddress.ip_address(rec.SRC_IP)
    DstIP = ipaddress.ip_address(rec.DST_IP)    
    #===============================================================================    
    #banned Ip address (broadcast,...)    
    ban1 = ipaddress.ip_address('0.0.0.0')
    ban2 = ipaddress.ip_address('255.255.255.255')
    #===============================================================================    
    #check if IP address isn't banned (multicasts,broadcasts), if yes return    
    if SrcIP.is_multicast or DstIP.is_multicast:
        return
    if rec.SRC_IP == ban1 or rec.DST_IP == ban1:
        return
    if rec.SRC_IP == ban2 or rec.DST_IP == ban2:
        return
    #===============================================================================    
    src = False     #src is boolean - True if SRC_IP is from setted networks     
    dst = False     #dst is boolean - True if SRC_IP is from setted networks
    #chceck if IP addresses isn't broadcasts of setted networks, if yes return    
    for nip in arguments.networks:
        NIP = ipaddress.ip_network(nip)
        if SrcIP in NIP:
            if NIP.version == 4:
                NIPv4 = ipaddress.IPv4Network(nip)       
                if SrcIP == NIPv4.broadcast_address:
                    return
            src = True
            break
        elif DstIP in NIP:
            if NIP.version == 4:
                NIPv4 = ipaddress.IPv4Network(nip)       
                if DstIP == NIPv4.broadcast_address:
                    return        
            dst = True
            break
        else:
            continue
    #===============================================================================    
    #Main funciton which call function for safing data to sqlite3 database    
    if (SrcIP.is_private and arguments.OnlySetNetworks == False) or src:        #Source Device is in local network
        NewDevice(rec.SRC_IP, rec.TIME_LAST, cursor, SQLiteConnection, arguments)
        if MACtemplate == True:
            MAC(rec.SRC_IP, rec.SRC_MAC, rec.TIME_LAST, cursor, SQLiteConnection, arguments)                
        if (DstIP.is_private and arguments.OnlySetNetworks == False) or dst:    #Destination Device is in local network
            NewDevice(rec.DST_IP, rec.TIME_LAST, cursor, SQLiteConnection, arguments)        
            if MACtemplate == True:
                MAC(rec.DST_IP, rec.DST_MAC, rec.TIME_LAST, cursor, SQLiteConnection, arguments)                
            #=====================================================================================
            NewDependencies("Dependencies", rec.SRC_IP, rec.DST_IP, rec.SRC_PORT, rec.DST_PORT, rec.PACKETS, cursor, SQLiteConnection, arguments)
            Services(rec.SRC_IP, rec.SRC_PORT, "LocalServices", cursor, SQLiteConnection, arguments)
            Services(rec.DST_IP, rec.DST_PORT, "LocalServices", cursor, SQLiteConnection, arguments)        
            DHCP(rec.SRC_IP, rec.DST_IP, rec.SRC_PORT, rec.DST_PORT, rec.TIME_LAST, cursor, SQLiteConnection)                    
        else:    #Destination Device is in global network
            Services(rec.SRC_IP, rec.SRC_PORT, "LocalServices", cursor, SQLiteConnection, arguments)
            if arguments.GlobalDependencies == True:
                NewDependencies("Global", rec.SRC_IP, rec.DST_IP, rec.SRC_PORT, rec.DST_PORT, rec.PACKETS, cursor, SQLiteConnection, arguments)
                Services(rec.DST_IP, rec.DST_PORT, "GlobalServices", cursor, SQLiteConnection, arguments)
            if MACtemplate == True:
                Routers(rec.DST_IP, rec.DST_MAC, cursor, SQLiteConnection)
    else:    #Source Device is in global network
        if (DstIP.is_private and arguments.OnlySetNetworks == False) or dst:
            NewDevice(rec.DST_IP, rec.TIME_LAST, cursor, SQLiteConnection, arguments)        
            #=====================================================================================        
            Services(rec.DST_IP, rec.DST_PORT, "LocalServices", cursor, SQLiteConnection, arguments)
            if arguments.GlobalDependencies == True:
                NewDependencies("Global", rec.SRC_IP, rec.DST_IP, rec.SRC_PORT, rec.DST_PORT, rec.PACKETS, cursor, SQLiteConnection, arguments)
                Services(rec.SRC_IP, rec.SRC_PORT, "GlobalServices", cursor, SQLiteConnection, arguments)
            if MACtemplate == True:
                MAC(rec.DST_IP, rec.DST_MAC, rec.TIME_LAST, cursor, SQLiteConnection, arguments)                
                Routers(rec.SRC_IP, rec.SRC_MAC, cursor, SQLiteConnection)
        else:
            return
#=================================================================================================================================
#=================================================================================================================================
#=================================================================================================================================
