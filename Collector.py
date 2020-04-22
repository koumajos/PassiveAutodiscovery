#!/usr/bin/python3.6
"""
Collector script analyze IP flow that get from PassiveAutodiscovery module. 

Collector get database connection, arguments and IP flow.
IP flow si analyzed and arguemnts specificate how to do it.
The analyze get information from IP flow and add them to sqlite3 database. 
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
    
    Parameters:
    -----------
    IP : str
    
    PORT : int

    table : str

    cursor : sqlite3

    SQLiteConnection : sqlite3

    arguments : argparse   
    """
    cursor.execute("SELECT * FROM {tb} WHERE PortNumber={pos}".format(tb="Services", pos=PORT ) )
    row = cursor.fetchone()
    if row:     #if port is services  
        cursor.execute("SELECT * FROM {tb} WHERE IP='{io}' AND PortNumber={pos}".format(tb=table, io=IP, pos=PORT ) )
        rows = cursor.fetchall()
        if rows:        #if port and IP is in database, do nothing
            return
        else:           #push services to db
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
def NewDependencies(table, SRC_IP, DST_IP, SRC_PORT, DST_PORT, PACKETS, BYTES, cursor, SQLiteConnection, arguments):
    """
    
    Parameters:
    -----------
    
    Returns:
    --------
    
    """
    if arguments.UsualyPorts == True:
        try:
            cursor.execute("SELECT * FROM Services WHERE PortNumber={pts} OR PortNumber={pos}".format(pts=SRC_PORT, pos=DST_PORT ) )
            row = cursor.fetchone()
            if not row:
                return
        except sqlite3.IntegrityError:
            print("Error while SELECT")            
            return
    #=================================================================================================================================================================    
    try:    
        cursor.execute("SELECT * FROM {tb} WHERE IP_origin='{io}' AND IP_target='{it}' AND (Port_target={pt} OR Port_origin={po} OR Port_target={pts} OR Port_origin={pos})".format(tb=table, io=SRC_IP, it=DST_IP, pt=DST_PORT, po=DST_PORT, pts=SRC_PORT, pos=SRC_PORT ) )
        rows1 = cursor.fetchone()
    except sqlite3.IntegrityError:
        print("Error in SELECT")
        return
    #=================================================================================================================================================================    
    if rows1:   #if record rows1 is in database, then update PACKETS and BYTES
        NumPackets = rows1[5] + PACKETS
        try:    
            cursor.execute("UPDATE {tb} SET NumPackets={NP} WHERE IP_origin='{io}' AND IP_target='{it}' AND (Port_target='{pt}' OR Port_origin='{po}' OR Port_target='{pts}' OR Port_origin='{pos}')".format(tb=table, io=SRC_IP, it=DST_IP, pt=DST_PORT, po=DST_PORT, pts=SRC_PORT, pos=SRC_PORT, NP=NumPackets ) )
            SQLiteConnection.commit()        
        except sqlite3.IntegrityError:
            print("Error with inserting into table ", table)
        return
    #=================================================================================================================================================================    
    cursor.execute("SELECT * FROM {tb} WHERE IP_origin='{io}' AND IP_target='{it}' AND (Port_target={pt} OR Port_origin={po} OR Port_target={pts} OR Port_origin={pos})".format(tb=table, io=DST_IP, it=SRC_IP, pt=DST_PORT, po=DST_PORT, pts=SRC_PORT, pos=SRC_PORT ) )
    rows2 = cursor.fetchone()
    #=================================================================================================================================================================    
    if rows2: #else if record rows2 is in database, then update PACKETS and BYTES
        NumPackets = rows2[5] + PACKETS
        try:
            cursor.execute("UPDATE {tb} SET NumPackets={NP} WHERE IP_origin='{io}' AND IP_target='{it}' AND (Port_target='{pt}' OR Port_origin='{po}' OR Port_target='{pts}' OR Port_origin='{pos}')".format(tb=table, io=DST_IP, it=SRC_IP, pt=DST_PORT, po=DST_PORT, pts=SRC_PORT, pos=SRC_PORT, NP=NumPackets ) )
            SQLiteConnection.commit()        
        except sqlite3.IntegrityError:
            print("Error with inserting into table ", table)    
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
            print("Error with inserting into table ", table)
#=================================================================================================================================
#=================================================================================================================================
def DHCP(SRC_IP, DST_IP, SRC_PORT, DST_PORT, TIME, cursor, SQLiteConnection):
    """
    
    Parameters:
    -----------
    
    Returns:
    --------
    
    """
    if (SRC_PORT == 68 and DST_PORT == 67) or (SRC_PORT == 546 and DST_PORT == 547):
        #print("DHCP for ip address: ", SRC_IP)
        try:
            cursor.execute("INSERT INTO DHCP (DeviceIP, ServerIP, Time) VALUES ('%s', '%s', '%s')"% (SRC_IP, DST_IP, TIME) )
            SQLiteConnection.commit()
        except sqlite3.IntegrityError:
            print("Error with inserting into table DHCP")
    elif (SRC_PORT == 67 and DST_PORT == 68) or (SRC_PORT == 547 and DST_PORT == 546):
        #print("DHCP for ip address: ", DST_IP)
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
    """
    
    Parameters:
    -----------
    
    Returns:
    --------
    
    """
    cursor.execute("SELECT * FROM Routers WHERE MAC='%s' AND IP='%s'" % (MAC, IP))
    row = cursor.fetchone()
    if row:
        return    
    else:
        #print("New device ", IP, " behind router ", MAC)
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
    
    Parameters:
    -----------
    
    Returns:
    --------
    
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
    """
    
    Parameters:
    -----------
    
    Returns:
    --------
    
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
            if row[4] != '':    #check if it currect recod of MAC address
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
    """
    
    Parameters:
    -----------
    
    Returns:
    --------
    
    """
    cursor.execute("SELECT * FROM LocalDevice WHERE LocalDevice.IP='%s'" % IP)
    row = cursor.fetchone()
    if row:
        try:
            cursor.execute("UPDATE LocalDevice SET LastCom={LC} WHERE IP='{ip}'".format(LC=TIME, ip=IP) )
            SQLiteConnection.commit()
        except sqlite3.IntegrityError:
            print("Error with updating value in table LocalDevice")
        return
    else:
        if arguments.localdev == True:
            print("New local device: ", IP)
        try:
            cursor.execute("INSERT INTO LocalDevice (IP, LastCom) VALUES ('%s', '%s')" % (IP, TIME) )
            SQLiteConnection.commit()
        except sqlite3.IntegrityError:
            print("Error with inserting into table LocalDevice")
#=================================================================================================================================
#=================================================================================================================================
#deleting small packets dependencies from global
def DeleteGlobalDependencies(SQLiteConnection, PacketNumber):
    """
    
    Parameters:
    -----------
    
    Returns:
    --------
    
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
    """
    
    Parameters:
    -----------
    
    Returns:
    --------
    
    """
    MACtemplate = True
    SrcIP = ipaddress.ip_address(rec.SRC_IP)
    DstIP = ipaddress.ip_address(rec.DST_IP)    
    ban1 = ipaddress.ip_address('0.0.0.0')
    ban2 = ipaddress.ip_address('255.255.255.255')
    if SrcIP.is_multicast or DstIP.is_multicast:
        return
    try:    
        if rec.DST_MAC == "ff:ff:ff:ff:ff:ff" or rec.SRC_MAC == "ff:ff:ff:ff:ff:ff":
            return
    except:
        MACtemplate = False    
    if rec.SRC_IP == ban1 or rec.DST_IP == ban1:
        return
    if rec.SRC_IP == ban2 or rec.DST_IP == ban2:
        return
    src = False    
    dst = False    
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
    if arguments.OnlySetNetworks == True:        
        if src:        #Source Device is in local network
            NewDevice(rec.SRC_IP, rec.TIME_LAST, cursor, SQLiteConnection, arguments)
            if MACtemplate == True:
                MAC(rec.SRC_IP, rec.SRC_MAC, rec.TIME_LAST, cursor, SQLiteConnection, arguments)                
            if DstIP.is_private or dst:    #Destination Device is in local network
                NewDevice(rec.DST_IP, rec.TIME_LAST, cursor, SQLiteConnection, arguments)        
                if MACtemplate == True:
                    MAC(rec.DST_IP, rec.DST_MAC, rec.TIME_LAST, cursor, SQLiteConnection, arguments)                
                #=====================================================================================
                NewDependencies("Dependencies", rec.SRC_IP, rec.DST_IP, rec.SRC_PORT, rec.DST_PORT, rec.PACKETS, rec.BYTES, cursor, SQLiteConnection, arguments)
                Services(rec.SRC_IP, rec.SRC_PORT, "LocalServices", cursor, SQLiteConnection, arguments)
                Services(rec.DST_IP, rec.DST_PORT, "LocalServices", cursor, SQLiteConnection, arguments)        
                DHCP(rec.SRC_IP, rec.DST_IP, rec.SRC_PORT, rec.DST_PORT, rec.TIME_LAST, cursor, SQLiteConnection)                    
            else:    #Destination Device is in global network
                Services(rec.SRC_IP, rec.SRC_PORT, "LocalServices", cursor, SQLiteConnection, arguments)
                if arguments.GlobalDependencies == True:
                    NewDependencies("Global", rec.SRC_IP, rec.DST_IP, rec.SRC_PORT, rec.DST_PORT, rec.PACKETS, rec.BYTES, cursor, SQLiteConnection, arguments)
                    Services(rec.DST_IP, rec.DST_PORT, "GlobalServices", cursor, SQLiteConnection, arguments)
                if MACtemplate == True:
                    Routers(rec.DST_IP, rec.DST_MAC, cursor, SQLiteConnection)
        else:    #Source Device is in global network
            if dst:
                NewDevice(rec.DST_IP, rec.TIME_LAST, cursor, SQLiteConnection, arguments)        
                Services(rec.DST_IP, rec.DST_PORT, "LocalServices", cursor, SQLiteConnection, arguments)
                #=====================================================================================        
                if arguments.GlobalDependencies == True:
                    NewDependencies("Global", rec.SRC_IP, rec.DST_IP, rec.SRC_PORT, rec.DST_PORT, rec.PACKETS, rec.BYTES, cursor, SQLiteConnection, arguments)
                    Services(rec.SRC_IP, rec.SRC_PORT, "GlobalServices", cursor, SQLiteConnection, arguments)
                if MACtemplate == True:
                    MAC(rec.DST_IP, rec.DST_MAC, rec.TIME_LAST, cursor, SQLiteConnection, arguments)                
                    Routers(rec.SRC_IP, rec.SRC_MAC, cursor, SQLiteConnection)
            else:
                return 
    else:
        if SrcIP.is_private or src:        #Source Device is in local network
            NewDevice(rec.SRC_IP, rec.TIME_LAST, cursor, SQLiteConnection, arguments)
            if MACtemplate == True:
                MAC(rec.SRC_IP, rec.SRC_MAC, rec.TIME_LAST, cursor, SQLiteConnection, arguments)                
            if DstIP.is_private or dst:    #Destination Device is in local network
                NewDevice(rec.DST_IP, rec.TIME_LAST, cursor, SQLiteConnection, arguments)        
                if MACtemplate == True:
                    MAC(rec.DST_IP, rec.DST_MAC, rec.TIME_LAST, cursor, SQLiteConnection, arguments)                
                #=====================================================================================
                NewDependencies("Dependencies", rec.SRC_IP, rec.DST_IP, rec.SRC_PORT, rec.DST_PORT, rec.PACKETS, rec.BYTES, cursor, SQLiteConnection, arguments)
                Services(rec.SRC_IP, rec.SRC_PORT, "LocalServices", cursor, SQLiteConnection, arguments)
                Services(rec.DST_IP, rec.DST_PORT, "LocalServices", cursor, SQLiteConnection, arguments)        
                DHCP(rec.SRC_IP, rec.DST_IP, rec.SRC_PORT, rec.DST_PORT, rec.TIME_LAST, cursor, SQLiteConnection)                    
            else:    #Destination Device is in global network
                Services(rec.SRC_IP, rec.SRC_PORT, "LocalServices", cursor, SQLiteConnection, arguments)
                if arguments.GlobalDependencies == True:
                    NewDependencies("Global", rec.SRC_IP, rec.DST_IP, rec.SRC_PORT, rec.DST_PORT, rec.PACKETS, rec.BYTES, cursor, SQLiteConnection, arguments)
                    Services(rec.DST_IP, rec.DST_PORT, "GlobalServices", cursor, SQLiteConnection, arguments)
                if MACtemplate == True:
                    Routers(rec.DST_IP, rec.DST_MAC, cursor, SQLiteConnection)
        else:    #Source Device is in global network
            if DstIP.is_private or dst:
                NewDevice(rec.DST_IP, rec.TIME_LAST, cursor, SQLiteConnection, arguments)        
                #=====================================================================================        
                Services(rec.DST_IP, rec.DST_PORT, "LocalServices", cursor, SQLiteConnection, arguments)
                if arguments.GlobalDependencies == True:
                    NewDependencies("Global", rec.SRC_IP, rec.DST_IP, rec.SRC_PORT, rec.DST_PORT, rec.PACKETS, rec.BYTES, cursor, SQLiteConnection, arguments)
                    Services(rec.SRC_IP, rec.SRC_PORT, "GlobalServices", cursor, SQLiteConnection, arguments)
                if MACtemplate == True:
                    MAC(rec.DST_IP, rec.DST_MAC, rec.TIME_LAST, cursor, SQLiteConnection, arguments)                
                    Routers(rec.SRC_IP, rec.SRC_MAC, cursor, SQLiteConnection)
            else:
                return 
#=================================================================================================================================
#=================================================================================================================================
#=================================================================================================================================
