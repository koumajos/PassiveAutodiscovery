#!/usr/bin/python3.6
import sys
import os
import ipaddress
import sqlite3

#=================================================================================================================================
#Check if port is some services and if port services is in database, if port is a service and if it is NOT in database, put in them
#IP = ip address; PORT = transport layer port; table = string of table (local or global services); cursor and SQLiteConnection = sqlite3 database
def Services(IP, PORT, table, cursor, SQLiteConnection):
    cursor.execute("SELECT * FROM {tb} WHERE IP='{io}' AND PortNumber={pos}".format(tb=table, io=IP, pos=PORT ) )
    rows = cursor.fetchall()
    if rows:        #if port and IP is in database, do nothing
        return
    else:
        cursor.execute("SELECT * FROM {tb} WHERE PortNumber={pos}".format(tb="Services", pos=PORT ) )
        row = cursor.fetchone()
        if row:     #if port is services, push informatings to database  
            if table == "LocalServices":
                print("New local services: ", IP, " -> ", row[1])
            else:
                print("New global services: ", IP, " -> ", row[1])
            try:
                cursor.execute("INSERT INTO {tb} (PortNumber, IP) VALUES ('{port}', '{ip}')".format(tb=table, port=PORT, ip=IP) )
                SQLiteConnection.commit()
            except sqlite3.IntegrityError:
                print("Error with inserting into table ", table)        
        else:
            return        
#=================================================================================================================================
#Dependencies resolved, push into database or update
def NewDependencies(table, SRC_IP, DST_IP, SRC_PORT, DST_PORT, PACKETS, BYTES, cursor, SQLiteConnection):
    cursor.execute("SELECT * FROM {tb} WHERE IP_origin='{io}' AND IP_target='{it}' AND (Port_target={pt} OR Port_origin={po} OR Port_target={pts} OR Port_origin={pos})".format(tb=table, io=SRC_IP, it=DST_IP, pt=DST_PORT, po=DST_PORT, pts=SRC_PORT, pos=SRC_PORT ) )
    rows1 = cursor.fetchone()
    cursor.execute("SELECT * FROM {tb} WHERE IP_origin='{io}' AND IP_target='{it}' AND (Port_target={pt} OR Port_origin={po} OR Port_target={pts} OR Port_origin={pos})".format(tb=table, io=DST_IP, it=SRC_IP, pt=DST_PORT, po=DST_PORT, pts=SRC_PORT, pos=SRC_PORT ) )
    rows2 = cursor.fetchone()
    #=================================================================================================================================================================    
    if rows1:   #if record rows1 is in database, then update PACKETS and BYTES
        NumPackets = rows1[5] + PACKETS
        NumBytes = rows1[6] + BYTES
        cursor.execute("UPDATE {tb} SET NumPackets={NP} WHERE IP_origin='{io}' AND IP_target='{it}' AND (Port_target='{pt}' OR Port_origin='{po}' OR Port_target='{pts}' OR Port_origin='{pos}')".format(tb=table, io=SRC_IP, it=DST_IP, pt=DST_PORT, po=DST_PORT, pts=SRC_PORT, pos=SRC_PORT, NP=NumPackets ) )
        cursor.execute("UPDATE {tb} SET NumBytes={NB} WHERE IP_origin='{io}' AND IP_target='{it}' AND (Port_target='{pt}' OR Port_origin='{po}' OR Port_target='{pts}' OR Port_origin='{pos}')".format(tb=table, io=SRC_IP, it=DST_IP, pt=DST_PORT, po=DST_PORT, pts=SRC_PORT, pos=SRC_PORT, NB=NumBytes ) )
        SQLiteConnection.commit()
    #=================================================================================================================================================================    
    elif rows2: #else if record rows2 is in database, then update PACKETS and BYTES
        NumPackets = rows2[5] + PACKETS
        NumBytes = rows2[6] + BYTES
        cursor.execute("UPDATE {tb} SET NumPackets={NP} WHERE IP_origin='{io}' AND IP_target='{it}' AND (Port_target='{pt}' OR Port_origin='{po}' OR Port_target='{pts}' OR Port_origin='{pos}')".format(tb=table, io=DST_IP, it=SRC_IP, pt=DST_PORT, po=DST_PORT, pts=SRC_PORT, pos=SRC_PORT, NP=NumPackets ) )
        cursor.execute("UPDATE {tb} SET NumBytes={NB} WHERE IP_origin='{io}' AND IP_target='{it}' AND (Port_target='{pt}' OR Port_origin='{po}' OR Port_target='{pts}' OR Port_origin='{pos}')".format(tb=table, io=DST_IP, it=SRC_IP, pt=DST_PORT, po=DST_PORT, pts=SRC_PORT, pos=SRC_PORT, NB=NumBytes ) )
        SQLiteConnection.commit()    
    #=================================================================================================================================================================    
    else:   #else found a new local or global dependencies
        if table == "Dependencies":
            print("new local dependencies: ", SRC_IP, " -> ", DST_IP)
        else:
            print("new global dependencies: ", SRC_IP, " -> ", DST_IP)
        try:
            cursor.execute("INSERT INTO {tb} (IP_origin, IP_target, Port_origin, Port_target, NumPackets, NumBytes) VALUES ('%s', '%s', '%s', '%s', '%s', '%s')".format(tb=table) % (SRC_IP, DST_IP, SRC_PORT, DST_PORT, PACKETS, BYTES) )
            SQLiteConnection.commit()
        except sqlite3.IntegrityError:
            print("Error with inserting into table ", table)
#=================================================================================================================================
#
#
def DHCP(SRC_IP, DST_IP, SRC_PORT, DST_PORT, TIME, cursor, SQLiteConnection):
    SrcIP = ipaddress.ip_address(SRC_IP)
    DstIP = ipaddress.ip_address(DST_IP)
    ban1 = ipaddress.ip_address('0.0.0.0')
    ban2 = ipaddress.ip_address('255.255.255.255')
    if SrcIP == ban1 or SrcIP == ban2 or DstIP == ban1 or DstIP == ban2:
        return
    if (SRC_PORT == 68 and DST_PORT == 67) or (SRC_PORT == 546 and DST_PORT == 547):
        print("DHCP for ip address: ", SRC_IP)
        try:
            cursor.execute("INSERT INTO DHCP (DeviceIP, ServerIP, Time) VALUES ('%s', '%s', '%s')"% (SRC_IP, DST_IP, TIME) )
            SQLiteConnection.commit()
        except sqlite3.IntegrityError:
            print("Error with inserting into table DHCP")
    elif (SRC_PORT == 67 and DST_PORT == 68) or (SRC_PORT == 547 and DST_PORT == 546):
        print("DHCP for ip address: ", DST_IP)
        try:
            cursor.execute("INSERT INTO DHCP (DeviceIP, ServerIP, Time) VALUES ('%s', '%s', '%s')"% (DST_IP, SRC_IP, TIME) )
            SQLiteConnection.commit()
        except sqlite3.IntegrityError:
            print("Error with inserting into table DHCP")
    else:
        return
#=================================================================================================================================
#Add router dependencies to database
#IP = IP address of device behind router; MAC = mac address of router, cursor and SQLiteConnection = database connection
def Routers(IP, MAC, cursor, SQLiteConnection):
    cursor.execute("SELECT * FROM Routers WHERE MAC='%s' AND IP='%s'" % (MAC, IP))
    row = cursor.fetchone()
    if row:
        return    
    else:
        print("New device ", IP, " behind router ", MAC)
        try:
            cursor.execute("INSERT INTO Routers (MAC, IP) VALUES ('%s', '%s')"% (MAC, IP) )
            SQLiteConnection.commit()
        except sqlite3.IntegrityError:
            print("Error with inserting into table Routers")
#=================================================================================================================================
#Add MAC
def MACAdd(IP, MAC, TIME, cursor, SQLiteConnection):
    print("New MAC address: ", IP, " -> ", MAC)
    try:
        cursor.execute("INSERT INTO MAC (IP, MAC, FirstUse, LastUse) VALUES ('%s', '%s', '%s', '%s')" % (IP, MAC, TIME, '') )
        SQLiteConnection.commit()
    except sqlite3.IntegrityError:
        print("Error with inserting into table MAC")
#=================================================================================================================================
#Check if MAC address is in database for this IP address and if no add it to database, if yes do stuffs
def MAC(IP, MAC, TIME, cursor, SQLiteConnection):
    #=======If device mac is router, do not continue in MAC code=======    
    cursor.execute("SELECT * FROM Routers WHERE MAC='%s'" % MAC )
    routers = cursor.fetchall()
    if routers:
        Routers(IP, MAC, cursor, SQLiteConnection)
        return    
    #==================================================================    
    ipadr = ipaddress.ip_address(IP)
    ban1 = ipaddress.ip_address('0.0.0.0')
    ban2 = ipaddress.ip_address('255.255.255.255')
    if ipadr == ban1 or ipadr == ban2:
        return
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
                if newip.is_link_local or oldip.is_link_local or ipadr.is_multicast:
                    tmp = 1
                    continue    
                #TODO TEST THIS!!!                
                tmp = 2                
                cursor.execute("SELECT * FROM DHCP WHERE DeviceIP='%s'" % IP)
                DHCProws = cursor.fetchall()
                lastrow = DHCProws[0]                
                for DHCProw in DHCProws:
                    if DHCProw[3] > lastrow[3]:    #if DHCP com. for IP was after MAC use and  
                        lastrow = DHCProw         
                    else:
                        None
                if TIME > DHCProw[3] and row[3] < DHCProw[3]:
                    cursor.execute("UPDATE MAC SET LastUse='%s' WHERE MAC.IP='%s' AND MAC.MAC='%s' AND MAC.FirstUse='%s'" % (TIME, row[1], row[2], row[3]) )
                    SQLiteConnection.commit()                    
                    MACAdd(IP, MAC, TIME, cursor, SQLiteConnection)
                    return
                elif TIME > DHCProw[3] and row[3] > DHCProw[3]:
                    Routers(IP, MAC, cursor, SQLiteConnection)
                    Routers(row[1], MAC, cursor, SQLiteConnection)
                    cursor.execute("DELETE FROM MAC WHERE MAC.IP='%s' AND MAC.MAC='%s' AND MAC.FirstUse='%s'" % (row[1], row[2], row[3]) )
                    SQLiteConnection.commit()
                    return                    
                else:
                    continue
            else:           
                if tmp == 2:
                    continue
                else:
                    tmp = 1        
        if tmp == 1:
            MACAdd(IP, MAC, TIME, cursor, SQLiteConnection)
            return
    else:
        MACAdd(IP, MAC, TIME, cursor, SQLiteConnection)
#=================================================================================================================================
#Check if local IP address is in database, if not push it do table LocalDevice
def NewDevice(IP, TIME, cursor, SQLiteConnection):
    ipadr = ipaddress.ip_address(IP)
    ban1 = ipaddress.ip_address('0.0.0.0')
    ban2 = ipaddress.ip_address('255.255.255.255')
    if ipadr == ban1 or ipadr == ban2:
        return
    cursor.execute("SELECT * FROM LocalDevice WHERE LocalDevice.IP='%s'" % IP)
    row = cursor.fetchone()
    if row:
        cursor.execute("UPDATE LocalDevice SET LastCom={LC} WHERE IP='{ip}'".format(LC=TIME, ip=IP) )
        SQLiteConnection.commit()
        return
    else:
        print("New local device: ", IP)
        try:
            cursor.execute("INSERT INTO LocalDevice (IP, LastCom) VALUES ('%s', '%s')" % (IP, TIME) )
            SQLiteConnection.commit()
        except sqlite3.IntegrityError:
            print("Error with inserting into table LocalDevice")
#=================================================================================================================================
#collector collect information from ipflows and push them into database
def collector(rec, SQLiteConnection, NetworkLocalAddresses):
    SrcIP = ipaddress.ip_address(rec.SRC_IP)
    DstIP = ipaddress.ip_address(rec.DST_IP)
    cursor = SQLiteConnection.cursor()
    if SrcIP.is_multicast or DstIP.is_multicast:
        return
    if rec.DST_MAC == "ff:ff:ff:ff:ff:ff" or rec.SRC_MAC == "ff:ff:ff:ff:ff:ff":
        return    
    if rec.SRC_IP == "255.255.255.255" or rec.DST_IP == "255.255.255.255":
        return
    if rec.SRC_IP == "0.0.0.0" or rec.DST_IP == "0.0.0.0":
        return
    src = False    
    dst = False    
    for nip in NetworkLocalAddresses:
        NIP = ipaddress.ip_network(nip)
        if SrcIP in NIP:
            src = True
            break
        elif DstIP in NIP:
            dst = True
            break
        else:
            continue        
    print("src: ", src, "  dst: ", dst)
    if SrcIP.is_private or src:        #Source Device is in local network
        NewDevice(rec.SRC_IP, rec.TIME_LAST, cursor, SQLiteConnection)
        MAC(rec.SRC_IP, rec.SRC_MAC, rec.TIME_LAST, cursor, SQLiteConnection)                
        if DstIP.is_private or dst:    #Destination Device is in local network
            NewDevice(rec.DST_IP, rec.TIME_LAST, cursor, SQLiteConnection)        
            MAC(rec.DST_IP, rec.DST_MAC, rec.TIME_LAST, cursor, SQLiteConnection)                
            #=====================================================================================
            NewDependencies("Dependencies", rec.SRC_IP, rec.DST_IP, rec.SRC_PORT, rec.DST_PORT, rec.PACKETS, rec.BYTES, cursor, SQLiteConnection)
            Services(rec.SRC_IP, rec.SRC_PORT, "LocalServices", cursor, SQLiteConnection)
            Services(rec.DST_IP, rec.DST_PORT, "LocalServices", cursor, SQLiteConnection)        
            DHCP(rec.SRC_IP, rec.DST_IP, rec.SRC_PORT, rec.DST_PORT, rec.TIME_LAST, cursor, SQLiteConnection)                    
        else:    #Destination Device is in global network
            NewDependencies("Global", rec.SRC_IP, rec.DST_IP, rec.SRC_PORT, rec.DST_PORT, rec.PACKETS, rec.BYTES, cursor, SQLiteConnection)
            Services(rec.SRC_IP, rec.SRC_PORT, "LocalServices", cursor, SQLiteConnection)
            Services(rec.DST_IP, rec.DST_PORT, "GlobalServices", cursor, SQLiteConnection)
            Routers(rec.DST_IP, rec.DST_MAC, cursor, SQLiteConnection)
    else:    #Source Device is in global network
        if DstIP.is_private or dst:
            NewDevice(rec.DST_IP, rec.TIME_LAST, cursor, SQLiteConnection)        
            #=====================================================================================        
            NewDependencies("Global", rec.SRC_IP, rec.DST_IP, rec.SRC_PORT, rec.DST_PORT, rec.PACKETS, rec.BYTES, cursor, SQLiteConnection)
            Services(rec.SRC_IP, rec.SRC_PORT, "GlobalServices", cursor, SQLiteConnection)
            Services(rec.DST_IP, rec.DST_PORT, "LocalServices", cursor, SQLiteConnection)
            Routers(rec.SRC_IP, rec.SRC_MAC, cursor, SQLiteConnection)
        else:
            return 
#=================================================================================================================================
#=================================================================================================================================
#=================================================================================================================================

