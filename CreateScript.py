#!/usr/bin/python3.6
import sqlite3
import csv
import os
import sys
import urllib
import urllib.request
#import urllib2
#===============================================================================================
try:
    print("Connecting to database....", end = '')
    if os.path.exists('Database.db'):
        print("")
        print("Database already exists. Do you want do delete it and create new? [yes] - ", end = '')
        if(input() == "yes"):
            print("Removing old database and create new one....", end = '')
            os.remove("Database.db")
        else:
            print("Exiting script....")
            sys.exit()
    SQLiteConnection = sqlite3.connect('Database.db')
    c = SQLiteConnection.cursor()
    print("done")
    with open('Database_sqlite_create.sql') as sqlite_file:
        sql_script = sqlite_file.read()
    print("Creating Database schema....", end = '')
    c.executescript(sql_script)
except sqlite3.Error as error:
    print("Error while executing sqlite script", error)
#===============================================================================================
#===============================================================================================
try:
    print("done")
    urlP = "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv"
    urlV = "https://macaddress.io/database/macaddress.io-db.csv"
    #===============================================================================================
    print("Downloading Transport Layer Ports data....", end='')
    urllib.request.urlretrieve(urlP, "Ports_url.csv")
    print("done")
    print("Inserting data to table Ports....", end='')
    reader = csv.reader(open('Ports_url.csv','r'), delimiter=',')
    #if url does not exist comment 5 lines above this and uncomment lines below
#    print("Inserting data to table Ports....", end='')
#    reader = csv.reader(open('Ports.csv','r'), delimiter=',')
    for row in reader:
         to_db = [row[0], row[1], row[2], row[3]]
         c.execute("INSERT INTO Ports (ServiceName, PortNumber, TransportProtocol, Description) VALUES (?, ?, ?, ?);", to_db)
    SQLiteConnection.commit()
    print("done")
    #===============================================================================================
    print("Downloading MAC address assigned to vendors data....", end='')
    urllib.request.urlretrieve(urlV, "VendorsMAC_url.csv")
    print("done")
    print("Inserting data to table VendorsMAC....", end='')
    reader = csv.reader(open('VendorsMAC_url.csv','r'), delimiter=',')
    #if url does not exist comment 5 lines above this and uncomment lines below
#    print("Inserting data to table VendorsMAC....", end='')
#    reader = csv.reader(open('VendorsMAC.csv','r'), delimiter=',')    
    for row in reader:
        to_db = [row[0], row[1], row[2], row[4], row[5]]
        c.execute("INSERT INTO VendorsMAC (VendorMAC, IsPrivate, CompanyName, CountryCode, AssignmentBlockSize) VALUES (?, ?, ?, ?, ?);", to_db)
    SQLiteConnection.commit()
    print("done")
    #===============================================================================================
    print("Inserting Services data to table....", end='')
    reader = csv.reader(open('Services.csv','r'), delimiter=',')    
    for row in reader:
        to_db = [row[0], row[1], row[2], row[3]]
        c.execute("INSERT INTO Services (PortNumber, DeviceType, Shortcut, Description) VALUES (?, ?, ?, ?);", to_db)
    SQLiteConnection.commit()
    print("done")
    #===============================================================================================
    c.close()
except sqlite3.Error as error:
    print("Error while executing sqlite script", error)
#===============================================================================================
#===============================================================================================
finally:
    if(SQLiteConnection):
        SQLiteConnection.close()

