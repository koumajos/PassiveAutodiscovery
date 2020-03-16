#!/usr/bin/python3.6
import sys
import os
import ipaddress
import sqlite3

    
def AnalyzeLocalDevice(LocalDevice, cursor, SQLiteConnection):
    print("Device: ", LocalDevice[0])
#=======================================================================================================================================
#Main function of Analyzer
def DoAnalyze(SQLiteConnection):
    cursor = SQLiteConnection.cursor()
    cursor.execute("SELECT * FROM LocalDevice")
    LocalDevices = cursor.fetchall()
    for LocalDevice in LocalDevices:
        AnalyzeLocalDevice(LocalDevice, cursor, SQLiteConnection)
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

