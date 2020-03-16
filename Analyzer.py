#!/usr/bin/python3.6
import sys
import os
import ipaddress
import sqlite3

#=======================================================================================================================================
#Main function of Analyzer
def DoAnalyze(SQLiteConnection):
    None
#=======================================================================================================================================
# Main loop
try:    #connect to a database
    print("Connecting to a database....")
    if os.path.exists('Database.db'):
        print("", end='')
    else:
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

