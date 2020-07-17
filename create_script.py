"""CreateScript:

    This script is part of PassiveAutodiscovery modul for modular monitoring system NEMEA (Network Measurement Analysis).
    This part is for:
        Script allows to create sqlite3 database file with inserted name. Then the database file will be scructured by SQL file (Database_sqlite_create.sql).

        Script will try download actualizate initial data from web database and download it (.csv files).If donwloading of anz file failed, the script will use backup file which is (in default state) stored in the same folder.

        The initial data from files will be added to tables: Ports, VendorsMAC and Services





    Copyright (C) 2020 CESNET


    LICENSE TERMS

        Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
            1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
  
            2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

            3. Neither the name of the Company nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

        ALTERNATIVELY, provided that this notice is retained in full, this product may be distributed under the terms of the GNU General Public License (GPL) version 2 or later, in which case the provisions of the GPL apply INSTEAD OF those given above. 

        This software is provided as is'', and any express or implied warranties, including, but not limited to, the implied warranties of merchantability and fitness for a particular purpose are disclaimed. In no event shall the company or contributors be liable for any direct, indirect, incidental, special, exemplary, or consequential damages (including, but not limited to, procurement of substitute goods or services; loss of use, data, or profits; or business interruption) however caused and on any theory of liability, whether in contract, strict liability, or tort (including negligence or otherwise) arising in any way out of the use of this software, even if advised of the possibility of such damage.


"""
#!/usr/bin/python3.6

# Standard Library Imports
import sqlite3
import csv
import os
import sys
import urllib
import urllib.request
import argparse
from argparse import RawTextHelpFormatter

# Constants
URL_PORTS = "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv"
URL_MAC = "https://macaddress.io/database/macaddress.io-db.csv"


def check_str(string, suffix):
    """Function check if string have DOT suffix in end of string. Like suffix .txt in text.txt.

    Parameters
    --------
    string : str 
        String of file name.
    suffix : str
        String of file suffix.
    Returns
    --------
    Boolean : boolean
        True if string have suffix DOT.
        False if string havn't suffix DOT.
    """
    spl = string.split(suffix)
    if spl[-1] == "":
        return True
    return False


def create_db(file, arg):
    """Create sqlite3 database file and then created scructure of tables in it
    
    Parameters
    --------
    file : str 
        The database file to create.

    Returns
    --------
    sqlite_connection : sqlite3
        The connection to created sqlite3 database.
    cursor : sqlite3
        The cursor for execute SQL queries in created sqlite3 database.
    """
    try:
        print("Connecting to database....", end="")
        if os.path.exists(file):  # if database file exist:
            if arg.y:
                os.remove(file)
            else:
                print(
                    "\nDatabase already exists. Do you want do delete it and create new? [yes] - ",
                    end="",
                )
                if input() == "yes":  # choose if:
                    print("Removing old database and create new one....", end="")
                    os.remove(file)  # remove file and continue
                else:
                    print("Exiting script....")
                    sys.exit()  # exit
        sqlite_connection = sqlite3.connect(
            file
        )  # create ne connection to new sqlite database file
        cursor = sqlite_connection.cursor()
        print("done")
        with open("Database_sqlite_create.sql") as sqlite_file:  # open the sql file
            sql_script = sqlite_file.read()
        print("Creating Database schema....", end="")
        cursor.executescript(
            sql_script
        )  # and execute it for create sql scructure in database
        print("done")
        return sqlite_connection, cursor
        # return connectiona nd cursor for work with database
    except sqlite3.Error as error:
        print("Error while executing sqlite script", error)


def download_data(name, arg):
    """Download initial data for sqlite3 database and open it
    
    Parameters
    -----------
    name : str 
        The name of table for that are downloaded data.

    Returns
    --------
    reader : csv
        The opened data taht have been downloaded.
    """
    if arg.s:
        if os.path.exists(name + "_url.csv"):
            reader = csv.reader(open(name + "_url.csv", "r"), delimiter=",")
        elif os.path.exists(name + ".csv"):
            reader = csv.reader(open(name + ".csv", "r"), delimiter=",")
        else:
            print("Archive file ", name, " doesn't found.")
            sys.exit()
        return reader
    try:  # try download the file from url, if can't download or connect, use the archive local file (can be deprecated)
        if name == "Ports":
            print("Downloading Transport Layer Ports data....", end="")
            urllib.request.urlretrieve(URL_PORTS, name + "_url.csv")
        else:
            print("Downloading Vendors of MAC address data....", end="")
            urllib.request.urlretrieve(URL_MAC, name + "_url.csv")
        print("done")
        reader = csv.reader(open(name + "_url.csv", "r"), delimiter=",")
    except:
        print("Download failed, open local archive file...")
        if os.path.exists(name + ".csv"):
            reader = csv.reader(open(name + ".csv", "r"), delimiter=",")
        else:
            print("Archive file ", name, " doesn't found.")
            sys.exit()
    return reader


def inser_data(
    sqlite_connection, cursor, read_ports, read_mac, read_services, read_filter
):
    """Insert initial data to tables
    
    Parameters
    -----------
    sqlite_connection : sqlite3 
        The connection to the sqlite3 database.
    cursor : sqlite3
        The cursor at the sqlite3 database for execute SQL queries.
    read_ports : csv
        The opened file that is fill with initial Ports table data
    read_mac : csv
        The opened file that is fill with initial VendorsMAC table data
    read_services : csv
        The opened file that is fill with initial Services table data
    read_filter : csv
        The opened file that is fill with initial Filter table data
    """
    try:
        print("Inserting data to table Ports....", end="")
        for row in read_ports:
            to_db = [row[0], row[1], row[2], row[3]]
            cursor.execute(
                "INSERT INTO Ports (ServiceName, PortNumber, TransportProtocol, Description) VALUES (?, ?, ?, ?);",
                to_db,
            )
        print("done")
        print("Inserting data to table VendorsMAC....", end="")
        for row in read_mac:
            to_db = [row[0], row[1], row[2], row[4], row[5]]
            cursor.execute(
                "INSERT INTO VendorsMAC (VendorMAC, IsPrivate, CompanyName, CountryCode, AssignmentBlockSize) VALUES (?, ?, ?, ?, ?);",
                to_db,
            )
        print("done")
        print("Inserting Services data to table....", end="")
        for row in read_services:
            to_db = [row[0], row[1], row[2], row[3]]
            cursor.execute(
                "INSERT INTO Services (PortNumber, DeviceType, Shortcut, Description) VALUES (?, ?, ?, ?);",
                to_db,
            )
        print("done")
        print("Inserting Filter data to table....", end="")
        for row in read_filter:
            to_db = [row[0], row[1], row[2], row[3]]
            cursor.execute(
                "INSERT INTO Filter (ID_Filter, PortNumber, Protocol, MinPackets) VALUES (?, ?, ?, ?);",
                to_db,
            )
        print("done")
        sqlite_connection.commit()
    except sqlite3.Error as error:
        print("Error while inserting data to sqlite3 database", error)


def arguments():
    """The function loads the script parameters.

    Returns:
        argparse: Arguments of the script
    """
    parser = argparse.ArgumentParser(
        description="""Create sqlite3 database from sql file: Database_sqlite_create.sql 
    Database is filled with PassiveAutodiscovery.py NEMEA modul with coaporate Collector.py.
    Then analyze with DeviceAnalyzer.py.

    Usage:""",
        formatter_class=RawTextHelpFormatter,
    )
    parser.add_argument(
        "-d",
        "--database",
        help="Set name of the database without . part,  default is Database",
        type=str,
        metavar="NAME",
        default="Database",
    )
    parser.add_argument(
        "-y", help="Consent to overwrite exists database", action="store_true"
    )
    parser.add_argument(
        "-s", help="Skip downloading new data and use archive data", action="store_true"
    )
    arg = parser.parse_args()
    return arg


def main():
    """Main function of script. Work with other functions to create database, get a initial data and fill the initial data to tables.
    
    """
    arg = arguments()
    file = ""  # name of sqlite3 database file that will be create
    if check_str(arg.database, ".db"):
        file = arg.database
    else:
        file = arg.database + ".db"
    sqlite_connection, cursor = create_db(file, arg)  # create sqlite3 database

    read_ports = download_data("Ports", arg)
    read_mac = download_data("VendorsMAC", arg)
    read_services = csv.reader(open("Services.csv", "r"), delimiter=",")
    read_filter = csv.reader(open("Filter.csv", "r"), delimiter=",")
    inser_data(
        sqlite_connection, cursor, read_ports, read_mac, read_services, read_filter,
    )

    cursor.close()
    if sqlite_connection:
        sqlite_connection.close()


if __name__ == "__main__":
    main()

