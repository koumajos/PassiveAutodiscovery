# DeppendencyMapping
Design a NEMEA module to analyze extended bi-directional network flows (biflow) to identify servers and their services, and possibly other device information. 
The output of the program must be obtained information and graph of client dependencies on server services, try visualizing with existing tools.
### NEMEA system: 
        https://nemea.liberouter.org/
### How to install NEMEA system: 
        https://nemea.liberouter.org/doc/installation/

Ideal Operating system is CentOS 7 or 8
* Install on Centos 8:
  * install some stuffs
  
        yum install git

  * clone NEMEA repository

        git clone --recursive https://github.com/CESNET/nemea

  * install some depenencies

        yum install -y bc autoconf automake gcc gcc-c++ libtool libxml2-devel make pkg-config libpcap-devel libidn-devel bison flex

  * not all on centos8 will install by yum - libpcap-devel and libidn-devel
    => must install by hand:

    * libpcap-devel:

        https://centos.pkgs.org/8/centos-powertools-x86_64/libpcap-devel-1.9.0-3.el8.x86_64.rpm.html

    * libidn-devel:
 
        https://centos.pkgs.org/8/centos-powertools-x86_64/libidn-devel-1.34-5.el8.x86_64.rpm.html

  * commands:
        
        cd nemea/

        ./bootstrap.sh

        ./configure --enable-repobuild --prefix=/usr --bindir=/usr/bin/nemea --sysconfdir=/etc/nemea --libdir=/usr/lib64

        make

        make install

  * install nemea-framework:
        
        cd  nemea/nemea-framework

        ./bootstrap.sh

        ./configure

        make

        sudo make install

        yum install python3-devel

        cd pytrap

        mkdir -p /usr/local/lib64/python3.6/site-packages/

        sudo python3 setup.py install

        cd pycommon

        mkdir -p /usr/local/lib/python3.6/site-packages/

        sudo python3 setup.py install

## Database Inplementation
  
  Module use sqlite3 database. Install on CentOS8:
    * yum install sqlite3
    
 * Tables filled before running the module by CreateScript.py:
   * Services
        - Table of protocols that are using by specific type of device. 

   * Filtres
        - Table of protocols and their number of packet for complete communication.

   * Ports
        - Table of protocols from IANA organization.

   * VendorsMAC
        - Table of vendors and their MAC addresses prefixes.
    
 * Tables filled by module from IP flows:
   * LocalDevice
        - Table of finded "local" devices.

   * LocalServices
        - Table of finded services on finded "local" devices.

   * LocalDependencies
        - Table of dependencies between finded "local" devices.
    
   * Global
        - Table of dependencies between finded "local" device and global devices that was by "local" device visited.

   * GlobalServices
        - Table of services on global devices that was visited by some "local" device.

   * MAC
        - Table of mac addresses of finded "local" devices.
    
   * Routers
        - Table of ip addresses of devices behind mac addresses.
    
   * DHCP
        - Table of DHCP records.

![Database proposal](https://github.com/koumajos/DeppendencyMapping/blob/master/navrh_databaze.png)

# PassiveAutodiscovery module

## Instalation
* git clone https://github.com/koumajos/PassiveAutodiscovery.git
* pip3 install -r requirements.txt

## Module Scripts description

### CreateScript
* Python libraries: 
  * sqlite3
  * csv
  * os
  * sys
  * urllib
  * from urllib - urllib.request
  * argparse
  * from argparse - RawTextHelpFormatter

* What script do?

        This script is part of PassiveAutodiscovery modul for modular monitoring system NEMEA (Network Measurement Analysis).
        This part is for:
        Script allows to create sqlite3 database file with inserted name. Then the database file will be scructured by SQL file (Database_sqlite_create.sql).

        Script will try download actualizate initial data from web database and download it (.csv files).If donwloading of anz file failed, the script will use backup file which is (in default state) stored in the same folder.

        The initial data from files will be added to tables: Ports, VendorsMAC and Services

  
### PassiveAutodiscovery
* Python libraries: 
  * pytrap
  * sys
  * os
  * sqlite3
  * ipaddress
  * re
  * argparse
  * from argparse - RawTextHelpFormatter
  * Python modules:  Collector

* What script do?

        This is module for modular monitoring system NEMEA (Network Measurement Analysis).
    
        Module main funkcionality is Autodiscovery, Device Recognition and Deppendency mapping.For this funkcionalities module use passive analyze. That mean that module take IP flows from IFC interface, that is always filled by flow_meter, and analyze them. Flow_meter capture packets on network interface and create from it IP flows. (Module can also use files of IP flows as IFC interface)
        Module use sqlite3 database for safing data from IP flows.     
        --------------
        Autodiscovery:
          Finds "local" device from network traffic. (local device = device that is from private subnet 10.0.0.0/8 or 172.16.0.0/16 or 192.168.0.0/24 OR device from subnet that was inserted by user with parameter -N)
        Device Recognition:
          Module recognize the roles of device in network and set to the device labels. This labels marks the roles of device. In the example for device that has role dhcp server fro the network, will module set to device label [DHCP Server].
        Deppendency mapping:
          Module safe all dependencies between "local" devices. Can also safe dependencies between "local" device and "global" devices(devices that aren't "local").

        Module is coaporate with Collector.py script that fill sqlite3 database. 
        The output from the database (entire analyze) is created by DeviceAnalyzer.py script.

### Collector
* Python libraries: 
  * sys
  * os
  * ipaddress
  * sqlite3

* What script do?

        Collector script analyze IP flow that get from PassiveAutodiscovery module. 

        Collector get database connection, arguments and IP flow.
        IP flow si analyzed and arguemnts specificate how to do it.
        The analyze get information from IP flow and add them to sqlite3 database. 

        Collector function collector is call from PassiveAutodiscovery module.


### Analyzer
* Python libraries: 
  * sys
  * os
  * ipaddress
  * sqlite3
  * time
  * json
  * math
  * socket
  * datetime
  * from termgraph - termgraph
  * tempfile
  * pandas
  * numpy
  * networkx
  * matplotlib.pyplot
  * argparse
  * from argparse - RawTextHelpFormatter

* What script do?

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

