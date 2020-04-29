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

        Table of protocols that are using by specific type of device. 

   * Filtres

        Table of protocols and their number of packet for complete communication.

   * Ports

        Table of protocols from IANA organization.

   * VendorsMAC

        Table of vendors and their MAC addresses prefixes.
    
 * Tables filled by module from IP flows:
   * LocalDevice

        Table of finded "local" devices.

   * LocalServices

        Table of finded services on finded "local" devices.

   * Dependencies

        Table of dependencies between finded "local" devices.
    
   * Global

        Table of dependencies between finded "local" device and global devices that was by "local" device visited.

   * GlobalServices

        Table of services on global devices that was visited by some "local" device.

   * MAC

        Table of mac addresses of finded "local" devices.
    
   * Routers

        Table of ip addresses of devices behind mac addresses.
    
   * DHCP
        
        Table of DHCP records.

![Database proposal](https://github.com/koumajos/DeppendencyMapping/blob/master/navrh_databaze.png)

# PassiveAutodiscovery module

## Instalation
* git clone https://github.com/koumajos/PassiveAutodiscovery.git
* pip3 install -r requirements.txt

## Module Scripts description

### CreateScript
Python libraries: 
* sqlite3
* csv
* os
* sys
* urllib
* from urllib - urllib.request
* argparse
* from argparse - RawTextHelpFormatter

### PassiveAutodiscovery
Python libraries: 
* pytrap
* sys
* os
* sqlite3
* ipaddress
* re
* argparse
* from argparse - RawTextHelpFormatter

Python modules:
* Collector

### Collector
Python libraries: 
* sys
* os
* ipaddress
* sqlite3

### Analyzer
Python libraries: 
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

