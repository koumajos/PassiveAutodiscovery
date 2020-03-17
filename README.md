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

  * nenainstaluje se přes yum - libpcap-devel a libidn-devel
    => nutnost nainstalovat jinak, například:

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

  * nemea-framework:
        
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
![Database proposal](https://github.com/koumajos/DeppendencyMapping/blob/master/navrh_databaze.png)

## CreateScript

## Collector

## Analyzer

