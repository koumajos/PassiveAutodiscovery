/*
    Copyright (C) 2020 CESNET


    LICENSE TERMS

        Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
            1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
  
            2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

            3. Neither the name of the Company nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

        ALTERNATIVELY, provided that this notice is retained in full, this product may be distributed under the terms of the GNU General Public License (GPL) version 2 or later, in which case the provisions of the GPL apply INSTEAD OF those given above. 

        This software is provided as is'', and any express or implied warranties, including, but not limited to, the implied warranties of merchantability and fitness for a particular purpose are disclaimed. In no event shall the company or contributors be liable for any direct, indirect, incidental, special, exemplary, or consequential damages (including, but not limited to, procurement of substitute goods or services; loss of use, data, or profits; or business interruption) however caused and on any theory of liability, whether in contract, strict liability, or tort (including negligence or otherwise) arising in any way out of the use of this software, even if advised of the possibility of such damage.



*/
CREATE TABLE LocalDevice (
	IP text
);

CREATE TABLE LocalDependencies (
	ID_Dependencies integer PRIMARY KEY AUTOINCREMENT,
	IP_origin text,
	IP_target text,
	Port_origin integer,
	Port_target integer
);

CREATE TABLE LocalServices (
	PortNumber integer,
	IP text
);

CREATE TABLE Services (
	PortNumber integer,
	DeviceType text,
	Shortcut text,
	Description text
);

CREATE TABLE Ports (
	ID_Ports integer PRIMARY KEY AUTOINCREMENT,
	ServiceName text,
	PortNumber integer,
	TransportProtocol text,
	Description text
);

CREATE TABLE Global (
	ID_Global integer PRIMARY KEY AUTOINCREMENT,
	IP_origin text,
	IP_target text,
	Port_origin integer,
	Port_target integer
);

CREATE TABLE VendorsMAC (
	ID_VendorsMAC integer PRIMARY KEY AUTOINCREMENT,
	VendorMAC text,
	IsPrivate integer,
	CompanyName text,
	CountryCode text,
	AssignmentBlockSize text
);

CREATE TABLE MAC (
	ID_MAC integer PRIMARY KEY AUTOINCREMENT,
	IP text,
	MAC text,
	FirstUse text,
	LastUse text
);

CREATE TABLE Routers (
	ID_Routers integer PRIMARY KEY AUTOINCREMENT,
	MAC text,
	IP text
);

CREATE TABLE DHCP (
	ID_DHCP integer PRIMARY KEY AUTOINCREMENT,
	DeviceIP text,
	ServerIP text,
	Time text
);

CREATE TABLE GlobalServices (
	PortNumber integer,
	IP text
);
CREATE TABLE Filter (
	ID_Filter integer,
	PortNumber integer,
	Protocol text,
	MinPackets integer
);

CREATE TABLE DependenciesTime (
	ID_DT integer PRIMARY KEY AUTOINCREMENT,
	DependenciesID integer,
	Time text,
	NumPackets integer
);

CREATE TABLE GlobalTime (
	ID_GT integer PRIMARY KEY AUTOINCREMENT,
	GlobalID integer,
	Time text,
	NumPackets integer
);

