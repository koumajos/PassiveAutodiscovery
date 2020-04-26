CREATE TABLE LocalDevice (
	IP text,
	LastCom text
);

CREATE TABLE Dependencies (
	ID_Dependencies integer PRIMARY KEY AUTOINCREMENT,
	IP_origin text,
	IP_target text,
	Port_origin integer,
	Port_target integer,
	NumPackets integer,
	NumBytes integer
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
	Port_target integer,
	NumPackets integer,
	NumBytes integer
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
	ID_Filter integer PRIMARY KEY,
	PortNumber integer,
	Protocol text,
	MinPackets integer
);
