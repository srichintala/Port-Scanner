Project 4: Port Scanner

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Name: Mrunal M Pagnis
uname: mmpagnis

Name: Sri Laxmi Chintala
uname: chintals

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Contents:
~~~~~~~~~

1. Introduction
2. Files used
3. Description of code
4. Implementation

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
1. Introduction:
~~~~~~~~~~~~~~~

Port Scanner is a tool used by network administrators to verify the security of machines 
in their network. In this project we created a basic port scanner with IPv4 support 
that is written for network administrators interested in ensuring that machines on their 
network run only expected services 

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
2. Files used:
~~~~~~~~~~~~~

portScanner.c 		: 					This is the main program in which scanning is performed 
										and their respective conclusions are given.
										
ps_parser.cpp       :                   In this file the command line arguments are processed.

parse.h				:					It defines a structure which consists of parsed arguments.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
3. Description of code:
~~~~~~~~~~~~~~~~~~~~~~~

The main aim of this project is when given an IP address of a machine and a list of interesting 
TCP or UDP ports to scan, the scanner will connect on each port using TCP or UDP sockets, make 
a determination of whether or not the port is open based on success of the connection request 
and close the socket before moving on to the next port to scan.

In this project, we have implemented all the TCP scanning techniques in scan() function. In order
to set the TCP flags for each type of scan it is done in scan_func() function. 

In scan(), the TCP and IP headers are filled and the packet is sent and received using raw sockets.
If no packet is received through TCP socket, then the packet is retransmitted for three times by 
waiting for 4-7secs. If no response occurred, then check is done for ICMP socket, in order to find 
if any unreachable errors are detected. If icmp errors are received then the status of port is 
returned as filtered. 

If the type of scan specified is UDP and the ports given contain 53, then a function dns_fill() is 
called. Other wise(ie., for other ports) a function called scan_udp() is called. In dns_fill() function
dns header and query values are set and dns packet is sent. If a dns packet is received then the status 
of that port is open. If no packet is received using dns socket then check is done on icmp socket. If 
unreachable errors are received then the port is marked as filtered or closed depending on the icmp types
and codes received.

In the scan_udp() function, ip and udp headers are filled and the packet is sent by using raw udp sockets.
Receiving an udp packet indicated the port is open. Otherwise check is done on icmp socket. If icmp 
unreachable errors are received then the port is marked as filtered or closed depending on the icmp types 
and codes received.

For SSH, HTTP, SMTP2, POP, IMAP, and WHOIS, portScanner verifies these services in the service_verify() 
function which is called only when the ports 22 or 24 or 43 or 80 or 110 or 143 are specified. For these 
ports service version is printed along with service names. Only service names are printed for ports between 
1-1024 by calling the function get_service_name(). 

Finally, the status of each port is returned and the results of each scan is combined to draw conclusion about 
the port. In order to implement this, map is used.

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
4. Implementation:
~~~~~~~~~~~~~~~~~~

This project is implemented in C++ language. 

The commands for compiling and running the program are as follows:

Compile
~~~~~~~
Compile the program by including the pthread library -pthread as first argument for the compiler:

g++ -pthread portScanner.cpp -o portScanner

Port Scanner is run using the following options
~~~~~~~~~~~~~~~~~~~~~~
./portScanner --help 						: It displays the usage of options.

./portScanner --ports 1,2,9,10-15 			: By default the portScanner will scan for 1-1024
											  ports unless specified through the command line.
											  
./portScanner --ip 127.79.247.79			: It specifies the ip address to scan.

./portScanner --preﬁx 127.89.292.99/12		: It allows to scan an IP prefix.

./portScanner --ﬁle ip.txt					: The list of IP addresses to be scanned are given 
											  through a file.
											  
./portScanner --speedup 6					: Inorder to use the multithreaded version of portScanner,
											  the user specifies the number of threads to be used.
											  
./portScanner --scan SYN NULL FIN XMAS		: By default all scans are performed and user specified 
											  scans are performed by taking these flags.

											  
Any other command otherwise specified in the README will print the usage on standard display.