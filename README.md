# NetX
NetX is a simple to use Linux tool that I've written in C++ with the libcrafter library (library created by Pellegre). It's not a security programm, it's a little hacking programm that I coded just for fun.
It allows you to scan a network, detect the connected devices on the network and sniff a specific connection (for example the http port can be sniffed and its packets can be intercepted and readed).
It aslo allows to kill a simple connection device/gateway or kill all connections on the network.

My programm can have some bugs and imperfections, that is why I publish the source code if you want improve it or add new features.
If you have any questions, contact me.

# Installation and dependancies
This programm requires 2 dependancies : libpcap and libcrafter, you can install libpcap with this command :

$ sudo apt-get install libpcap-dev

For install libcrafter, this's a bit more complicated, but still easy. Just follow these instructions :

- sudo apt-get install autoconf libtool make (check if these tools are installed on your system)
- git clone https://github.com/pellegre/libcrafter
- cd libcrafter/libcrafter
- ./autogen.sh
- make
- sudo make install
- sudo ldconfig

# How to use and compile sources
Note : This programm can be compiled only on Linux systems because the libcrafter's author build his library only on Linux, sorry for Windows and Mac users.
After installing dependancies, the executable file is able to be launched with this command :

- sudo ./NetX your_network_interface

You must replace the "your_network_interface" argument by the network interface that your computer use to connect to your network (the most common network interfaces are "wlan0" if you use the WiFi and "eth0" if you use the Ethernet wire. Type "ifconfig" in a terminal if you don't know), you don't have to write quotes between the argument. If you don't write any argument, the default argument that is given to the programm is "wlan0".

If you want to compile sources, don't forget to link with these 3 arguments, like this :

- g++ main.cpp -o name_of_executable -lpcap -lpthread -lcrafter
