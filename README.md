- NetX
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
