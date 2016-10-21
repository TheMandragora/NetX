#include <iostream>
#include <string>
#include <crafter.h>
#include "headers.hpp"
#include "scan_network.cpp"
#include "kill_connection.cpp"
#include "kill_all_connections.cpp"
#include "sniff_connection.cpp"

using namespace std;
using namespace Crafter;

void ctrl_c(int sig_num)
{
    cout << "[@] Ctrl+C : " << sig_num << endl;
    exit(sig_num);
}

void display_root_error();

int main(int argc, char *argv[])
{
    InitCrafter();
    bool cont = true;
    string iface = "";
    const string MyIP = GetMyIP(iface), MyMAC = GetMyMAC(iface);

    if(argc > 2)
    {
        cout << "[" << ERROR_COLOR << "ERROR" << NORMAL_COLOR << "] Bad arguments" << endl;
        return EXIT_FAILURE;
    }
    else if(argc < 2)
        iface = "wlp4s0";
    else
        iface = argv[1];

    signal(SIGINT, ctrl_c);

    if(getuid() != 0)
    {
        cout << "[" << ERROR_COLOR << "ERROR" << NORMAL_COLOR << "] You must have " << ERROR_COLOR << "root privileges" << NORMAL_COLOR << " to use this tool" << endl;
        return EXIT_FAILURE;
    }
    cout << endl;
    cout << "                 uuuuuuu" << endl;
    cout << "             uu$$$$$$$$$$$uu" << endl;
    cout << "          uu$$$$$$$$$$$$$$$$$uu" << endl;
    cout << "         u$$$$$$$$$$$$$$$$$$$$$u" << endl;
    cout << "        u$$$$$$$$$$$$$$$$$$$$$$$u" << endl;
    cout << "       u$$$$$$$$$$$$$$$$$$$$$$$$$u" << endl;
    cout << "       u$$$$$$$$$$$$$$$$$$$$$$$$$u" << endl;
    cout << "       u$$$$$$\"   \"$$$\"   \"$$$$$$u" << endl;
    cout << "       \"$$$$\"      u$u       $$$$\"" << endl;
    cout << "        $$$u       u$u       u$$$      ____________" << endl;
    cout << "        $$$u      u$$$u      u$$$     |            |" << endl;
    cout << "         \"$$$$uu$$$   $$$uu$$$$\"     <     " << ERROR_COLOR << "NetX" << NORMAL_COLOR << "    |" << endl;
    cout << "          \"$$$$$$$\"   \"$$$$$$$\"       |____________|" << endl;
    cout << "            u$$$$$$$u$$$$$$$u" << endl;
    cout << "             u$\"$\"$\"$\"$\"$\"$u" << endl;
    cout << "  uuu        $$u$ $ $ $ $u$$       uuu" << endl;
    cout << " u$$$$        $$$$$u$u$u$$$       u$$$$" << endl;
    cout << "  $$$$$uu      \"$$$$$$$$$\"     uu$$$$$$" << endl;
    cout << "u$$$$$$$$$$$uu    \"\"\"\"\"    uuuu$$$$$$$$$$" << endl;
    cout << "$$$$\"\"\"$$$$$$$$$$uuu   uu$$$$$$$$$\"\"\"$$$\"" << endl;
    cout << " \"\"\"      \"\"$$$$$$$$$$$uu \"\"$\"\"\"" << endl;
    cout << "           uuuu \"\"$$$$$$$$$$uuu" << endl;
    cout << "  u$$$uuu$$$$$$$$$uu \"\"$$$$$$$$$$$uuu$$$" << endl;
    cout << "  $$$$$$$$$$\"\"\"\"           \"\"$$$$$$$$$$$\"" << endl;
    cout << "   \"$$$$$\"                      \"\"$$$$\"\"" << endl;
    cout << "     $$$\"                         $$$$\"" << endl << endl << endl;
    cout << "Super-user privileges : " << SUCCESS_COLOR << "ok" << NORMAL_COLOR << endl;
    cout << "Last compilation : 17/10/2016" << endl;
    cout << "Network interface : " << MENU_COLOR << iface << NORMAL_COLOR << endl;
    cout << "IP address : " + SUCCESS_COLOR << MyIP + NORMAL_COLOR << endl;
    cout << "MAC address : " + SUCCESS_COLOR << MyMAC + NORMAL_COLOR << endl << endl;
    while(cont)
    {
        cout << "    ========== " + MENU_COLOR + "Menu" + NORMAL_COLOR + " ==========" << endl;
        cout << "    Select from this menu" << endl;
        cout << MENU_COLOR + "    1" + NORMAL_COLOR + ") Scan this network and found connected devices" << endl;
        cout << MENU_COLOR + "    2" + NORMAL_COLOR + ") Kill a specific connection on this network" << endl;
        cout << MENU_COLOR + "    3" + NORMAL_COLOR + ") Kill all connections on this network " << ERROR_COLOR << " <- NOT YET READY" << NORMAL_COLOR << endl;
        cout << MENU_COLOR + "    4" + NORMAL_COLOR + ") Sniff network traffic" << endl;
        cout << MENU_COLOR + "    99" + NORMAL_COLOR + ") Exit programm" << endl << endl;
        cout << SUCCESS_COLOR + "NetX" + NORMAL_COLOR + "> ";
        string line = "";
        getline(cin, line);

        if(line == "1") scan_network(iface);
        else if(line == "2") kill_connection(iface);
        else if(line == "3") kill_all_connections(iface);
        else if(line == "4") sniff_connection(iface);
        else if(line == "99" || line == "exit" || line == "quit") cont = false;
        else cout << "[" + ERROR_COLOR + "ERROR" + NORMAL_COLOR + "] Bad command" << endl;
    }

    cout << endl << endl << "Thank you for using " << MENU_COLOR << "NetX" << NORMAL_COLOR << " Tool and ... remember :" << endl << endl;
    cout << "Their ignorance is our " << ERROR_COLOR << "power" << NORMAL_COLOR << " !" << endl << endl;
    CleanCrafter();
	return EXIT_SUCCESS;
}
