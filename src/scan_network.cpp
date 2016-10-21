using namespace std;
using namespace Crafter;

void scan_network(const string iface)
{
	IP ip_header;
	ip_header.SetSourceIP(GetMyIP(iface));
	ICMP icmp_header;
	icmp_header.SetType(ICMP::EchoRequest);
	icmp_header.SetPayload("\n");

	const string MyIP = GetMyIP(iface);
	int dotCounter = 0;
    char networkToScan[13] = "";
    struct hostent *he = NULL;
    struct in_addr ipv4addr{};

    for(int i = 0; i < MyIP.size(); i++)
    {
        if(MyIP[i] != '.')
            networkToScan[i] = MyIP[i];
        else
        {
            networkToScan[i] = '.';
            dotCounter++;
            if(dotCounter == 3)
            {
                networkToScan[i+1] = '*';
                break;
            }
        }
    }
    cout << endl << "========== " << MENU_COLOR << "Scan all devices connected on this network" << NORMAL_COLOR << " ==========" << endl << endl;
    cout << "[" << INFO_COLOR << "@" << NORMAL_COLOR << "] The network to scan is : " << INFO_COLOR << networkToScan << NORMAL_COLOR << endl;
	vector<string> net = GetIPs(networkToScan);
	vector<string>::iterator it_IP;

	vector<Packet*> pings_packets;

	for(it_IP = net.begin(); it_IP != net.end(); it_IP++)
	{
		ip_header.SetDestinationIP(*it_IP);
		icmp_header.SetIdentifier(RNG16());
		pings_packets.push_back(new Packet(ip_header / icmp_header));
	}

	cout << "[" << INFO_COLOR << "@" << NORMAL_COLOR << "] Network scan in process..." << endl;

	vector<Packet*> pongs_packets(pings_packets.size());
	SendRecv(pings_packets.begin(), pings_packets.end(), pongs_packets.begin(), iface, 1, 3, 48);

	cout << "[" << INFO_COLOR << "@" << NORMAL_COLOR << "] Scan finished, resolve names..." << endl;

	vector<Packet*>::iterator it_pck;
	int counter = 0;
	for(it_pck = pongs_packets.begin(); it_pck < pongs_packets.end(); it_pck++)
	{
		Packet* reply_packet = (*it_pck);
		if(reply_packet)
		{
            ICMP* icmp_layer = reply_packet->GetLayer<ICMP>();
            if(icmp_layer->GetType() == ICMP::EchoReply)
            {
                Ethernet *ether_layer = reply_packet->GetLayer<Ethernet>();
				IP *ip_layer = reply_packet->GetLayer<IP>();
				inet_pton(AF_INET, ip_layer->GetSourceIP().c_str(), &ipv4addr);
				he = gethostbyaddr(&ipv4addr, sizeof(ipv4addr), AF_INET);
				cout << "[" << SUCCESS_COLOR << "+" << NORMAL_COLOR << "] Host up, IP : " << SUCCESS_COLOR << ip_layer->GetSourceIP() << NORMAL_COLOR << " MAC : " << ERROR_COLOR << ether_layer->GetSourceMAC() << NORMAL_COLOR << " Device name : ";
				if(he)
                    cout << "(" << MENU_COLOR << he->h_name << NORMAL_COLOR << ")" << endl;
				else
                    cout << "Unresolved" << NORMAL_COLOR << endl;
				counter++;
            }
		}
	}

	cout << "[" << INFO_COLOR << "@" << NORMAL_COLOR << "] " << counter << " host(s) found " << endl << endl;

	for(it_pck = pings_packets.begin(); it_pck < pings_packets.end(); it_pck++)
		delete (*it_pck);

	for(it_pck = pongs_packets.begin(); it_pck < pongs_packets.end(); it_pck++)
		delete (*it_pck);
}
