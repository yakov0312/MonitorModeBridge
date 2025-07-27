//
// Created by yakov on 6/13/25.
//
#pragma once

#include <vector>

#include "WifiDefenitions.h"

struct libwifi_bss;
struct libwifi_frame;

class ConnectionHandler
{
public:
	ConnectionHandler();
	~ConnectionHandler();
	void connect(const BasicNetworkInfo &network);
private:

	void getNetworkInfo(const BasicNetworkInfo &network);
	void authenticateNetwork();
	void associateNetwork();
	void performHandshake();
	void setIp(); //using dhcp

	void getHandshakePacketNonSAE(libwifi_frame* frame);
	void performHandshakeNonSAE();
	void performHandshakeSAE();

	//helpers
	void setSecurity(libwifi_bss* bss);

	uint8_t m_channel;
	uint16_t m_aid;
	uint8_t m_securityType;
	uint8_t* m_rsnTag;
	uint16_t m_groupSuite;
	uint16_t m_akmSuite;
	uint16_t m_pairSuite;
	uint8_t m_gtkKey[GTK_SIZE];
	uint8_t m_bssid[MAC_SIZE_BYTES];
	std::string m_ssid;

	AdapterHandler& m_adapterHandler;
	pcap_t* m_deviceHandle;

	//ap
	std::string m_password;
	std::vector<uint8_t> m_supportedRates;
};
