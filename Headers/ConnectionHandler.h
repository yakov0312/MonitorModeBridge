//
// Created by yakov on 6/13/25.
//
#pragma once

#include "WifiRelatedPackets.h"
#include "libwifi.h"

class HIDDEN ConnectionHandler
{
public:
	ConnectionHandler();
	~ConnectionHandler();
	void connect(const BasicNetworkInfo &network);
private:
	void getNetworkInfo(const BasicNetworkInfo &network);
	void authenticateNetwork();
	void associateNetwork();
	void performeHandshake();
	void setIp(); //using dhcp


	//helpers
	uint8_t setChannel(uint8_t channel);
	void SendNumberPackets(uint8_t numberOfPackets, const u_char* packet, int packetSize);

	AdapterHandler& m_adapterHandler;
	pcap_t* m_deviceHandle;

	EncryptionHandler m_encryptionHandler;

	libwifi_bss m_networkInfo;

	std::string password;
};