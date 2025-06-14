//
// Created by yakov on 6/13/25.
//
#pragma once

#include <functional>
#include <vector>

#include "WifiRelatedPackets.h"
#include "libwifi.h"

enum PacketStatus
{
	SUCCESS,
	WRONG_PACKET_TYPE,
	INVALID_PACKET,
	FAILED
};

class HIDDEN ConnectionHandler
{
public:
	ConnectionHandler();
	~ConnectionHandler();
	void connect(const BasicNetworkInfo &network);
private:
	using PacketHandlerFunc = std::function<PacketStatus(const u_char*, uint16_t)>;


	void getNetworkInfo(const BasicNetworkInfo &network);
	void authenticateNetwork();
	void associateNetwork();
	void performeHandshake();
	void setIp(); //using dhcp


	//helpers
	uint8_t setChannel(uint8_t channel);
	bool sendPackets(uint8_t numberOfPackets, const PacketHandlerFunc& packetHandler, const std::vector<uint8_t>& packet);
	void checkStatus(uint8_t status, bool conditionResult);

	static bool checkPacket(libwifi_frame* frame, const uint8_t* rawPacket, uint16_t packetSize, uint8_t subtype);

	uint8_t m_channel;
	uint16_t m_aid;

	AdapterHandler& m_adapterHandler;
	pcap_t* m_deviceHandle;

	EncryptionHandler m_encryptionHandler;

	libwifi_bss m_networkInfo;

	std::string password;
};