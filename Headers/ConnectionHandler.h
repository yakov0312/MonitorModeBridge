//
// Created by yakov on 6/13/25.
//
#pragma once

#include <vector>
#include <pcap/pcap.h>

#include "WifiDefenitions.h"
#include "AdapterHandler.h"
#include "PacketHandler.h"

struct libwifi_wpa_auth_data;
struct libwifi_bss;
struct libwifi_frame;

constexpr uint8_t MAX_TIMEOUTS = 5;

class ConnectionHandler
{
public:
	ConnectionHandler();
	~ConnectionHandler();
	void connect(const BasicNetworkInfo &network);
private:

	void getNetworkInfo();
	bool parseNetworkInfo(const libwifi_bss* bss);
	void authenticateNetwork();
	void associateNetwork();
	void performHandshake();
	void setIp(); //using dhcp

	//handshake related
	std::optional<libwifi_frame> getHandshakePacketNonSAE();
	void performHandshakeNonSAE();
	void performHandshakeSAE();
	std::pair<EapolFrame, std::vector<uint8_t>> createM2(const libwifi_wpa_auth_data& wpaData);

	//helpers
	void setSecurity(const libwifi_bss* bss);

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

	const uint8_t* m_deviceMac;

	PacketHandler m_packetHandler;
};
