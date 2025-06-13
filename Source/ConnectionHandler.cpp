//
// Created by yakov on 6/13/25.
//
#include "ConnectionHandler.h"

#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <vector>

#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/wireless.h>
#include <unistd.h>

constexpr uint8_t PROBE_REQUEST_COUNT = 5;

constexpr uint8_t SUPPORTED_RATES_BITMASK = 0x8F;

constexpr uint8_t CHANNELS = 15; //there are 14 channels(channel 14 is only in japan)

ConnectionHandler::ConnectionHandler() : m_adapterHandler(AdapterHandler::getInstance()),
	m_networkInfo(), m_deviceHandle(m_adapterHandler.getDeviceHandle())
{
}

ConnectionHandler::~ConnectionHandler()
{
}

void ConnectionHandler::getNetworkInfo(const BasicNetworkInfo& network)
{
	if (network.networkName.size() > SSID_SIZE_BYTES)
		throw std::runtime_error("Network name is too long");

	else if (network.networkName.empty())
		throw std::runtime_error("Network name is empty");
	int channel = 1;
	for (channel = 1; channel < CHANNELS; channel++)
	{
		this->setChannel(channel);

		libwifi_probe_req probeRequest;
		libwifi_create_probe_req(&probeRequest,	BROADCAST_MAC_ADDRESS, m_adapterHandler.getDeviceMac(), BROADCAST_MAC_ADDRESS, network.networkName.data(), channel);

		this->SendNumberPackets(PROBE_REQUEST_COUNT, reinterpret_cast<const u_char*>(&probeRequest), sizeof(probeRequest));

		pcap_pkthdr* header;
		const u_char* packet;
		uint8_t res = pcap_next_ex(m_deviceHandle, &header, &packet);
		if (res == -1) //pcap return error, 0 for timeout
		{
			throw std::runtime_error(pcap_geterr(m_deviceHandle));
		}
		else if (res == 0 && channel == CHANNELS - 1)
		{
			throw std::runtime_error("Cannot find the specified network");
		}
		else if (res == 0)
		{
			continue;
		}

		libwifi_frame response = {0};
		if (libwifi_get_wifi_frame(&response, packet, header->caplen, true) != 0)
			throw std::runtime_error("cannot parse the frame");

		if (response.frame_control.type == TYPE_MANAGEMENT && response.frame_control.subtype == SUBTYPE_PROBE_RESP && libwifi_parse_probe_resp(&m_networkInfo, &response) != 0)
			throw std::runtime_error("cannot parse the frame");

		if (memcmp(m_networkInfo.ssid, network.networkName.data(), network.networkName.size() != 0))
		{
			continue;
		}
		break;
	}
}

void ConnectionHandler::SendNumberPackets(uint8_t numberOfPackets, const u_char *packet, int packetSize)
{
	for (int i = 0; i < numberOfPackets; i++)
	{
		if (pcap_sendpacket(m_deviceHandle, packet, packetSize) != 0)
		{
			throw std::runtime_error(pcap_geterr(m_deviceHandle)); //return the error
		}
	}
}

uint8_t ConnectionHandler::setChannel(uint8_t channel)
{
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) return -1;

	iwreq wrq;
	memset(&wrq, 0, sizeof(wrq));
	strncpy(wrq.ifr_name, this->m_adapterHandler.getDeviceName().data(), IFNAMSIZ);

	wrq.u.freq.m = 2412 + 5 * (channel - 1);
	wrq.u.freq.e = 6;

	int result = ioctl(sock, SIOCSIWFREQ, &wrq);

	close(sock);
	return result;
}

void ConnectionHandler::connect(const BasicNetworkInfo &network)
{
	this->getNetworkInfo(network);
	this->authenticateNetwork();
	this->associateNetwork();
	this->performeHandshake();
	this->setIp();
}

void ConnectionHandler::authenticateNetwork()
{

}
