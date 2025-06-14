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

constexpr uint8_t PROBE_REQUEST_COUNT = 3;
constexpr uint8_t MAX_AUTH_ATTEMPTS = 3;
constexpr uint8_t MAX_ASSOC_ATTEMPTS = 3;

constexpr uint8_t SUPPORTED_RATES_BITMASK = 0x8F;

constexpr uint8_t CHANNELS = 15; //there are 14 channels(channel 14 is only in japan)

constexpr uint8_t MAC_HEADER_SIZE = 24;

constexpr uint8_t TRANSACTION_SEQUENCE_REQ = 1;
constexpr uint8_t TRANSACTION_SEQUENCE_RESP = 2;
constexpr uint8_t AUTH_SUCCESS = 0;
constexpr uint8_t ASSOC_SUCCESS = 0;

#define PACKET_HANDLER(X) (const u_char* rawResponse, uint16_t length) -> PacketStatus { X }

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
		throw std::invalid_argument("Network name is too long");

	else if (network.networkName.empty())
		throw std::invalid_argument("Network name is empty");

	auto packetHandler = [this, &network]PACKET_HANDLER({
		libwifi_frame response = {0};
		if (!ConnectionHandler::checkPacket(&response, rawResponse, length, SUBTYPE_PROBE_RESP))
			return WRONG_PACKET_TYPE;

		libwifi_free_wifi_frame(&response);

		if (this->m_networkInfo.channel != 0) //its not the first packet(channel can never be 0)
			libwifi_free_bss(&this->m_networkInfo);

		if (libwifi_parse_probe_resp(&this->m_networkInfo, &response) != 0)
			throw std::runtime_error("cannot parse the frame");

		if (memcmp(this->m_networkInfo.ssid, network.networkName.data(), network.networkName.size()) == 0)
			return SUCCESS;
		return INVALID_PACKET; //invalid name
	});

	for (m_channel = 1; m_channel < CHANNELS; m_channel++)
	{
		this->setChannel(m_channel); //set the channel
		libwifi_probe_req probeRequest = {0};
		libwifi_create_probe_req(&probeRequest, BROADCAST_MAC_ADDRESS, //create the packet
			m_adapterHandler.getDeviceMac(), BROADCAST_MAC_ADDRESS, network.networkName.data(), m_channel);

		uint16_t probeLength = libwifi_get_probe_req_length(&probeRequest);
		std::vector<uint8_t> packet(probeLength);
		libwifi_dump_probe_req(&probeRequest, packet.data(), packet.size());

		if (this->sendPackets(PROBE_REQUEST_COUNT, packetHandler, packet))
			return;
	}
	throw std::invalid_argument("cannot find specified network");
}

void ConnectionHandler::authenticateNetwork()
{
	libwifi_auth auth = {0};
	libwifi_create_auth(&auth, this->m_networkInfo.bssid, this->m_adapterHandler.getDeviceMac(),
		this->m_networkInfo.bssid, AUTH_OPEN, TRANSACTION_SEQUENCE_REQ, AUTH_SUCCESS);

	uint16_t length = libwifi_get_auth_length(&auth);
	std::vector<uint8_t> packet(length);
	libwifi_dump_auth(&auth, packet.data(), packet.size());

	auto packetHandler = []PACKET_HANDLER({
			libwifi_frame frameResp = {0};
			if (!ConnectionHandler::checkPacket(&frameResp, rawResponse, length, SUBTYPE_AUTH))
			{
				libwifi_free_wifi_frame(&frameResp);
				return WRONG_PACKET_TYPE;
			}

			if (frameResp.len <= (frameResp.header_len + sizeof(struct libwifi_auth_fixed_parameters)))
				return WRONG_PACKET_TYPE;

			auto* auth = reinterpret_cast<libwifi_auth_fixed_parameters *>(frameResp.body);

			if (auth->transaction_sequence == TRANSACTION_SEQUENCE_RESP && auth->status_code != AUTH_SUCCESS)
				return SUCCESS;
			if (auth->transaction_sequence == TRANSACTION_SEQUENCE_RESP && auth->status_code != AUTH_SUCCESS)
				return FAILED;
			return INVALID_PACKET;
	});

	if (!this->sendPackets(MAX_AUTH_ATTEMPTS, packetHandler, packet))
		throw std::runtime_error("cannot authenticate to the network");
}

void ConnectionHandler::associateNetwork()
{
	setChannel(m_networkInfo.channel); //ensure the channel is right

	libwifi_assoc_req association = {0};
	libwifi_create_assoc_req(&association, this->m_networkInfo.bssid, this->m_adapterHandler.getDeviceMac(),
		m_networkInfo.bssid, m_networkInfo.ssid, m_networkInfo.channel);

	uint16_t length = libwifi_get_assoc_req_length(&association);
	std::vector<uint8_t> packet(length);
	libwifi_dump_assoc_req(&association, packet.data(), packet.size());


	auto packetHandler = [this]PACKET_HANDLER({
		libwifi_frame response = {0};
		if (!ConnectionHandler::checkPacket(&response, rawResponse, length, SUBTYPE_ASSOC_RESP))
		{
			libwifi_free_wifi_frame(&response); //free the frame
			return WRONG_PACKET_TYPE;
		}

		if (response.len <= (response.header_len + sizeof(struct libwifi_assoc_resp_fixed_parameters)))
		{
			libwifi_free_wifi_frame(&response);
			return WRONG_PACKET_TYPE;
		}

		auto* params = reinterpret_cast<libwifi_assoc_resp_fixed_parameters *>(response.body);
		PacketStatus status = FAILED;

		if (params->status_code == ASSOC_SUCCESS)
		{
			m_aid = params->association_id;
			status = SUCCESS;
		}
		libwifi_free_wifi_frame(&response);
		return status;
	});

	this->sendPackets(MAX_ASSOC_ATTEMPTS,packetHandler, packet);
}

void ConnectionHandler::connect(const BasicNetworkInfo &network)
{
	this->getNetworkInfo(network);
	this->authenticateNetwork();
	this->associateNetwork();
	this->performeHandshake();
	this->setIp();
}

bool ConnectionHandler::sendPackets(uint8_t numberOfPackets, const PacketHandlerFunc& packetHandler, const std::vector<uint8_t>& packet)
{

	uint8_t status = 0;
	PacketStatus packetHandlerStatus = PacketStatus::FAILED;
	pcap_pkthdr* header = {0};
	const u_char* rawResponse = nullptr;
	bool result = false;
	for (int i=0; i < numberOfPackets; i++)
	{
		//if the last packet was a random packet then dont send again but wait for the prev once
		if (packetHandlerStatus != PacketStatus::WRONG_PACKET_TYPE && pcap_sendpacket(m_deviceHandle, packet.data(), packet.size()) != 0)
		{
			throw std::runtime_error("Cannot reach the specified network");
		}

		status = pcap_next_ex(m_deviceHandle, &header, &rawResponse);
		this->checkStatus(status, i == MAX_AUTH_ATTEMPTS -1);
		if (status == 0)
		{
			packetHandlerStatus = PacketStatus::FAILED; //restore the status
			continue;
		}

		packetHandlerStatus = packetHandler(rawResponse, header->caplen);
		if (packetHandlerStatus == PacketStatus::SUCCESS)
			return true;
		if (packetHandlerStatus == PacketStatus::FAILED)
			throw std::runtime_error("AP returned an error");
		if (packetHandlerStatus == PacketStatus::WRONG_PACKET_TYPE) //the packet was a random packet
			i--;
	}
	return false;
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

bool ConnectionHandler::checkPacket(libwifi_frame *frame, const uint8_t *rawPacket, uint16_t packetSize,
	uint8_t subtype)
{
	if (libwifi_get_wifi_frame(frame, rawPacket, packetSize, true) != 0)
		throw std::runtime_error("cannot parse the frame");
	else if (frame->frame_control.type != TYPE_MANAGEMENT && frame->frame_control.subtype != subtype)
		return false;
	return true;
}

void ConnectionHandler::checkStatus(uint8_t status, bool conditionResult)
{
	if (status == PCAP_ERROR)
		throw std::runtime_error(pcap_geterr(m_deviceHandle));
	else if (status != 1 && conditionResult)
		throw std::runtime_error("Cannot reach the specified network");
}
