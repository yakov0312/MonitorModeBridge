//
// Created by yakov on 6/13/25.
//
#include "ConnectionHandler.h"

#include <algorithm>
#include <cstring>
#include <iostream>
#include <stdexcept>

#include "Helper.h"
#include <openssl/evp.h>
#include <sys/random.h>

extern "C" {
#include "libwifi.h"
}
#include <iomanip> //for debug

#define PACKET_HANDLER(X) (const u_char* rawResponse, uint16_t length) -> PacketStatus { X }

ConnectionHandler::ConnectionHandler() : m_adapterHandler(AdapterHandler::getInstance()),
	m_deviceHandle(m_adapterHandler.getDeviceHandle()), m_channel(0), m_aid(0), m_akmSuite(0),
	m_bssid{0}, m_groupSuite(0), m_pairSuite(0), m_password(""), m_rsnTag(0), m_securityType(0),
	m_ssid("")
{
}

ConnectionHandler::~ConnectionHandler()
{
}

void ConnectionHandler::connect(const BasicNetworkInfo &network)
{
	this->getNetworkInfo(network);
	this->authenticateNetwork();
	this->associateNetwork();
	if (m_securityType != NONE_SECURITY)
		this->performHandshake();
	this->setIp();
}

void ConnectionHandler::getNetworkInfo(const BasicNetworkInfo& network)
{
	if (network.networkName.size() > SSID_SIZE_BYTES)
		throw std::invalid_argument("Network name is too long");

	else if (network.networkName.empty())
		throw std::invalid_argument("Network name is empty");

	auto packetHandler = [this, &network](const u_char* rawResponse, uint16_t length) -> PacketStatus{

		libwifi_frame response = {0};
		if (!Helper::checkPacket(&response, rawResponse, length, SUBTYPE_PROBE_RESP))
			return WRONG_PACKET_TYPE;

		libwifi_bss bss;
		if (libwifi_parse_probe_resp(&bss, &response) != 0)
			throw std::runtime_error("cannot parse the frame");

		PacketStatus packetStatus = INVALID_PACKET;
		if (memcmp(bss.ssid, network.networkName.data(), network.networkName.size()) == 0)
		{
			m_ssid = std::string(bss.ssid, network.networkName.size());
			memcpy(m_bssid, bss.bssid, MAC_SIZE_BYTES);
			this->setSecurity(&bss);
			packetStatus = SUCCESS;
		}
		libwifi_free_bss(&bss);
		libwifi_free_wifi_frame(&response);
		return packetStatus;
	};

	for (m_channel = 1; m_channel < CHANNELS; m_channel++)
	{
		Helper::setChannel(m_channel); //set the channel
		libwifi_probe_req probeRequest = {0};
		libwifi_create_probe_req(&probeRequest, BROADCAST_MAC_ADDRESS, //create the packet
			m_adapterHandler.getDeviceMac(), BROADCAST_MAC_ADDRESS, network.networkName.data(), m_channel);

		uint16_t probeLength = libwifi_get_probe_req_length(&probeRequest);
		std::vector<uint8_t> packet(probeLength);
		libwifi_dump_probe_req(&probeRequest, packet.data(), packet.size());

		if (Helper::sendPackets(PROBE_REQUEST_COUNT, packetHandler, packet))
			return;
	}
	throw std::invalid_argument("cannot find specified network");
}

void ConnectionHandler::authenticateNetwork()
{
	libwifi_auth auth = {0};
	libwifi_create_auth(&auth, this->m_bssid, this->m_adapterHandler.getDeviceMac(),
		this->m_bssid, AUTH_OPEN, TRANSACTION_SEQUENCE_REQ, AUTH_SUCCESS);

	uint16_t length = libwifi_get_auth_length(&auth);
	std::vector<uint8_t> packet(length);
	libwifi_dump_auth(&auth, packet.data(), packet.size());

	auto packetHandler = [](const u_char* rawResponse, uint16_t length) -> PacketStatus{
			Helper::printPacketDebug(rawResponse, length);

			libwifi_frame frameResp = {0};
			if (!Helper::checkPacket(&frameResp, rawResponse, length, SUBTYPE_AUTH))
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
	};

	if (!Helper::sendPackets(MAX_AUTH_ATTEMPTS, packetHandler, packet))
		throw std::runtime_error("cannot authenticate to the network");
}

void ConnectionHandler::associateNetwork()
{
	Helper::setChannel(m_channel); //ensure the channel is right

	libwifi_assoc_req association = {0};
	libwifi_create_assoc_req(&association, this->m_bssid, this->m_adapterHandler.getDeviceMac(),
		this->m_bssid, this->m_ssid.data(), m_channel);
	if (m_securityType == NONE_SECURITY) //add only if there is a security
		libwifi_quick_add_tag(&association.tags, TAG_RSN, m_rsnTag, sizeof(m_rsnTag));

	uint16_t length = libwifi_get_assoc_req_length(&association);
	std::vector<uint8_t> packet(length);
	libwifi_dump_assoc_req(&association, packet.data(), packet.size());
	libwifi_free_assoc_req(&association);

	auto packetHandler = [this]PACKET_HANDLER({
		libwifi_frame response = {0};
		if (!Helper::checkPacket(&response, rawResponse, length, SUBTYPE_ASSOC_RESP))
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
	Helper::sendPackets(MAX_ASSOC_ATTEMPTS,packetHandler, packet);
}

void ConnectionHandler::performHandshake()
{
	bpf_program filter;
	if (pcap_compile(this->m_deviceHandle, &filter, HANDSHAKE_FILTER, 1, PCAP_NETMASK_UNKNOWN) == -1)
		throw std::runtime_error(pcap_geterr(m_deviceHandle));
	if (pcap_setfilter(m_deviceHandle, &filter) == -1)
		throw std::runtime_error(pcap_geterr(m_deviceHandle));

	if (m_securityType == WPA2 || m_akmSuite == LIBWIFI_AKM_PSK_SHA384)
		performHandshakeNonSAE(); //connection using normal psk calculations
	else
		performHandshakeSAE(); //connection using SAE (wpa3)
}

void ConnectionHandler::performHandshakeNonSAE()
{
	libwifi_frame frame = {0};
	getHandshakePacketNonSAE(&frame);

	libwifi_wpa_auth_data wpaData;
	if (libwifi_get_wpa_data(&frame, &wpaData) != 0)
		throw std::runtime_error("Failed to parse WPA data");
	if (libwifi_check_wpa_message(&frame) != HANDSHAKE_M1)
		throw std::runtime_error("Invalid wpa data");

	uint8_t pmk[MAX_PMK_SIZE] = {0};
	Helper::getPmk(m_password, m_akmSuite, m_ssid, pmk);
	//calculate data for ptk
	uint8_t data[PTK_DATA_SIZE] = {0};

	uint8_t sNonce[NONCE_SIZE];
	if (getrandom(sNonce, sizeof(sNonce), 0) != sizeof(sNonce))
		throw std::invalid_argument("Failed to generate SNonce");

	Helper::getPtkData(data, wpaData.key_info.nonce, sNonce, m_bssid);
	uint8_t ptk[PTK_SIZE] = {0};
	Helper::getPtk(ptk, pmk, data, m_akmSuite);

	//construct the m2
	wpaAuthData wpaDataResp {
		.version = VERSION,
		.type = EAPOL_KEY_INFO,
		.length = htons(sizeof(wpaKeyInfo)),
		.descriptorType = WPA2_Key_Descriptor,
		.keyInfo{
			.information = INFORMATION_FLAG_M2,
			.keyLength = 0,
			.replayCounter = wpaData.key_info.replay_counter,
			.iv = {0},
			.rsc = 0,
			.id = 0,
			.mic = {0}
		}
	};
	switch(m_akmSuite) {
		case AKM_SUITE_PSK: wpaDataResp.keyInfo.information += AKM_SUITE_PSK_VERSION; break;
		case AKM_SUITE_PSK_SHA256: wpaDataResp.keyInfo.information += AKM_SUITE_PSK_SHA256_VERSION; break;
		case AKM_PSK_SHA384: wpaDataResp.keyInfo.information += AKM_PSK_SHAE384_VERSION; break;
		default: throw std::runtime_error("Invalid akm suite");}
	wpaDataResp.keyInfo.information = htons(wpaDataResp.keyInfo.information);
	Helper::setMic(wpaDataResp, ptk, m_akmSuite);
	if (pcap_sendpacket(m_deviceHandle, reinterpret_cast<const u_char*>(&wpaDataResp), sizeof(wpaDataResp)) == PCAP_ERROR)
		throw std::runtime_error("Failed to send m2");
	memset(&frame, 0, sizeof(frame));
	getHandshakePacketNonSAE(&frame);

	memset(&wpaData, 0, sizeof(wpaData));
	if (libwifi_get_wpa_data(&frame, &wpaData) != 0)
		throw std::runtime_error("Failed to parse WPA data");
	if (libwifi_check_wpa_message(&frame) != HANDSHAKE_M3)
		throw std::runtime_error("Invalid wpa data");

	Helper::decryptGtk(ptk, m_akmSuite, wpaData.key_info.key_data,
		wpaData.key_info.key_data_length, m_gtkKey);

	wpaDataResp.keyInfo.information = htons(INFORMATION_FLAG_M4);
	wpaDataResp.keyInfo.replayCounter = wpaData.key_info.replay_counter;
	Helper::setMic(wpaDataResp, ptk, m_akmSuite);
	if (pcap_sendpacket(m_deviceHandle, reinterpret_cast<const u_char*>(&wpaDataResp), sizeof(wpaDataResp)) == PCAP_ERROR)
		throw std::runtime_error("Failed to send m4");
	//handshake finished(no SAE)
}

void ConnectionHandler::performHandshakeSAE()
{
	return;
}

void ConnectionHandler::setIp()
{
	return;
}

void ConnectionHandler::getHandshakePacketNonSAE(libwifi_frame* frame)
{
	pcap_pkthdr* header;
	const u_char* packet;
	bool found = false;
	while (!found)
	{
		pcap_next_ex(m_deviceHandle, &header, &packet);
		if (libwifi_get_wifi_frame(frame, packet, header->caplen, IS_RADIOTAP) != LIBWIFI_SUCCESS)
			throw std::runtime_error("Failed to parse frame");
		if (libwifi_check_wpa_handshake(frame) == LIBWIFI_SUCCESS)
			found = true;
	}
}

void ConnectionHandler::setSecurity(libwifi_bss* bss)
{
	if (bss->encryption_info == NONE_SECURITY)
	{
		m_securityType = NONE_SECURITY;
		m_rsnTag = nullptr;
		return;
	}
	if (bss->encryption_info & WPA || bss->encryption_info & WEP)
		throw std::runtime_error("Encryption protocol is too old");

	if (bss->encryption_info & WPA3)
	{
		m_securityType = WPA3;
		//pairwise suite selection
		if (bss->encryption_info & LIBWIFI_PAIRWISE_CIPHER_SUITE_GCMP256)
			m_pairSuite = CIPHER_SUITE_GCMP256;
		else if (bss->encryption_info & LIBWIFI_PAIRWISE_CIPHER_SUITE_CCMP256)
			m_pairSuite = CIPHER_SUITE_CCMP256;
		else if (bss->encryption_info & LIBWIFI_PAIRWISE_CIPHER_SUITE_GCMP128)
			m_pairSuite = CIPHER_SUITE_GCMP128;
		else if (bss->encryption_info & LIBWIFI_PAIRWISE_CIPHER_SUITE_CCMP128)
			m_pairSuite = CIPHER_SUITE_CCMP128;
		else
			throw std::runtime_error("Chosen suite is not supported. connection will be dropped");

		//akm suite selection
		if (bss->encryption_info & LIBWIFI_AKM_PSK_SHA384)
			m_akmSuite = AKM_PSK_SHA384;
		else if (bss->encryption_info & LIBWIFI_AKM_SUITE_SAE)
			m_akmSuite = AKM_SUITE_SAE;
		else if (bss->encryption_info & LIBWIFI_AKM_SUITE_OWE)
			m_akmSuite = AKM_SUITE_OWE;
		else
			throw std::runtime_error("Chosen suite is not supported. connection will be dropped");

		m_rsnTag = RSN_WPA3;
		m_rsnTag[PAIR_SUITE_INDEX] = m_pairSuite;

	}
	else if (bss->encryption_info & WPA2)
	{
		m_securityType = WPA2;
		//akm suite selection
		if (bss->encryption_info & LIBWIFI_AKM_SUITE_PSK_SHA256)
			m_akmSuite = AKM_SUITE_PSK_SHA256;
		else if (bss->encryption_info & LIBWIFI_AKM_SUITE_PSK)
			m_akmSuite = AKM_SUITE_PSK;
		else
			throw std::runtime_error("Given akm suites are not supported yet");
		m_rsnTag = RSN_WPA2;
	}
	else
		throw std::runtime_error("Chosen security is unsecure. connection will be dropped");

	m_rsnTag[GROUP_SUITE_INDEX] = bss->rsn_info.group_cipher_suite.suite_type;
	m_rsnTag[AKM_TYPE_INDEX] = m_akmSuite;
}
