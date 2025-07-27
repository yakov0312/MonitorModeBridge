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
	//todo deauth here for clean up
}

void ConnectionHandler::connect(const BasicNetworkInfo &network)
{
	if (network.networkName.size() > SSID_SIZE_BYTES)
		throw std::invalid_argument("Network name is too long");

	if (network.networkName.empty())
		throw std::invalid_argument("Network name is empty");
	m_ssid = network.networkName;
	m_password = network.networkPassword;

	this->getNetworkInfo();
	m_adapterHandler.setFilters();
	this->authenticateNetwork();
	this->associateNetwork();
	if (m_securityType != NONE_SECURITY)
		this->performHandshake();
	this->setIp();
}

void ConnectionHandler::getNetworkInfo()
{
	uint8_t status = 0;
	pcap_pkthdr* header = {0};
	const u_char* rawResponse = nullptr;
	for (m_channel = 1; m_channel < CHANNELS; m_channel++)
	{
		Helper::setChannel(m_channel); //set the channel

		for (int i =0; i < PROBE_REQUEST_COUNT;i++)
		{
			status = pcap_next_ex(m_adapterHandler.getDeviceHandle(), &header, &rawResponse);
			Helper::checkStatus(status, i == PROBE_REQUEST_COUNT -1);
			if (status == 0)
				continue;

			libwifi_frame response = {0};
			if (!Helper::checkPacket(&response, rawResponse, header->caplen, SUBTYPE_BEACON))
			{
				i--;
				continue;
			}

			libwifi_bss bss;
			if (libwifi_parse_beacon(&bss, &response) != 0)
				throw std::runtime_error("cannot parse the frame");
			bool found = this->parseNetworkInfo(&bss);
			libwifi_free_bss(&bss);
			libwifi_free_wifi_frame(&response);
			if (found)
				return;
		}
	}
	throw std::invalid_argument("cannot find specified network");
}

bool ConnectionHandler::parseNetworkInfo(const libwifi_bss* bss)
{
	bool found = false;
	if (memcmp(bss->ssid, m_ssid.data(), m_ssid.size()) == 0)
	{
		memcpy(m_bssid, bss->bssid, MAC_SIZE_BYTES);
		this->setSecurity(bss);
		m_channel = bss->channel;
		if (bss->tags.length != 0)
		{
			struct libwifi_tag_iterator it = {0};
			if (libwifi_tag_iterator_init(&it, bss->tags.parameters, bss->tags.length) != 0)
				throw std::runtime_error("Cannot initialize tag iterator");
			do {
				if (it.tag_header->tag_num == TAG_SUPP_RATES)
				{
					m_supportedRates.insert(m_supportedRates.begin(), it.tag_data, it.tag_data + it.tag_header->tag_len);
					found = true;
					break;
				}
			} while (libwifi_tag_iterator_next(&it) != -1);
			if (!found)
				throw std::runtime_error("Invalid packet: supported rates are not present");
		}
		return found;
	}
	return found;
}

void ConnectionHandler::authenticateNetwork()
{
	libwifi_auth auth = {0};
	libwifi_create_auth(&auth, this->m_bssid, this->m_adapterHandler.getDeviceMac(),
		this->m_bssid, AUTH_OPEN, TRANSACTION_SEQUENCE_REQ, AUTH_SUCCESS);

	uint16_t length = libwifi_get_auth_length(&auth);
	std::vector<uint8_t> packet(length);
	libwifi_dump_auth(&auth, packet.data(), packet.size());
	auto packetHandler = [this](const u_char* rawResponse, uint16_t length) -> PacketStatus{
			libwifi_frame frameResp = {0};
			if (!Helper::checkPacket(&frameResp, rawResponse, length, SUBTYPE_AUTH))
			{
				//std::cout << "type: " << frameResp.frame_control.type << " subtype: " << frameResp.frame_control.subtype << std::endl;
				libwifi_free_wifi_frame(&frameResp);
				return WRONG_PACKET_TYPE;
			}

			if (frameResp.len <= (frameResp.header_len + sizeof(struct libwifi_auth_fixed_parameters)))
				return WRONG_PACKET_TYPE;

			sendAck(frameResp.header.mgmt_unordered.addr2);

			auto* auth = reinterpret_cast<libwifi_auth_fixed_parameters *>(frameResp.body);
			if (auth->transaction_sequence == TRANSACTION_SEQUENCE_RESP && auth->status_code == AUTH_SUCCESS)
				return SUCCESS;
			if (auth->transaction_sequence == TRANSACTION_SEQUENCE_RESP && auth->status_code != AUTH_SUCCESS)
				return FAILED;
			return INVALID_PACKET;
	};

	if (!Helper::sendPackets(MAX_AUTH_ATTEMPTS, packetHandler, packet, m_channel))
		throw std::runtime_error("cannot authenticate to the network");
}

void ConnectionHandler::associateNetwork()
{
	libwifi_assoc_req association = {0};
	libwifi_create_assoc_req(&association, this->m_bssid, this->m_adapterHandler.getDeviceMac(),
		this->m_bssid, this->m_ssid.c_str(), m_channel);

	libwifi_quick_add_tag(&association.tags, TAG_SUPP_RATES, m_supportedRates.data(), m_supportedRates.size());
	if (m_securityType != NONE_SECURITY) //add only if there is a security
		libwifi_quick_add_tag(&association.tags, TAG_RSN, m_rsnTag, RSN_TAG_SIZE);

	uint16_t length = libwifi_get_assoc_req_length(&association);
	std::vector<uint8_t> packet(length);
	libwifi_dump_assoc_req(&association, packet.data(), packet.size());
	libwifi_free_assoc_req(&association);

	auto packetHandler = [this](const u_char* rawResponse, uint16_t length) -> PacketStatus{
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
		sendAck(response.header.mgmt_ordered.addr2);

		libwifi_assoc_resp_fixed_parameters* params = reinterpret_cast<libwifi_assoc_resp_fixed_parameters *>(response.body);
		PacketStatus status = FAILED;

		if (params->status_code == ASSOC_SUCCESS)
		{
			m_aid = params->association_id;
			status = SUCCESS;
		}
		libwifi_free_wifi_frame(&response);
		return status;
	};
	if (!Helper::sendPackets(MAX_ASSOC_ATTEMPTS,packetHandler, packet, m_channel))
		throw std::runtime_error("cannot authenticate to the network");
}

void ConnectionHandler::performHandshake()
{
	// bpf_program filter;
	// if (pcap_compile(this->m_deviceHandle, &filter, HANDSHAKE_FILTER, 1, PCAP_NETMASK_UNKNOWN) == -1)
	// 	throw std::runtime_error(pcap_geterr(m_deviceHandle));
	// if (pcap_setfilter(m_deviceHandle, &filter) == -1)
	// 	throw std::runtime_error(pcap_geterr(m_deviceHandle));

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

void ConnectionHandler::sendAck(const uint8_t *receiver)
{

	AckPacket ack;
	memcpy(ack.receiver, receiver, MAC_SIZE_BYTES);

	std::vector<uint8_t> ackData(reinterpret_cast<uint8_t*>(&ack), reinterpret_cast<uint8_t*>(&ack) + sizeof(AckPacket) - sizeof(uint32_t));

	uint32_t fcs = Helper::computeCrc32(ackData.data(), ackData.size());
	// Append FCS in little-endian
	ackData.push_back(fcs & 0xFF);
	ackData.push_back((fcs >> 8) & 0xFF);
	ackData.push_back((fcs >> 16) & 0xFF);
	ackData.push_back((fcs >> 24) & 0xFF);

	Helper::addRadioTap(ackData, m_channel);

	if (pcap_sendpacket(m_deviceHandle, ackData.data(), ackData.size()) == PCAP_ERROR)
		throw std::runtime_error("Failed to send ACK");
}

void ConnectionHandler::getHandshakePacketNonSAE(libwifi_frame* frame)
{
	pcap_pkthdr* header;
	const u_char* packet;
	int status = 0;
	while (true)
	{
		status = pcap_next_ex(m_deviceHandle, &header, &packet);
		if (status == PCAP_ERROR || status == 0)
			continue;
		if (libwifi_get_wifi_frame(frame, packet, header->caplen, IS_RADIOTAP) != LIBWIFI_SUCCESS)
			throw std::runtime_error("Failed to parse frame");
		//todo parse the wpa handshake by myself since it does not recognize the packet
		if (libwifi_check_wpa_handshake(frame) == LIBWIFI_SUCCESS)
		{
			sendAck(frame->header.mgmt_ordered.addr2);
			break;
		}

	}
}

void ConnectionHandler::setSecurity(const libwifi_bss* bss)
{
	if (bss->encryption_info == NONE_SECURITY)
	{
		m_securityType = NONE_SECURITY;
		m_rsnTag = nullptr;
		return;
	}
	if (!(bss->encryption_info & WPA2) && bss->encryption_info & WPA || bss->encryption_info & WEP)
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
