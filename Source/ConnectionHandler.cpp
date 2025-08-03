//
// Created by yakov on 6/13/25.
//
#include "ConnectionHandler.h"

#include <cstring>
#include <format>
#include <iostream>
#include <stdexcept>
#include <vector>

#include "EncryptionHelper.h"
#include <openssl/evp.h>
#include <sys/random.h>

extern "C" {
#include "libwifi.h"
}
#include <iomanip> //for debug


ConnectionHandler::ConnectionHandler() : m_adapterHandler(AdapterHandler::getInstance()), m_aid(0), m_akmSuite(0),
	m_bssid{0}, m_groupSuite(0), m_pairSuite(0), m_password(""), m_rsnTag(0), m_securityType(0),
	m_ssid(""), m_deviceMac(m_adapterHandler.getDeviceMac()), m_gtkKey{}, m_packetHandler()
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

	this->m_adapterHandler.setFilters();
	m_packetHandler.toggleSniffing();

	this->getNetworkInfo();
	this->authenticateNetwork();
	this->associateNetwork();
	if (m_securityType != NONE_SECURITY)
		this->performHandshake();
	this->setIp();
}

void ConnectionHandler::getNetworkInfo()
{
	libwifi_probe_req req = {0};
	std::vector<uint8_t> probeReq;
	libwifi_frame* framePtr = nullptr;
	std::optional<libwifi_frame> frame = std::nullopt;

	uint8_t channel = 0;
	uint8_t probeSize = 0;

	libwifi_create_probe_req(&req, BROADCAST_MAC_ADDRESS, m_deviceMac, BROADCAST_MAC_ADDRESS, m_ssid.data(), 1);
	probeSize = libwifi_get_probe_req_length(&req);
	probeReq.resize(probeSize);
	libwifi_dump_probe_req(&req, probeReq.data(), probeReq.size());
	libwifi_free_probe_req(&req);
	for (channel = 1; channel <= CHANNELS; channel++)
	{
		m_packetHandler.setChannel(channel);
		for (int i = 0; i < PROBE_COUNT; i++)
		{
			m_packetHandler.sendPacket(probeReq);

			while (m_packetHandler.waitForPacket(MAX_WAITING_TIME))
			{
				frame = m_packetHandler.getPacket();
				if (!frame.has_value())
					break;
				framePtr = &frame.value();

				if (!(framePtr->frame_control.type == TYPE_MANAGEMENT && framePtr->frame_control.subtype == SUBTYPE_PROBE_RESP))
				{
					libwifi_free_wifi_frame(framePtr);
					continue;
				}

				libwifi_bss bss = {0};
				if (libwifi_parse_probe_resp(&bss, framePtr) != 0)
				{
					libwifi_free_wifi_frame(framePtr);
					throw std::runtime_error("cannot parse the frame");
				}
				bool found = this->parseNetworkInfo(&bss);
				m_packetHandler.changeMacAp(bss.bssid);
				libwifi_free_bss(&bss);
				libwifi_free_wifi_frame(framePtr);
				if (found)
					return;
			}
		}
		probeReq[probeReq.size() -1] = channel + 1;
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
		return true;
	}
	return false;
}

void ConnectionHandler::authenticateNetwork()
{
	libwifi_auth auth = {0};
	libwifi_create_auth(&auth, this->m_bssid, m_deviceMac,
		this->m_bssid, AUTH_OPEN, TRANSACTION_SEQUENCE_REQ, AUTH_SUCCESS);

	uint16_t length = libwifi_get_auth_length(&auth);
	std::vector<uint8_t> packet(length);
	libwifi_dump_auth(&auth, packet.data(), packet.size());
	libwifi_free_auth(&auth);
	libwifi_frame* framePtr = nullptr;
	std::optional<libwifi_frame> frame;
	for (uint8_t counter = 0; counter < MAX_AUTH_ATTEMPTS; counter++)
	{
		m_packetHandler.sendPacket(packet);

		while (m_packetHandler.waitForPacket(MAX_WAITING_TIME))
		{

			frame = m_packetHandler.getPacket();
			if (!frame.has_value())
				break;
			framePtr = &frame.value();
			if (!(framePtr->frame_control.type == TYPE_MANAGEMENT && framePtr->frame_control.subtype == SUBTYPE_AUTH))
			{
				libwifi_free_wifi_frame(&frame.value());
				continue;
			}
			if (framePtr->len <= (framePtr->header_len + sizeof(struct libwifi_auth_fixed_parameters)))
			{
				libwifi_free_wifi_frame(&frame.value());
				continue;
			}
			auto* auth = reinterpret_cast<libwifi_auth_fixed_parameters *>(framePtr->body);
			if (auth->status_code == AUTH_SUCCESS)
			{
				libwifi_free_wifi_frame(framePtr);
				return;
			}
			libwifi_free_wifi_frame(framePtr);
			throw std::runtime_error("Auth: Ap returned status failed to authenticate. If the network is busy please try again later");
		}
	}

	throw std::runtime_error("Cannot authenticate to the network. Please check connection and signal strength");
}

void ConnectionHandler::associateNetwork()
{
	libwifi_assoc_req association = {0};
	libwifi_create_assoc_req(&association, this->m_bssid, m_deviceMac,
		this->m_bssid, this->m_ssid.c_str(), PacketHandler::getChannel());

	libwifi_quick_add_tag(&association.tags, TAG_SUPP_RATES, m_supportedRates.data(), m_supportedRates.size());
	if (m_securityType != NONE_SECURITY) //add only if there is a security
		libwifi_quick_add_tag(&association.tags, TAG_RSN, m_rsnTag, RSN_INFO_SIZE);

	uint16_t length = libwifi_get_assoc_req_length(&association);
	std::vector<uint8_t> packet(length);
	libwifi_dump_assoc_req(&association, packet.data(), packet.size());
	libwifi_free_assoc_req(&association);

	libwifi_frame* framePtr = nullptr;
	std::optional<libwifi_frame> frame;
	m_packetHandler.emptyQueue();
	for (uint8_t counter = 0; counter < MAX_ASSOC_ATTEMPTS; counter++)
	{
		m_packetHandler.sendPacket(packet);

		while (m_packetHandler.waitForPacket(MAX_WAITING_TIME))
		{
			frame = m_packetHandler.getPacket();
			if (!frame.has_value())
				break;
			framePtr = &frame.value();

			//check for invalid packet format
			if (!(framePtr->frame_control.type == TYPE_MANAGEMENT && framePtr->frame_control.subtype == SUBTYPE_ASSOC_RESP))
			{
				libwifi_free_wifi_frame(&frame.value());
				continue;
			}
			if (framePtr->len <= (framePtr->header_len + sizeof(struct libwifi_assoc_resp_fixed_parameters)))
			{
				libwifi_free_wifi_frame(framePtr);
				continue;

			}

			libwifi_assoc_resp_fixed_parameters* params = reinterpret_cast<libwifi_assoc_resp_fixed_parameters *>(framePtr->body);

			if (params->status_code == ASSOC_SUCCESS)
			{
				m_aid = params->association_id;
				libwifi_free_wifi_frame(framePtr);
				return;
			}
			libwifi_free_wifi_frame(framePtr);
			throw std::runtime_error("Ap returned status failed to assoc. If the network is busy please try again later");
		}
	}
	throw std::runtime_error("Assoc: Ap is not responding please try again later the network might be busy");
}

void ConnectionHandler::performHandshake()
{
	if (m_securityType == WPA2 || m_akmSuite == LIBWIFI_AKM_PSK_SHA384)
		performHandshakeNonSAE(); //connection using normal psk calculations
	else
		performHandshakeSAE(); //connection using SAE (wpa3)
}

void ConnectionHandler::performHandshakeNonSAE()
{
	std::optional<libwifi_frame> frame;
	libwifi_frame* framePtr = nullptr;
	for (int i = 0; i <= MAX_EAPOL_RECEIVE; i++)
	{
		frame = getHandshakePacketNonSAE();
		if (frame.has_value())
			break;
	}
	if (!frame.has_value())
		throw std::runtime_error("Ap is not starting the eapol handshake");
	framePtr = &frame.value();

	libwifi_wpa_auth_data wpaData;
	if (libwifi_get_wpa_data(framePtr, &wpaData) != 0)
		throw std::runtime_error("Failed to parse WPA data");
	if (libwifi_check_wpa_message(framePtr) != HANDSHAKE_M1)
		throw std::runtime_error("Invalid wpa data");
	auto [eapol, ptk] = createM2(wpaData);
	memcpy(eapol.frameHeader.addr1, m_bssid, MAC_SIZE_BYTES);
	memcpy(eapol.frameHeader.addr2, m_deviceMac, MAC_SIZE_BYTES);
	memcpy(eapol.frameHeader.addr3, m_bssid, MAC_SIZE_BYTES);

	std::vector<uint8_t> m2((uint8_t*)&eapol, (uint8_t*)&eapol + sizeof(eapol));
	libwifi_free_wifi_frame(framePtr);

	for (int i = 0; i <= MAX_EAPOL_SEND; i++)
	{
		m_packetHandler.sendPacket(m2);
		frame = getHandshakePacketNonSAE();
		if (frame.has_value())
			break;
	}
	if (!frame.has_value())
		throw std::runtime_error("Ap is not starting the eapol handshake");
	framePtr = &frame.value();

	memset(&wpaData, 0, sizeof(wpaData));
	if (libwifi_get_wpa_data(framePtr, &wpaData) != 0)
		throw std::runtime_error("Failed to parse WPA data");
	if (libwifi_check_wpa_message(framePtr) != HANDSHAKE_M3)
		throw std::runtime_error("Invalid wpa data");

	EncryptionHelper::decryptGtk(ptk.data(), m_akmSuite, wpaData.key_info.key_data,
		wpaData.key_info.key_data_length, m_gtkKey);

	eapol.keyDesc.keyInfo = htons(INFORMATION_FLAG_M4);
	eapol.keyDesc.replayCounter = wpaData.key_info.replay_counter;
	EncryptionHelper::setMic(eapol, ptk.data(), m_akmSuite);
	std::vector<uint8_t> m4((uint8_t*)&eapol, (uint8_t*)&eapol + sizeof(EapolFrame));
	m_packetHandler.sendPacket(m4);
	//handshake finished(no SAE)
	std::cout << "finished eapol" << std::endl;
}

void ConnectionHandler::performHandshakeSAE()
{
	return;
}

std::pair<EapolFrame, std::vector<uint8_t>> ConnectionHandler::createM2(const libwifi_wpa_auth_data& wpaData)
{
	uint8_t pmk[MAX_PMK_SIZE] = {0};
	EncryptionHelper::getPmk(m_password, m_akmSuite, m_ssid, pmk);
	//calculate data for ptk
	uint8_t data[PTK_DATA_SIZE] = {0};

	uint8_t sNonce[NONCE_SIZE];
	if (getrandom(sNonce, sizeof(sNonce), 0) != sizeof(sNonce))
		throw std::invalid_argument("Failed to generate SNonce");

	EncryptionHelper::getPtkData(data, wpaData.key_info.nonce, sNonce, m_bssid);
	uint8_t ptk[PTK_SIZE] = {0};
	EncryptionHelper::getPtk(ptk, pmk, data, m_akmSuite);

	//construct the m2
	EapolFrame eapol {
		.keyDesc = {
			.replayCounter = htobe64(wpaData.key_info.replay_counter),
		}
	};
	uint16_t keyInfo = INFORMATION_FLAG_M2;

	switch (m_akmSuite) {
		case AKM_SUITE_PSK:         keyInfo |= AKM_SUITE_PSK_VERSION; break;
		case AKM_SUITE_PSK_SHA256:  keyInfo |= AKM_SUITE_PSK_SHA256_VERSION; break;
		case AKM_PSK_SHA384:        keyInfo |= AKM_PSK_SHAE384_VERSION; break;
		default: throw std::runtime_error("Invalid akm suite");
	}

	eapol.keyDesc.keyInfo = htons(keyInfo);

	memcpy(eapol.keyDesc.nonce, sNonce, NONCE_SIZE);
	memcpy(eapol.keyDesc.keyData, m_rsnTag, RSN_INFO_SIZE);
	EncryptionHelper::setMic(eapol, ptk, m_akmSuite);
	return {eapol, std::vector<uint8_t>(ptk, ptk + PTK_SIZE)};
}

void ConnectionHandler::setIp()
{
	return;
}


std::optional<libwifi_frame> ConnectionHandler::getHandshakePacketNonSAE()
{
	libwifi_frame* framePtr = nullptr;
	std::optional<libwifi_frame> frame;
	while (m_packetHandler.waitForPacket(MAX_WAITING_TIME))
	{
		frame = m_packetHandler.getPacket();
		if (!frame.has_value())
			break;
		framePtr = &frame.value();

		if (framePtr->frame_control.type == TYPE_DATA && framePtr->frame_control.subtype == SUBTYPE_DATA_NULL)
		{
			libwifi_free_wifi_frame(framePtr);
			continue;
		}
		if (libwifi_check_wpa_handshake(framePtr) > 0)
			return frame.value();
	}
	return std::nullopt;
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

	m_rsnTag[GROUP_SUITE_INDEX] = bss->rsn_info.group_cipher_suite.suite_type;
	m_rsnTag[AKM_TYPE_INDEX] = m_akmSuite;
}