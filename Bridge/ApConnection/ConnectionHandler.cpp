// Created by yakov on 6/13/25.

#include "ConnectionHandler.h"
#include "../Encryption/CryptoManager.h"

#include <cstring>
#include <format>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <vector>
#include <openssl/evp.h>
#include <sys/random.h>

extern "C" {
  #include <libwifi.h>
}


ConnectionHandler::ConnectionHandler() : m_aid(0), m_securityType(0), m_rsnTag(nullptr),
	m_groupSuite(0), m_akmSuite(0), m_pairSuite(0), m_bssid{},
	m_interfaceHandler(InterfaceHandler::getInstance()), m_deviceMac(m_interfaceHandler.getInterfaceMac()), m_cryptoManager()
{
}

ConnectionHandler::~ConnectionHandler()
{
	//todo deauth here for clean up
}

void ConnectionHandler::connect(const BasicNetworkInfo& network)
{
	if (network.networkName.size() > SSID_SIZE_BYTES)
		throw std::invalid_argument("Network name is too long");

	if (network.networkName.empty())
		throw std::invalid_argument("Network name is empty");

	m_ssid = network.networkName;
	m_password = network.networkPassword;

	this->m_interfaceHandler.setFilters();
	m_packetHandler.toggleSniffing();

	this->getNetworkInfo();
	this->authenticateNetwork();
	this->associateNetwork();

	if (m_securityType != NONE_SECURITY)
		this->performHandshake();

	this->setIp();
}

/*-------------------------------*/
/* GATHER DATA ABOUT THE NETWORK */
/*-------------------------------*/

void ConnectionHandler::getNetworkInfo()
{
	libwifi_probe_req req = {};
	std::vector<uint8_t> probeReq;
	libwifi_frame* framePtr = nullptr;
	uint8_t channel = 0;
	uint8_t probeSize = 0;

	libwifi_create_probe_req(&req, BROADCAST_MAC_ADDRESS, m_deviceMac, BROADCAST_MAC_ADDRESS, m_ssid.data(), 1);

	probeSize = libwifi_get_probe_req_length(&req);
	probeReq.resize(probeSize);

	libwifi_dump_probe_req(&req, probeReq.data(), probeReq.size());
	libwifi_free_probe_req(&req);

	// Iterate over all the channels and probe for the network
	for (channel = 1; channel <= CHANNELS; channel++)
	{
		m_packetHandler.setChannel(channel);
		for (int i = 0; i < PROBE_COUNT; i++)
		{
			m_packetHandler.sendPacket(probeReq);

			while (m_packetHandler.waitForPacket(MAX_WAITING_TIME))
			{
				std::optional<libwifi_frame> frame = m_packetHandler.getPacket();

				if (!frame.has_value())
					break;

				framePtr = &frame.value();

				// Validate the frame type
				if (!(framePtr->frame_control.type == TYPE_MANAGEMENT && framePtr->frame_control.subtype == SUBTYPE_PROBE_RESP))
				{
					libwifi_free_wifi_frame(framePtr);
					continue;
				}

				libwifi_bss bss = {};
				if (libwifi_parse_probe_resp(&bss, framePtr) != 0)
				{
					libwifi_free_wifi_frame(framePtr);
					throw std::runtime_error("cannot parse the frame");
				}

				// Analyze the packet and update the info about the network
				const bool found = this->parseNetworkInfo(&bss);
				m_packetHandler.changeMacAp(bss.bssid);

				libwifi_free_bss(&bss);
				libwifi_free_wifi_frame(framePtr);

				if (found)
					return;
			}
		}

		probeReq[probeReq.size() - 1] = channel + 1;
	}

	throw std::invalid_argument("cannot find specified network");
}

bool ConnectionHandler::parseNetworkInfo(const libwifi_bss* bss)
{
	// Validate the network name
	if (memcmp(bss->ssid, m_ssid.data(), m_ssid.size()) == 0)
	{
		memcpy(m_bssid, bss->bssid, MAC_SIZE_BYTES);

		// Choose the best akm and cipher suit.
		this->setSecurity(bss);

		// Check for additional tags
		if (bss->tags.length != 0)
		{
			bool found = false;
			libwifi_tag_iterator it = {};

			if (libwifi_tag_iterator_init(&it, bss->tags.parameters, bss->tags.length) != 0)
				throw std::runtime_error("Cannot initialize tag iterator");

			do
			{
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

		// Akm suite selection for WPA3
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

		// Akm suite selection for WPA2
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

	// Pairwise suite selection
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

	// Update the crypto manager to the chosen suit
	m_cryptoManager.setSuit(m_akmSuite, m_pairSuite);
	// Calculate the PMK
	m_cryptoManager.setPmk(m_password, m_ssid);
}

/*-----------------------------*/
/* AUTHENTICATE TO THE NETWORK */
/*-----------------------------*/

void ConnectionHandler::authenticateNetwork()
{
	libwifi_auth authPacket = {};
	libwifi_create_auth(&authPacket, this->m_bssid, m_deviceMac,
		this->m_bssid, AUTH_OPEN, TRANSACTION_SEQUENCE_REQ, AUTH_SUCCESS);

	const uint16_t length = libwifi_get_auth_length(&authPacket);
	std::vector<uint8_t> packet(length);

	libwifi_dump_auth(&authPacket, packet.data(), packet.size());
	libwifi_free_auth(&authPacket);

	m_packetHandler.emptyQueue();

	// Send auth frame to the AP and retry up to MAX_AUTH_ATTEMPTS times
	libwifi_frame* framePtr = nullptr;
	for (uint8_t counter = 0; counter < MAX_AUTH_ATTEMPTS; counter++)
	{
		m_packetHandler.sendPacket(packet);

		while (m_packetHandler.waitForPacket(MAX_WAITING_TIME))
		{
			std::optional<libwifi_frame> frame = m_packetHandler.getPacket();
			if (!frame.has_value())
				break;

			framePtr = &frame.value();

			// Validate the frame's type
			if (!(framePtr->frame_control.type == TYPE_MANAGEMENT && framePtr->frame_control.subtype == SUBTYPE_AUTH))
			{
				libwifi_free_wifi_frame(&frame.value());
				continue;
			}

			// Validate the frame's format
			if (framePtr->len < (framePtr->header_len + sizeof(libwifi_auth_fixed_parameters)))
			{
				libwifi_free_wifi_frame(&frame.value());
				continue;
			}

			// Check the status code
			const auto* authData = reinterpret_cast<libwifi_auth_fixed_parameters*>(framePtr->body);
			if (authData->status_code == AUTH_SUCCESS)
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

/*--------------------------*/
/* ASSOCIATE TO THE NETWORK */
/*--------------------------*/

void ConnectionHandler::associateNetwork()
{
	libwifi_assoc_req association = {};
	libwifi_create_assoc_req(&association, this->m_bssid, m_deviceMac,
		this->m_bssid, this->m_ssid.c_str(), PacketHandler::getChannel());

	libwifi_quick_add_tag(&association.tags, TAG_SUPP_RATES, m_supportedRates.data(), m_supportedRates.size());

	// Add RSN tag if security is present
	if (m_securityType != NONE_SECURITY)
		libwifi_quick_add_tag(&association.tags, TAG_RSN, m_rsnTag, RSN_INFO_SIZE);

	const uint16_t length = libwifi_get_assoc_req_length(&association);
	std::vector<uint8_t> packet(length);

	libwifi_dump_assoc_req(&association, packet.data(), packet.size());
	libwifi_free_assoc_req(&association);

	m_packetHandler.emptyQueue();

	libwifi_frame* framePtr = nullptr;
	for (uint8_t counter = 0; counter < MAX_ASSOC_ATTEMPTS; counter++)
	{
		m_packetHandler.sendPacket(packet);

		while (m_packetHandler.waitForPacket(MAX_WAITING_TIME))
		{
			std::optional<libwifi_frame> frame = m_packetHandler.getPacket();
			if (!frame.has_value())
				break;

			framePtr = &frame.value();

			// Validate the frame's type
			if (!(framePtr->frame_control.type == TYPE_MANAGEMENT && framePtr->frame_control.subtype == SUBTYPE_ASSOC_RESP))
			{
				libwifi_free_wifi_frame(&frame.value());
				continue;
			}

			// Validate the frame's format
			if (framePtr->len <= (framePtr->header_len + sizeof(libwifi_assoc_resp_fixed_parameters)))
			{
				libwifi_free_wifi_frame(framePtr);
				continue;
			}

			// Check the status code
			const auto* params = reinterpret_cast<libwifi_assoc_resp_fixed_parameters*>(framePtr->body);
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

/*-----------------------------------------*/
/* PERFORM THE HANDSHAKE AND EXCHANGE KEYS */
/*-----------------------------------------*/

void ConnectionHandler::performHandshake()
{
	if (m_securityType == WPA2 || m_akmSuite == LIBWIFI_AKM_PSK_SHA384)
		performHandshakeNonSAE(); // Connection using normal psk calculations
	else
		performHandshakeSAE(); // Connection using SAE (wpa3)
}

void ConnectionHandler::performHandshakeNonSAE()
{
	libwifi_frame frame{};
	libwifi_frame* pFrame = nullptr;
	libwifi_wpa_auth_data wpaData = {};

	frame = getHandshakePacketNonSAE();

	pFrame = &frame;

	if (libwifi_get_wpa_data(pFrame, &wpaData) != 0)
		throw std::runtime_error("Failed to parse WPA data");

	if (libwifi_check_wpa_message(pFrame) != HANDSHAKE_M1)
		throw std::runtime_error("Invalid wpa data");

	libwifi_free_wifi_frame(pFrame);

	uint8_t sNonce[NONCE_SIZE];
	if (getrandom(sNonce, sizeof(sNonce), 0) != sizeof(sNonce))
		throw std::invalid_argument("Failed to generate SNonce");

	m_cryptoManager.setPtk(wpaData.key_info.nonce, sNonce, m_bssid);

	// Construct the m2
	EapolFrame eapol { .keyDesc = { .replayCounter = htobe64(wpaData.key_info.replay_counter) }};

	eapol.keyDesc.keyInfo = htons(INFORMATION_FLAG_M2);

	memcpy(eapol.keyDesc.nonce, sNonce, NONCE_SIZE);
	memcpy(eapol.keyDesc.keyData, m_rsnTag, RSN_INFO_SIZE);

	m_cryptoManager.setMic(eapol);

	memcpy(eapol.frameHeader.addr1, m_bssid, MAC_SIZE_BYTES);
	memcpy(eapol.frameHeader.addr2, m_deviceMac, MAC_SIZE_BYTES);
	memcpy(eapol.frameHeader.addr3, m_bssid, MAC_SIZE_BYTES);

	std::vector m2(reinterpret_cast<uint8_t*>(&eapol), reinterpret_cast<uint8_t*>(&eapol) + sizeof(eapol));

	m_packetHandler.sendPacket(m2);
	frame = getHandshakePacketNonSAE();

	pFrame = &frame;
	memset(&wpaData, 0, sizeof(wpaData));

	if (libwifi_get_wpa_data(pFrame, &wpaData) != 0)
		throw std::runtime_error("Failed to parse WPA data");

	if (libwifi_check_wpa_message(pFrame) != HANDSHAKE_M3)
		throw std::runtime_error("Invalid wpa data");

	m_cryptoManager.decryptGtk(wpaData.key_info.key_data);

	eapol.keyDesc.keyInfo = htons(INFORMATION_FLAG_M4);
	eapol.keyDesc.replayCounter = wpaData.key_info.replay_counter;

	m_cryptoManager.setMic(eapol);

	std::vector m4(reinterpret_cast<uint8_t*>(&eapol), reinterpret_cast<uint8_t*>(&eapol) + sizeof(EapolFrame));

	m_packetHandler.sendPacket(m4);

	// Handshake finished(no SAE)
	std::cout << "finished EAPOL" << std::endl;
}

void ConnectionHandler::performHandshakeSAE()
{
}

libwifi_frame ConnectionHandler::getHandshakePacketNonSAE()
{
	for (int i = 0; i <= MAX_EAPOL_RECEIVE; i++)
	{
		libwifi_frame* framePtr = nullptr;
		while (m_packetHandler.waitForPacket(MAX_WAITING_TIME))
		{
			std::optional<libwifi_frame> frame = m_packetHandler.getPacket();
			if (!frame.has_value())
				break;

			framePtr = &frame.value();

			// Validate the frame's type
			if (framePtr->frame_control.type == TYPE_DATA && framePtr->frame_control.subtype == SUBTYPE_DATA_NULL)
			{
				libwifi_free_wifi_frame(framePtr);
				continue;
			}

			if (libwifi_check_wpa_handshake(framePtr) > 0)
				return frame.value();
		}
	}

	throw std::runtime_error("Ap is not starting the EAPOL handshake");
}

void ConnectionHandler::setIp()
{
}
