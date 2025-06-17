#pragma once
#include "AdapterHandler.h"
#include "string"
#include "EncryptionHandler.h"

//ap related
constexpr uint8_t SSID_SIZE_BYTES = 32;

//frame related
constexpr uint8_t BROADCAST_MAC_ADDRESS[MAC_SIZE_BYTES] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

//max attempts
constexpr uint8_t PROBE_REQUEST_COUNT = 3;
constexpr uint8_t MAX_AUTH_ATTEMPTS = 3;
constexpr uint8_t MAX_ASSOC_ATTEMPTS = 3;


//adapter related
constexpr uint8_t CHANNELS = 15; //there are 14 channels(channel 14 is only in japan)
constexpr uint8_t SUPPORTED_RATES_BITMASK = 0x8F;

//verification related
constexpr uint8_t TRANSACTION_SEQUENCE_REQ = 1;
constexpr uint8_t TRANSACTION_SEQUENCE_RESP = 2;
constexpr uint8_t AUTH_SUCCESS = 0;
constexpr uint8_t ASSOC_SUCCESS = 0;

//libwifi related
constexpr bool IS_RADIOTAP = true;
constexpr uint8_t LIBWIFI_SUCCESS = 0;

//handshake related
constexpr const char* HANDSHAKE_FILTER = "ether proto 0x888e and wlan type data";

//encryption related
constexpr uint16_t PMK_ITERATIONS = 4096;
constexpr uint8_t MAX_PMK_SIZE = 48;
constexpr uint8_t PMK_SIZE_256 = 32;
constexpr uint8_t NONCE_SIZE = 32;
constexpr uint8_t PTK_DATA_SIZE = 76;
constexpr size_t PTK_SIZE = 64;
constexpr uint8_t MIC_SIZE = 32;
constexpr uint8_t KCK_SIZE = 16;
constexpr uint8_t GTK_SIZE = 56;

//suite related
constexpr uint8_t CIPHER_SUITE_SIZE = 4;
constexpr uint8_t AKM_TYPE_INDEX = 17;
constexpr uint8_t GROUP_SUITE_INDEX = 5;
constexpr uint8_t PAIR_SUITE_INDEX = 11;

//security related
constexpr uint8_t NONE_SECURITY = 0;

//eapol related
constexpr uint8_t VERSION = 2;
constexpr uint8_t EAPOL_KEY_INFO = 3;
constexpr uint8_t WPA2_Key_Descriptor = 2;
constexpr uint8_t AKM_SUITE_PSK_VERSION = 1;
constexpr uint8_t AKM_SUITE_PSK_SHA256_VERSION = 2;
constexpr uint8_t AKM_PSK_SHAE384_VERSION = 3;
constexpr uint8_t INFORMATION_FLAG_M2 = 0x0108;
constexpr uint8_t INFORMATION_FLAG_M4 = 0x0300;

//rsn info related
uint8_t RSN_WPA2[] = {
	0x01, 0x00,                         // Version = 1
	0x00, 0x0F, 0xAC, 0x04,             // Group Cipher Suite: dynamically changing
	0x01, 0x00,                         // Pairwise Cipher Suite Count = 1
	0x00, 0x0F, 0xAC, 0x04,             // Pairwise Cipher Suite: AES (CCMP) if not supported drop connection
	0x01, 0x00,                         // AKM Suite Count = 1
	0x00, 0x0F, 0xAC, 0x00,             // AKM Suite: dynamically changing
	0x40, 0x00                          // RSN Capabilities: PMF supported
};

uint8_t RSN_WPA3[] = {
	0x01, 0x00,                         // Version = 1
	0x00, 0x0F, 0xAC, 0x00,             // Group Cipher Suite: dynamically changing
	0x01, 0x00,                         // Pairwise Cipher Suite Count = 1
	0x00, 0x0F, 0xAC, 0x00,             // Pairwise Cipher Suite: dynamically changing
	0x01, 0x00,                         // AKM Suite Count = 1
	0x00, 0x0F, 0xAC, 0x00,             // AKM Suite: dynamically changing
	0x80, 0x00                          // RSN Capabilities: PMF required
};


struct BasicNetworkInfo
{
	std::string networkName;
	std::string networkPassword; //optional - based on security
};

struct HIDDEN wpaKeyInfo {
	uint16_t information;
	uint16_t keyLength;
	uint64_t replayCounter;
	unsigned char nonce[NONCE_SIZE];
	unsigned char iv[16];
	uint64_t rsc;
	uint64_t id;
	unsigned char mic[MIC_SIZE];
} __attribute__((packed));

struct HIDDEN wpaAuthData {
	uint8_t version;
	uint8_t type;
	uint16_t length;
	uint8_t descriptorType;
	wpaKeyInfo keyInfo;
	// RSN IE will be manually appended after this
} __attribute__((packed));
