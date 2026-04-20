// Created by yakov on 6/17/25.

#pragma once

#include "string"

#include <netinet/in.h>

extern "C"
{
  #include <libwifi/core/frame/tag.h>
}

constexpr size_t MAX_PACKET_SIZE = 4096;

// Ap related
constexpr uint8_t MAC_SIZE_BYTES = 6;
constexpr uint8_t SSID_SIZE_BYTES = 32;

// Frame related
constexpr uint8_t BROADCAST_MAC_ADDRESS[MAC_SIZE_BYTES] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
constexpr uint8_t ACK_FRAME_CTRL = 0xD4;

// Max attempts
constexpr uint8_t MAX_AUTH_ATTEMPTS = 3;
constexpr uint8_t MAX_ASSOC_ATTEMPTS = 3;
constexpr uint16_t MAX_WAITING_TIME = 500;
constexpr uint8_t MAX_EAPOL_RECEIVE = 2;
constexpr uint8_t MAX_EAPOL_SEND = 3;

// Adapter related
constexpr uint8_t CHANNELS = 13; // Rhere are 14 channels(channel 14 is only in japan)
constexpr uint8_t SUPPORTED_RATES_BITMASK = 0x8F;

// Verification related
constexpr uint16_t TRANSACTION_SEQUENCE_REQ = 1;
constexpr uint16_t TRANSACTION_SEQUENCE_RESP = 2;
constexpr uint8_t AUTH_SUCCESS = 0;
constexpr uint8_t ASSOC_SUCCESS = 0;
constexpr uint8_t PROBE_COUNT = 2;

// Libwifi related
constexpr bool IS_RADIOTAP = true;
constexpr uint8_t LIBWIFI_SUCCESS = 0;

// LLC related
constexpr uint8_t LLC_SAP = 0xAA;
constexpr uint8_t LLC_CONTROL = 0x03;
constexpr uint16_t LLC_ETHER_TYPE = 0x8E88;

// handshake related
constexpr auto HANDSHAKE_FILTER = "ether proto 0x888e and wlan type data";

// Encryption related
constexpr uint16_t PMK_ITERATIONS = 4096;
constexpr uint8_t MAX_PMK_SIZE = 48;
constexpr uint8_t PMK_SIZE_256 = 32;
constexpr uint8_t NONCE_SIZE = 32;
constexpr uint8_t PTK_DATA_SIZE = 76;
constexpr size_t PTK_SIZE = 64;
constexpr uint8_t MIC_SIZE = 16;
constexpr uint8_t KCK_SIZE = 16;
constexpr uint8_t GTK_SIZE = 56;
constexpr uint8_t IV_SIZE = 16;

// Suite related
constexpr uint8_t CIPHER_SUITE_SIZE = 4;
constexpr uint8_t AKM_TYPE_INDEX = 17;
constexpr uint8_t GROUP_SUITE_INDEX = 5;
constexpr uint8_t PAIR_SUITE_INDEX = 11;

// Security related
constexpr uint8_t NONE_SECURITY = 0;

// EAPOL related
constexpr uint8_t EAPOL_VERSION = 2;
constexpr uint8_t EAPOL_KEY_INFO = 3;
constexpr uint8_t WPA2_Key_Descriptor = 2;
constexpr uint8_t AKM_SUITE_PSK_VERSION = 1;
constexpr uint8_t AKM_SUITE_PSK_SHA256_VERSION = 2;
constexpr uint8_t AKM_PSK_SHAE384_VERSION = 3;
constexpr uint16_t INFORMATION_FLAG_M2 = 0x0108;
constexpr uint16_t INFORMATION_FLAG_M4 = 0x0300;
constexpr uint16_t EAPOL_FRAME_CONTROL = 0x0008;
constexpr uint16_t EAPOL_SEC_CTRL = 0x0010;

// WPA size
constexpr uint8_t WPA_AUTH_DATA_SIZE = 5;

// RSN info related
constexpr uint8_t RSN_INFO_SIZE = 20;
extern uint8_t RSN_WPA2[];
extern uint8_t RSN_WPA3[];

// Radiotap related
constexpr uint8_t RADIO_TAP_HEADER_SIZE = 14;


struct BasicNetworkInfo
{
	std::string networkName;
	std::string networkPassword; // Optional - based on security
};

struct AckPacket
{
	uint16_t frameControl = ACK_FRAME_CTRL;  // IEEE 802.11 ACK frame (type=Ctrl, subtype=ACK)
	uint16_t duration = 0;
	uint8_t receiver[MAC_SIZE_BYTES]; // Receiver MAC (Addr1)
	uint32_t fcs; // Layer calculated
} __attribute__((packed));

struct IeeeHeader
{
	uint16_t frameControl = EAPOL_FRAME_CONTROL;
	uint16_t duration = 0;
	uint8_t  addr1[MAC_SIZE_BYTES];        // DA = AP MAC
	uint8_t  addr2[MAC_SIZE_BYTES];        // SA = STA MAC
	uint8_t  addr3[MAC_SIZE_BYTES];        // BSSID
	uint16_t seqControl = EAPOL_SEC_CTRL;
} __attribute__((packed));

struct LLCHeader
{
	uint8_t  dsap = LLC_SAP;
	uint8_t  ssap = LLC_SAP;
	uint8_t  control = LLC_CONTROL;
	uint8_t  orgCode[3] = {};
	uint16_t etherType = LLC_ETHER_TYPE;
} __attribute__((packed));

struct WPA2KeyDesc
{
	uint8_t  descriptorType = WPA2_Key_Descriptor;
	uint16_t keyInfo;         // Flags + AKM bits (BE)
	uint16_t keyLength = 0;   // Cipher key len (BE)
	uint64_t replayCounter;   // From M1/M3 (BE)
	uint8_t  nonce[NONCE_SIZE] = {}; // SNonce for M2
	uint8_t  iv[IV_SIZE] = {};       // Zero
	uint64_t rsc = 0;                // Zero
	uint64_t id = 0;                 // Zero
	uint8_t  mic[MIC_SIZE] = {};     // HMAC output
	uint16_t keyDataLength = htons(RSN_INFO_SIZE + 2); // Len of RSN IE (BE) + id + length
	uint8_t tagNumber = TAG_RSN;
	uint8_t tagLength = RSN_INFO_SIZE;
	uint8_t keyData[RSN_INFO_SIZE] = {};
} __attribute__((packed));

// EAPOL header
struct EAPOLHeader
{
	uint8_t  version = EAPOL_VERSION;
	uint8_t  type = EAPOL_KEY_INFO;
	uint16_t length = htons(sizeof(WPA2KeyDesc));;
} __attribute__((packed));

struct EapolFrame
{
	IeeeHeader   frameHeader;
	LLCHeader llc;
	EAPOLHeader    eapolHeader;
	WPA2KeyDesc    keyDesc;
} __attribute__((packed));