#pragma once
#include "AdapterHandler.h"
#include "string"
#include "EncryptionHandler.h"

constexpr uint8_t MAC_SIZE_BYTES = 6;
constexpr uint8_t SSID_SIZE_BYTES = 32;

// Frame Control field values for 802.11 management frames
constexpr uint16_t FRAME_CONTROL_PROBE_REQUEST = 0x0040;
constexpr uint16_t FRAME_CONTROL_PROBE_RESPONSE = 0x0050;

// Broadcast MAC address (6 bytes all 0xFF)
constexpr uint8_t BROADCAST_MAC_ADDRESS[MAC_SIZE_BYTES] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

//tag related
constexpr uint8_t TAG_SUPPORTED_RATES = 0x01;

// Supported rates (in 500kbps units)
constexpr uint8_t SUPPORTED_RATES = 4;
constexpr uint8_t FULL_SUPPORTED_RATES = 8;
constexpr uint8_t DEFAULT_SUPPORTED_RATES[SUPPORTED_RATES] = {0x02, 0x04, 0x0B, 0x16}; // 1Mbps, 2Mbps, 5.5Mbps, 11Mbps

static uint16_t SEQUENCE_CONTROL = 0;

struct BasicNetworkInfo
{
	std::string networkName;
	std::string networkPassword; //optional - based on security
};