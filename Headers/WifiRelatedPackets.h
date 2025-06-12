#pragma once
#include <cstdint>
#include <cstring>
#include "NetworkHandler.h"

// Frame Control field values for 802.11 management frames
constexpr uint16_t FRAME_CONTROL_PROBE_REQUEST = 0x0040;

// Broadcast MAC address (6 bytes all 0xFF)
constexpr uint8_t BROADCAST_MAC_ADDRESS[MAC_SIZE_BYTES] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

constexpr uint8_t TAG_SUPPORTED_RATES = 0x01;

// Supported rates (in 500kbps units)
constexpr uint8_t DEFAULT_SUPPORTED_RATES[4] = {0x02, 0x04, 0x0B, 0x16}; // 1Mbps, 2Mbps, 5.5Mbps, 11Mbps

#pragma pack(push, 1)
struct MacHeader
{
	uint16_t frameControl;
	uint16_t duration;
	uint8_t destAddr[MAC_SIZE_BYTES];
	uint8_t sourceAddr[MAC_SIZE_BYTES];
	uint8_t bssid[MAC_SIZE_BYTES];
	uint16_t sequenceControl;
};

class ProbeRequestFrame
{
public:
	MacHeader macHeader;

	uint8_t ssidTagNumber;
	uint8_t ssidLength;
	uint8_t ssid[32];

	uint8_t ratesTagNumber;
	uint8_t ratesLength;
	uint8_t supportedRates[8];

	ProbeRequestFrame() : macHeader(), ssid{0}, supportedRates{0},
	ssidTagNumber(0), ssidLength(0), ratesTagNumber(TAG_SUPPORTED_RATES),
	ratesLength(sizeof(DEFAULT_SUPPORTED_RATES))
	{
		macHeader.frameControl = FRAME_CONTROL_PROBE_REQUEST;
		macHeader.duration = 0x0000;

		std::memcpy(macHeader.destAddr, BROADCAST_MAC_ADDRESS, MAC_SIZE_BYTES);
		std::memcpy(macHeader.bssid, BROADCAST_MAC_ADDRESS, MAC_SIZE_BYTES);
		std::memcpy(macHeader.sourceAddr, NetworkHandler::getInstance().getDeviceMac(), MAC_SIZE_BYTES);
		macHeader.sequenceControl = 0x0000;

		std::memcpy(supportedRates, DEFAULT_SUPPORTED_RATES, ratesLength);
	}
};
#pragma pack(pop)
