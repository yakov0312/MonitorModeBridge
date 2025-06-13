//
// Created by yakov on 6/13/25.
//
#include <cstring>

#include "WifiRelatedPackets.h"

Packets::Probe::ProbeRequestFrame::ProbeRequestFrame() : macHeader(), ssid{0}, supportedRates{0},
		ssidTagNumber(0), ssidLength(0), ratesTagNumber(TAG_SUPPORTED_RATES),
		ratesLength(SUPPORTED_RATES)
{

	macHeader.frameControl = FRAME_CONTROL_PROBE_REQUEST;
	macHeader.duration = 0x0000;

	std::memcpy(macHeader.destAddr, BROADCAST_MAC_ADDRESS, MAC_SIZE_BYTES);
	std::memcpy(macHeader.bssid, BROADCAST_MAC_ADDRESS, MAC_SIZE_BYTES);
	std::memcpy(macHeader.sourceAddr, AdapterHandler::getInstance().getDeviceMac(), MAC_SIZE_BYTES);

	macHeader.sequenceControl = SEQUENCE_CONTROL;
	SEQUENCE_CONTROL++;

	std::memcpy(supportedRates, DEFAULT_SUPPORTED_RATES, ratesLength);
}
