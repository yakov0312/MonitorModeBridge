//
// Created by yakov on 6/16/25.
//

#pragma once
#include <functional>
#include <pcap/pcap.h>

#include "AdapterHandler.h"
#include "WifiDefenitions.h"

extern "C" {
#include "libwifi/core/frame/frame.h"
}

enum HIDDEN PacketStatus
{
	SUCCESS,
	WRONG_PACKET_TYPE,
	INVALID_PACKET,
	FAILED
};

class HIDDEN Helper
{
public:
	using PacketHandlerFunc = std::function<PacketStatus(const unsigned char*, uint16_t)>;

	//adapter related
	static void setChannel(uint8_t channel);

	//packet related
	static bool sendPackets(uint8_t numberOfPackets, const PacketHandlerFunc& packetHandler, std::vector<uint8_t>& packet, uint8_t channel);
	static void checkStatus(uint8_t status, bool conditionResult);
	static bool checkPacket(libwifi_frame* frame, const uint8_t* rawPacket, uint16_t packetSize, uint8_t subtype);
	static void addRadioTap(std::vector<uint8_t>& packet, uint8_t channel);
	static uint32_t computeCrc32(const uint8_t* data, size_t length);

	//encryption related
	static void getPmk(const std::string& password, uint8_t suite, const std::string& ssid, uint8_t* pmk);
	static void getPtkData(uint8_t* data, const uint8_t* nonce1, const uint8_t* nonce2, const uint8_t* mac1);
	static void getPtk(uint8_t* ptk, const uint8_t* pmk, const uint8_t* data, uint8_t suite);
	static void setMic(wpaAuthData& m2WpaData, const uint8_t* ptk, int akmSuite);
	static void decryptGtk(const uint8_t* ptk, uint8_t suite, const uint8_t* encryptedGtk,
		size_t encryptedLen, uint8_t* decryptedGtk);

	static void printPacketDebug(const u_char* packet, uint32_t length);

private:
	static int getKekLength(uint8_t suite);
	static AdapterHandler& m_adapterHandler;
};
