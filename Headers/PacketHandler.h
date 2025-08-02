//
// Created by yakov on 8/1/25.
//

#pragma once
#include <condition_variable>
#include <optional>
#include <queue>

#include "AdapterHandler.h"

extern "C"
{
	#include "libwifi/core/frame/frame.h"
}

class PacketHandler
{

public:
	PacketHandler();
	PacketHandler(uint8_t channel, const uint8_t* apMac);

	//receive related
	bool waitForPacket(uint16_t timeout); //in milisec
	void toggleSniffing();
	std::optional<libwifi_frame> getPacket();

	//send related
	void sendPacket(std::vector<uint8_t>& packet) const;

	//queue related
	void emptyQueue();

	//modify packets related
	void addRadioTap(std::vector<uint8_t>& packet) const;

	//maintain connection
	void sendAck() const;
	static std::vector<uint8_t> createAck(const uint8_t* receiver);
	const uint8_t* getReceiver(const libwifi_frame* frame);

	//ap related
	void changeMacAp(const uint8_t* apMAc);

	// channel related
	void setChannel(uint8_t channel) const;
	static uint8_t getChannel();
private:

	static void addPackets(u_char* user, const pcap_pkthdr* header, const u_char* packet);

	//channel related
	void setChannel() const;
	static uint8_t m_channel;

	bool m_isSniffing;

	std::condition_variable m_cv;
	std::mutex m_mutex;
	std::queue<libwifi_frame> m_packets;

	AdapterHandler& m_adapterHandler;
	pcap_t* m_device;
	const uint8_t* m_deviceMac;

	std::vector<uint8_t> m_apAck;
	uint8_t m_apMac[MAC_SIZE_BYTES];

};
