// Created by yakov on 8/1/25.

#pragma once

#include "AdapterHandler.h"

#include <condition_variable>
#include <optional>
#include <queue>

extern "C" {
  #include <libwifi/core/frame/frame.h>
}

class PacketHandler
{

public:
	PacketHandler();
	PacketHandler(uint8_t channel, const uint8_t* apMac);

	// Receive related
	bool waitForPacket(uint16_t timeout); // In ms
	void toggleSniffing();
	std::optional<libwifi_frame> getPacket();

	// Send related
	void sendPacket(std::vector<uint8_t>& packet) const;

	// Queue related
	void emptyQueue();

	// Modify packets related
	static void addRadioTap(std::vector<uint8_t>& packet);

	// Maintain connection
	void sendAck() const;
	static std::vector<uint8_t> createAck(const uint8_t* receiver);
	const uint8_t* getReceiver(const libwifi_frame* frame) const;

	// AP related
	void changeMacAp(const uint8_t* apMAc);

	// Channel related
	void setChannel(uint8_t channel) const;
	static uint8_t getChannel();

private:
	void parsePackets(const u_char* packet, size_t size);

	// Channel related
	void setChannel() const;
	static uint8_t m_channel;

	bool m_isSniffing;
	std::thread m_sniffer;

	std::condition_variable m_cv;
	std::mutex m_mutex;
	std::queue<libwifi_frame> m_packets;

	AdapterHandler& m_adapterHandler;
	int m_socket;
	const uint8_t* m_deviceMac;

	std::vector<uint8_t> m_apAck;
	uint8_t m_apMac[MAC_SIZE_BYTES];

};
