// Created by yakov on 8/1/25.

#pragma once

#include "../Interface/InterfaceHandler.h"

#include <atomic>
#include <condition_variable>
#include <thread>
#include <optional>
#include <queue>

extern "C" {
  #include <libwifi/core/frame/frame.h>
}

class PacketHandler
{

public:
	PacketHandler();

	explicit PacketHandler(const uint8_t* apMac);
	~PacketHandler();

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

	// Frames addressed to us, and how many of them were retransmissions
	struct RxStats
	{
		uint64_t toUs;
		uint64_t retries;
	};
	[[nodiscard]] RxStats getRxStats() const;

private:
	void parsePackets(const u_char* packet, size_t size);

	std::atomic<bool> m_isSniffing;
	std::thread m_sniffer;

	std::condition_variable m_cv;
	std::mutex m_mutex;
	std::queue<libwifi_frame> m_packets;

	InterfaceHandler& m_interfaceHandler;
	int m_socket;
	const uint8_t* m_deviceMac;
	bool m_hardwareAck;

	std::atomic<uint64_t> m_rxToUs{0};
	std::atomic<uint64_t> m_rxRetries{0};

	std::vector<uint8_t> m_apAck;
	uint8_t m_apMac[MAC_SIZE_BYTES]{};

};
