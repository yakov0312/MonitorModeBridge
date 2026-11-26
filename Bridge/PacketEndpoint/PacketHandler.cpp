// Created by yakov on 8/1/25.

#include "PacketHandler.h"

#include <cstring>
#include <iostream>
#include <mutex>
#include <sys/ioctl.h>
#include <unistd.h>

extern "C"
{
	#include <libwifi/core/radiotap/radiotap.h>
	#include <libwifi/gen/misc/radiotap.h>
}

constexpr uint8_t RADIOTAP_HEADER_MIN_LENGTH = 12;
constexpr uint8_t CHANNEL_FREQ_OFFSET = 10;

PacketHandler::PacketHandler() :
	m_isSniffing(false), m_interfaceHandler(InterfaceHandler::getInstance()),
	m_socket(m_interfaceHandler.getSocket()), m_deviceMac(m_interfaceHandler.getInterfaceMac()),
	m_hardwareAck(m_interfaceHandler.hasHardwareAck()), m_apMac{}
{
}

PacketHandler::PacketHandler(const uint8_t* apMac) :
	m_isSniffing(false), m_interfaceHandler(InterfaceHandler::getInstance()),
	m_socket(m_interfaceHandler.getSocket()),
	m_deviceMac(m_interfaceHandler.getInterfaceMac()),
	m_hardwareAck(m_interfaceHandler.hasHardwareAck()), m_apAck(createAck(apMac))
{
	memcpy(m_apMac, apMac, MAC_SIZE_BYTES);
	addRadioTap(m_apAck);
}

PacketHandler::~PacketHandler()
{
	// A joinable std::thread in a destructor calls std::terminate
	if (m_isSniffing)
		toggleSniffing();
	else if (m_sniffer.joinable())
		m_sniffer.join();
}

bool PacketHandler::waitForPacket(const uint16_t timeout)
{
	std::unique_lock lock(m_mutex);

	return m_cv.wait_for(lock, std::chrono::milliseconds(timeout), [this] {
		return !m_packets.empty();
	});
}

void PacketHandler::toggleSniffing()
{
	if (!m_isSniffing)
	{
		// Wake up recv() regularly so toggling sniffing off can join the thread
		constexpr timeval RECV_TIMEOUT = { .tv_sec = 0, .tv_usec = 200000 };
		setsockopt(m_socket, SOL_SOCKET, SO_RCVTIMEO, &RECV_TIMEOUT, sizeof(RECV_TIMEOUT));

		m_isSniffing = true;
		auto startLoop = [this]()
		{
			constexpr sched_param sch = { .sched_priority = 98 };

			// Real-time priority helps, but is not required (needs CAP_SYS_NICE)
			if (pthread_setschedparam(pthread_self(), SCHED_FIFO, &sch) != 0)
				std::cerr << "Warning: could not set real-time priority for the receive thread" << std::endl;

			uint8_t buffer[MAX_PACKET_SIZE];

			while (m_isSniffing)
			{
				const ssize_t len = recv(m_socket, buffer, MAX_PACKET_SIZE, 0);
				if (len < 0)
				{
					if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
						continue; // Interrupted by signal or timeout
					std::cerr << "Recv failed with code " << errno << std::endl;
					m_isSniffing = false;
					break;
				}

				// An exception escaping this thread would terminate the process
				try
				{
					this->parsePackets(buffer, len);
				}
				catch (const std::exception& e)
				{
					std::cerr << "Packet handling failed: " << e.what() << std::endl;
				}
			}
		};

		m_sniffer = std::thread(startLoop);
		return;
	}

	m_isSniffing = false;
	if (m_sniffer.joinable())
		m_sniffer.join();
	emptyQueue(); // Delete the remaining packets
}

std::optional<libwifi_frame> PacketHandler::getPacket()
{
	std::lock_guard lock(m_mutex);
	if (!m_packets.empty())
	{
		libwifi_frame frame = m_packets.front();
		m_packets.pop();
		return frame;
	}

	return std::nullopt;
}

void PacketHandler::parsePackets(const u_char* packet, const size_t size)
{
	libwifi_frame frame{};

	if (libwifi_get_wifi_frame(&frame, packet, size, IS_RADIOTAP) != 0)
		return;

	const uint8_t* receiver = this->getReceiver(&frame); // This ensures the packet was not broadcasted
	if (receiver == nullptr)
	{
		libwifi_free_wifi_frame(&frame);
		return;
	}

	m_rxToUs++;
	if (frame.frame_control.flags.retry)
		m_rxRetries++; // The sender did not get our ACK for an earlier copy

	// With active monitor the card ACKs within SIFS in hardware. An ACK sent
	// from userspace arrives milliseconds late and only wastes airtime, so it
	// is only a fallback for cards without active monitor support.
	if (!m_hardwareAck)
	{
		if (memcmp(receiver, this->m_apMac, MAC_SIZE_BYTES) == 0)
			this->sendAck();
		else
		{
			std::vector<uint8_t> ack = createAck(receiver);
			this->sendPacket(ack);
		}
	}

	if (frame.frame_control.type == TYPE_DATA &&
		(frame.frame_control.subtype == SUBTYPE_DATA_NULL || frame.frame_control.subtype == SUBTYPE_DATA_QOS_NULL))
	{
		libwifi_free_wifi_frame(&frame);
		return; // We dont want to store it
	}

	std::lock_guard lock(this->m_mutex);
	this->m_packets.push(frame); // We don't free it since there is a ptr inside the frame
	this->m_cv.notify_all();
}

void PacketHandler::sendPacket(std::vector<uint8_t>& packet) const
{
	addRadioTap(packet);
	if (send(m_socket, packet.data(), packet.size(), 0) <= 0)
		throw std::runtime_error("Cannot reach the specified network");
}

void PacketHandler::emptyQueue()
{
	std::lock_guard lock(m_mutex);
	while (!m_packets.empty())
		m_packets.pop();
}

void PacketHandler::addRadioTap(std::vector<uint8_t> &packet)
{
	constexpr uint16_t RADIOTAP_SIZE = 14;
	// Check if packet already has radiotap header:
	// Radiotap header starts with version = 0
	// and length stored in bytes 2 and 3 (little endian)
	const uint16_t channel = InterfaceHandler::getInterfaceChannel();

	if (packet.size() >= 4 && // Bounds checking
		packet[0] == 0x00  && // Version == 0
		packet[1] == 0x00  && // padding = 0
 		*reinterpret_cast<uint16_t*>(&packet[2]) == RADIOTAP_SIZE) // Header size match
	{
		const uint16_t newFreq = 2412 + 5 * (channel - 1);
		const auto freq = reinterpret_cast<uint16_t*>(&packet[CHANNEL_FREQ_OFFSET]);
		*freq = newFreq; //you cannot change the channel without setting him so no need to do it
		return;
	}

	libwifi_radiotap_info info = {};

	info.present = (1 << IEEE80211_RADIOTAP_FLAGS) | (1 << IEEE80211_RADIOTAP_CHANNEL);

	info.flags = 0x00;
	info.channel.freq = 2412 + 5 * (channel - 1);
	info.channel.flags = 0x00a0;

	char radiotapHeader[LIBWIFI_MAX_RADIOTAP_LEN] = {0};
	const uint8_t rtapLen = libwifi_create_radiotap(&info, radiotapHeader);

	radiotapHeader[2] = rtapLen & 0xff; // write length in little endian
	radiotapHeader[3] = (rtapLen >> 8) & 0xff;

	packet.insert(packet.begin(), radiotapHeader, radiotapHeader + rtapLen);
}

void PacketHandler::sendAck() const
{
	if (send(m_socket, m_apAck.data(), m_apAck.size(), 0) < 0)
		throw std::runtime_error("Failed to send ACK");
}

std::vector<uint8_t> PacketHandler::createAck(const uint8_t* receiver)
{
	if (receiver == nullptr)
		throw std::runtime_error("Invalid receiver");

	AckPacket ack;
	memcpy(ack.receiver, receiver, MAC_SIZE_BYTES);

	// No FCS: the radiotap header does not set the FCS flag, so the
	// hardware appends it (an extra one would make the frame invalid).
	return {reinterpret_cast<uint8_t*>(&ack), reinterpret_cast<uint8_t*>(&ack) + sizeof(AckPacket) - sizeof(uint32_t)};
}

const uint8_t* PacketHandler::getReceiver(const libwifi_frame* frame) const
{
	const uint8_t type = frame->frame_control.type;
	if (type == TYPE_CONTROL)
		return nullptr;

	const uint8_t* receiver = nullptr;
	const uint8_t* destination = nullptr;

	if (type == TYPE_DATA)
	{
		receiver = frame->header.data.addr2;
		destination = frame->header.data.addr1;
	}
	else if (type == TYPE_MANAGEMENT)
	{
		receiver = frame->header.mgmt_unordered.addr2;
		destination = frame->header.mgmt_unordered.addr1;
	}

	if (!(receiver != nullptr && destination != nullptr &&
		memcmp(destination, m_deviceMac, MAC_SIZE_BYTES) == 0))
		return nullptr;

	return receiver;
}

void PacketHandler::changeMacAp(const uint8_t* apMAc)
{
	memcpy(m_apMac, apMAc, MAC_SIZE_BYTES);
	m_apAck = std::move(createAck(m_apMac)); //since the ap has changed the ack should too
	addRadioTap(m_apAck);
}

PacketHandler::RxStats PacketHandler::getRxStats() const
{
	return {m_rxToUs.load(), m_rxRetries.load()};
}
