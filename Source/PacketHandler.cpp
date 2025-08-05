//
// Created by yakov on 8/1/25.
//

#include "PacketHandler.h"

#include <cstring>
#include <iostream>
#include <mutex>
#include <linux/wireless.h>
#include <sys/ioctl.h>

extern "C"
{
	#include "libwifi/core/frame/crc.h"
	#include "libwifi/core/radiotap/radiotap.h"
	#include "libwifi/gen/misc/radiotap.h"
}

constexpr uint8_t RADIOTAP_HEADER_MIN_LENGTH = 12;
constexpr uint8_t CHANNEL_FREQ_OFFSET = 8;
constexpr uint8_t CHANNEL_FLAGS_OFFSET = 10;

uint8_t PacketHandler::m_channel = 0; //no one will be able to use anything so the value here does not really matter

PacketHandler::PacketHandler() : m_adapterHandler(AdapterHandler::getInstance()),
	m_isSniffing(false), m_socket(m_adapterHandler.getSocket()) , m_mutex(), m_cv(), m_packets(), m_deviceMac(m_adapterHandler.getDeviceMac())
{
}

PacketHandler::PacketHandler(uint8_t channel, const uint8_t* apMac) :
	m_adapterHandler(AdapterHandler::getInstance()), m_isSniffing(false),
	m_socket(m_adapterHandler.getSocket()), m_mutex(), m_cv(), m_packets(),
	m_apAck(createAck(apMac)), m_deviceMac(m_adapterHandler.getDeviceMac())
{
	memcpy(m_apMac, apMac, MAC_SIZE_BYTES);
	setChannel(channel);
	addRadioTap(m_apAck);
}

bool PacketHandler::waitForPacket(uint16_t timeout)
{
	std::unique_lock<std::mutex> lock(m_mutex);

	return m_cv.wait_for(lock, std::chrono::milliseconds(timeout), [this] {
		return !m_packets.empty();
	});
}

void PacketHandler::toggleSniffing()
{
	if (!m_isSniffing)
	{
		m_isSniffing = true;
		auto startLoop = [this]()
		{
			pthread_t tid = pthread_self();
			struct sched_param sch = { .sched_priority = 98 };
			if (pthread_setschedparam(tid, SCHED_FIFO, &sch) != 0)
				throw std::runtime_error("Failed to set thread to real-time priority");

			uint8_t buffer[MAX_PACKET_SIZE];

			while (m_isSniffing)
			{
				ssize_t len = recv(m_socket, buffer, MAX_PACKET_SIZE, 0);
				if (len < 0)
				{
					if (errno == EINTR) continue;  // Interrupted by signal
					std::cerr << "recv failed" << std::endl;
					break;
				}

				// Process packet
				this->parsePackets(buffer, len);
			}
		};

		m_sniffer = std::thread(startLoop);
		return;
	}
	m_isSniffing = false;
	m_sniffer.join();
	emptyQueue(); // delete the remaining packets
}

std::optional<libwifi_frame> PacketHandler::getPacket()
{
	std::lock_guard<std::mutex> lock(m_mutex);
	if (!m_packets.empty())
	{
		libwifi_frame frame = m_packets.front();
		m_packets.pop();
		return frame;
	}
	return std::nullopt;
}

void PacketHandler::setChannel() const
{
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) throw std::runtime_error("Cannot init socket");

	iwreq wrq = {0};
	strncpy(wrq.ifr_name, m_adapterHandler.getDeviceName().data(), IFNAMSIZ);
	wrq.u.freq.m = 2412 + 5 * (m_channel - 1);
	wrq.u.freq.e = 6;

	if (ioctl(sock, SIOCSIWFREQ, &wrq) != 0)
		throw std::runtime_error("Can't set channel. channel: " + std::to_string(m_channel));
	close(sock);
}

void PacketHandler::parsePackets(const u_char* packet, size_t size)
{
	uint8_t status = 0;
	libwifi_frame frame;

	if (libwifi_get_wifi_frame(&frame, packet, size, IS_RADIOTAP) != 0)
		return;

	const uint8_t* receiver = this->getReceiver(&frame); //this ensure the packet was not broadcasted
	if (receiver != nullptr && memcmp(receiver, this->m_apMac, MAC_SIZE_BYTES) == 0)
	{
		this->sendAck();
	}
	else if (receiver != nullptr)
	{
		std::vector<uint8_t> ack = createAck(receiver);
		this->sendPacket(ack);
	}
	else
		return;

	if (frame.frame_control.type == TYPE_DATA &&
		(frame.frame_control.subtype == SUBTYPE_DATA_NULL || frame.frame_control.subtype == SUBTYPE_DATA_QOS_NULL))
		return; //we dont want to store it

	std::lock_guard<std::mutex> lock(this->m_mutex);
	this->m_packets.push(frame); //we dont free it since there is a ptr inside the frame
	this->m_cv.notify_all();
}

void PacketHandler::sendPacket(std::vector<uint8_t>& packet) const
{
	PacketHandler::addRadioTap(packet);
	if (send(m_socket, packet.data(), packet.size(), 0) <= 0)
		throw std::runtime_error("Cannot reach the specified network");
}

void PacketHandler::emptyQueue()
{
	std::lock_guard<std::mutex> lock(m_mutex);
	while (!m_packets.empty())
		m_packets.pop();
}

void PacketHandler::addRadioTap(std::vector<uint8_t> &packet) const
{
	// Check if packet already has radiotap header:
	// Radiotap header starts with version = 0
	// and length stored in bytes 2 and 3 (little endian)
	if (packet.size() >= 4 && *(uint16_t*)&packet[0] == 0x00 && *(uint16_t*)&packet[2] < packet.size()
		&& *(uint16_t*)&packet[2] != 0)
	{
		uint16_t newFreq = 2412 + 5 * (m_channel - 1);
		uint16_t* freq = reinterpret_cast<uint16_t*>(&packet[CHANNEL_FREQ_OFFSET]);
		*freq = newFreq; //you cannot change the channel without setting him so no need to do it
		return;
	}

	libwifi_radiotap_info info = {0};

	info.present = (1 << IEEE80211_RADIOTAP_FLAGS) | (1 << IEEE80211_RADIOTAP_CHANNEL);

	info.flags = 0x00;
	info.channel.freq = 2412 + 5 * (m_channel - 1);
	info.channel.flags = 0x00a0;

	char radiotapHeader[LIBWIFI_MAX_RADIOTAP_LEN] = {0};
	uint8_t rtapLen = libwifi_create_radiotap(&info, radiotapHeader);

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

	std::vector<uint8_t> ackData(reinterpret_cast<uint8_t*>(&ack), reinterpret_cast<uint8_t*>(&ack) + sizeof(AckPacket) - sizeof(uint32_t));

	uint32_t fcs = libwifi_crc32(ackData.data(), ackData.size());
	// Append FCS in little-endian
	ackData.push_back(fcs & 0xFF);
	ackData.push_back((fcs >> 8) & 0xFF);
	ackData.push_back((fcs >> 16) & 0xFF);
	ackData.push_back((fcs >> 24) & 0xFF);

	return ackData;
}

const uint8_t* PacketHandler::getReceiver(const libwifi_frame* frame)
{
	uint8_t type = frame->frame_control.type;
	if (type == TYPE_CONTROL)
		return nullptr;

	const uint8_t* receiver = nullptr;
	const uint8_t* destination = nullptr;

	if (type == TYPE_DATA) {
		receiver = frame->header.data.addr2;
		destination = frame->header.data.addr1;
	}
	else if (type == TYPE_MANAGEMENT){
		receiver = frame->header.mgmt_unordered.addr2;
		destination = frame->header.mgmt_unordered.addr1;
	}

	if (!(receiver != nullptr && destination != nullptr &&
		memcmp(destination, m_deviceMac, MAC_SIZE_BYTES) == 0))
		return nullptr;
	return receiver;
}

void PacketHandler::changeMacAp(const uint8_t *apMAc)
{
	memcpy(m_apMac, apMAc, MAC_SIZE_BYTES);
	m_apAck = std::move(createAck(m_apMac)); //since the ap has changed the ack should too
	addRadioTap(m_apAck);
}

void PacketHandler::setChannel(uint8_t channel) const
{
	if (channel != m_channel)
	{
		m_channel = channel;
		setChannel();
	}
}

uint8_t PacketHandler::getChannel()
{
	return m_channel;
}
