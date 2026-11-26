#include "Common.h"

#include <chrono>
#include <cstdio>

namespace Wifi
{

MacAddress toMac(const uint8_t* mac)
{
	MacAddress out{};
	if (mac != nullptr)
		std::copy_n(mac, MAC_LENGTH, out.begin());
	return out;
}

std::string macToString(const MacAddress& mac)
{
	char buf[18];
	std::snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	return buf;
}

bool isRandomizedMac(const MacAddress& mac)
{
	return (mac[0] & 0x02) != 0;
}

bool isMulticastMac(const MacAddress& mac)
{
	return (mac[0] & 0x01) != 0;
}

/*-------------*/
/* BYTE WRITER */
/*-------------*/

void ByteWriter::le16(const uint16_t value)
{
	u8(value & 0xFF);
	u8(value >> 8);
}

void ByteWriter::le32(const uint32_t value)
{
	le16(value & 0xFFFF);
	le16(value >> 16);
}

void ByteWriter::le64(const uint64_t value)
{
	le32(value & 0xFFFFFFFF);
	le32(value >> 32);
}

void ByteWriter::be16(const uint16_t value)
{
	u8(value >> 8);
	u8(value & 0xFF);
}

void ByteWriter::be64(const uint64_t value)
{
	for (int shift = 56; shift >= 0; shift -= 8)
		u8(static_cast<uint8_t>(value >> shift));
}

void ByteWriter::bytes(const std::span<const uint8_t> data)
{
	m_out.insert(m_out.end(), data.begin(), data.end());
}

/*-------------*/
/* BYTE READER */
/*-------------*/

bool ByteReader::take(const size_t count)
{
	if (!m_ok || count > m_data.size() - m_offset)
	{
		m_ok = false;
		return false;
	}
	return true;
}

uint8_t ByteReader::u8()
{
	if (!take(1))
		return 0;
	return m_data[m_offset++];
}

uint16_t ByteReader::le16()
{
	if (!take(2))
		return 0;
	const uint16_t value = m_data[m_offset] | m_data[m_offset + 1] << 8;
	m_offset += 2;
	return value;
}

uint32_t ByteReader::le32()
{
	if (!take(4))
		return 0;
	const uint32_t low = le16();
	return low | static_cast<uint32_t>(le16()) << 16;
}

uint64_t ByteReader::le64()
{
	if (!take(8))
		return 0;
	const uint64_t low = le32();
	return low | static_cast<uint64_t>(le32()) << 32;
}

uint16_t ByteReader::be16()
{
	if (!take(2))
		return 0;
	const uint16_t value = m_data[m_offset] << 8 | m_data[m_offset + 1];
	m_offset += 2;
	return value;
}

uint64_t ByteReader::be64()
{
	if (!take(8))
		return 0;
	uint64_t value = 0;
	for (int i = 0; i < 8; i++)
		value = value << 8 | m_data[m_offset++];
	return value;
}

MacAddress ByteReader::mac()
{
	MacAddress out{};
	const auto data = bytes(MAC_LENGTH);
	if (data.size() == MAC_LENGTH)
		std::copy(data.begin(), data.end(), out.begin());
	return out;
}

std::span<const uint8_t> ByteReader::bytes(const size_t count)
{
	if (!take(count))
		return {};
	const auto out = m_data.subspan(m_offset, count);
	m_offset += count;
	return out;
}

void ByteReader::skip(const size_t count)
{
	if (take(count))
		m_offset += count;
}

/*---------------*/
/* FRAME CONTROL */
/*---------------*/

uint16_t FrameControl::pack() const
{
	const uint8_t first = (version & 0x03) | (static_cast<uint8_t>(type) & 0x03) << 2 | (subtype & 0x0F) << 4;
	return static_cast<uint16_t>(first | flags << 8);
}

FrameControl FrameControl::unpack(const uint16_t value)
{
	FrameControl fc;
	fc.version = value & 0x03;
	fc.type = static_cast<FrameType>((value >> 2) & 0x03);
	fc.subtype = (value >> 4) & 0x0F;
	fc.flags = value >> 8;
	return fc;
}

/*------------*/
/* MAC HEADER */
/*------------*/

MacHeader MacHeader::management(const ManagementSubtype subtype, const MacAddress& receiver,
	const MacAddress& transmitter, const MacAddress& bssid)
{
	MacHeader header;
	header.frameControl = FrameControl(subtype);
	header.addr1 = receiver;
	header.addr2 = transmitter;
	header.addr3 = bssid;
	return header;
}

// Control frame header length by subtype: ACK/CTS (and wrappers) only carry
// the receiver, the others carry receiver + transmitter.
static size_t controlHeaderLength(const uint8_t subtype)
{
	switch (static_cast<ControlSubtype>(subtype))
	{
	case ControlSubtype::Ack:
	case ControlSubtype::Cts:
	case ControlSubtype::Wrapper:
	case ControlSubtype::CfExtension:
		return CONTROL_HEADER_LENGTH + MAC_LENGTH;
	default:
		return CONTROL_HEADER_LENGTH + 2 * MAC_LENGTH;
	}
}

size_t MacHeader::length() const
{
	if (frameControl.type == FrameType::Control)
		return controlHeaderLength(frameControl.subtype);

	size_t len = MANAGEMENT_HEADER_LENGTH;
	if (addr4)
		len += MAC_LENGTH;
	if (qosControl)
		len += sizeof(uint16_t);
	if (htControl)
		len += sizeof(uint32_t);
	return len;
}

void MacHeader::write(ByteWriter& writer) const
{
	writer.le16(frameControl.pack());
	writer.le16(duration);
	writer.mac(addr1);
	if (frameControl.type == FrameType::Control)
	{
		if (controlHeaderLength(frameControl.subtype) > CONTROL_HEADER_LENGTH + MAC_LENGTH)
			writer.mac(addr2);
		return;
	}
	writer.mac(addr2);
	writer.mac(addr3);
	writer.le16(sequenceControl.pack());
	if (addr4)
		writer.mac(*addr4);
	if (qosControl)
		writer.le16(*qosControl);
	if (htControl)
		writer.le32(*htControl);
}

std::optional<MacHeader> MacHeader::parse(const std::span<const uint8_t> data, size_t& headerLength)
{
	ByteReader reader(data);
	MacHeader header;
	header.frameControl = FrameControl::unpack(reader.le16());
	header.duration = reader.le16();
	const FrameControl& fc = header.frameControl;

	switch (fc.type)
	{
	case FrameType::Control:
		header.addr1 = reader.mac();
		if (controlHeaderLength(fc.subtype) > CONTROL_HEADER_LENGTH + MAC_LENGTH)
			header.addr2 = reader.mac();
		break;

	case FrameType::Management:
	case FrameType::Data:
		header.addr1 = reader.mac();
		header.addr2 = reader.mac();
		header.addr3 = reader.mac();
		header.sequenceControl = SequenceControl::unpack(reader.le16());
		if (fc.type == FrameType::Data && fc.toDs() && fc.fromDs())
			header.addr4 = reader.mac();
		if (fc.isQosData())
			header.qosControl = reader.le16();
		// +HTC exists on management frames and on QoS data frames
		if (fc.order() && (fc.type == FrameType::Management || fc.isQosData()))
			header.htControl = reader.le32();
		break;

	default:
		return std::nullopt; // Extension frames are not supported
	}

	if (!reader.ok())
		return std::nullopt;
	headerLength = reader.offset();
	return header;
}

MacAddress MacHeader::bssid() const
{
	if (frameControl.type != FrameType::Data)
		return addr3;
	if (frameControl.toDs() && !frameControl.fromDs())
		return addr1;
	if (!frameControl.toDs() && frameControl.fromDs())
		return addr2;
	return addr3;
}

MacAddress MacHeader::destination() const
{
	if (frameControl.type == FrameType::Data && frameControl.toDs())
		return addr3;
	return addr1;
}

MacAddress MacHeader::source() const
{
	if (frameControl.type == FrameType::Data && frameControl.fromDs())
		return frameControl.toDs() && addr4 ? *addr4 : addr3;
	return addr2;
}

/*------*/
/* MISC */
/*------*/

uint64_t currentTimestamp()
{
	using namespace std::chrono;
	return duration_cast<microseconds>(system_clock::now().time_since_epoch()).count();
}

uint8_t frequencyToChannel(const uint16_t frequency)
{
	if (frequency == 2484)
		return 14;
	if (frequency >= 2412 && frequency < 2484)
		return (frequency - 2407) / 5;
	if (frequency >= 5160 && frequency <= 5885)
		return (frequency - 5000) / 5;
	if (frequency == 5935)
		return 2;
	if (frequency >= 5955 && frequency <= 7115)
		return (frequency - 5950) / 5;
	return 0;
}

uint16_t channelToFrequency(const uint8_t channel, const bool is6GHz)
{
	if (is6GHz)
		return channel == 2 ? 5935 : 5950 + 5 * channel;
	if (channel == 14)
		return 2484;
	if (channel >= 1 && channel <= 13)
		return 2407 + 5 * channel;
	if (channel >= 32 && channel <= 177)
		return 5000 + 5 * channel;
	return 0;
}

} // namespace Wifi
