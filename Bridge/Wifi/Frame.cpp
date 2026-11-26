#include "Frame.h"

namespace Wifi
{

std::optional<Frame> Frame::parse(std::span<const uint8_t> data, const bool hasRadiotap)
{
	Frame frame;

	if (hasRadiotap)
	{
		frame.m_radiotap = Radiotap::parse(data);
		if (!frame.m_radiotap)
			return std::nullopt;
		data = data.subspan(frame.m_radiotap->length);

		if (frame.m_radiotap->hasFcs())
		{
			if (data.size() < FCS_LENGTH)
				return std::nullopt;
			ByteReader r(data.last(FCS_LENGTH));
			frame.m_fcs = r.le32();
			data = data.first(data.size() - FCS_LENGTH);
		}
	}

	const auto header = MacHeader::parse(data, frame.m_headerLength);
	if (!header)
		return std::nullopt;

	frame.m_header = *header;
	frame.m_bytes.assign(data.begin(), data.end());
	return frame;
}

std::optional<int8_t> Frame::signal() const
{
	if (!m_radiotap)
		return std::nullopt;
	if (m_radiotap->signal)
		return m_radiotap->signal;
	for (const RadiotapAntenna& antenna : m_radiotap->antennas)
		if (antenna.signal)
			return antenna.signal;
	return std::nullopt;
}

uint32_t crc32(const std::span<const uint8_t> data)
{
	uint32_t crc = 0xFFFFFFFF;
	for (const uint8_t byte : data)
	{
		crc ^= byte;
		for (int i = 0; i < 8; i++)
			crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
	}
	return ~crc;
}

} // namespace Wifi
