#include "Frame.h"

namespace Wifi
{

std::optional<Frame> Frame::parse(std::span<const uint8_t> data, const bool hasRadiotap)
{
	Frame frame;
	auto frameData = data;

	if (hasRadiotap)
	{
		frame.m_radiotapLength = Radiotap::headerLength(data);
		if (frame.m_radiotapLength == 0)
			return std::nullopt;
		frameData = data.subspan(frame.m_radiotapLength);

		if (Radiotap::flags(data) & RadiotapFlag::Fcs)
		{
			if (frameData.size() < FCS_LENGTH)
				return std::nullopt;
			const auto fcs = frameData.last(FCS_LENGTH);
			frame.m_fcs = fcs[0] | fcs[1] << 8 | fcs[2] << 16 | static_cast<uint32_t>(fcs[3]) << 24;
			frameData = frameData.first(frameData.size() - FCS_LENGTH);
			data = data.first(data.size() - FCS_LENGTH);
		}
	}

	size_t headerLength = 0;
	const auto header = MacHeader::parse(frameData, headerLength);
	if (!header)
		return std::nullopt;

	frame.m_header = *header;
	frame.m_headerLength = static_cast<uint16_t>(headerLength);
	frame.m_raw.assign(data.begin(), data.end());
	return frame;
}

std::optional<RadiotapInfo> Frame::radiotap() const
{
	if (m_radiotapLength == 0)
		return std::nullopt;
	return Radiotap::parse(radiotapBytes());
}

std::optional<int8_t> Frame::signal() const
{
	const auto info = radiotap();
	if (!info)
		return std::nullopt;
	if (info->signal)
		return info->signal;
	for (const RadiotapAntenna& antenna : info->antennas)
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
