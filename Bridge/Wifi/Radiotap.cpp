#include "Radiotap.h"

#include <bit>
#include <iterator>

namespace Wifi
{

namespace
{
	struct FieldLayout
	{
		uint8_t align;
		uint8_t size;
	};

	// Alignment and size of the fields in the radiotap namespace. A size of
	// 0 means "unknown": parsing stops there, since the next offset cannot
	// be computed.
	constexpr FieldLayout FIELD_LAYOUT[29] = {
		{8, 8},  // 0  TSFT
		{1, 1},  // 1  Flags
		{1, 1},  // 2  Rate
		{2, 4},  // 3  Channel
		{2, 2},  // 4  FHSS
		{1, 1},  // 5  dBm antenna signal
		{1, 1},  // 6  dBm antenna noise
		{2, 2},  // 7  Lock quality
		{2, 2},  // 8  TX attenuation
		{2, 2},  // 9  dB TX attenuation
		{1, 1},  // 10 dBm TX power
		{1, 1},  // 11 Antenna
		{1, 1},  // 12 dB antenna signal
		{1, 1},  // 13 dB antenna noise
		{2, 2},  // 14 RX flags
		{2, 2},  // 15 TX flags
		{1, 1},  // 16 RTS retries
		{1, 1},  // 17 data retries
		{4, 8},  // 18 XChannel
		{1, 3},  // 19 MCS
		{4, 8},  // 20 A-MPDU status
		{2, 12}, // 21 VHT
		{8, 12}, // 22 timestamp
		{2, 12}, // 23 HE
		{2, 12}, // 24 HE-MU
		{2, 6},  // 25 HE-MU-other-user
		{1, 1},  // 26 0-length-PSDU
		{2, 4},  // 27 L-SIG
		{0, 0},  // 28 TLVs (variable, not parsed)
	};

	size_t alignUp(const size_t offset, const size_t align)
	{
		return (offset + align - 1) / align * align;
	}

	uint8_t bandOf(const uint16_t freq)
	{
		if (freq >= 2412 && freq <= 2484)
			return RadiotapBand::Band2GHz;
		if (freq >= 5160 && freq <= 5885)
			return RadiotapBand::Band5GHz;
		if (freq >= 5925 && freq <= 7125)
			return RadiotapBand::Band6GHz;
		if (freq >= 902 && freq <= 928)
			return RadiotapBand::Band900MHz;
		return 0;
	}

	void storeField(RadiotapInfo& info, const uint8_t field, const size_t ns, std::span<const uint8_t> raw)
	{
		ByteReader r(raw);

		// Namespaces after the first one describe one antenna each
		if (ns > 0)
		{
			if (ns > info.antennas.capacity())
				return;
			if (info.antennas.size() < ns)
				info.antennas.resize(ns);
			RadiotapAntenna& antenna = info.antennas[ns - 1];
			if (field == RadiotapField::DbmAntennaSignal)
				antenna.signal = static_cast<int8_t>(r.u8());
			else if (field == RadiotapField::DbmAntennaNoise)
				antenna.noise = static_cast<int8_t>(r.u8());
			else if (field == RadiotapField::Antenna)
				antenna.number = r.u8();
			return;
		}

		switch (field)
		{
		case RadiotapField::Tsft:
			info.tsft = r.le64();
			break;
		case RadiotapField::Flags:
			info.flags = r.u8();
			break;
		case RadiotapField::Rate:
			info.rate = r.u8();
			break;
		case RadiotapField::Channel:
		{
			RadiotapChannel channel;
			channel.frequency = r.le16();
			channel.flags = r.le16();
			channel.number = frequencyToChannel(channel.frequency);
			channel.band = bandOf(channel.frequency);
			info.channel = channel;
			break;
		}
		case RadiotapField::DbmAntennaSignal:
			info.signal = static_cast<int8_t>(r.u8());
			break;
		case RadiotapField::DbmAntennaNoise:
			info.noise = static_cast<int8_t>(r.u8());
			break;
		case RadiotapField::DbmTxPower:
			info.txPower = static_cast<int8_t>(r.u8());
			break;
		case RadiotapField::Antenna:
			info.antenna = r.u8();
			break;
		case RadiotapField::RxFlags:
			info.rxFlags = r.le16();
			break;
		case RadiotapField::TxFlags:
			info.txFlags = r.le16();
			break;
		case RadiotapField::RtsRetries:
			info.rtsRetries = r.u8();
			break;
		case RadiotapField::DataRetries:
			info.dataRetries = r.u8();
			break;
		case RadiotapField::Mcs:
			info.mcs = RadiotapMcs{r.u8(), r.u8(), r.u8()};
			break;
		case RadiotapField::Timestamp:
		{
			RadiotapTimestamp ts;
			ts.timestamp = r.le64();
			ts.accuracy = r.le16();
			ts.unit = r.u8();
			ts.flags = r.u8();
			info.timestamp = ts;
			break;
		}
		default:
			break; // known size, value not kept
		}
	}
}

uint16_t Radiotap::headerLength(const std::span<const uint8_t> data)
{
	if (data.size() < RADIOTAP_HEADER_LENGTH || data[0] != 0)
		return 0;
	const uint16_t len = data[2] | data[3] << 8;
	if (len < RADIOTAP_HEADER_LENGTH || len > data.size())
		return 0;
	return len;
}

uint8_t Radiotap::flags(const std::span<const uint8_t> data)
{
	const uint16_t len = headerLength(data);
	if (len == 0)
		return 0;

	const uint32_t first = data[4] | data[5] << 8 | data[6] << 16 | static_cast<uint32_t>(data[7]) << 24;
	if (!(first & (1u << RadiotapField::Flags)))
		return 0;

	// Skip the remaining presence words (bit 31 of each says another follows)
	size_t offset = 8;
	for (uint8_t last = data[7]; last & 0x80; offset += 4)
	{
		if (offset + 4 > len)
			return 0;
		last = data[offset + 3];
	}
	// Only TSFT (8 bytes, 8-aligned) can come before Flags
	if (first & (1u << RadiotapField::Tsft))
		offset = alignUp(offset, 8) + 8;
	return offset < len ? data[offset] : 0;
}

std::optional<RadiotapInfo> Radiotap::parse(const std::span<const uint8_t> data)
{
	const uint16_t len = headerLength(data);
	if (len == 0)
		return std::nullopt;

	const auto header = data.first(len);
	RadiotapInfo info;
	info.length = len;

	// Presence words: each one with bit 31 set is followed by another
	size_t offset = 4;
	do
	{
		if (offset + 4 > len)
			return std::nullopt;
		ByteReader r(header.subspan(offset, 4));
		if (!info.present.push_back(r.le32()))
			return std::nullopt; // more presence words than anyone uses
		offset += 4;
	} while (info.present.back() & (1u << RadiotapField::Ext));

	enum class Namespace { Radiotap, Vendor };
	Namespace current = Namespace::Radiotap;
	size_t radiotapNamespaces = 0; // index of the current radiotap namespace
	size_t vendorSkip = 0;
	size_t bitBase = 0;            // 32 * words already used by this namespace

	for (size_t word = 0; word < info.present.size(); word++)
	{
		const uint32_t bits = info.present[word];
		Namespace next = current;
		bool nextIsNew = false;

		if (current == Namespace::Vendor)
		{
			// Vendor data follows as one block of skip_length bytes
			offset += vendorSkip;
			if (offset > len)
				return info;
			vendorSkip = 0;
		}

		// Visit only the set bits, lowest first
		for (uint32_t pending = bits; pending != 0; pending &= pending - 1)
		{
			const auto bit = static_cast<uint8_t>(std::countr_zero(pending));

			if (bit == RadiotapField::Ext)
				continue;
			if (bit == RadiotapField::RadiotapNamespace)
			{
				next = Namespace::Radiotap;
				nextIsNew = true;
				continue;
			}
			if (bit == RadiotapField::VendorNamespace)
			{
				// OUI(3) + sub namespace(1) + skip_length(2), 2-byte aligned
				offset = alignUp(offset, 2);
				if (offset + 6 > len)
					return info;
				vendorSkip = header[offset + 4] | header[offset + 5] << 8;
				offset += 6;
				next = Namespace::Vendor;
				nextIsNew = true;
				continue;
			}
			if (current == Namespace::Vendor)
				continue; // vendor fields were skipped as a block

			const size_t index = bitBase + bit;
			if (index >= std::size(FIELD_LAYOUT) || FIELD_LAYOUT[index].size == 0)
				return info; // unknown size: cannot go on
			const FieldLayout layout = FIELD_LAYOUT[index];
			offset = alignUp(offset, layout.align);
			if (offset + layout.size > len)
				return info;
			storeField(info, static_cast<uint8_t>(index), radiotapNamespaces, header.subspan(offset, layout.size));
			offset += layout.size;
		}

		if (nextIsNew)
		{
			// Bit 29/30: the next word starts a namespace, numbered from 0
			if (next == Namespace::Radiotap)
				radiotapNamespaces++;
			current = next;
			bitBase = 0;
		}
		else
		{
			// Only bit 31: the next word continues this namespace (bits 32+)
			bitBase += 32;
		}
	}

	return info;
}

std::vector<uint8_t> Radiotap::build(const RadiotapInfo& info)
{
	uint32_t present = 0;
	std::vector<uint8_t> out(RADIOTAP_HEADER_LENGTH, 0);
	ByteWriter w(out);

	auto field = [&](const uint8_t bit) {
		present |= 1u << bit;
		// Alignment is relative to the start of the header
		while (out.size() % FIELD_LAYOUT[bit].align != 0)
			w.u8(0);
	};

	if (info.tsft) { field(RadiotapField::Tsft); w.le64(*info.tsft); }
	if (info.flags) { field(RadiotapField::Flags); w.u8(*info.flags); }
	if (info.rate) { field(RadiotapField::Rate); w.u8(*info.rate); }
	if (info.channel)
	{
		field(RadiotapField::Channel);
		w.le16(info.channel->frequency);
		w.le16(info.channel->flags);
	}
	if (info.signal) { field(RadiotapField::DbmAntennaSignal); w.u8(static_cast<uint8_t>(*info.signal)); }
	if (info.noise) { field(RadiotapField::DbmAntennaNoise); w.u8(static_cast<uint8_t>(*info.noise)); }
	if (info.txPower) { field(RadiotapField::DbmTxPower); w.u8(static_cast<uint8_t>(*info.txPower)); }
	if (info.antenna) { field(RadiotapField::Antenna); w.u8(*info.antenna); }
	if (info.rxFlags) { field(RadiotapField::RxFlags); w.le16(*info.rxFlags); }
	if (info.txFlags) { field(RadiotapField::TxFlags); w.le16(*info.txFlags); }
	if (info.rtsRetries) { field(RadiotapField::RtsRetries); w.u8(*info.rtsRetries); }
	if (info.dataRetries) { field(RadiotapField::DataRetries); w.u8(*info.dataRetries); }
	if (info.mcs)
	{
		field(RadiotapField::Mcs);
		w.u8(info.mcs->known);
		w.u8(info.mcs->flags);
		w.u8(info.mcs->index);
	}
	if (info.timestamp)
	{
		field(RadiotapField::Timestamp);
		w.le64(info.timestamp->timestamp);
		w.le16(info.timestamp->accuracy);
		w.u8(info.timestamp->unit);
		w.u8(info.timestamp->flags);
	}

	// version 0, pad 0, length, presence word
	const auto len = static_cast<uint16_t>(out.size());
	out[2] = len & 0xFF;
	out[3] = len >> 8;
	for (int i = 0; i < 4; i++)
		out[4 + i] = static_cast<uint8_t>(present >> (8 * i));
	return out;
}

std::vector<uint8_t> Radiotap::buildForChannel(const uint16_t frequency, const uint8_t flags, const uint16_t channelFlags)
{
	RadiotapInfo info;
	info.flags = flags;
	info.channel = RadiotapChannel{frequency, channelFlags};
	return build(info);
}

void Radiotap::prepend(std::vector<uint8_t>& frame, const RadiotapInfo& info)
{
	const auto header = build(info);
	frame.insert(frame.begin(), header.begin(), header.end());
}

} // namespace Wifi
