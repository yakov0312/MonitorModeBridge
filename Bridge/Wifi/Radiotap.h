// C++ replacement for libwifi: radiotap header parsing and generation.

#pragma once

#include "Common.h"

namespace Wifi
{

// Presence bit numbers (radiotap.org/fields/defined)
namespace RadiotapField
{
	constexpr uint8_t Tsft = 0;
	constexpr uint8_t Flags = 1;
	constexpr uint8_t Rate = 2;
	constexpr uint8_t Channel = 3;
	constexpr uint8_t Fhss = 4;
	constexpr uint8_t DbmAntennaSignal = 5;
	constexpr uint8_t DbmAntennaNoise = 6;
	constexpr uint8_t LockQuality = 7;
	constexpr uint8_t TxAttenuation = 8;
	constexpr uint8_t DbTxAttenuation = 9;
	constexpr uint8_t DbmTxPower = 10;
	constexpr uint8_t Antenna = 11;
	constexpr uint8_t DbAntennaSignal = 12;
	constexpr uint8_t DbAntennaNoise = 13;
	constexpr uint8_t RxFlags = 14;
	constexpr uint8_t TxFlags = 15;
	constexpr uint8_t RtsRetries = 16;
	constexpr uint8_t DataRetries = 17;
	constexpr uint8_t XChannel = 18;
	constexpr uint8_t Mcs = 19;
	constexpr uint8_t AmpduStatus = 20;
	constexpr uint8_t Vht = 21;
	constexpr uint8_t Timestamp = 22;
	constexpr uint8_t He = 23;
	constexpr uint8_t HeMu = 24;
	constexpr uint8_t HeMuOtherUser = 25;
	constexpr uint8_t ZeroLengthPsdu = 26;
	constexpr uint8_t LSig = 27;
	constexpr uint8_t Tlv = 28;
	constexpr uint8_t RadiotapNamespace = 29;
	constexpr uint8_t VendorNamespace = 30;
	constexpr uint8_t Ext = 31;
}

// Flags field (bit 1)
namespace RadiotapFlag
{
	constexpr uint8_t Cfp = 0x01;
	constexpr uint8_t ShortPreamble = 0x02;
	constexpr uint8_t Wep = 0x04;
	constexpr uint8_t Fragmentation = 0x08;
	constexpr uint8_t Fcs = 0x10; // frame ends with a 4-byte FCS
	constexpr uint8_t DataPad = 0x20;
	constexpr uint8_t BadFcs = 0x40;
	constexpr uint8_t ShortGi = 0x80;
}

// Channel flags (second half of the channel field)
namespace RadiotapChannelFlag
{
	constexpr uint16_t Turbo = 0x0010;
	constexpr uint16_t Cck = 0x0020;
	constexpr uint16_t Ofdm = 0x0040;
	constexpr uint16_t Spectrum2GHz = 0x0080;
	constexpr uint16_t Spectrum5GHz = 0x0100;
	constexpr uint16_t Passive = 0x0200;
	constexpr uint16_t Dynamic = 0x0400;
	constexpr uint16_t Gfsk = 0x0800;
}

namespace RadiotapRxFlag
{
	constexpr uint16_t BadPlcp = 0x0002;
}

namespace RadiotapTxFlag
{
	constexpr uint16_t Fail = 0x0001;
	constexpr uint16_t Cts = 0x0002;
	constexpr uint16_t Rts = 0x0004;
	constexpr uint16_t NoAck = 0x0008;
	constexpr uint16_t NoSequence = 0x0010;
	constexpr uint16_t NoReorder = 0x0020;
}

namespace RadiotapBand
{
	constexpr uint8_t Band2GHz = 1 << 0;
	constexpr uint8_t Band5GHz = 1 << 1;
	constexpr uint8_t Band6GHz = 1 << 2;
	constexpr uint8_t Band900MHz = 1 << 3;
}

constexpr size_t RADIOTAP_HEADER_LENGTH = 8;

struct RadiotapChannel
{
	uint16_t frequency = 0; // MHz
	uint16_t flags = 0;     // RadiotapChannelFlag bits
	uint8_t number = 0;     // derived from the frequency on parse
	uint8_t band = 0;       // RadiotapBand bit, derived on parse
};

struct RadiotapMcs
{
	uint8_t known = 0;
	uint8_t flags = 0;
	uint8_t index = 0;
};

struct RadiotapTimestamp
{
	uint64_t timestamp = 0;
	uint16_t accuracy = 0;
	uint8_t unit = 0;
	uint8_t flags = 0;
};

// Per-antenna values from the extra radiotap namespaces after the first
struct RadiotapAntenna
{
	std::optional<uint8_t> number;
	std::optional<int8_t> signal;
	std::optional<int8_t> noise;
};

struct RadiotapInfo
{
	uint16_t length = 0;               // whole radiotap header, set by parse
	std::vector<uint32_t> present;     // all presence words, set by parse

	std::optional<uint64_t> tsft;
	std::optional<uint8_t> flags;      // RadiotapFlag bits
	std::optional<uint8_t> rate;       // 500 kbps units
	std::optional<RadiotapChannel> channel;
	std::optional<int8_t> signal;      // dBm (combined)
	std::optional<int8_t> noise;       // dBm
	std::optional<int8_t> txPower;     // dBm
	std::optional<uint8_t> antenna;
	std::optional<uint16_t> rxFlags;
	std::optional<uint16_t> txFlags;
	std::optional<uint8_t> rtsRetries;
	std::optional<uint8_t> dataRetries;
	std::optional<RadiotapMcs> mcs;
	std::optional<RadiotapTimestamp> timestamp;
	std::vector<RadiotapAntenna> antennas;

	[[nodiscard]] bool hasFcs() const { return flags.value_or(0) & RadiotapFlag::Fcs; }
	[[nodiscard]] bool badFcs() const { return flags.value_or(0) & RadiotapFlag::BadFcs; }
	[[nodiscard]] float rateMbps() const { return rate.value_or(0) / 2.0f; }
};

class Radiotap
{
public:
	// Parses the radiotap header at the start of data. Fields after one this
	// parser does not know the size of are skipped (length is still right).
	static std::optional<RadiotapInfo> parse(std::span<const uint8_t> data);

	// Header length from bytes 2-3, or 0 if data does not start with a
	// valid radiotap header
	static uint16_t headerLength(std::span<const uint8_t> data);

	// Builds a radiotap header with one presence word, containing every
	// field of info that is set (tsft, flags, rate, channel, signal, noise,
	// txPower, antenna, rxFlags, txFlags, rtsRetries, dataRetries, mcs,
	// timestamp). Fields are aligned as radiotap requires.
	static std::vector<uint8_t> build(const RadiotapInfo& info);

	// The header PacketHandler used: flags + channel (14 bytes)
	static std::vector<uint8_t> buildForChannel(uint16_t frequency, uint8_t flags = 0,
		uint16_t channelFlags = RadiotapChannelFlag::Cck | RadiotapChannelFlag::Spectrum2GHz);

	// Puts the radiotap header in front of an 802.11 frame
	static void prepend(std::vector<uint8_t>& frame, const RadiotapInfo& info);
};

} // namespace Wifi
