// C++ replacement for libwifi: tagged parameters (information elements).
//
// Tags keeps all tags in one byte buffer, exactly as they are on the air
// (number, length, data, number, length, data...). Iterating or find()
// hands out Tag views into that buffer: no copies. A Tag view is valid
// until the Tags it came from is changed or destroyed.

#pragma once

#include "Common.h"

#include <string_view>

namespace Wifi
{

// 802.11 element IDs
enum class TagNumber : uint8_t
{
	Ssid = 0,
	SupportedRates = 1,
	DsParameter = 3,
	CfParameter = 4,
	Tim = 5,
	BssParameters = 6,
	Country = 7,
	Request = 10,
	BssLoad = 11,
	EdcaParameters = 12,
	Tspec = 13,
	Tclas = 14,
	Schedule = 15,
	ChallengeText = 16,
	PowerConstraint = 32,
	PowerCapability = 33,
	TpcRequest = 34,
	TpcReport = 35,
	SupportedChannels = 36,
	ChannelSwitchAnnouncement = 37,
	MeasurementRequest = 38,
	MeasurementReport = 39,
	Quiet = 40,
	IbssDfs = 41,
	Erp = 42,
	TsDelay = 43,
	TclasProcessing = 44,
	HtCapabilities = 45,
	QosCapability = 46,
	Rsn = 48,
	ExtendedSupportedRates = 50,
	ApChannelReport = 51,
	NeighborReport = 52,
	Rcpi = 53,
	MobilityDomain = 54,
	FastBssTransition = 55,
	TimeoutInterval = 56,
	RicData = 57,
	DseRegisteredLocation = 58,
	SupportedOperatingClasses = 59,
	ExtendedChannelSwitchAnnouncement = 60,
	HtOperation = 61,
	SecondaryChannelOffset = 62,
	BssAverageAccessDelay = 63,
	Antenna = 64,
	Rsni = 65,
	MeasurementPilotTransmission = 66,
	BssAvailableAdmissionCapacity = 67,
	BssAcAccessDelay = 68,
	TimeAdvertisement = 69,
	RmEnabledCapabilities = 70,
	MultipleBssid = 71,
	BssCoexistence = 72,
	BssIntolerantChannelReport = 73,
	OverlappingBssParameters = 74,
	RicDescriptor = 75,
	ManagementMic = 76,
	EventRequest = 78,
	EventReport = 79,
	DiagnosticRequest = 80,
	DiagnosticReport = 81,
	LocationParameters = 82,
	NontransmittedBssidCapability = 83,
	SsidList = 84,
	MultipleBssidIndex = 85,
	FmsDescriptor = 86,
	FmsRequest = 87,
	FmsResponse = 88,
	QosTrafficCapability = 89,
	BssMaxIdlePeriod = 90,
	TfsRequest = 91,
	TfsResponse = 92,
	WnmSleepMode = 93,
	TimBroadcastRequest = 94,
	TimBroadcastResponse = 95,
	CollocatedInterferenceReport = 96,
	ChannelUsage = 97,
	TimeZone = 98,
	DmsRequest = 99,
	DmsResponse = 100,
	LinkIdentifier = 101,
	WakeupSchedule = 102,
	ChannelSwitchTiming = 104,
	PtiControl = 105,
	TpuBufferStatus = 106,
	Interworking = 107,
	AdvertisementProtocol = 108,
	ExpeditedBandwidthRequest = 109,
	QosMap = 110,
	RoamingConsortium = 111,
	EmergencyAlertIdentifier = 112,
	MeshConfiguration = 113,
	MeshId = 114,
	MeshLinkMetricReport = 115,
	CongestionNotification = 116,
	MeshPeeringManagement = 117,
	MeshChannelSwitchParameters = 118,
	MeshAwakeWindow = 119,
	BeaconTiming = 120,
	MccaopSetupRequest = 121,
	MccaopSetupReply = 122,
	MccaopAdvertisement = 123,
	MccaopTeardown = 124,
	Gann = 125,
	Rann = 126,
	ExtendedCapabilities = 127,
	Preq = 130,
	Prep = 131,
	Perr = 132,
	Pxu = 137,
	Pxuc = 138,
	AuthenticatedMeshPeeringExchange = 139,
	Mic = 140,
	DestinationUri = 141,
	UApsdCoexistence = 142,
	DmgWakeupSchedule = 143,
	ExtendedSchedule = 144,
	StaAvailability = 145,
	DmgTspec = 146,
	NextDmgAti = 147,
	DmgOperation = 151,
	DmgBssParameterChange = 152,
	DmgBeamRefinement = 153,
	ChannelMeasurementFeedback = 154,
	AwakeWindow = 157,
	MultiBand = 158,
	AddbaExtension = 159,
	NextpcpList = 160,
	PcpHandover = 161,
	DmgLinkMargin = 162,
	SwitchingStream = 163,
	SessionTransition = 164,
	DynamicTonePairingReport = 165,
	ClusterReport = 166,
	RelayCapabilities = 167,
	RelayTransferParameterSet = 168,
	BeamlinkMaintenance = 169,
	MultipleMacSublayers = 170,
	UPid = 171,
	DmgLinkAdaptationAcknowledgement = 172,
	MccaopAdvertisementOverview = 174,
	QuietPeriodRequest = 175,
	QuietPeriodResponse = 177,
	QmfPolicy = 181,
	EcapcPolicy = 182,
	ClusterTimeOffset = 183,
	IntraAccessCategoryPriority = 184,
	ScsDescriptor = 185,
	QloadReport = 186,
	HccaTxopUpdateCount = 187,
	HigherLayerStreamId = 188,
	GcrGroupAddress = 189,
	AntennaSectorIdPattern = 190,
	VhtCapabilities = 191,
	VhtOperation = 192,
	ExtendedBssLoad = 193,
	WideBandwidthChannelSwitch = 194,
	TransmitPowerEnvelope = 195,
	ChannelSwitchWrapper = 196,
	Aid = 197,
	QuietChannel = 198,
	Upsim = 200,
	ReducedNeighborReport = 201,
	TvhtOperation = 202,
	DeviceLocation = 204,
	WhiteSpaceMap = 205,
	FineTimingMeasurementParameters = 206,
	VendorSpecific = 221,
	ElementExtension = 255,
};

// Element ID Extension values (tag 255, first byte of the body)
enum class TagExtension : uint8_t
{
	HeCapabilities = 35,
	HeOperation = 36,
	EhtOperation = 106,
	MultiLink = 107,
	EhtCapabilities = 108,
};

constexpr size_t TAG_HEADER_LENGTH = 2;
constexpr size_t MAX_TAG_LENGTH = 255;
// What create() reserves: SSID, channel, rates and RSN fit without regrowing
constexpr size_t TYPICAL_TAGS_LENGTH = 96;

// One tag: a view into a Tags buffer (or any byte buffer)
struct Tag
{
	uint8_t number = 0;
	std::span<const uint8_t> data;

	[[nodiscard]] bool is(TagNumber tag) const { return number == static_cast<uint8_t>(tag); }
	[[nodiscard]] size_t length() const { return TAG_HEADER_LENGTH + data.size(); }
	// Vendor specific tags start with a 3-byte OUI and a 1-byte type
	[[nodiscard]] bool isVendor(const std::array<uint8_t, 3>& oui, uint8_t type) const;
	[[nodiscard]] std::vector<uint8_t> copy() const { return {data.begin(), data.end()}; }
};

class Tags
{
public:
	class Iterator
	{
	public:
		using value_type = Tag;
		using difference_type = std::ptrdiff_t;

		Iterator() = default;
		explicit Iterator(const uint8_t* pos) : m_pos(pos) {}
		Tag operator*() const { return {m_pos[0], {m_pos + TAG_HEADER_LENGTH, m_pos[1]}}; }
		Iterator& operator++() { m_pos += TAG_HEADER_LENGTH + m_pos[1]; return *this; }
		Iterator operator++(int) { Iterator old = *this; ++*this; return old; }
		bool operator==(const Iterator& other) const { return m_pos == other.m_pos; }

	private:
		const uint8_t* m_pos = nullptr;
	};

	Tags() = default;

	// Copies raw tagged parameters. A truncated last tag is dropped and
	// marks the result as not complete(); everything before it is kept.
	static Tags parse(std::span<const uint8_t> data);

	// Append. Throws std::invalid_argument when data is longer than 255 bytes.
	void add(uint8_t number, std::span<const uint8_t> data);
	void add(TagNumber number, std::span<const uint8_t> data) { add(static_cast<uint8_t>(number), data); }
	void add(TagNumber number, std::string_view text);
	void add(TagNumber number, uint8_t value) { add(number, std::span<const uint8_t>(&value, 1)); }
	// Replace the first tag with this number in place, or append it
	void set(TagNumber number, std::span<const uint8_t> data);
	void set(TagNumber number, std::string_view text);
	// Removes every tag with this number, returns how many were removed
	size_t remove(TagNumber number);
	void clear() { m_raw.clear(); }
	void reserve(size_t bytes) { m_raw.reserve(bytes); }

	[[nodiscard]] std::optional<Tag> find(uint8_t number) const;
	[[nodiscard]] std::optional<Tag> find(TagNumber number) const { return find(static_cast<uint8_t>(number)); }
	[[nodiscard]] std::optional<Tag> findVendor(const std::array<uint8_t, 3>& oui, uint8_t type) const;
	[[nodiscard]] std::optional<Tag> findExtension(TagExtension extension) const;
	[[nodiscard]] size_t count(TagNumber number) const;
	[[nodiscard]] bool contains(TagNumber number) const { return find(number).has_value(); }

	// The serialized tags: nothing to compute, it is the buffer itself
	[[nodiscard]] std::span<const uint8_t> bytes() const { return m_raw; }
	[[nodiscard]] size_t length() const { return m_raw.size(); }
	void write(ByteWriter& writer) const { writer.bytes(m_raw); }
	[[nodiscard]] std::vector<uint8_t> serialize() const { return m_raw; }

	[[nodiscard]] bool complete() const { return m_complete; }
	[[nodiscard]] bool empty() const { return m_raw.empty(); }
	// Number of tags (walks the buffer)
	[[nodiscard]] size_t size() const;
	[[nodiscard]] Iterator begin() const { return Iterator(m_raw.data()); }
	[[nodiscard]] Iterator end() const { return Iterator(m_raw.data() + m_raw.size()); }

private:
	// Byte offset of the first tag with this number, or npos
	[[nodiscard]] size_t offsetOf(uint8_t number) const;

	std::vector<uint8_t> m_raw;
	bool m_complete = true;
};

} // namespace Wifi
