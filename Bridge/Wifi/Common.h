// C++ replacement for libwifi: shared 802.11 types.
//
// Every multi-byte 802.11 field is little-endian on the air and EAPOL fields
// are big-endian. ByteWriter/ByteReader do the conversion explicitly, so
// nothing here depends on the host byte order or on packed struct layout.

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace Wifi
{

constexpr size_t MAC_LENGTH = 6;
using MacAddress = std::array<uint8_t, MAC_LENGTH>;

constexpr MacAddress BROADCAST = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

// Copy 6 bytes from a raw pointer (as used by the existing code)
MacAddress toMac(const uint8_t* mac);
std::string macToString(const MacAddress& mac);
// A locally administered address has bit 1 of the first byte set
bool isRandomizedMac(const MacAddress& mac);
bool isMulticastMac(const MacAddress& mac);

/*---------------------*/
/* BYTE READER/WRITER  */
/*---------------------*/

// Appends fields to a byte vector in the requested byte order.
class ByteWriter
{
public:
	explicit ByteWriter(std::vector<uint8_t>& out) : m_out(out) {}

	void u8(uint8_t value) { m_out.push_back(value); }
	void le16(uint16_t value);
	void le32(uint32_t value);
	void le64(uint64_t value);
	void be16(uint16_t value);
	void be64(uint64_t value);
	void bytes(std::span<const uint8_t> data);
	void mac(const MacAddress& mac) { bytes(mac); }
	void zeros(size_t count) { m_out.insert(m_out.end(), count, 0); }
	[[nodiscard]] size_t size() const { return m_out.size(); }

private:
	std::vector<uint8_t>& m_out;
};

// Reads fields with bounds checking. Reading past the end does not throw:
// it returns zeros and clears ok(), so a parser checks ok() once at the end.
class ByteReader
{
public:
	explicit ByteReader(std::span<const uint8_t> data) : m_data(data) {}

	uint8_t u8();
	uint16_t le16();
	uint32_t le32();
	uint64_t le64();
	uint16_t be16();
	uint64_t be64();
	MacAddress mac();
	std::span<const uint8_t> bytes(size_t count);
	void skip(size_t count);

	[[nodiscard]] bool ok() const { return m_ok; }
	[[nodiscard]] size_t offset() const { return m_offset; }
	[[nodiscard]] size_t remaining() const { return m_ok ? m_data.size() - m_offset : 0; }
	[[nodiscard]] std::span<const uint8_t> rest() const { return m_data.subspan(m_ok ? m_offset : m_data.size()); }

private:
	bool take(size_t count);

	std::span<const uint8_t> m_data;
	size_t m_offset = 0;
	bool m_ok = true;
};

/*---------------*/
/* FRAME CONTROL */
/*---------------*/

enum class FrameType : uint8_t
{
	Management = 0,
	Control = 1,
	Data = 2,
	Extension = 3,
};

enum class ManagementSubtype : uint8_t
{
	AssocReq = 0,
	AssocResp = 1,
	ReassocReq = 2,
	ReassocResp = 3,
	ProbeReq = 4,
	ProbeResp = 5,
	TimeAdv = 6,
	Beacon = 8,
	Atim = 9,
	Disassoc = 10,
	Auth = 11,
	Deauth = 12,
	Action = 13,
	ActionNoAck = 14,
};

enum class ControlSubtype : uint8_t
{
	Tack = 3,
	BeamformReportPoll = 4,
	VhtNdpAnnounce = 5,
	CfExtension = 6,
	Wrapper = 7,
	BlockAckReq = 8,
	BlockAck = 9,
	PsPoll = 10,
	Rts = 11,
	Cts = 12,
	Ack = 13,
	CfEnd = 14,
	CfEndCfAck = 15,
};

enum class DataSubtype : uint8_t
{
	Data = 0,
	Null = 4,
	QosData = 8,
	QosDataCfAck = 9,
	QosDataCfPoll = 10,
	QosDataCfAckCfPoll = 11,
	QosNull = 12,
	QosCfPoll = 14,
	QosCfAckCfPoll = 15,
};

enum class ExtensionSubtype : uint8_t
{
	DmgBeacon = 0,
	S1gBeacon = 1,
};

// Bits of the second frame control byte
namespace FrameFlag
{
	constexpr uint8_t ToDs = 0x01;
	constexpr uint8_t FromDs = 0x02;
	constexpr uint8_t MoreFragments = 0x04;
	constexpr uint8_t Retry = 0x08;
	constexpr uint8_t PowerManagement = 0x10;
	constexpr uint8_t MoreData = 0x20;
	constexpr uint8_t Protected = 0x40;
	constexpr uint8_t Order = 0x80; // +HTC: an HT Control field follows
}

struct FrameControl
{
	uint8_t version = 0;
	FrameType type = FrameType::Management;
	uint8_t subtype = 0;
	uint8_t flags = 0; // FrameFlag bits

	FrameControl() = default;
	FrameControl(FrameType frameType, uint8_t frameSubtype, uint8_t frameFlags = 0)
		: type(frameType), subtype(frameSubtype), flags(frameFlags) {}
	explicit FrameControl(ManagementSubtype s, uint8_t f = 0) : FrameControl(FrameType::Management, static_cast<uint8_t>(s), f) {}
	explicit FrameControl(ControlSubtype s, uint8_t f = 0) : FrameControl(FrameType::Control, static_cast<uint8_t>(s), f) {}
	explicit FrameControl(DataSubtype s, uint8_t f = 0) : FrameControl(FrameType::Data, static_cast<uint8_t>(s), f) {}

	// Wire format: byte 0 = version | type << 2 | subtype << 4, byte 1 = flags
	[[nodiscard]] uint16_t pack() const;
	static FrameControl unpack(uint16_t value);

	[[nodiscard]] bool is(ManagementSubtype s) const { return type == FrameType::Management && subtype == static_cast<uint8_t>(s); }
	[[nodiscard]] bool is(ControlSubtype s) const { return type == FrameType::Control && subtype == static_cast<uint8_t>(s); }
	[[nodiscard]] bool is(DataSubtype s) const { return type == FrameType::Data && subtype == static_cast<uint8_t>(s); }

	[[nodiscard]] bool has(uint8_t flag) const { return (flags & flag) != 0; }
	void set(uint8_t flag, bool on = true) { flags = on ? (flags | flag) : (flags & ~flag); }

	[[nodiscard]] bool toDs() const { return has(FrameFlag::ToDs); }
	[[nodiscard]] bool fromDs() const { return has(FrameFlag::FromDs); }
	[[nodiscard]] bool retry() const { return has(FrameFlag::Retry); }
	[[nodiscard]] bool isProtected() const { return has(FrameFlag::Protected); }
	[[nodiscard]] bool order() const { return has(FrameFlag::Order); }
	// QoS data subtypes have bit 3 of the subtype set
	[[nodiscard]] bool isQosData() const { return type == FrameType::Data && (subtype & 0x08) != 0; }
};

struct SequenceControl
{
	uint8_t fragment = 0;  // 4 bits
	uint16_t sequence = 0; // 12 bits

	[[nodiscard]] uint16_t pack() const { return static_cast<uint16_t>((sequence & 0x0FFF) << 4 | (fragment & 0x0F)); }
	static SequenceControl unpack(uint16_t value) { return {static_cast<uint8_t>(value & 0x0F), static_cast<uint16_t>(value >> 4)}; }
};

/*------------*/
/* MAC HEADER */
/*------------*/

constexpr size_t MANAGEMENT_HEADER_LENGTH = 24;
constexpr size_t CONTROL_HEADER_LENGTH = 4; // frame control + duration only
constexpr size_t FCS_LENGTH = 4;

// Generic 802.11 MAC header. Which optional fields exist follows from the
// frame control: addr4 when ToDS and FromDS are both set on a data frame,
// qosControl on QoS data frames, htControl when the Order (+HTC) bit is set
// on management or QoS data frames.
struct MacHeader
{
	FrameControl frameControl;
	uint16_t duration = 0;
	MacAddress addr1{};
	MacAddress addr2{};
	MacAddress addr3{};
	SequenceControl sequenceControl;
	std::optional<MacAddress> addr4;
	std::optional<uint16_t> qosControl;
	std::optional<uint32_t> htControl;

	// Management header: addr1 = receiver, addr2 = transmitter, addr3 = BSSID
	static MacHeader management(ManagementSubtype subtype, const MacAddress& receiver,
		const MacAddress& transmitter, const MacAddress& bssid);

	[[nodiscard]] size_t length() const;
	void write(ByteWriter& writer) const;
	// Parses the header that the frame control asks for. Control frames only
	// have frame control + duration here (+ addr1/addr2 when present).
	static std::optional<MacHeader> parse(std::span<const uint8_t> data, size_t& headerLength);

	// Address roles (802.11-2020 table 9-26)
	[[nodiscard]] const MacAddress& receiver() const { return addr1; }
	[[nodiscard]] const MacAddress& transmitter() const { return addr2; }
	[[nodiscard]] MacAddress bssid() const;
	[[nodiscard]] MacAddress destination() const;
	[[nodiscard]] MacAddress source() const;
};

/*-------------------------------------*/
/* FIXED PARAMETER VALUES (FLAGS/CODES) */
/*-------------------------------------*/

// Capability Information field bits
namespace Capability
{
	constexpr uint16_t Ess = 1 << 0;
	constexpr uint16_t Ibss = 1 << 1;
	constexpr uint16_t CfPollable = 1 << 2;
	constexpr uint16_t CfPollRequest = 1 << 3;
	constexpr uint16_t Privacy = 1 << 4;
	constexpr uint16_t ShortPreamble = 1 << 5;
	constexpr uint16_t Pbcc = 1 << 6;
	constexpr uint16_t ChannelAgility = 1 << 7;
	constexpr uint16_t SpectrumManagement = 1 << 8;
	constexpr uint16_t Qos = 1 << 9;
	constexpr uint16_t ShortSlotTime = 1 << 10;
	constexpr uint16_t Apsd = 1 << 11;
	constexpr uint16_t RadioMeasurement = 1 << 12;
	constexpr uint16_t DsssOfdm = 1 << 13;
	constexpr uint16_t DelayedBlockAck = 1 << 14;
	constexpr uint16_t ImmediateBlockAck = 1 << 15;
}

// Defaults libwifi used when generating frames (kept so frames stay identical)
constexpr uint16_t DEFAULT_AP_CAPABILITIES = Capability::Ess;
constexpr uint16_t DEFAULT_STA_CAPABILITIES = 0x0000;
constexpr uint16_t DEFAULT_LISTEN_INTERVAL = 0x0001;
constexpr uint16_t DEFAULT_BEACON_INTERVAL = 0x0064; // 100 TU
constexpr std::array<uint8_t, 8> DEFAULT_SUPPORTED_RATES = {0x82, 0x84, 0x8B, 0x96, 0x24, 0x30, 0x48, 0x6C};

enum class AuthAlgorithm : uint16_t
{
	Open = 0,
	SharedKey = 1,
	FastBss = 2,
	Sae = 3,
	Fils = 4,
	FilsPfs = 5,
	FilsPublicKey = 6,
	Pasn = 7,
	Vendor = 65535,
};

enum class StatusCode : uint16_t
{
	Success = 0,
	Refused = 1,
	TdlsRejectedAlternativeProvided = 2,
	SecurityDisabled = 5,
	UnacceptableLifetime = 6,
	NotInSameBss = 7,
	RefusedCapabilitiesMismatch = 10,
	DeniedNoAssociationExists = 11,
	DeniedOtherReason = 12,
	UnsupportedAuthAlgorithm = 13,
	TransactionSequenceError = 14,
	ChallengeFailure = 15,
	RejectedSequenceTimeout = 16,
	DeniedNoMoreStas = 17,
	RefusedBasicRatesMismatch = 18,
	DeniedNoShortPreambleSupport = 19,
	RejectedSpectrumManagementRequired = 22,
	RejectedBadPowerCapability = 23,
	RejectedBadSupportedChannels = 24,
	DeniedNoShortSlotTimeSupport = 25,
	DeniedNoHtSupport = 27,
	R0khUnreachable = 28,
	DeniedPcoTimeNotSupported = 29,
	RefusedTemporarily = 30,
	RobustManagementPolicyViolation = 31,
	UnspecifiedQosFailure = 32,
	DeniedInsufficientBandwidth = 33,
	DeniedPoorChannelConditions = 34,
	DeniedQosNotSupported = 35,
	RequestDeclined = 37,
	InvalidParameters = 38,
	RejectedWithSuggestedChanges = 39,
	InvalidElement = 40,
	InvalidGroupCipher = 41,
	InvalidPairwiseCipher = 42,
	InvalidAkmp = 43,
	UnsupportedRsneVersion = 44,
	InvalidRsneCapabilities = 45,
	CipherOutOfPolicy = 46,
	RejectedForDelayPeriod = 47,
	DlsNotAllowed = 48,
	NotPresent = 49,
	NotQosSta = 50,
	DeniedListenIntervalTooLarge = 51,
	InvalidFtActionFrameCount = 52,
	InvalidPmkid = 53,
	InvalidMde = 54,
	InvalidFte = 55,
	RequestedTclasNotSupported = 56,
	InsufficientTclasProcessingResources = 57,
	TryAnotherBss = 58,
	GasAdvertisementProtocolNotSupported = 59,
	NoOutstandingGasRequest = 60,
	GasResponseNotReceivedFrom = 61,
	GasQueryTimeout = 62,
	GasQueryResponseTooLarge = 63,
	RejectedHomeWithSuggestedChanges = 64,
	ServerUnreachable = 65,
	RejectedForSspPermissions = 67,
	RefusedUnauthenticatedAccessNotSupported = 68,
	InvalidRsne = 72,
	UApsdCoexistenceNotSupported = 73,
	UApsdCoexModeNotSupported = 74,
	BadIntervalWithUApsdCoex = 75,
	AntiCloggingTokenRequired = 76,
	UnsupportedFiniteCyclicGroup = 77,
	CannotFindAlternativeTbtt = 78,
	TransmissionFailure = 79,
	RequestedTclasNotSupported2 = 80,
	TclasResourcesExhausted = 81,
	RejectedWithSuggestedBssTransition = 82,
	RejectWithSchedule = 83,
	RejectNoWakeupSpecified = 84,
	SuccessPowerSaveMode = 85,
	PendingAdmittingFstSession = 86,
	PerformingFstNow = 87,
	PendingGapInBaWindow = 88,
	RejectUPidSetting = 89,
	RefusedExternalReason = 92,
	RefusedApOutOfMemory = 93,
	RejectedEmergencyServicesNotSupported = 94,
	QueryResponseOutstanding = 95,
	RejectDseBand = 96,
	TclasProcessingTerminated = 97,
	TsScheduleConflict = 98,
	DeniedWithSuggestedBandAndChannel = 99,
	MccaopReservationConflict = 100,
	MafLimitExceeded = 101,
	MccaTrackLimitExceeded = 102,
	DeniedDueToSpectrumManagement = 103,
	DeniedVhtNotSupported = 104,
	EnablementDenied = 105,
	RestrictionFromAuthorizedGdb = 106,
	AuthorizationDeenabled = 107,
};

enum class ReasonCode : uint16_t
{
	UnspecifiedFailure = 1,
	PreviousAuthInvalid = 2,
	StaLeavingEss = 3,
	Inactive = 4,
	TooManyStas = 5,
	Class2Frame = 6,
	Class3Frame = 7,
	StaLeavingBss = 8,
	StaRequestingReassocNotAuthed = 9,
	UnacceptablePowerCapability = 10,
	UnacceptableChannels = 11,
	BssTransitionMgmt = 12,
	InvalidElement = 13,
	MicFailure = 14,
	FourwayHandshakeTimeout = 15,
	GroupkeyHandshakeTimeout = 16,
	InvalidFourway = 17,
	InvalidGroupCipher = 18,
	InvalidPairwiseCipher = 19,
	InvalidAkmp = 20,
	UnsupportedRsneVersion = 21,
	InvalidRsneCapabilities = 22,
	Invalid8021xAuth = 23,
	CipherSuiteRejected = 24,
	TdlsDirectLinkTeardownUnreachable = 25,
	TdlsDirectLinkTeardownUnspecified = 26,
	SspRequest = 27,
	LacksSspRoaming = 28,
	CipherOrAkmRequired = 29,
	ServiceNotAuthorized = 30,
	ServiceChangePrecludesTs = 31,
	UnspecifiedQos = 32,
	InsufficientBandwidth = 33,
	ExcessiveAcksRequired = 34,
	TxopsExceeded = 35,
	StaLeaving = 36,
	EndTs = 37,
	UnknownTsOrBa = 38,
	Timeout = 39,
	PeerkeyMismatch = 45,
	PeerInitiated = 46,
	ApInitiated = 47,
	InvalidFtActionFramecount = 48,
	InvalidPmki = 49,
	InvalidMde = 50,
	InvalidFte = 51,
	MeshPeeringCanceled = 52,
	MeshMaxPeers = 53,
	MeshConfigurationPolicyViolation = 54,
	MeshCloseRcvd = 55,
	MeshMaxRetries = 56,
	MeshConfirmTimeout = 57,
	MeshInvalidGtk = 58,
	MeshInconsistentParameters = 59,
	MeshInvalidSecurityCapability = 60,
	MeshPathErrorNoProxyInformation = 61,
	MeshPathErrorNoForwardingInformation = 62,
	MeshPathErrorDestinationUnreachable = 63,
	MacAddressAlreadyExistsInMbss = 64,
	MeshChannelSwitchRegulatoryRequirements = 65,
	MeshChannelSwitchUnspecified = 66,
};

// Microseconds of wall-clock time, for the beacon/probe response timestamp
uint64_t currentTimestamp();

// 2.4/5/6 GHz channel <-> frequency (MHz). 0 when unknown.
uint8_t frequencyToChannel(uint16_t frequency);
uint16_t channelToFrequency(uint8_t channel, bool is6GHz = false);

} // namespace Wifi
