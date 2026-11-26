#include "Tags.h"

#include <algorithm>
#include <stdexcept>

namespace Wifi
{

const char* tagName(const uint8_t tagNumber)
{
	switch (static_cast<TagNumber>(tagNumber))
	{
		case TagNumber::Ssid: return "TAG_SSID";
		case TagNumber::SupportedRates: return "TAG_SUPP_RATES";
		case TagNumber::DsParameter: return "TAG_DS_PARAMETER";
		case TagNumber::CfParameter: return "TAG_CF_PARAMETER";
		case TagNumber::Tim: return "TAG_TIM";
		case TagNumber::BssParameters: return "TAG_BSS_PARAMETERS";
		case TagNumber::Country: return "TAG_COUNTRY";
		case TagNumber::Request: return "TAG_REQUEST";
		case TagNumber::BssLoad: return "TAG_BSS_LOAD";
		case TagNumber::EdcaParameters: return "TAG_EDCA_PARAMETERS";
		case TagNumber::Tspec: return "TAG_TSPEC";
		case TagNumber::Tclas: return "TAG_TCLAS";
		case TagNumber::Schedule: return "TAG_SCHEDULE";
		case TagNumber::ChallengeText: return "TAG_CHALLENGE_TEXT";
		case TagNumber::PowerConstraint: return "TAG_POWER_CONSTRAINT";
		case TagNumber::PowerCapability: return "TAG_POWER_CAPABILITY";
		case TagNumber::TpcRequest: return "TAG_TPC_REQUEST";
		case TagNumber::TpcReport: return "TAG_TPC_REPORT";
		case TagNumber::SupportedChannels: return "TAG_SUPPORTED_CHANNELS";
		case TagNumber::ChannelSwitchAnnouncement: return "TAG_CHANNEL_SWITCH_ANNOUNCEMENT";
		case TagNumber::MeasurementRequest: return "TAG_MEASUREMENT_REQUEST";
		case TagNumber::MeasurementReport: return "TAG_MEASUREMENT_REPORT";
		case TagNumber::Quiet: return "TAG_QUIET";
		case TagNumber::IbssDfs: return "TAG_IBSS_DFS";
		case TagNumber::Erp: return "TAG_ERP";
		case TagNumber::TsDelay: return "TAG_TS_DELAY";
		case TagNumber::TclasProcessing: return "TAG_TCLAS_PROCESSING";
		case TagNumber::HtCapabilities: return "TAG_HT_CAPABILITIES";
		case TagNumber::QosCapability: return "TAG_QOS_CAPABILITY";
		case TagNumber::Rsn: return "TAG_RSN";
		case TagNumber::ExtendedSupportedRates: return "TAG_EXTENDED_SUPPORTED_RATES";
		case TagNumber::ApChannelReport: return "TAG_AP_CHANNEL_REPORT";
		case TagNumber::NeighborReport: return "TAG_NEIGHBOR_REPORT";
		case TagNumber::Rcpi: return "TAG_RCPI";
		case TagNumber::MobilityDomain: return "TAG_MOBILITY_DOMAIN";
		case TagNumber::FastBssTransition: return "TAG_FAST_BSS_TRANSITION";
		case TagNumber::TimeoutInterval: return "TAG_TIMEOUT_INTERVAL";
		case TagNumber::RicData: return "TAG_RIC_DATA";
		case TagNumber::DseRegisteredLocation: return "TAG_DSE_REGISTERED_LOCATION";
		case TagNumber::SupportedOperatingClasses: return "TAG_SUPPORTED_OPERATING_CLASSES";
		case TagNumber::ExtendedChannelSwitchAnnouncement: return "TAG_EXTENDED_CHANNEL_SWITCH_ANNOUNCEMENT";
		case TagNumber::HtOperation: return "TAG_HT_OPERATION";
		case TagNumber::SecondaryChannelOffset: return "TAG_SECONDARY_CHANNEL_OFFSET";
		case TagNumber::BssAverageAccessDelay: return "TAG_BSS_AVERAGE_ACCESS_DELAY";
		case TagNumber::Antenna: return "TAG_ANTENNA";
		case TagNumber::Rsni: return "TAG_RSNI";
		case TagNumber::MeasurementPilotTransmission: return "TAG_MEASUREMENT_PILOT_TRANSMISSION";
		case TagNumber::BssAvailableAdmissionCapacity: return "TAG_BSS_AVAILABLE_ADMISSION_CAPACITY";
		case TagNumber::BssAcAccessDelay: return "TAG_BSS_AC_ACCESS_DELAY";
		case TagNumber::TimeAdvertisement: return "TAG_TIME_ADVERTISEMENT";
		case TagNumber::RmEnabledCapabilities: return "TAG_RM_ENABLED_CAPABILITIES";
		case TagNumber::MultipleBssid: return "TAG_MULTIPLE_BSSID";
		case TagNumber::BssCoexistence: return "TAG_BSS_COEXISTENCE";
		case TagNumber::BssIntolerantChannelReport: return "TAG_BSS_INTOLERANT_CHANNEL_REPORT";
		case TagNumber::OverlappingBssParameters: return "TAG_OVERLAPPING_BSS_PARAMETERS";
		case TagNumber::RicDescriptor: return "TAG_RIC_DESCRIPTOR";
		case TagNumber::ManagementMic: return "TAG_MANAGEMENT_MIC";
		case TagNumber::EventRequest: return "TAG_EVENT_REQUEST";
		case TagNumber::EventReport: return "TAG_EVENT_REPORT";
		case TagNumber::DiagnosticRequest: return "TAG_DIAGNOSTIC_REQUEST";
		case TagNumber::DiagnosticReport: return "TAG_DIAGNOSTIC_REPORT";
		case TagNumber::LocationParameters: return "TAG_LOCATION_PARAMETERS";
		case TagNumber::NontransmittedBssidCapability: return "TAG_NONTRANSMITTED_BSSID_CAPABILITY";
		case TagNumber::SsidList: return "TAG_SSID_LIST";
		case TagNumber::MultipleBssidIndex: return "TAG_MULTIPLE_BSSID_INDEX";
		case TagNumber::FmsDescriptor: return "TAG_FMS_DESCRIPTOR";
		case TagNumber::FmsRequest: return "TAG_FMS_REQUEST";
		case TagNumber::FmsResponse: return "TAG_FMS_RESPONSE";
		case TagNumber::QosTrafficCapability: return "TAG_QOS_TRAFFIC_CAPABILITY";
		case TagNumber::BssMaxIdlePeriod: return "TAG_BSS_MAX_IDLE_PERIOD";
		case TagNumber::TfsRequest: return "TAG_TFS_REQUEST";
		case TagNumber::TfsResponse: return "TAG_TFS_RESPONSE";
		case TagNumber::WnmSleepMode: return "TAG_WNM_SLEEP_MODE";
		case TagNumber::TimBroadcastRequest: return "TAG_TIM_BROADCAST_REQUEST";
		case TagNumber::TimBroadcastResponse: return "TAG_TIM_BROADCAST_RESPONSE";
		case TagNumber::CollocatedInterferenceReport: return "TAG_COLLOCATED_INTERFERENCE_REPORT";
		case TagNumber::ChannelUsage: return "TAG_CHANNEL_USAGE";
		case TagNumber::TimeZone: return "TAG_TIME_ZONE";
		case TagNumber::DmsRequest: return "TAG_DMS_REQUEST";
		case TagNumber::DmsResponse: return "TAG_DMS_RESPONSE";
		case TagNumber::LinkIdentifier: return "TAG_LINK_IDENTIFIER";
		case TagNumber::WakeupSchedule: return "TAG_WAKEUP_SCHEDULE";
		case TagNumber::ChannelSwitchTiming: return "TAG_CHANNEL_SWITCH_TIMING";
		case TagNumber::PtiControl: return "TAG_PTI_CONTROL";
		case TagNumber::TpuBufferStatus: return "TAG_TPU_BUFFER_STATUS";
		case TagNumber::Interworking: return "TAG_INTERWORKING";
		case TagNumber::AdvertisementProtocol: return "TAG_ADVERTISEMENT_PROTOCOL";
		case TagNumber::ExpeditedBandwidthRequest: return "TAG_EXPEDITED_BANDWIDTH_REQUEST";
		case TagNumber::QosMap: return "TAG_QOS_MAP";
		case TagNumber::RoamingConsortium: return "TAG_ROAMING_CONSORTIUM";
		case TagNumber::EmergencyAlertIdentifier: return "TAG_EMERGENCY_ALERT_IDENTIFIER";
		case TagNumber::MeshConfiguration: return "TAG_MESH_CONFIGURATION";
		case TagNumber::MeshId: return "TAG_MESH_ID";
		case TagNumber::MeshLinkMetricReport: return "TAG_MESH_LINK_METRIC_REPORT";
		case TagNumber::CongestionNotification: return "TAG_CONGESTION_NOTIFICATION";
		case TagNumber::MeshPeeringManagement: return "TAG_MESH_PEERING_MANAGEMENT";
		case TagNumber::MeshChannelSwitchParameters: return "TAG_MESH_CHANNEL_SWITCH_PARAMETERS";
		case TagNumber::MeshAwakeWindow: return "TAG_MESH_AWAKE_WINDOW";
		case TagNumber::BeaconTiming: return "TAG_BEACON_TIMING";
		case TagNumber::MccaopSetupRequest: return "TAG_MCCAOP_SETUP_REQUEST";
		case TagNumber::MccaopSetupReply: return "TAG_MCCAOP_SETUP_REPLY";
		case TagNumber::MccaopAdvertisement: return "TAG_MCCAOP_ADVERTISEMENT";
		case TagNumber::MccaopTeardown: return "TAG_MCCAOP_TEARDOWN";
		case TagNumber::Gann: return "TAG_GANN";
		case TagNumber::Rann: return "TAG_RANN";
		case TagNumber::ExtendedCapabilities: return "TAG_EXTENDED_CAPABILITIES";
		case TagNumber::Preq: return "TAG_PREQ";
		case TagNumber::Prep: return "TAG_PREP";
		case TagNumber::Perr: return "TAG_PERR";
		case TagNumber::Pxu: return "TAG_PXU";
		case TagNumber::Pxuc: return "TAG_PXUC";
		case TagNumber::AuthenticatedMeshPeeringExchange: return "TAG_AUTHENTICATED_MESH_PEERING_EXCHANGE";
		case TagNumber::Mic: return "TAG_MIC";
		case TagNumber::DestinationUri: return "TAG_DESTINATION_URI";
		case TagNumber::UApsdCoexistence: return "TAG_U_APSD_COEXISTENCE";
		case TagNumber::DmgWakeupSchedule: return "TAG_DMG_WAKEUP_SCHEDULE";
		case TagNumber::ExtendedSchedule: return "TAG_EXTENDED_SCHEDULE";
		case TagNumber::StaAvailability: return "TAG_STA_AVAILABILITY";
		case TagNumber::DmgTspec: return "TAG_DMG_TSPEC";
		case TagNumber::NextDmgAti: return "TAG_NEXT_DMG_ATI";
		case TagNumber::DmgOperation: return "TAG_DMG_OPERATION";
		case TagNumber::DmgBssParameterChange: return "TAG_DMG_BSS_PARAMETER_CHANGE";
		case TagNumber::DmgBeamRefinement: return "TAG_DMG_BEAM_REFINEMENT";
		case TagNumber::ChannelMeasurementFeedback: return "TAG_CHANNEL_MEASUREMENT_FEEDBACK";
		case TagNumber::AwakeWindow: return "TAG_AWAKE_WINDOW";
		case TagNumber::MultiBand: return "TAG_MULTI_BAND";
		case TagNumber::AddbaExtension: return "TAG_ADDBA_EXTENSION";
		case TagNumber::NextpcpList: return "TAG_NEXTPCP_LIST";
		case TagNumber::PcpHandover: return "TAG_PCP_HANDOVER";
		case TagNumber::DmgLinkMargin: return "TAG_DMG_LINK_MARGIN";
		case TagNumber::SwitchingStream: return "TAG_SWITCHING_STREAM";
		case TagNumber::SessionTransition: return "TAG_SESSION_TRANSITION";
		case TagNumber::DynamicTonePairingReport: return "TAG_DYNAMIC_TONE_PAIRING_REPORT";
		case TagNumber::ClusterReport: return "TAG_CLUSTER_REPORT";
		case TagNumber::RelayCapabilities: return "TAG_RELAY_CAPABILITIES";
		case TagNumber::RelayTransferParameterSet: return "TAG_RELAY_TRANSFER_PARAMETER_SET";
		case TagNumber::BeamlinkMaintenance: return "TAG_BEAMLINK_MAINTENANCE";
		case TagNumber::MultipleMacSublayers: return "TAG_MULTIPLE_MAC_SUBLAYERS";
		case TagNumber::UPid: return "TAG_U_PID";
		case TagNumber::DmgLinkAdaptationAcknowledgement: return "TAG_DMG_LINK_ADAPTATION_ACKNOWLEDGEMENT";
		case TagNumber::MccaopAdvertisementOverview: return "TAG_MCCAOP_ADVERTISEMENT_OVERVIEW";
		case TagNumber::QuietPeriodRequest: return "TAG_QUIET_PERIOD_REQUEST";
		case TagNumber::QuietPeriodResponse: return "TAG_QUIET_PERIOD_RESPONSE";
		case TagNumber::QmfPolicy: return "TAG_QMF_POLICY";
		case TagNumber::EcapcPolicy: return "TAG_ECAPC_POLICY";
		case TagNumber::ClusterTimeOffset: return "TAG_CLUSTER_TIME_OFFSET";
		case TagNumber::IntraAccessCategoryPriority: return "TAG_INTRA_ACCESS_CATEGORY_PRIORITY";
		case TagNumber::ScsDescriptor: return "TAG_SCS_DESCRIPTOR";
		case TagNumber::QloadReport: return "TAG_QLOAD_REPORT";
		case TagNumber::HccaTxopUpdateCount: return "TAG_HCCA_TXOP_UPDATE_COUNT";
		case TagNumber::HigherLayerStreamId: return "TAG_HIGHER_LAYER_STREAM_ID";
		case TagNumber::GcrGroupAddress: return "TAG_GCR_GROUP_ADDRESS";
		case TagNumber::AntennaSectorIdPattern: return "TAG_ANTENNA_SECTOR_ID_PATTERN";
		case TagNumber::VhtCapabilities: return "TAG_VHT_CAPABILITIES";
		case TagNumber::VhtOperation: return "TAG_VHT_OPERATION";
		case TagNumber::ExtendedBssLoad: return "TAG_EXTENDED_BSS_LOAD";
		case TagNumber::WideBandwidthChannelSwitch: return "TAG_WIDE_BANDWIDTH_CHANNEL_SWITCH";
		case TagNumber::TransmitPowerEnvelope: return "TAG_TRANSMIT_POWER_ENVELOPE";
		case TagNumber::ChannelSwitchWrapper: return "TAG_CHANNEL_SWITCH_WRAPPER";
		case TagNumber::Aid: return "TAG_AID";
		case TagNumber::QuietChannel: return "TAG_QUIET_CHANNEL";
		case TagNumber::Upsim: return "TAG_UPSIM";
		case TagNumber::ReducedNeighborReport: return "TAG_REDUCED_NEIGHBOR_REPORT";
		case TagNumber::TvhtOperation: return "TAG_TVHT_OPERATION";
		case TagNumber::DeviceLocation: return "TAG_DEVICE_LOCATION";
		case TagNumber::WhiteSpaceMap: return "TAG_WHITE_SPACE_MAP";
		case TagNumber::FineTimingMeasurementParameters: return "TAG_FINE_TIMING_MEASUREMENT_PARAMETERS";
		case TagNumber::VendorSpecific: return "TAG_VENDOR_SPECIFIC";
		case TagNumber::ElementExtension: return "TAG_ELEMENT_EXTENSION";
		default: return "Unknown Tag";
	}
}

bool Tag::isVendor(const std::array<uint8_t, 3>& oui, const uint8_t type) const
{
	return is(TagNumber::VendorSpecific) && data.size() >= 4 &&
		std::equal(oui.begin(), oui.end(), data.begin()) && data[3] == type;
}

Tags Tags::parse(const std::span<const uint8_t> data)
{
	Tags tags;
	ByteReader reader(data);
	while (reader.remaining() >= TAG_HEADER_LENGTH)
	{
		const uint8_t number = reader.u8();
		const uint8_t length = reader.u8();
		const auto body = reader.bytes(length);
		if (!reader.ok())
		{
			tags.m_complete = false;
			break;
		}
		tags.m_tags.push_back({number, {body.begin(), body.end()}});
	}
	// A single dangling byte is not a tag either
	if (reader.remaining() != 0)
		tags.m_complete = false;
	return tags;
}

void Tags::add(const uint8_t number, const std::span<const uint8_t> data)
{
	if (data.size() > MAX_TAG_LENGTH)
		throw std::invalid_argument("Tag data is longer than 255 bytes");
	m_tags.push_back({number, {data.begin(), data.end()}});
}

void Tags::add(const TagNumber number, const std::string_view text)
{
	add(number, std::span(reinterpret_cast<const uint8_t*>(text.data()), text.size()));
}

void Tags::set(const TagNumber number, const std::span<const uint8_t> data)
{
	if (data.size() > MAX_TAG_LENGTH)
		throw std::invalid_argument("Tag data is longer than 255 bytes");
	for (Tag& tag : m_tags)
	{
		if (tag.is(number))
		{
			tag.data.assign(data.begin(), data.end());
			return;
		}
	}
	add(number, data);
}

void Tags::set(const TagNumber number, const std::string_view text)
{
	set(number, std::span(reinterpret_cast<const uint8_t*>(text.data()), text.size()));
}

size_t Tags::remove(const TagNumber number)
{
	return std::erase_if(m_tags, [number](const Tag& tag) { return tag.is(number); });
}

const Tag* Tags::find(const uint8_t number) const
{
	const auto it = std::ranges::find_if(m_tags, [number](const Tag& tag) { return tag.number == number; });
	return it == m_tags.end() ? nullptr : &*it;
}

const Tag* Tags::findVendor(const std::array<uint8_t, 3>& oui, const uint8_t type) const
{
	const auto it = std::ranges::find_if(m_tags, [&](const Tag& tag) { return tag.isVendor(oui, type); });
	return it == m_tags.end() ? nullptr : &*it;
}

const Tag* Tags::findExtension(const TagExtension extension) const
{
	const auto it = std::ranges::find_if(m_tags, [extension](const Tag& tag) {
		return tag.is(TagNumber::ElementExtension) && !tag.data.empty() &&
			tag.data[0] == static_cast<uint8_t>(extension);
	});
	return it == m_tags.end() ? nullptr : &*it;
}

size_t Tags::count(const TagNumber number) const
{
	return std::ranges::count_if(m_tags, [number](const Tag& tag) { return tag.is(number); });
}

size_t Tags::length() const
{
	size_t len = 0;
	for (const Tag& tag : m_tags)
		len += tag.length();
	return len;
}

void Tags::write(ByteWriter& writer) const
{
	for (const Tag& tag : m_tags)
	{
		writer.u8(tag.number);
		writer.u8(static_cast<uint8_t>(tag.data.size()));
		writer.bytes(tag.data);
	}
}

std::vector<uint8_t> Tags::serialize() const
{
	std::vector<uint8_t> out;
	out.reserve(length());
	ByteWriter writer(out);
	write(writer);
	return out;
}

} // namespace Wifi
