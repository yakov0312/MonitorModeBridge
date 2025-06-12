#pragma once
#include "attributeControl.h"
#include "pcap.h"

constexpr int MAC_LEN_BYTES = 6;


HIDDEN class NetworkHandler
{
public:
	~NetworkHandler();
	static NetworkHandler& getInstance();

	//error related
	void checkErr() const;
	void resolveErrors();

	//helper
	static u_char* getMacOffset(uint64_t* mac);

	//getters
	[[nodiscard]] bool getErr() const;
	[[nodiscard]] pcap_if_t* getDevice() const;
	[[nodiscard]] pcap_t* getDeviceHandle() const;
	[[nodiscard]] uint32_t getDeviceIp() const;
	[[nodiscard]] const uint8_t* getDeviceMac() const;
	[[nodiscard]] uint32_t getGatewayIp() const;
	[[nodiscard]] const uint8_t* getGatewayMac() const;

private:
	NetworkHandler();

	//initialize
	bool initDevice();
	bool initNetwork();
	bool initDeviceNetwork();
	bool initGatewayNetwork();

	//instance
	static NetworkHandler m_instance;

	//device
	pcap_if_t* m_device;
	pcap_t* m_deviceHandle;
	uint8_t m_deviceMac[MAC_LEN_BYTES];
	uint32_t m_deviceIp;

	//gateway
	uint32_t m_gateWayIp;
	uint8_t m_gateWayMac[MAC_LEN_BYTES];

	//flags
	bool m_errFlag;
};
