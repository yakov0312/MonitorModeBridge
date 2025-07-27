#pragma once
#include <string>

#include "attributeControl.h"
#include "pcap.h"

constexpr uint8_t MAC_SIZE_BYTES = 6;

class AdapterHandler
{
public:
	~AdapterHandler();
	static AdapterHandler& getInstance();

	//error related
	void checkErr() const;
	void resolveErrors();

	//helper
	static u_char* getMacOffset(uint64_t* mac);
	static void setDeviceToManaged();
	static void setDeviceToManaged(int sig);

	//getters
	[[nodiscard]] bool getErr() const;
	[[nodiscard]] pcap_if_t* getDevice() const;
	[[nodiscard]] pcap_t* getDeviceHandle() const;
	[[nodiscard]] const uint8_t* getDeviceMac() const;
	[[nodiscard]] std::string getDeviceName() const;

private:
	AdapterHandler();

	//initialize
	bool initDevice();
	bool initDeviceNetwork();

	//instance
	static AdapterHandler m_instance;

	//device
	pcap_if_t* m_device;
	pcap_t* m_deviceHandle;
	uint8_t m_deviceMac[MAC_SIZE_BYTES];
	std::string m_deviceName;

	//flags
	bool m_errFlag;
};
