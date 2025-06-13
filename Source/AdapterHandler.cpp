#include "AdapterHandler.h"

#include <cstring>
#include <memory>
#include <ifaddrs.h>
#include <netpacket/packet.h>

constexpr uint32_t TIMEOUT = 1000; //10 sec

AdapterHandler AdapterHandler::m_instance = AdapterHandler();

AdapterHandler::AdapterHandler() : m_device(nullptr), m_deviceHandle(nullptr), m_deviceMac{0},
    m_errFlag(false)
{
    if (initDevice())
        initDeviceNetwork();
}

AdapterHandler::~AdapterHandler()
{
    if (m_device != nullptr)
        pcap_freealldevs(m_device);
}

AdapterHandler& AdapterHandler::getInstance()
{
    return m_instance;
}

void AdapterHandler::checkErr() const
{
    if (m_errFlag == true)
        throw std::runtime_error("There were errors while setting up!");
}

bool AdapterHandler::initDevice()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&m_device, errbuf) == -1)
    {
        m_errFlag = true;
        return false;
    }
    if (!m_device)
    {
        m_errFlag = true;
        return false;
    }
    m_deviceHandle = pcap_open_live(m_device->name, 65536, 1, TIMEOUT, errbuf);
    if (!m_deviceHandle)
    {
        pcap_freealldevs(m_device);
        m_device = nullptr;
        m_errFlag = true;
        return false;
    }
    return true;
}

bool AdapterHandler::initDeviceNetwork()
{
    ifaddrs* addrs = nullptr;
    getifaddrs(&addrs);
    ifaddrs* addr = addrs;
    bool foundMac = false;
    while (addr && !foundMac)
    {
        if (!strcmp( addr->ifa_name, m_device->name))
        {
            //adapter mac
            if (addr->ifa_addr->sa_family == AF_PACKET)
            {
                auto* s = reinterpret_cast<struct sockaddr_ll *>(addr->ifa_addr);
                memcpy(m_deviceMac, s->sll_addr, 6);
                foundMac = true;
            }
        }
        addr = addr->ifa_next;
    }
    freeifaddrs(addrs);
    if (!foundMac) // cannot find the adapter
    {
        m_errFlag = true;
        return false;
    }
    m_deviceName = m_device->name;
    return true;
}

void AdapterHandler::resolveErrors()
{
    if (initDevice()) {
        if (initDeviceNetwork()) {
            m_errFlag = false;
        }
    }
}

u_char* AdapterHandler::getMacOffset(uint64_t* mac)
{
    u_char* macOffset = nullptr;
    if constexpr (std::endian::native == std::endian::little)
    {
        macOffset = reinterpret_cast<u_char*>(mac);
    }
    else
    {
        macOffset = reinterpret_cast<u_char*>(mac) + 2;
    }
    return macOffset;
}

bool AdapterHandler::getErr() const
{
    return m_errFlag;
}

pcap_if_t * AdapterHandler::getDevice() const
{
    return m_device;
}

pcap_t * AdapterHandler::getDeviceHandle() const
{
    return m_deviceHandle;
}

const uint8_t * AdapterHandler::getDeviceMac() const
{
    return m_deviceMac;
}

std::string AdapterHandler::getDeviceName() const
{
    return m_deviceName;
}
