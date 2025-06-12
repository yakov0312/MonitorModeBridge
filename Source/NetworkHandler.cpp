#include "NetworkHandler.h"

#include <cstring>
#include <memory>
#include <ifaddrs.h>
#include <netpacket/packet.h>

constexpr uint8_t TIMEOUT = 10000; //10 sec

NetworkHandler NetworkHandler::m_instance = NetworkHandler();

NetworkHandler::NetworkHandler() : m_device(nullptr), m_deviceHandle(nullptr), m_deviceMac{0},
    m_deviceIp(0), m_gateWayIp(0), m_gateWayMac{0}, m_errFlag(false)
{
    if (initDevice())
        initNetwork();
}

NetworkHandler::~NetworkHandler()
{
    if (m_device != nullptr)
        pcap_freealldevs(m_device);
}

NetworkHandler& NetworkHandler::getInstance()
{
    return m_instance;
}

void NetworkHandler::checkErr() const
{
    if (m_errFlag == true)
        throw std::runtime_error("There were errors while setting up!");
}

bool NetworkHandler::initDevice()
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

bool NetworkHandler::initNetwork()
{
    bool result = (initDeviceNetwork()) ? initGatewayNetwork() : false;
    return result;
}

bool NetworkHandler::initDeviceNetwork()
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
    return true;
}

bool NetworkHandler::initGatewayNetwork()
{
    return true;
}

void NetworkHandler::resolveErrors()
{
    if (initDevice()) {
        if (initNetwork()) {
            m_errFlag = false;
        }
    }
}

u_char* NetworkHandler::getMacOffset(uint64_t* mac)
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

bool NetworkHandler::getErr() const {
    return m_errFlag;
}

pcap_if_t * NetworkHandler::getDevice() const {
    return m_device;
}

pcap_t * NetworkHandler::getDeviceHandle() const {
    return m_deviceHandle;
}

uint32_t NetworkHandler::getDeviceIp() const {
    return m_deviceIp;
}

const uint8_t * NetworkHandler::getDeviceMac() const {
    return m_deviceMac;
}

uint32_t NetworkHandler::getGatewayIp() const {
    return m_gateWayIp;
}

const uint8_t * NetworkHandler::getGatewayMac() const {
    return m_gateWayMac;
}
