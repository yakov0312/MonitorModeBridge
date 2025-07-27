#include "AdapterHandler.h"

#include <csignal>
#include <cstring>
#include <memory>
#include <ifaddrs.h>
#include <netpacket/packet.h>
#include "WifiDefenitions.h"

constexpr uint32_t TIMEOUT = 5;

AdapterHandler AdapterHandler::m_instance = AdapterHandler(DEFAULT_RATE);

AdapterHandler::AdapterHandler(uint8_t rate) : m_device(nullptr), m_deviceHandle(nullptr), m_deviceMac{0},
    m_errFlag(false), m_deviceRate(rate)
{
    system("sudo airmon-ng start wlan0 > /dev/null 2>&1"); //temporary and only for testing later will be using system api
    if (initDevice())
        initDeviceNetwork();
    atexit(AdapterHandler::setDeviceToManaged);
    signal(SIGINT, AdapterHandler::setDeviceToManaged);   // Ctrl+C
    signal(SIGTERM, AdapterHandler::setDeviceToManaged);  // kill
    signal(SIGHUP, AdapterHandler::setDeviceToManaged);
    signal(SIGSEGV, AdapterHandler::setDeviceToManaged);
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
    int linkType = pcap_datalink(m_deviceHandle);
    if (linkType == DLT_IEEE802_11_RADIO)
        IS_RADIOTAP = true;
    else if (linkType == DLT_IEEE802_11)
        IS_RADIOTAP = false;
    else
        throw std::runtime_error("Link type is unsupported or device is not in monitor mode");
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

void AdapterHandler::setFilters()
{
    char buf[18]; // 6 * 2 hex + 5 colons + 1 null terminator = 18
    snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
             m_deviceMac[0], m_deviceMac[1], m_deviceMac[2], m_deviceMac[3], m_deviceMac[4], m_deviceMac[5]);
    std::string mac = buf;
    std::string filter_exp = "wlan addr1 " + mac +
                         " or wlan addr2 " + mac +
                         " or wlan addr3 " + mac;

    struct bpf_program fp;
    if (pcap_compile(m_deviceHandle, &fp, filter_exp.c_str(), 1, PCAP_NETMASK_UNKNOWN) == PCAP_ERROR
        && pcap_setfilter(m_deviceHandle, &fp) == PCAP_ERROR)
        throw std::runtime_error("Cannot set up filters");
    pcap_freecode(&fp);
}

void AdapterHandler::removeFilters()
{
    struct bpf_program fp;
    const char* filter_exp = "";  // empty filter, capture everything

    if (pcap_compile(m_deviceHandle, &fp, filter_exp, 1, PCAP_NETMASK_UNKNOWN) == PCAP_ERROR
        && pcap_setfilter(m_deviceHandle, &fp) == PCAP_ERROR)
        throw std::runtime_error("Cannot remove filters");
    pcap_freecode(&fp);
}

void AdapterHandler::resolveErrors()
{
    if (initDevice())
        if (initDeviceNetwork())
            m_errFlag = false;
}

void AdapterHandler::setDeviceToManaged()
{
    system("sudo airmon-ng stop wlan0mon > /dev/null 2>&1"); //temporary and only for testing later will be using system api
}

void AdapterHandler::setDeviceToManaged(int sig)
{
    system("sudo airmon-ng stop wlan0mon > /dev/null 2>&1"); //temporary and only for testing later will be using system api
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

uint8_t AdapterHandler::getDeviceRate() const
{
    return m_deviceRate;
}

void AdapterHandler::setDeviceRate(uint16_t rate)
{
    m_deviceRate = rate;
}

