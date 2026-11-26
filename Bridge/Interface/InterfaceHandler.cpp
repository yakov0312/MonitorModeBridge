#include "InterfaceHandler.h"
#include "pcap.h"

#include <csignal>
#include <cstring>
#include <filesystem>
#include <iostream>

#include <ifaddrs.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <sys/socket.h>

#include <net/if.h>
#include <linux/nl80211.h>

#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <netlink/msg.h>
#include <netlink/route/link.h>

struct rtmNewlink
{
    nlmsghdr nlh;
    ifinfomsg ifi;
};

// Singleton instance
InterfaceHandler InterfaceHandler::m_instance = InterfaceHandler();
uint16_t InterfaceHandler::m_channel = 0;

// Main initialization flow (runs on startup)
InterfaceHandler::InterfaceHandler() : m_socket(-1), m_interfaceMac{}, m_interfaceIndex(-1)
{
    // Initialize nl80211 communication with kernel Wi-Fi subsystem
    initNL();

    // Detect available wireless interface
    findWirelessInterface();

    if (!setInterfaceState(false)) // Bring interface DOWN
        throw std::runtime_error("Failed to bring interface DOWN: " + m_interfaceName);

    setMonitorMode(); // Switch to monitor mode

    if (!setInterfaceState(true)) // Bring interface UP
        throw std::runtime_error("Failed to bring interface UP: " + m_interfaceName + \
            "\nRecovery:\n" \
            "sudo iw dev " + m_interfaceName + " set type managed\n" \
            "sudo ip link set " + m_interfaceName + " up");

    // Open raw socket and retrieve interface MAC
    initializeInterface();

    if (!setInterfaceChannel(1))
        throw std::runtime_error("Failed to set channel " + std::to_string(m_channel) + " on interface" + m_interfaceName);

    // Attach packet filtering rules (BPF)
    setFilters();

    // Ensure safe cleanup on exit or crash signals
    atexit(setInterfaceToManaged);
    signal(SIGINT, setInterfaceToManaged);
    signal(SIGTERM, setInterfaceToManaged);
    signal(SIGHUP, setInterfaceToManaged);
    signal(SIGSEGV, setInterfaceToManaged);
}

// Initialize Netlink communication with kernel (nl80211)
void InterfaceHandler::initNL()
{
    std::cout << "Initializing Netlink communication with kernel" << std::endl;

    // Route socket
    m_nl.rtSock = nl_socket_alloc();
    if (!m_nl.rtSock)
        throw std::runtime_error("Failed to open netlink socket (nl_socket_alloc). Possible cause: memory pressure or libnl misconfiguration.");

    if (nl_connect(m_nl.rtSock, NETLINK_ROUTE))
        throw std::runtime_error("Failed to connect to Generic Netlink (nl_connect). Likely cause: kernel nl80211 subsystem unavailable or broken driver stack.");

    // Generic socket
    m_nl.genericSock = nl_socket_alloc();
    if (!m_nl.genericSock)
        throw std::runtime_error("Failed to allocate Netlink socket (nl_socket_alloc). Possible cause: memory pressure or libnl misconfiguration.");

    if (genl_connect(m_nl.genericSock) < 0)
        throw std::runtime_error("Failed to connect to Generic Netlink (genl_connect). Likely cause: kernel nl80211 subsystem unavailable or broken driver stack.");

    m_nl.family = genl_ctrl_resolve(m_nl.genericSock, "nl80211");
    if (m_nl.family < 0)
        throw std::runtime_error("nl80211 family not found. Wireless driver may not be loaded or kernel lacks nl80211 support.");
}


// Locate wireless interface from system
void InterfaceHandler::findWirelessInterface()
{
    std::cout << "Locating wireless interface from system" << std::endl;

    std::string iface;

    for (const auto& e : std::filesystem::directory_iterator("/sys/class/net"))
    {
        iface = e.path().filename();

        if (std::filesystem::exists("/sys/class/net/" + iface + "/wireless"))
        {
            m_interfaceName = iface;
            break;
        }
    }

    if (!iface.empty())
    {
        m_interfaceIndex = if_nametoindex(m_interfaceName.c_str());

        if (!m_interfaceIndex)
            throw std::runtime_error("Failed to resolve interface index from name. Interface may have disappeared or name is invalid.");

        std::cout << "Found wireless interface " << iface << " with index of " << m_interfaceIndex << std::endl;
    }
    else
        throw std::runtime_error("No wireless interface detected in /sys/class/net. Ensure WiFi adapter exists and driver is loaded.");
}


// Open AF_PACKET socket, bind to interface, and fetch MAC address
void InterfaceHandler::initializeInterface()
{
    std::cout << "Opening AF_PACKET socket, binding to interface, and fetching MAC address" << std::endl;

    openRawSocket();

    sockaddr_ll sll{};
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex  = m_interfaceIndex;

    if (bind(m_socket, reinterpret_cast<sockaddr*>(&sll), sizeof(sll)) < 0)
    {
        closeSocket();
        throw std::runtime_error("Failed to bind AF_PACKET socket. Possible causes: insufficient privileges (run as root) or interface is down.");
    }

    ifaddrs* addrs = nullptr;
    if (getifaddrs(&addrs) < 0)
        throw std::runtime_error("getifaddrs failed. System networking stack issue or insufficient permissions.");

    bool found = false;

    for (const auto* addr = addrs; addr && !found; addr = addr->ifa_next)
    {
        if (addr->ifa_addr && addr->ifa_addr->sa_family == AF_PACKET)
        {
            if (m_interfaceName == addr->ifa_name)
            {
                const auto* sock = reinterpret_cast<sockaddr_ll*>(addr->ifa_addr);
                memcpy(m_interfaceMac, sock->sll_addr, 6);
                found = true;
            }
        }
    }

    freeifaddrs(addrs);

    if (!found)
        throw std::runtime_error("Failed to resolve MAC address for interface. Interface name mismatch or link-layer info unavailable.");
}


// Create raw socket
void InterfaceHandler::openRawSocket()
{
    m_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (m_socket < 0)
        throw std::runtime_error("Failed to create raw socket (AF_PACKET). Requires root privileges or CAP_NET_RAW capability.");
}


// Close socket safely
void InterfaceHandler::closeSocket()
{
    if (m_socket >= 0)
    {
        close(m_socket);
        m_socket = -1;
    }
}


InterfaceHandler::~InterfaceHandler()
{
}

InterfaceHandler & InterfaceHandler::getInstance()
{
    return m_instance;
}

bool InterfaceHandler::setInterfaceChannel(const uint16_t channel) const
{
    if (m_channel == channel)
        return true;

    nl_msg* msg = nlmsg_alloc();

    genlmsg_put(msg, 0, 0, m_nl.family, 0, 0, NL80211_CMD_SET_WIPHY, 0);

    nla_put_u32(msg, NL80211_ATTR_IFINDEX, m_interfaceIndex);
    const int freq = 2412 + 5 * (channel - 1);
    nla_put_u32(msg, NL80211_ATTR_WIPHY_FREQ, freq);

    bool res = false;

    if (nl_send_auto(m_nl.genericSock, msg) >= 0)
        if (nl_wait_for_ack(m_nl.genericSock) == 0)
        {
            m_channel = channel;
            res = true;
        }

    nlmsg_free(msg);

    return res;
}

// Recover from errors by reinitializing interface and filters
void InterfaceHandler::resolveErrors()
{
    initializeInterface();
    setFilters();
}

// Attach BPF filter to socket
void InterfaceHandler::setFilters() const
{
    std::cout << "Attaching BPF filter to socket" << std::endl;

    char buf[18];
    snprintf(buf, sizeof(buf),
             "%02x:%02x:%02x:%02x:%02x:%02x",
             m_interfaceMac[0], m_interfaceMac[1], m_interfaceMac[2],
             m_interfaceMac[3], m_interfaceMac[4], m_interfaceMac[5]);

    std::cout << "Mac: " << buf << std::endl;

    const std::string macStr = buf;
    const std::string filter = "wlan addr1 " + macStr + " and not wlan type ctl";

    pcap_t* h = pcap_open_dead(DLT_IEEE802_11_RADIO, 65535);
    if (!h)
        throw std::runtime_error("Failed to create BPF compilation context. libpcap installation issue or unsupported link type.");

    bpf_program fp{};

    if (pcap_compile(h, &fp, filter.c_str(), 1, PCAP_NETMASK_UNKNOWN) == PCAP_ERROR)
    {
        pcap_close(h);
        throw std::runtime_error("BPF compilation failed. Likely invalid filter syntax or unsupported 802.11 fields for current libpcap version.");
    }

    sock_fprog prog{};
    prog.len = fp.bf_len;
    prog.filter = reinterpret_cast<sock_filter*>(fp.bf_insns);

    if (setsockopt(m_socket, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)) < 0)
    {
        pcap_freecode(&fp);
        pcap_close(h);
        throw std::runtime_error("Failed to attach BPF filter to socket. Kernel rejected filter or socket type is incompatible.");
    }

    pcap_freecode(&fp);
    pcap_close(h);
}

// Switch interface mode using nl80211
bool InterfaceHandler::setInterfaceMode(const uint32_t mode) const
{
    nl_msg* msg = nlmsg_alloc();
    if (!msg)
        return false;

    genlmsg_put(msg, 0, 0, m_nl.family, 0, 0, NL80211_CMD_SET_INTERFACE, 0);
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, m_interfaceIndex);
    nla_put_u32(msg, NL80211_ATTR_IFTYPE, mode);

    // Add monitor flags if switching to monitor mode
    if (mode == NL80211_IFTYPE_MONITOR)
    {
        nl_msg* flagsMsg = nlmsg_alloc();
        if (!flagsMsg)
        {
            nlmsg_free(msg);
            return false;
        }

        nla_put_flag(flagsMsg, NL80211_MNTR_FLAG_ACTIVE);
        nla_put_nested(msg, NL80211_ATTR_MNTR_FLAGS, flagsMsg);
        nlmsg_free(flagsMsg);
    }

    bool res = false;
    if (nl_send_auto(m_nl.genericSock, msg) >= 0)
    {
        const int err = nl_wait_for_ack(m_nl.genericSock);
        res = (err == 0);
    }
    nlmsg_free(msg);
    return res;
}

bool InterfaceHandler::setInterfaceState(bool up)
{
    if (up == m_interfaceState)
        return true;

    rtnl_link* link = nullptr;
    int err = rtnl_link_get_kernel(m_nl.rtSock, m_interfaceIndex, nullptr, &link);
    if (err < 0 || !link)
        return false;

    // Create a change request object — only the delta goes here
    rtnl_link* change = rtnl_link_alloc();
    if (!change)
    {
        rtnl_link_put(link);
        return false;
    }

    if (up)
        rtnl_link_set_flags(change, IFF_UP);
    else
        rtnl_link_unset_flags(change, IFF_UP);

    err = rtnl_link_change(m_nl.rtSock, link, change, 0);

    rtnl_link_put(change);
    rtnl_link_put(link);

    if (err < 0)
        return false;

    m_interfaceState = up;
    return true;
}

// Enable monitor mode
void InterfaceHandler::setMonitorMode() const
{
    std::cout << "Enabling monitor mode" << std::endl;

    if (!setInterfaceMode(NL80211_IFTYPE_MONITOR))
        throw std::runtime_error("Failed to switch interface to monitor mode via nl80211. Driver may not support mode switching or interface is controlled by NetworkManager/wpa_supplicant.");
}


// Restore managed mode on exit or crash
void InterfaceHandler::setInterfaceToManaged()
{
    std::cout << "Restoring managed mode" << std::endl;

    if (!m_instance.setInterfaceState(false) ||
        !m_instance.setInterfaceMode(NL80211_IFTYPE_STATION) ||
        !m_instance.setInterfaceState(true))
    {
        const std::string_view iface = m_instance.m_interfaceName;

        std::cerr <<
            "Failed to restore interface to managed mode automatically.\n"
            "Manual recovery required:\n"
            "  sudo ip link set " << iface << " down\n"
            "  sudo iw dev " << iface << " set type managed\n"
            "  sudo ip link set " << iface << " up\n"
            "Possible cause: interface controlled by NetworkManager or nl80211 rejected mode change.\n";
    }
}

// Signal safe wrapper
void InterfaceHandler::setInterfaceToManaged(int)
{
    setInterfaceToManaged();
}

// Getters
const uint8_t* InterfaceHandler::getInterfaceMac() const { return m_interfaceMac; }
std::string InterfaceHandler::getInterfaceName() const { return m_interfaceName; }
int InterfaceHandler::getSocket() const { return m_socket; }

uint16_t InterfaceHandler::getInterfaceChannel() { return m_channel; }
