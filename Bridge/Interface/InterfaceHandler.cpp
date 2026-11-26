#include "InterfaceHandler.h"
#include "pcap.h"

#include <atomic>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>

#include <fcntl.h>
#include <ifaddrs.h>
#include <spawn.h>
#include <unistd.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <net/if.h>
#include <linux/nl80211.h>

#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <netlink/msg.h>
#include <netlink/route/link.h>

extern char** environ;

constexpr int ARPHRD_RADIOTAP_TYPE = 803; // ARPHRD_IEEE80211_RADIOTAP

uint16_t InterfaceHandler::m_channel = 0;

// The live instance, for cleanup from atexit/signal handlers
static InterfaceHandler* s_active = nullptr;
static std::atomic<bool> s_restored{false};

// Created on first use, so loading the library does not touch the card and
// setup errors reach the caller instead of terminating during static init.
InterfaceHandler& InterfaceHandler::getInstance()
{
    static InterfaceHandler instance;
    return instance;
}

// Main initialization flow
InterfaceHandler::InterfaceHandler() :
    m_socket(-1), m_interfaceMac{}, m_interfaceIndex(0), m_hardwareAck(false),
    m_managedIndex(0), m_wiphy(0)
{
    // Initialize nl80211 communication with kernel Wi-Fi subsystem
    initNL();

    // Detect the card's managed interface (e.g. wlan0)
    findWirelessInterface();

    // Ensure safe cleanup on exit or crash signals. Registered before we
    // change anything, so a failure half way still gives the card back.
    s_active = this;
    s_restored = false;
    static bool handlersInstalled = false;
    if (!handlersInstalled)
    {
        atexit(setInterfaceToManaged);
        signal(SIGINT, handleSignal);
        signal(SIGTERM, handleSignal);
        signal(SIGHUP, handleSignal);
        signal(SIGSEGV, handleSignal);
        handlersInstalled = true;
    }

    try
    {
        createMonitorInterface();

        // Open raw socket and retrieve interface MAC
        initializeInterface();

        if (!setInterfaceChannel(1))
            throw std::runtime_error("Failed to set channel 1 on interface " + m_interfaceName);

        // Attach packet filtering rules (BPF)
        setFilters();
    }
    catch (...)
    {
        setInterfaceToManaged();
        throw;
    }
}

InterfaceHandler::~InterfaceHandler()
{
    closeSocket();
    setInterfaceToManaged();
    s_active = nullptr;

    if (m_nl.genericSock)
        nl_socket_free(m_nl.genericSock);
    if (m_nl.rtSock)
        nl_socket_free(m_nl.rtSock);
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
        throw std::runtime_error("Failed to connect to route Netlink (nl_connect).");

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

// Locate the card's managed interface (skips monitor interfaces, ours included)
void InterfaceHandler::findWirelessInterface()
{
    std::cout << "Locating wireless interface from system" << std::endl;

    for (const auto& e : std::filesystem::directory_iterator("/sys/class/net"))
    {
        const std::string iface = e.path().filename();
        const std::string phyIndex = "/sys/class/net/" + iface + "/phy80211/index";

        if (iface == MONITOR_INTERFACE || !std::filesystem::exists(phyIndex) || isMonitorMode(iface))
            continue;

        std::ifstream indexFile(phyIndex);
        if (!(indexFile >> m_wiphy))
            continue;

        m_managedIndex = if_nametoindex(iface.c_str());
        if (!m_managedIndex)
            throw std::runtime_error("Failed to resolve interface index from name. Interface may have disappeared or name is invalid.");

        m_managedName = iface;
        std::cout << "Found wireless interface " << iface << " (phy" << m_wiphy << ")" << std::endl;
        return;
    }

    throw std::runtime_error("No wireless interface detected in /sys/class/net. Ensure WiFi adapter exists and driver is loaded.");
}

/*
 * Create our own monitor interface (mmb0) next to the managed one:
 *   type monitor, flags active control otherbss
 * "active" makes the card ACK frames sent to the interface's MAC in hardware.
 * Drivers without active monitor support get a plain monitor interface and
 * the bridge falls back to sending ACKs itself.
 */
void InterfaceHandler::createMonitorInterface()
{
    std::cout << "Creating monitor interface " << MONITOR_INTERFACE << std::endl;

    // Remove a leftover interface from a previous run
    if (const uint32_t old = if_nametoindex(MONITOR_INTERFACE))
        (void)deleteInterface(old);

    // Take the card away from NetworkManager so it does not fight us.
    // NetworkManager has no netlink API, so use nmcli (missing nmcli is fine).
    runCommand({"nmcli", "device", "set", m_managedName, "managed", "no"});
    if (!setInterfaceState(m_managedIndex, false))
        throw std::runtime_error("Failed to bring interface DOWN: " + m_managedName);

    m_hardwareAck = newMonitorInterface(true);
    if (!m_hardwareAck && !newMonitorInterface(false))
        throw std::runtime_error("Failed to create monitor interface via nl80211. Driver may not support monitor mode.");

    // For comparing against the old behaviour: MMB_SOFTWARE_ACK=1
    if (const char* env = std::getenv("MMB_SOFTWARE_ACK"); env && env[0] == '1')
        m_hardwareAck = false;

    m_interfaceName = MONITOR_INTERFACE;
    m_interfaceIndex = if_nametoindex(MONITOR_INTERFACE);
    if (!m_interfaceIndex)
        throw std::runtime_error(std::string("Monitor interface ") + MONITOR_INTERFACE + " disappeared");

    if (!setInterfaceState(m_interfaceIndex, true))
        throw std::runtime_error("Failed to bring interface UP: " + m_interfaceName);

    std::cout << "Monitor interface " << m_interfaceName << " on phy" << m_wiphy
              << (m_hardwareAck ? " (active monitor: hardware ACK)"
                                : " (plain monitor: software ACK)") << std::endl;
}

bool InterfaceHandler::newMonitorInterface(const bool active) const
{
    nl_msg* msg = nlmsg_alloc();
    if (!msg)
        return false;

    genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, m_nl.family, 0, 0, NL80211_CMD_NEW_INTERFACE, 0);
    nla_put_u32(msg, NL80211_ATTR_WIPHY, m_wiphy);
    nla_put_string(msg, NL80211_ATTR_IFNAME, MONITOR_INTERFACE);
    nla_put_u32(msg, NL80211_ATTR_IFTYPE, NL80211_IFTYPE_MONITOR);

    nlattr* flags = nla_nest_start(msg, NL80211_ATTR_MNTR_FLAGS);
    if (active)
        nla_put_flag(msg, NL80211_MNTR_FLAG_ACTIVE);
    nla_put_flag(msg, NL80211_MNTR_FLAG_CONTROL);
    nla_put_flag(msg, NL80211_MNTR_FLAG_OTHER_BSS);
    nla_nest_end(msg, flags);

    return sendAndWait(msg);
}

bool InterfaceHandler::deleteInterface(const uint32_t ifindex) const
{
    nl_msg* msg = nlmsg_alloc();
    if (!msg)
        return false;

    genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, m_nl.family, 0, 0, NL80211_CMD_DEL_INTERFACE, 0);
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, ifindex);

    return sendAndWait(msg);
}

// Send an nl80211 request and wait for the kernel's ACK. Frees msg.
bool InterfaceHandler::sendAndWait(nl_msg* msg) const
{
    bool res = false;
    if (nl_send_auto(m_nl.genericSock, msg) >= 0)
        res = nl_wait_for_ack(m_nl.genericSock) == 0;

    nlmsg_free(msg);
    return res;
}

// Open AF_PACKET socket, bind to interface, and fetch MAC address
void InterfaceHandler::initializeInterface()
{
    std::cout << "Opening AF_PACKET socket, binding to interface, and fetching MAC address" << std::endl;

    openRawSocket();

    sockaddr_ll sll{};
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex  = static_cast<int>(m_interfaceIndex);

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
                memcpy(m_interfaceMac, sock->sll_addr, MAC_SIZE_BYTES);
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

bool InterfaceHandler::setInterfaceChannel(const uint16_t channel) const
{
    if (m_channel == channel)
        return true;

    nl_msg* msg = nlmsg_alloc();
    if (!msg)
        return false;

    genlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, m_nl.family, 0, 0, NL80211_CMD_SET_WIPHY, 0);
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, m_interfaceIndex);
    nla_put_u32(msg, NL80211_ATTR_WIPHY_FREQ, 2412 + 5 * (channel - 1));

    if (!sendAndWait(msg))
        return false;

    m_channel = channel;
    return true;
}

// Recover from errors by reinitializing interface and filters
void InterfaceHandler::resolveErrors()
{
    closeSocket();
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

bool InterfaceHandler::setInterfaceState(const uint32_t ifindex, const bool up) const
{
    rtnl_link* link = nullptr;
    int err = rtnl_link_get_kernel(m_nl.rtSock, static_cast<int>(ifindex), nullptr, &link);
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

    return err >= 0;
}

/*
 * Monitor interfaces deliver radiotap frames (link type 803). Wireless
 * extensions (SIOCGIWMODE) are not available on kernels built without
 * CONFIG_CFG80211_WEXT, e.g. Fedora.
 */
bool InterfaceHandler::isMonitorMode(const std::string& iface)
{
    std::ifstream typeFile("/sys/class/net/" + iface + "/type");
    int type = 0;
    return (typeFile >> type) && type == ARPHRD_RADIOTAP_TYPE;
}

// Run a command without a shell. Returns true on exit status 0.
bool InterfaceHandler::runCommand(const std::vector<std::string>& args)
{
    std::vector<char*> argv;
    for (const auto& arg : args)
        argv.push_back(const_cast<char*>(arg.c_str()));
    argv.push_back(nullptr);

    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO, "/dev/null", O_WRONLY, 0);
    posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0);

    pid_t pid;
    const int err = posix_spawnp(&pid, argv[0], &actions, nullptr, argv.data(), environ);
    posix_spawn_file_actions_destroy(&actions);
    if (err != 0)
        return false;

    int status = 0;
    if (waitpid(pid, &status, 0) < 0)
        return false;

    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

// Delete mmb0 and give the managed interface back to NetworkManager
void InterfaceHandler::restore()
{
    std::cout << "Restoring managed mode" << std::endl;

    bool ok = true;
    if (m_interfaceIndex)
        ok = deleteInterface(m_interfaceIndex) && ok;
    if (m_managedIndex)
        ok = setInterfaceState(m_managedIndex, true) && ok;
    runCommand({"nmcli", "device", "set", m_managedName, "managed", "yes"});

    if (!ok)
    {
        std::cerr <<
            "Failed to restore the interface automatically.\n"
            "Manual recovery:\n"
            "  sudo iw dev " << MONITOR_INTERFACE << " del\n"
            "  sudo ip link set " << m_managedName << " up\n"
            "  sudo nmcli device set " << m_managedName << " managed yes\n";
    }
}

void InterfaceHandler::setInterfaceToManaged()
{
    if (s_active && !s_restored.exchange(true))
        s_active->restore();
}

void InterfaceHandler::handleSignal(const int sig)
{
    setInterfaceToManaged();
    // Default action (terminate / core dump) instead of returning into the
    // code that was interrupted or crashed.
    signal(sig, SIG_DFL);
    raise(sig);
}

// Getters
const uint8_t* InterfaceHandler::getInterfaceMac() const { return m_interfaceMac; }
std::string InterfaceHandler::getInterfaceName() const { return m_interfaceName; }
int InterfaceHandler::getSocket() const { return m_socket; }
uint16_t InterfaceHandler::getInterfaceChannel() { return m_channel; }
bool InterfaceHandler::hasHardwareAck() const { return m_hardwareAck; }
