package network

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

const (
	DefaultBridgeName = "gojail0"
	DefaultBridgeCIDR = "10.200.0.1/24"
	DefaultSubnetCIDR = "10.200.0.0/24"
)

// PortMapping defines host-to-container port forwarding rules for bridge networking.
type PortMapping struct {
	HostPort      int    `json:"host_port"`
	ContainerPort int    `json:"container_port"`
	Protocol      string `json:"protocol"` // "tcp" or "udp"
}

// Manager coordinates host bridge devices, container veth pairings, and NAT/DNAT routing.
type Manager struct {
	bridgeName string
	bridgeCIDR string
	ipam       *IPAM
}

// NewManager initializes a network manager instance backed by an IPAM allocator.
func NewManager() *Manager {
	ipam, _ := NewIPAM(DefaultSubnetCIDR)
	return &Manager{
		bridgeName: DefaultBridgeName,
		bridgeCIDR: DefaultBridgeCIDR,
		ipam:       ipam,
	}
}

// IPAM returns the underlying IPAM instance.
func (m *Manager) IPAM() *IPAM {
	return m.ipam
}

// EnsureBridge initializes the host software bridge and configures NAT forwarding.
func (m *Manager) EnsureBridge() (*netlink.Bridge, error) {
	link, err := netlink.LinkByName(m.bridgeName)
	if err == nil {
		if br, ok := link.(*netlink.Bridge); ok {
			return br, nil
		}
		return nil, fmt.Errorf("interface %s exists but is not a bridge", m.bridgeName)
	}

	la := netlink.NewLinkAttrs()
	la.Name = m.bridgeName
	br := &netlink.Bridge{LinkAttrs: la}

	if err := netlink.LinkAdd(br); err != nil {
		return nil, fmt.Errorf("failed to create bridge %s: %w", m.bridgeName, err)
	}

	addr, err := netlink.ParseAddr(m.bridgeCIDR)
	if err != nil {
		return nil, fmt.Errorf("failed to parse bridge CIDR %s: %w", m.bridgeCIDR, err)
	}

	if err := netlink.AddrAdd(br, addr); err != nil {
		return nil, fmt.Errorf("failed to assign IP to bridge %s: %w", m.bridgeName, err)
	}

	if err := netlink.LinkSetUp(br); err != nil {
		return nil, fmt.Errorf("failed to bring bridge %s UP: %w", m.bridgeName, err)
	}

	// Enable kernel forwarding, localnet routing, and relax reverse-path filtering
	_ = os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0644)
	_ = os.WriteFile("/proc/sys/net/ipv4/conf/all/route_localnet", []byte("1\n"), 0644)
	_ = os.WriteFile("/proc/sys/net/ipv4/conf/all/rp_filter", []byte("0\n"), 0644)
	_ = os.WriteFile("/proc/sys/net/ipv4/conf/lo/route_localnet", []byte("1\n"), 0644)
	_ = os.WriteFile("/proc/sys/net/ipv4/conf/lo/rp_filter", []byte("0\n"), 0644)
	_ = os.WriteFile(fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/route_localnet", m.bridgeName), []byte("1\n"), 0644)
	_ = os.WriteFile(fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/rp_filter", m.bridgeName), []byte("0\n"), 0644)

	// Outbound Internet MASQUERADE
	_ = exec.Command("iptables", "-t", "nat", "-C", "POSTROUTING", "-s", DefaultSubnetCIDR, "!", "-o", m.bridgeName, "-j", "MASQUERADE").Run()
	_ = exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", DefaultSubnetCIDR, "!", "-o", m.bridgeName, "-j", "MASQUERADE").Run()

	// Unconditional bridge forwarding in both directions
	_ = exec.Command("iptables", "-C", "FORWARD", "-o", m.bridgeName, "-j", "ACCEPT").Run()
	_ = exec.Command("iptables", "-A", "FORWARD", "-o", m.bridgeName, "-j", "ACCEPT").Run()
	_ = exec.Command("iptables", "-C", "FORWARD", "-i", m.bridgeName, "-j", "ACCEPT").Run()
	_ = exec.Command("iptables", "-A", "FORWARD", "-i", m.bridgeName, "-j", "ACCEPT").Run()

	return br, nil
}

// SetupContainerNetwork provisions a veth pair, leases an IP via IPAM, attaches host end to bridge,
// moves container end into child PID's netns, configures routes, DNS, and port forwardings.
func (m *Manager) SetupContainerNetwork(containerID string, pid int, rootfs string, portMappings []PortMapping, dnsServers []string) error {
	br, err := m.EnsureBridge()
	if err != nil {
		return fmt.Errorf("failed to ensure bridge: %w", err)
	}

	containerIP, err := m.ipam.AllocateIP(containerID)
	if err != nil {
		return fmt.Errorf("failed to lease container IP: %w", err)
	}

	hash := sha256.Sum256([]byte(containerID))
	shortID := hex.EncodeToString(hash[:])[:7]
	vethHostName := "veth" + shortID
	vethPeerName := "ceth" + shortID

	if oldLink, err := netlink.LinkByName(vethHostName); err == nil {
		_ = netlink.LinkDel(oldLink)
	}

	vethAttrs := netlink.NewLinkAttrs()
	vethAttrs.Name = vethHostName
	vethAttrs.MasterIndex = br.Index

	veth := &netlink.Veth{
		LinkAttrs: vethAttrs,
		PeerName:  vethPeerName,
	}

	if err := netlink.LinkAdd(veth); err != nil {
		_ = m.ipam.ReleaseIP(containerID)
		return fmt.Errorf("failed to create veth pair (%s <-> %s): %w", vethHostName, vethPeerName, err)
	}

	if err := netlink.LinkSetUp(veth); err != nil {
		_ = netlink.LinkDel(veth)
		_ = m.ipam.ReleaseIP(containerID)
		return fmt.Errorf("failed to bring host veth %s UP: %w", vethHostName, err)
	}

	peerLink, err := netlink.LinkByName(vethPeerName)
	if err != nil {
		_ = netlink.LinkDel(veth)
		_ = m.ipam.ReleaseIP(containerID)
		return fmt.Errorf("failed to locate peer veth %s: %w", vethPeerName, err)
	}

	if err := netlink.LinkSetNsPid(peerLink, pid); err != nil {
		_ = netlink.LinkDel(veth)
		_ = m.ipam.ReleaseIP(containerID)
		return fmt.Errorf("failed to move peer veth into pid %d netns: %w", pid, err)
	}

	rawIP := containerIP.String()
	containerCIDR := rawIP + "/24"

	if err := configureInNetns(pid, vethPeerName, containerCIDR, m.ipam.Gateway().String()); err != nil {
		_ = netlink.LinkDel(veth)
		_ = m.ipam.ReleaseIP(containerID)
		return fmt.Errorf("failed to configure network inside container netns: %w", err)
	}

	if len(portMappings) > 0 {
		if err := m.applyPortForwarding(rawIP, portMappings); err != nil {
			_ = netlink.LinkDel(veth)
			_ = m.ipam.ReleaseIP(containerID)
			return fmt.Errorf("failed to apply port forwarding rules: %w", err)
		}
	}

	if rootfs != "" {
		_ = InjectResolvConf(rootfs, dnsServers)
	}

	return nil
}

// applyPortForwarding adds iptables DNAT rules for external and host ingress.
func (m *Manager) applyPortForwarding(containerIP string, mappings []PortMapping) error {
	for _, mapping := range mappings {
		proto := strings.ToLower(mapping.Protocol)
		if proto == "" {
			proto = "tcp"
		}
		if proto != "tcp" && proto != "udp" {
			return fmt.Errorf("unsupported protocol %q, must be tcp or udp", proto)
		}

		hostPortStr := strconv.Itoa(mapping.HostPort)
		targetStr := fmt.Sprintf("%s:%d", containerIP, mapping.ContainerPort)

		cmdPrerouting := exec.Command("iptables", "-t", "nat", "-A", "PREROUTING",
			"-p", proto, "--dport", hostPortStr,
			"-j", "DNAT", "--to-destination", targetStr)
		if out, err := cmdPrerouting.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to add PREROUTING DNAT rule: %s (%w)", string(out), err)
		}

		_ = exec.Command("iptables", "-t", "nat", "-A", "OUTPUT",
			"-p", proto, "-d", "127.0.0.1", "--dport", hostPortStr,
			"-j", "DNAT", "--to-destination", targetStr).Run()
		_ = exec.Command("iptables", "-t", "nat", "-A", "OUTPUT",
			"-p", proto, "-d", "10.200.0.1", "--dport", hostPortStr,
			"-j", "DNAT", "--to-destination", targetStr).Run()

		_ = exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING",
			"-p", proto, "-d", containerIP, "--dport", strconv.Itoa(mapping.ContainerPort),
			"-j", "MASQUERADE").Run()
	}
	return nil
}

// removePortForwarding tears down the iptables DNAT rules when the container terminates.
func (m *Manager) removePortForwarding(containerIP string, mappings []PortMapping) {
	for _, mapping := range mappings {
		proto := strings.ToLower(mapping.Protocol)
		if proto == "" {
			proto = "tcp"
		}

		hostPortStr := strconv.Itoa(mapping.HostPort)
		targetStr := fmt.Sprintf("%s:%d", containerIP, mapping.ContainerPort)

		_ = exec.Command("iptables", "-t", "nat", "-D", "PREROUTING",
			"-p", proto, "--dport", hostPortStr,
			"-j", "DNAT", "--to-destination", targetStr).Run()

		_ = exec.Command("iptables", "-t", "nat", "-D", "OUTPUT",
			"-p", proto, "-d", "127.0.0.1", "--dport", hostPortStr,
			"-j", "DNAT", "--to-destination", targetStr).Run()

		_ = exec.Command("iptables", "-t", "nat", "-D", "OUTPUT",
			"-p", proto, "-d", "10.200.0.1", "--dport", hostPortStr,
			"-j", "DNAT", "--to-destination", targetStr).Run()

		_ = exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING",
			"-p", proto, "-d", containerIP, "--dport", strconv.Itoa(mapping.ContainerPort),
			"-j", "MASQUERADE").Run()
	}
}

// configureInNetns executes link setup and default route inside the child namespace.
func configureInNetns(pid int, peerName, containerCIDR, gatewayIP string) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	hostNs, err := netns.Get()
	if err != nil {
		return fmt.Errorf("failed to get host netns: %w", err)
	}
	defer func() {
		_ = netns.Set(hostNs)
		_ = hostNs.Close()
	}()

	childNs, err := netns.GetFromPid(pid)
	if err != nil {
		return fmt.Errorf("failed to get child netns from pid %d: %w", pid, err)
	}
	defer func() { _ = childNs.Close() }()

	if err := netns.Set(childNs); err != nil {
		return fmt.Errorf("failed to switch to child netns: %w", err)
	}

	_ = os.WriteFile("/proc/sys/net/ipv4/ping_group_range", []byte("0 2147483647\n"), 0644)

	if loLink, err := netlink.LinkByName("lo"); err == nil {
		_ = netlink.LinkSetUp(loLink)
	}

	peerLink, err := netlink.LinkByName(peerName)
	if err != nil {
		return fmt.Errorf("failed to find %s inside child netns: %w", peerName, err)
	}

	if err := netlink.LinkSetName(peerLink, "eth0"); err != nil {
		return fmt.Errorf("failed to rename %s to eth0: %w", peerName, err)
	}

	eth0, err := netlink.LinkByName("eth0")
	if err != nil {
		return fmt.Errorf("failed to find eth0: %w", err)
	}

	addr, err := netlink.ParseAddr(containerCIDR)
	if err != nil {
		return fmt.Errorf("invalid container CIDR %s: %w", containerCIDR, err)
	}

	if err := netlink.AddrAdd(eth0, addr); err != nil {
		return fmt.Errorf("failed to add address %s to eth0: %w", containerCIDR, err)
	}

	if err := netlink.LinkSetUp(eth0); err != nil {
		return fmt.Errorf("failed to set eth0 UP: %w", err)
	}

	gw := net.ParseIP(gatewayIP)
	if gw == nil {
		return fmt.Errorf("invalid gateway IP: %s", gatewayIP)
	}

	defaultRoute := &netlink.Route{
		Scope:     netlink.SCOPE_UNIVERSE,
		LinkIndex: eth0.Attrs().Index,
		Gw:        gw,
	}

	if err := netlink.RouteAdd(defaultRoute); err != nil {
		return fmt.Errorf("failed to add default route to %s: %w", gatewayIP, err)
	}

	return nil
}

// Cleanup cleans up the host veth link, DNAT rules, and releases the IPAM lease.
func (m *Manager) Cleanup(containerID string, portMappings []PortMapping) {
	if containerIP, ok := m.ipam.GetIP(containerID); ok {
		if len(portMappings) > 0 {
			m.removePortForwarding(containerIP.String(), portMappings)
		}
		_ = m.ipam.ReleaseIP(containerID)
	}

	hash := sha256.Sum256([]byte(containerID))
	shortID := hex.EncodeToString(hash[:])[:7]
	vethHostName := "veth" + shortID

	if link, err := netlink.LinkByName(vethHostName); err == nil {
		_ = netlink.LinkDel(link)
	}
}
