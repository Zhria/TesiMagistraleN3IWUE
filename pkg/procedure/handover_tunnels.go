package procedure

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"syscall"

	"github.com/vishvananda/netlink"

	"github.com/free5gc/n3iwue/internal/gre"
	n3iwue_context "github.com/free5gc/n3iwue/pkg/context"
)

// rebuildHandoverTunnels recreates GRE tunnels based on the handover context and re-applies
// the routes that were previously pointing to the old GRE interfaces.
func (s *Server) rebuildHandoverTunnels(ctx *n3iwue_context.HandoverExecutionContext) error {
	n3ueSelf := s.Context()
	if ctx == nil {
		return fmt.Errorf("handover context is nil")
	}
	if n3ueSelf == nil {
		return fmt.Errorf("n3ue context is nil")
	}
	if len(ctx.Tunnels) == 0 {
		return nil // nothing to update
	}
	if n3ueSelf.UEInnerAddr == nil {
		return fmt.Errorf("ue inner address is not set")
	}
	if n3ueSelf.TemporaryXfrmiName == "" {
		return fmt.Errorf("missing parent XFRM interface name")
	}

	pduAddr := net.ParseIP(n3ueSelf.N3ueInfo.DnIPAddr)
	if pduAddr == nil {
		return fmt.Errorf("invalid or missing PDU address: %q", n3ueSelf.N3ueInfo.DnIPAddr)
	}

	tunnelTargets := make(map[uint8]net.IP)

	for _, tunnel := range ctx.Tunnels {
		remote := selectHandoverRemoteIP(tunnel, ctx)
		if remote == nil {
			continue
		}

		qfis := tunnel.QFIs
		if len(qfis) == 0 {
			qfis = []uint8{1}
		}

		for _, qfi := range qfis {
			if _, exists := tunnelTargets[qfi]; exists {
				continue
			}
			tunnelTargets[qfi] = remote
		}
	}

	if len(tunnelTargets) == 0 {
		return fmt.Errorf("no usable tunnel endpoints in handover context")
	}

	parentLink, err := netlink.LinkByName(n3ueSelf.TemporaryXfrmiName)
	if err != nil {
		return fmt.Errorf("lookup parent iface %s: %w", n3ueSelf.TemporaryXfrmiName, err)
	}

	greBase := fmt.Sprintf("%s-id-%d", n3ueSelf.N3ueInfo.GreIfaceName, n3ueSelf.N3ueInfo.XfrmiId)

	oldRoutes, err := collectAndRemoveGreLinks(greBase, n3ueSelf)
	if err != nil {
		return err
	}

	newLinks := map[uint8]netlink.Link{}

	for qfi, remote := range tunnelTargets {
		greName := fmt.Sprintf("%s-%d", greBase, qfi)
		AppLog.Infof("Handover GRE rebuild: qfi=%d local=%s remote=%s pdu=%s iface=%s", qfi, n3ueSelf.UEInnerAddr.IP, remote, pduAddr, n3ueSelf.TemporaryXfrmiName)
		link, err := gre.SetupGreTunnel(greName, parentLink, n3ueSelf.UEInnerAddr.IP, remote, pduAddr, qfi)
		if err != nil {
			return fmt.Errorf("setup GRE tunnel %s: %w", greName, err)
		}

		newLinks[qfi] = link
		n3ueSelf.CreatedIface = append(n3ueSelf.CreatedIface, &link)
	}

	// Reapply saved routes to the new GRE links so UL traffic continues without manual reconfiguration.
	for qfi, routes := range oldRoutes {
		link, ok := newLinks[qfi]
		if !ok {
			continue
		}
		for _, rt := range routes {
			rt.LinkIndex = link.Attrs().Index
			if err := netlink.RouteAdd(&rt); err != nil && !errors.Is(err, syscall.EEXIST) {
				AppLog.Warnf("re-adding route for GRE qfi %d failed: %+v", qfi, err)
			}
		}
	}

	return nil
}

func selectHandoverRemoteIP(t n3iwue_context.HandoverTunnelInfo, ctx *n3iwue_context.HandoverExecutionContext) net.IP {
	if ip := cloneIP(t.GTPBindIP); ip != nil {
		return ip
	}
	if ip := cloneIP(t.TargetIP); ip != nil {
		return ip
	}
	if ip := cloneIP(t.UPFIP); ip != nil {
		return ip
	}
	if ctx != nil {
		return cloneIP(ctx.TargetN3iwfIP)
	}
	return nil
}

func cloneIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	out := make(net.IP, len(ip))
	copy(out, ip)
	return out
}

func collectAndRemoveGreLinks(baseName string, n3ueSelf *n3iwue_context.N3UE) (map[uint8][]netlink.Route, error) {
	routesByQFI := make(map[uint8][]netlink.Route)

	links, err := netlink.LinkList()
	if err != nil {
		return routesByQFI, fmt.Errorf("list links: %w", err)
	}

	prefix := baseName + "-"
	for _, link := range links {
		if link == nil || !strings.HasPrefix(link.Attrs().Name, prefix) {
			continue
		}

		qfi, ok := parseQFIFromIface(link.Attrs().Name)
		if !ok {
			continue
		}

		if rt, err := netlink.RouteList(link, netlink.FAMILY_ALL); err == nil {
			routesByQFI[qfi] = append(routesByQFI[qfi], rt...)
		}

		if err := netlink.LinkDel(link); err != nil {
			AppLog.Warnf("delete GRE iface %s failed: %+v", link.Attrs().Name, err)
		} else {
			AppLog.Infof("Deleted GRE iface %s for handover update", link.Attrs().Name)
		}
	}

	// Keep only non-GRE interfaces in CreatedIface
	filtered := n3ueSelf.CreatedIface[:0]
	for _, iface := range n3ueSelf.CreatedIface {
		if iface == nil || (*iface).Attrs() == nil {
			continue
		}
		if strings.HasPrefix((*iface).Attrs().Name, prefix) {
			continue
		}
		filtered = append(filtered, iface)
	}
	n3ueSelf.CreatedIface = filtered

	return routesByQFI, nil
}

func parseQFIFromIface(name string) (uint8, bool) {
	parts := strings.Split(name, "-")
	if len(parts) == 0 {
		return 0, false
	}

	last := parts[len(parts)-1]
	val, err := strconv.Atoi(last)
	if err != nil || val < 0 || val > 255 {
		return 0, false
	}

	return uint8(val), true
}
