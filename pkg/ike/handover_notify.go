package ike

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"

	n3iwue_context "github.com/free5gc/n3iwue/pkg/context"
)

type targetToSourceContainer struct {
	Access      targetAccessInfo      `json:"access"`
	NAS         targetNasInfo         `json:"nas"`
	PduSessions []targetPduSessionRef `json:"pduSessions"`
}

type targetAccessInfo struct {
	N3iwfIP      string `json:"n3iwfIp"`
	FQDN         string `json:"fqdn,omitempty"`
	IKEPort      int    `json:"ikePort"`
	NATTPort     int    `json:"nattPort"`
	NATTraversal bool   `json:"natTraversal"`
	GTPBindAddr  string `json:"gtpBindAddr,omitempty"`
}

type targetNasInfo struct {
	NCC  int    `json:"ncc,omitempty"`
	NH   string `json:"nh,omitempty"`
	GUTI string `json:"guti,omitempty"`
}

type targetPduSessionRef struct {
	ID          int               `json:"id"`
	UPFAddr     string            `json:"upfAddr,omitempty"`
	TEID        uint32            `json:"teid"`
	QFIList     []json.RawMessage `json:"qfiList,omitempty"`
	GTPBindAddr string            `json:"gtpBindAddr,omitempty"`
}

func parseTargetToSourceContainer(data []byte) (*targetToSourceContainer, error) {
	container := new(targetToSourceContainer)
	if len(data) == 0 {
		return nil, fmt.Errorf("empty notification data")
	}
	if err := json.Unmarshal(data, container); err != nil {
		return nil, fmt.Errorf("decode target-to-source container: %w", err)
	}
	return container, nil
}

func buildHandoverContextFromContainer(container *targetToSourceContainer) (*n3iwue_context.HandoverExecutionContext, error) {
	if container == nil {
		return nil, fmt.Errorf("container is nil")
	}

	targetIP, err := resolveTargetIP(container.Access.N3iwfIP, container.Access.FQDN)
	if err != nil {
		return nil, err
	}

	ikePort := container.Access.IKEPort
	if ikePort == 0 {
		ikePort = DEFAULT_IKE_PORT
	}
	nattPort := container.Access.NATTPort
	if nattPort == 0 {
		nattPort = DEFAULT_NATT_PORT
	}

	exec := &n3iwue_context.HandoverExecutionContext{
		TargetN3iwfIP:   targetIP,
		TargetN3iwfFQDN: container.Access.FQDN,
		TargetIKEPort:   ikePort,
		TargetNATTPort:  nattPort,
		EnableNATT:      container.Access.NATTraversal,
	}

	if nasCtx, err := buildNasContext(container.NAS); err != nil {
		return nil, err
	} else if nasCtx != nil {
		exec.Nas = nasCtx
	}

	defaultGtpIP := parseOptionalIP(container.Access.GTPBindAddr)

	for _, session := range container.PduSessions {
		tunnel, err := buildHandoverTunnel(session, defaultGtpIP)
		if err != nil {
			return nil, fmt.Errorf("pduSession %d: %w", session.ID, err)
		}
		exec.Tunnels = append(exec.Tunnels, *tunnel)
	}

	if len(exec.Tunnels) == 0 {
		return nil, fmt.Errorf("no PDU session information provided")
	}

	return exec, nil
}

func buildNasContext(nas targetNasInfo) (*n3iwue_context.NasHandoverContext, error) {
	var nh []byte
	if nas.NH != "" {
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(nas.NH))
		if err != nil {
			return nil, fmt.Errorf("decode NAS NH: %w", err)
		}
		nh = decoded
	}

	if nas.NCC == 0 && len(nh) == 0 && nas.GUTI == "" {
		return nil, nil
	}

	if nas.NCC < 0 || nas.NCC > 255 {
		return nil, fmt.Errorf("invalid NAS NCC %d", nas.NCC)
	}

	return &n3iwue_context.NasHandoverContext{
		NCC:  uint8(nas.NCC),
		NH:   nh,
		GUTI: normalizeGuti(nas.GUTI),
	}, nil
}

func buildHandoverTunnel(session targetPduSessionRef, defaultGtpIP net.IP) (*n3iwue_context.HandoverTunnelInfo, error) {
	if session.ID == 0 {
		return nil, fmt.Errorf("missing PDU session ID")
	}
	if session.TEID == 0 {
		return nil, fmt.Errorf("missing TEID")
	}
	upfIP := net.ParseIP(session.UPFAddr)
	if upfIP == nil {
		return nil, fmt.Errorf("invalid UPF address %q", session.UPFAddr)
	}

	targetIP := parseOptionalIP(session.GTPBindAddr)
	if targetIP == nil {
		targetIP = defaultGtpIP
	}
	if targetIP == nil {
		targetIP = upfIP
	}

	qfis, err := decodeQFIList(session.QFIList)
	if err != nil {
		return nil, err
	}

	tunnel := &n3iwue_context.HandoverTunnelInfo{
		PDUSessionID: int64(session.ID),
		TargetIP:     cloneIP(targetIP),
		TargetTEID:   session.TEID,
		UPFIP:        cloneIP(upfIP),
		QFIs:         qfis,
		GTPBindIP:    cloneIP(targetIP),
	}
	return tunnel, nil
}

func decodeQFIList(rawList []json.RawMessage) ([]uint8, error) {
	qfis := make([]uint8, 0, len(rawList))
	for _, raw := range rawList {
		qfi, err := decodeSingleQFI(raw)
		if err != nil {
			return nil, err
		}
		qfis = append(qfis, qfi)
	}
	return qfis, nil
}

func decodeSingleQFI(raw json.RawMessage) (uint8, error) {
	var asUint uint8
	if err := json.Unmarshal(raw, &asUint); err == nil {
		return asUint, nil
	}

	var asUint64 uint64
	if err := json.Unmarshal(raw, &asUint64); err == nil {
		if asUint64 > 255 {
			return 0, fmt.Errorf("invalid QFI value %d", asUint64)
		}
		return uint8(asUint64), nil
	}

	var asString string
	if err := json.Unmarshal(raw, &asString); err == nil {
		value, err := strconv.Atoi(strings.TrimSpace(asString))
		if err != nil {
			return 0, fmt.Errorf("invalid QFI string %q", asString)
		}
		if value < 0 || value > 255 {
			return 0, fmt.Errorf("invalid QFI value %d", value)
		}
		return uint8(value), nil
	}

	return 0, fmt.Errorf("unsupported QFI format: %s", string(raw))
}

func resolveTargetIP(ipStr, fqdn string) (net.IP, error) {
	if ip := parseOptionalIP(ipStr); ip != nil {
		return ip, nil
	}

	if fqdn == "" {
		return nil, fmt.Errorf("missing both target IP and FQDN")
	}

	ips, err := net.LookupIP(fqdn)
	if err != nil {
		return nil, fmt.Errorf("resolve fqdn %q: %w", fqdn, err)
	}
	for _, ip := range ips {
		if ip.To4() != nil {
			return cloneIP(ip), nil
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("resolve fqdn %q: no addresses returned", fqdn)
	}
	return cloneIP(ips[0]), nil
}

func parseOptionalIP(addr string) net.IP {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return nil
	}
	return net.ParseIP(addr)
}

func normalizeGuti(guti string) string {
	guti = strings.TrimSpace(guti)
	guti = strings.TrimPrefix(strings.ToLower(guti), "5g-guti-")
	guti = strings.ReplaceAll(guti, "-", "")
	guti = strings.ReplaceAll(guti, ":", "")
	return guti
}

func cloneIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	out := make(net.IP, len(ip))
	copy(out, ip)
	return out
}
