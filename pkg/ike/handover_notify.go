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
	Wifi        *targetWifiInfo       `json:"wifi,omitempty"`
}

type targetAccessInfo struct {
	N3iwfIP      string `json:"n3iwfIp"`
	N3iwfBindIP  string `json:"n3iwfBindIp,omitempty"`
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
	ID          int     `json:"id"`
	UPFAddr     string  `json:"upfAddr,omitempty"`
	TEID        uint32  `json:"teid"`
	QFIList     qfiList `json:"qfiList,omitempty"`
	GTPBindAddr string  `json:"gtpBindAddr,omitempty"`
}

type targetWifiInfo struct {
	SSID                 string `json:"ssid,omitempty"`
	Password             string `json:"password,omitempty"`
	AccessPointInterface string `json:"accessPointInterface,omitempty"`
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

	if container.Wifi == nil {
		return nil, fmt.Errorf("wifi config missing in target-to-source container")
	}

	targetIP, err := resolveTargetIP(container.Access.N3iwfBindIP, container.Access.N3iwfIP, container.Access.FQDN)
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

	wifiCtx, err := buildWifiContext(container.Wifi)
	if err != nil {
		return nil, err
	}
	if wifiCtx != nil {
		exec.Wifi = wifiCtx
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

func buildWifiContext(wifi *targetWifiInfo) (*n3iwue_context.WifiHandoverInfo, error) {
	if wifi == nil {
		return nil, fmt.Errorf("wifi config is nil")
	}
	if wifi.SSID == "" {
		return nil, fmt.Errorf("wifi ssid is empty")
	}
	if wifi.AccessPointInterface == "" {
		return nil, fmt.Errorf("wifi accessPointInterface is empty")
	}
	return &n3iwue_context.WifiHandoverInfo{
		SSID:                 wifi.SSID,
		Password:             wifi.Password,
		AccessPointInterface: wifi.AccessPointInterface,
	}, nil
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

	qfis := decodeQFIList(session.QFIList)

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

func decodeQFIList(rawList qfiList) []uint8 {
	return append([]uint8(nil), rawList...)
}

// qfiList is a tolerant decoder that accepts:
// - JSON array of numbers: [5,9]
// - single number: 5
// - base64 string (default []byte JSON encoding): "AQI="
// - comma-separated string: "5,9"
// - string wrapping a JSON array: "[5,9]"
type qfiList []uint8

func (q *qfiList) UnmarshalJSON(b []byte) error {
	if len(b) == 0 {
		return nil
	}

	// Try array of uint8
	var arr8 []uint8
	if err := json.Unmarshal(b, &arr8); err == nil {
		*q = arr8
		return nil
	}

	// Try array of int
	var arrInt []int
	if err := json.Unmarshal(b, &arrInt); err == nil {
		for _, v := range arrInt {
			if v < 0 || v > 255 {
				return fmt.Errorf("invalid QFI value %d", v)
			}
			arr8 = append(arr8, uint8(v))
		}
		*q = arr8
		return nil
	}

	// Try single uint8
	var single8 uint8
	if err := json.Unmarshal(b, &single8); err == nil {
		*q = []uint8{single8}
		return nil
	}

	// Try single int
	var singleInt int
	if err := json.Unmarshal(b, &singleInt); err == nil {
		if singleInt < 0 || singleInt > 255 {
			return fmt.Errorf("invalid QFI value %d", singleInt)
		}
		*q = []uint8{uint8(singleInt)}
		return nil
	}

	// Try string forms
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		s = strings.TrimSpace(s)
		if s == "" {
			return nil
		}

		// Base64 decode
		if decoded, err := base64.StdEncoding.DecodeString(s); err == nil {
			*q = append([]uint8(nil), decoded...)
			return nil
		}

		if strings.HasPrefix(s, "[") {
			var embedded []uint8
			if err := json.Unmarshal([]byte(s), &embedded); err == nil {
				*q = embedded
				return nil
			}
		}

		parts := strings.Split(s, ",")
		var out []uint8
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			v, err := strconv.Atoi(p)
			if err != nil {
				return fmt.Errorf("invalid QFI string %q: %w", s, err)
			}
			if v < 0 || v > 255 {
				return fmt.Errorf("invalid QFI value %d", v)
			}
			out = append(out, uint8(v))
		}
		*q = out
		return nil
	}

	return fmt.Errorf("unsupported QFI format: %s", string(b))
}

func resolveTargetIP(bindIP, ipStr, fqdn string) (net.IP, error) {
	if ip := parseOptionalIP(bindIP); ip != nil {
		return ip, nil
	}
	if ip := parseOptionalIP(ipStr); ip != nil {
		return ip, nil
	}

	if fqdn == "" {
		return nil, fmt.Errorf("missing target IP/bind IP/FQDN")
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
