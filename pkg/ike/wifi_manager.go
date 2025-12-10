package ike

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/free5gc/n3iwue/internal/logger"
	n3iwue_context "github.com/free5gc/n3iwue/pkg/context"
)

// type wifiManager interface {
// 	// Switch connects to the target Wi-Fi using the UE interface and returns the previously connected SSID (if any).
// 	Switch(cfg *n3iwue_context.WifiHandoverInfo, scanIface string) (string, error)
// }

type nmcliWifiManager struct{}

func (m *nmcliWifiManager) Switch(cfg *n3iwue_context.WifiHandoverInfo, scanIface string) (string, error) {
	if cfg == nil {
		return "", fmt.Errorf("wifi config is nil")
	}
	if cfg.SSID == "" {
		return "", fmt.Errorf("wifi ssid is empty")
	}
	if scanIface == "" {
		return "", fmt.Errorf("scan interface is empty")
	}

	if present, err := m.hasSSID(cfg.SSID, scanIface); err != nil {
		return "", fmt.Errorf("scan wifi: %w", err)
	} else if !present {
		return "", fmt.Errorf("ssid %q not found on iface %s", cfg.SSID, scanIface)
	}

	current, _ := m.currentSSID(scanIface)
	if current == cfg.SSID {
		logger.IKELog.Infof("Wi-Fi already connected to target SSID %q on %s", cfg.SSID, scanIface)
		return current, nil
	}

	// Connect using the UE interface (scanIface)
	args := []string{"dev", "wifi", "connect", cfg.SSID, "ifname", scanIface}
	if cfg.Password != "" {
		args = append(args, "password", cfg.Password)
	}
	if _, err := runNmcli(args...); err != nil {
		if current != "" && current != cfg.SSID {
			if _, recErr := runNmcli("dev", "wifi", "connect", current, "ifname", scanIface); recErr != nil {
				logger.IKELog.Warnf("Wi-Fi rollback to %q on %s failed: %v", current, scanIface, recErr)
			} else {
				logger.IKELog.Infof("Wi-Fi rolled back to previous SSID %q on %s after failure", current, scanIface)
			}
		}
		return "", fmt.Errorf("wifi connect ssid %q: %w", cfg.SSID, err)
	}
	return current, nil
}

func (m *nmcliWifiManager) hasSSID(ssid, iface string) (bool, error) {
	out, err := runNmcli("-t", "-f", "SSID", "dev", "wifi", "ifname", iface)
	if err != nil {
		return false, err
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == ssid {
			return true, nil
		}
	}
	return false, nil
}

func (m *nmcliWifiManager) currentSSID(iface string) (string, error) {
	out, err := runNmcli("-t", "-f", "ACTIVE,SSID", "dev", "wifi", "ifname", iface)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(out, "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 && parts[0] == "yes" {
			return parts[1], nil
		}
	}
	return "", nil
}

func runNmcli(args ...string) (string, error) {
	cmd := exec.Command("nmcli", args...)
	output, err := cmd.CombinedOutput()
	outStr := string(output)
	if err != nil {
		return outStr, fmt.Errorf("%v (%s)", err, strings.TrimSpace(outStr))
	}
	return outStr, nil
}
