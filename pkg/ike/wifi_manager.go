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
// 	Switch(cfg *n3iwue_context.WifiHandoverInfo) (string, error)
// }

type nmcliWifiManager struct{}

func (m *nmcliWifiManager) Switch(cfg *n3iwue_context.WifiHandoverInfo) (string, error) {
	if cfg == nil {
		return "", fmt.Errorf("wifi config is nil")
	}
	if cfg.SSID == "" {
		return "", fmt.Errorf("wifi ssid is empty")
	}

	if present, err := m.hasSSID(cfg.SSID); err != nil {
		return "", fmt.Errorf("scan wifi: %w", err)
	} else if !present {
		return "", fmt.Errorf("ssid %q not found", cfg.SSID)
	}

	current, _ := m.currentSSID()
	if current == cfg.SSID {
		logger.IKELog.Infof("Wi-Fi already connected to target SSID %q", cfg.SSID)
		return current, nil
	}

	args := []string{"dev", "wifi", "connect", cfg.SSID}
	if cfg.Password != "" {
		args = append(args, "password", cfg.Password)
	}
	if _, err := runNmcli(args...); err != nil {
		if current != "" && current != cfg.SSID {
			if _, recErr := runNmcli("dev", "wifi", "connect", current); recErr != nil {
				logger.IKELog.Warnf("Wi-Fi rollback to %q failed: %v", current, recErr)
			} else {
				logger.IKELog.Infof("Wi-Fi rolled back to previous SSID %q after failure", current)
			}
		}
		return "", fmt.Errorf("wifi connect ssid %q: %w", cfg.SSID, err)
	}
	return current, nil
}

func (m *nmcliWifiManager) hasSSID(ssid string) (bool, error) {
	out, err := runNmcli("-t", "-f", "SSID", "dev", "wifi")
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

func (m *nmcliWifiManager) currentSSID() (string, error) {
	out, err := runNmcli("-t", "-f", "ACTIVE,SSID", "dev", "wifi")
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
