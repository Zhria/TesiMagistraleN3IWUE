package ike

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/free5gc/n3iwue/internal/logger"
	n3iwue_context "github.com/free5gc/n3iwue/pkg/context"
)

type nmcliWifiManager struct{}

func (m *nmcliWifiManager) Switch(cfg *n3iwue_context.WifiHandoverInfo) (string, error) {
	if cfg == nil {
		return "", fmt.Errorf("wifi config is nil")
	}
	if cfg.SSID == "" {
		return "", fmt.Errorf("wifi ssid is empty")
	}

	// Get current SSID without triggering a scan (queries active connections only)
	current, _ := m.currentSSID()
	if current == cfg.SSID {
		logger.IKELog.Infof("Wi-Fi already connected to target SSID %q", cfg.SSID)
		return current, nil
	}

	// Fast path: "con up" uses a saved profile — no scan, no DHCP negotiation if static IP
	logger.IKELog.Infof("Wi-Fi fast connect: trying 'nmcli con up %s'", cfg.SSID)
	if _, err := runNmcli("con", "up", cfg.SSID); err != nil {
		// Fallback: full "dev wifi connect" (triggers scan but handles unknown networks)
		logger.IKELog.Infof("Wi-Fi fast connect failed, falling back to 'dev wifi connect': %v", err)
		args := []string{"dev", "wifi", "connect", cfg.SSID}
		if cfg.Password != "" {
			args = append(args, "password", cfg.Password)
		}
		if _, err := runNmcli(args...); err != nil {
			// Rollback to previous SSID on failure
			if current != "" && current != cfg.SSID {
				if _, recErr := runNmcli("con", "up", current); recErr != nil {
					logger.IKELog.Warnf("Wi-Fi rollback to %q failed: %v", current, recErr)
				} else {
					logger.IKELog.Infof("Wi-Fi rolled back to previous SSID %q after failure", current)
				}
			}
			return "", fmt.Errorf("wifi connect ssid %q: %w", cfg.SSID, err)
		}
	}
	return current, nil
}

// currentSSID returns the SSID of the active wifi connection without scanning.
func (m *nmcliWifiManager) currentSSID() (string, error) {
	out, err := runNmcli("-t", "-f", "NAME,TYPE", "con", "show", "--active")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(out, "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), ":", 2)
		if len(parts) == 2 && strings.Contains(parts[1], "wireless") {
			return parts[0], nil
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
