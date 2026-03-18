package unifi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"unifi-control/internal/common"

	logger "github.com/multiversx/mx-chain-logger-go"
)

const offValue = "off"
const autoValue = "auto"
const proxyPrefix = "/proxy/network"
const cacheDuration = 10 * time.Second

var log = logger.GetOrCreate("unifi-client")

type client struct {
	url        string
	site       string
	httpClient *httpClientWithLogin

	apiPrefixMutex sync.RWMutex
	apiPrefix      string // To handle UniFi OS proxy paths like /proxy/network

	mutCaching         sync.RWMutex
	cachedUnifiDevices []common.UnifiDeviceData
	lastUpdated        time.Time
}

func NewClient(url, username, password, site string) *client {
	return &client{
		url:        url,
		site:       site,
		httpClient: newHTTPClientWithLogin(url, username, password),
	}
}

func (c *client) Login() error {
	return c.httpClient.Login()
}

func (c *client) SetPoeMode(switchMAC string, portIdx int, on bool) error {
	// 1. Ensure we are logged in
	err := c.httpClient.EnsureLoggedIn()
	if err != nil {
		return err
	}

	// 2. Get current device state to get ID and current overrides
	device, err := c.GetDeviceInfo(switchMAC)
	if err != nil {
		return err
	}

	newMode := offValue
	if on {
		newMode = autoValue
	}

	// 3. Update port_overrides
	updatedOverrides := make([]map[string]interface{}, 0)
	found := false
	for _, po := range device.PortOverrides {
		// When unmarshaling JSON into interface{}, numbers become float64.
		idx, ok := po["port_idx"].(float64)
		if ok && int(idx) == portIdx {
			po["poe_mode"] = newMode
			found = true
		}
		updatedOverrides = append(updatedOverrides, po)
	}

	if !found {
		updatedOverrides = append(updatedOverrides, map[string]interface{}{
			"port_idx":           portIdx,
			"poe_mode":           newMode,
			"setting_preference": "auto", // Required by newer firmware for manual overrides
		})
	}

	// 4. PUT the update
	return c.updateDevice(device.DeviceID, updatedOverrides)
}

func (c *client) updateDevice(deviceID string, overrides []map[string]interface{}) error {
	updateURL := fmt.Sprintf("%s%s/api/s/%s/rest/device/%s", c.url, c.getApiPrefix(), c.site, deviceID)
	payload, _ := json.Marshal(map[string]interface{}{
		"port_overrides": overrides,
	})

	req, _ := http.NewRequest(http.MethodPut, updateURL, bytes.NewBuffer(payload))
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		// Session might have expired or CSRF token is invalid, clear token and retry once
		log.Debug("Unauthorized or Forbidden on updateDevice, retrying login...", "status code", resp.StatusCode)
		err = c.httpClient.Login()
		if err != nil {
			return err
		}
		return c.updateDevice(deviceID, overrides)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to update port: status %d", resp.StatusCode)
	}

	c.mutCaching.Lock()
	c.lastUpdated = time.Time{} // cache will reset
	c.mutCaching.Unlock()

	log.Debug("Successfully updated port", "deviceID", deviceID)

	return nil
}

func (c *client) GetDeviceInfo(mac string) (*common.UnifiDeviceData, error) {
	devices, err := c.GetAllDevices()
	if err != nil {
		return nil, err
	}

	for _, dev := range devices {
		if dev.MAC == mac {
			log.Debug("GetDeviceInfo", "deviceID", dev.DeviceID, "mac", mac)
			return &dev, nil
		}
	}

	return nil, fmt.Errorf("device with MAC %s not found in stat/device list", mac)
}

func (c *client) GetAllDevices() ([]common.UnifiDeviceData, error) {
	devices, err := c.getAllDevices()
	if err == nil {
		return devices, nil
	}

	log.Debug("Auth error on GetAllDevices, attempting re-login", "status", err.Error())
	err = c.httpClient.Login()
	if err != nil {
		return nil, err
	}

	devices, err = c.getAllDevices()
	if err == nil {
		return devices, nil
	}

	log.Debug("Failed to re-login, returning error", "error", err.Error())

	return nil, err
}

func (c *client) getAllDevices() ([]common.UnifiDeviceData, error) {
	// First request attempt with current known prefix
	devices, err := c.doGetAllDevices(c.getApiPrefix())
	if err == nil {
		return devices, nil
	}

	// toggle prefix
	alternatePrefix := proxyPrefix
	if c.getApiPrefix() == proxyPrefix {
		alternatePrefix = ""
	}

	devices, err = c.doGetAllDevices(alternatePrefix)
	if err == nil {
		c.setApiPrefix(alternatePrefix)
		return devices, nil
	}

	return nil, err
}

func (c *client) doGetAllDevices(prefix string) ([]common.UnifiDeviceData, error) {
	c.mutCaching.RLock()
	if time.Since(c.lastUpdated) < cacheDuration && len(c.cachedUnifiDevices) > 0 {
		c.mutCaching.RUnlock()
		return c.cachedUnifiDevices, nil
	}
	c.mutCaching.RUnlock()

	c.mutCaching.Lock()
	defer c.mutCaching.Unlock()

	if time.Since(c.lastUpdated) < cacheDuration && len(c.cachedUnifiDevices) > 0 {
		return c.cachedUnifiDevices, nil
	}

	var err error
	c.cachedUnifiDevices, err = c.doGetAllDevicesFromUnifi(prefix)
	c.lastUpdated = time.Now()

	return c.cachedUnifiDevices, err
}

func (c *client) doGetAllDevicesFromUnifi(prefix string) ([]common.UnifiDeviceData, error) {
	apiURL := fmt.Sprintf("%s%s/api/s/%s/stat/device", c.url, prefix, c.site)
	req, _ := http.NewRequest(http.MethodGet, apiURL, nil)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode == http.StatusUnauthorized {
		reason, _ := io.ReadAll(resp.Body)
		log.Debug("Unauthorized request to Unifi controller", "reason", string(reason))

		return nil, fmt.Errorf("401")
	}

	if resp.StatusCode == http.StatusForbidden {
		reason, _ := io.ReadAll(resp.Body)
		log.Debug("Forbidden request to Unifi controller", "reason", string(reason))

		return nil, fmt.Errorf("403")
	}

	if resp.StatusCode == http.StatusNotFound {
		reason, _ := io.ReadAll(resp.Body)
		log.Debug("Status not found on request to Unifi controller", "reason", string(reason))

		return nil, fmt.Errorf("404")
	}

	if resp.StatusCode != http.StatusOK {
		reason, _ := io.ReadAll(resp.Body)
		log.Debug("Error on request to Unifi controller", "reason", string(reason), "status code", resp.StatusCode)

		return nil, fmt.Errorf("failed to get devices: status %d", resp.StatusCode)
	}

	var devResp common.UnifiDeviceResponse
	err = json.NewDecoder(resp.Body).Decode(&devResp)
	if err != nil {
		return nil, err
	}

	log.Debug("Fetched all devices from the Unifi controller", "count", len(devResp.Data))

	return devResp.Data, nil
}

func (c *client) IsPoeOn(switchMAC string, portIdx int) (bool, error) {
	dev, err := c.GetDeviceInfo(switchMAC)
	if err != nil {
		return false, err
	}

	for _, port := range dev.PortTable {
		if port.PortIdx == portIdx {
			log.Debug("IsPoeOn", "switch MAC", switchMAC, "port index", portIdx, "poe mode", port.PoeMode)

			return port.PoeMode != offValue, nil
		}
	}

	return false, fmt.Errorf("port %d not found on switch %s", portIdx, switchMAC)
}

func (c *client) getApiPrefix() string {
	c.apiPrefixMutex.RLock()
	defer c.apiPrefixMutex.RUnlock()

	return c.apiPrefix
}

func (c *client) setApiPrefix(prefix string) {
	c.apiPrefixMutex.Lock()
	log.Debug("Setting API prefix", "prefix", prefix)
	c.apiPrefix = prefix
	c.apiPrefixMutex.Unlock()
}
