package unifi

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/cookiejar"
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
	url      string
	username string
	password string
	site     string
	http     *http.Client

	tokenMutex sync.Mutex
	csrfToken  string

	apiPrefixMutex sync.RWMutex
	apiPrefix      string // To handle UniFi OS proxy paths like /proxy/network

	mutCaching         sync.RWMutex
	cachedUnifiDevices []common.UnifiDeviceData
	lastUpdated        time.Time
}

func NewClient(url, username, password, site string) *client {
	jar, _ := cookiejar.New(nil)
	return &client{
		url:      url,
		username: username,
		password: password,
		site:     site,
		http: &http.Client{
			Timeout: 10 * time.Second,
			Jar:     jar,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
	}
}

func (c *client) ensureLoggedIn() error {
	c.tokenMutex.Lock()
	defer c.tokenMutex.Unlock()

	if c.csrfToken != "" {
		return nil
	}

	return c.loginWithLock()
}

func (c *client) Login() error {
	c.tokenMutex.Lock()
	defer c.tokenMutex.Unlock()

	return c.loginWithLock()
}

func (c *client) setToken(token string) {
	c.tokenMutex.Lock()
	c.csrfToken = token
	c.tokenMutex.Unlock()
}

func (c *client) loginWithLock() error {
	loginURL := fmt.Sprintf("%s/api/auth/login", c.url)
	payload, _ := json.Marshal(map[string]string{
		"username": c.username,
		"password": c.password,
	})

	req, err := http.NewRequest(http.MethodPost, loginURL, bytes.NewBuffer(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Referer", c.url)

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("login failed with status: %d", resp.StatusCode)
	}

	// Capture CSRF token for subsequent requests
	c.csrfToken = resp.Header.Get("X-CSRF-Token")

	log.Debug("Successfully logged in to UniFi controller")

	return nil
}

func (c *client) SetPoeMode(switchMAC string, portIdx int, on bool) error {
	// 1. Ensure we are logged in
	if err := c.ensureLoggedIn(); err != nil {
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
	req.Header.Set("X-CSRF-Token", c.csrfToken)
	req.Header.Set("Referer", c.url)

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode == http.StatusUnauthorized {
		// Session might have expired, clear token and retry once
		c.setToken("")
		err = c.ensureLoggedIn()
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
	err := c.ensureLoggedIn()
	if err != nil {
		return nil, err
	}

	// First request attempt
	devices, err := c.doGetAllDevices(c.getApiPrefix())
	if err == nil {
		return devices, nil
	}

	// If 401 Unauthorized, session might have expired
	if err.Error() == "401" {
		c.setToken("")
		err = c.ensureLoggedIn()
		if err != nil {
			return nil, err
		}
		return c.doGetAllDevices("")
	}

	// If 404 and we haven't tried the prefix, try with /proxy/network
	if err.Error() == "404" {
		devices, err = c.doGetAllDevices(proxyPrefix)
		if err == nil {
			c.setApiPrefix(proxyPrefix)
			return devices, nil
		}
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
	req.Header.Set("X-CSRF-Token", c.csrfToken)
	req.Header.Set("Referer", c.url)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("401")
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("404")
	}

	if resp.StatusCode != http.StatusOK {
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
	c.apiPrefix = prefix
	c.apiPrefixMutex.Unlock()
}
