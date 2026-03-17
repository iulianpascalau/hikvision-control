package unifi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"unifi-control/internal/common"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClient_Login(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/auth/login", r.URL.Path)
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.NotEmpty(t, r.Header.Get("Referer"))

		var payload map[string]string
		err := json.NewDecoder(r.Body).Decode(&payload)
		require.NoError(t, err)
		assert.Equal(t, "user", payload["username"])
		assert.Equal(t, "pass", payload["password"])

		w.Header().Set("X-CSRF-Token", "fake-token")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	client := NewClient(ts.URL, "user", "pass", "default")
	err := client.Login()
	assert.NoError(t, err)
	assert.Equal(t, "fake-token", client.csrfToken)
}

func TestClient_GetDeviceInfo(t *testing.T) {
	t.Parallel()

	mac := "aa:bb:cc:dd:ee:ff"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/s/default/stat/device", r.URL.Path)
		assert.NotEmpty(t, r.Header.Get("Referer"))
		assert.Equal(t, "fake-token", r.Header.Get("X-CSRF-Token"))

		response := common.UnifiDeviceResponse{
			Data: []common.UnifiDeviceData{
				{
					MAC:      mac,
					DeviceID: "device123",
					PortOverrides: []map[string]interface{}{
						{"port_idx": float64(1), "poe_mode": "auto"},
					},
					PortTable: []common.UnifiPortStatus{
						{PortIdx: 1, PoeMode: "auto"},
					},
				},
			},
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer ts.Close()

	client := NewClient(ts.URL, "user", "pass", "default")
	client.csrfToken = "fake-token"
	info, err := client.GetDeviceInfo(mac)
	assert.NoError(t, err)
	assert.Equal(t, mac, info.MAC)
	assert.Equal(t, "device123", info.DeviceID)
	assert.Len(t, info.PortOverrides, 1)
	assert.Equal(t, "auto", info.PortOverrides[0]["poe_mode"])
}

func TestClient_SetPoeMode(t *testing.T) {
	t.Parallel()

	mac := "aa:bb:cc:dd:ee:ff"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/login":
			w.Header().Set("X-CSRF-Token", "fake-token")
			w.WriteHeader(http.StatusOK)
		case "/api/s/default/stat/device":
			assert.NotEmpty(t, r.Header.Get("Referer"))
			assert.Equal(t, "fake-token", r.Header.Get("X-CSRF-Token"))
			response := common.UnifiDeviceResponse{
				Data: []common.UnifiDeviceData{
					{
						MAC:           mac,
						DeviceID:      "device123",
						PortOverrides: []map[string]interface{}{},
					},
				},
			}
			_ = json.NewEncoder(w).Encode(response)
		case "/api/s/default/rest/device/device123":
			assert.Equal(t, http.MethodPut, r.Method)
			assert.Equal(t, "fake-token", r.Header.Get("X-CSRF-Token"))
			assert.NotEmpty(t, r.Header.Get("Referer"))
			var payload map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&payload)
			overrides := payload["port_overrides"].([]interface{})
			assert.Len(t, overrides, 1)
			override := overrides[0].(map[string]interface{})
			assert.Equal(t, float64(1), override["port_idx"])
			assert.Equal(t, "off", override["poe_mode"])
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer ts.Close()

	client := NewClient(ts.URL, "user", "pass", "default")
	err := client.SetPoeMode(mac, 1, false)
	assert.NoError(t, err)
}

func TestClient_IsPoeOn(t *testing.T) {
	t.Parallel()

	mac := "aa:bb:cc:dd:ee:ff"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/auth/login":
			w.Header().Set("X-CSRF-Token", "fake-token")
			w.WriteHeader(http.StatusOK)
		case "/api/s/default/stat/device":
			assert.NotEmpty(t, r.Header.Get("Referer"))
			assert.Equal(t, "fake-token", r.Header.Get("X-CSRF-Token"))
			response := common.UnifiDeviceResponse{
				Data: []common.UnifiDeviceData{
					{
						MAC:      mac,
						DeviceID: "device123",
						PortTable: []common.UnifiPortStatus{
							{PortIdx: 1, PoeMode: "auto"},
							{PortIdx: 2, PoeMode: "off"},
						},
					},
				},
			}
			_ = json.NewEncoder(w).Encode(response)
		}
	}))
	defer ts.Close()

	client := NewClient(ts.URL, "user", "pass", "default")

	on, err := client.IsPoeOn(mac, 1)
	assert.NoError(t, err)
	assert.True(t, on)

	on, err = client.IsPoeOn(mac, 2)
	assert.NoError(t, err)
	assert.False(t, on)
}
