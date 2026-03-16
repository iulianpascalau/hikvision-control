package hikvision

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClient_GetChannelConfig(t *testing.T) {
	t.Parallel()

	// Create a mock HTTP server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/ISAPI/ContentMgmt/InputProxy/channels/6", r.URL.Path)
		assert.Equal(t, http.MethodGet, r.Method)

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<InputProxyChannel><id>6</id></InputProxyChannel>`))
	}))
	defer ts.Close()

	// Extract the IP and port from the test server URL to use as our "NVR IP"
	// ts.URL looks like http://127.0.0.1:12345
	ip := ts.URL[len("http://"):]

	c := NewClient(ip, "admin", "password")
	config, err := c.GetChannelConfig("6")

	require.NoError(t, err)
	assert.Contains(t, string(config), "<id>6</id>")
}

func TestClient_GetChannelConfig_Error(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("Unauthorized"))
	}))
	defer ts.Close()

	ip := ts.URL[len("http://"):]
	c := NewClient(ip, "admin", "password")

	config, err := c.GetChannelConfig("6")
	require.Error(t, err)
	assert.Nil(t, config)
	assert.Contains(t, err.Error(), "unexpected status code: 401")
}

func TestClient_UpdateChannelConfig(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/ISAPI/ContentMgmt/InputProxy/channels/2", r.URL.Path)
		assert.Equal(t, http.MethodPut, r.Method)
		assert.Equal(t, "application/xml", r.Header.Get("Content-Type"))

		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	ip := ts.URL[len("http://"):]
	c := NewClient(ip, "admin", "password")

	payload := []byte(`<InputProxyChannel><ipAddress>1.2.3.4</ipAddress></InputProxyChannel>`)
	err := c.UpdateChannelConfig("2", payload)

	require.NoError(t, err)
}

func TestClient_UpdateChannelConfig_Error(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("Bad Request"))
	}))
	defer ts.Close()

	ip := ts.URL[len("http://"):]
	c := NewClient(ip, "admin", "password")

	err := c.UpdateChannelConfig("2", []byte("<invalid></invalid>"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected status code: 400")
}
