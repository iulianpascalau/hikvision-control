package hikvision

import (
	"bytes"
	"fmt"
	"io"
	"net/http"

	"github.com/icholy/digest"
)

type client struct {
	ip   string
	http *http.Client
}

// NewClient creates a new Hikvision Client
func NewClient(ip, username, password string) *client {
	return &client{
		ip: ip,
		http: &http.Client{
			Transport: &digest.Transport{
				Username: username,
				Password: password,
			},
		},
	}
}

func (c *client) GetChannelConfig(channel string) ([]byte, error) {
	url := fmt.Sprintf("http://%s/ISAPI/ContentMgmt/InputProxy/channels/%s", c.ip, channel)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	return io.ReadAll(resp.Body)
}

func (c *client) UpdateChannelConfig(channel string, payload []byte) error {
	url := fmt.Sprintf("http://%s/ISAPI/ContentMgmt/InputProxy/channels/%s", c.ip, channel)
	req, err := http.NewRequest(http.MethodPut, url, bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/xml")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("executing request: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}
