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
)

const reLoginDelay = 10 * time.Second

type httpClientWithLogin struct {
	httpClient *http.Client
	url        string
	username   string
	password   string

	criticalSection sync.Mutex
	csrfToken       string
	lastLogin       time.Time
}

func newHTTPClientWithLogin(url string, username string, password string) *httpClientWithLogin {
	jar, _ := cookiejar.New(nil)
	return &httpClientWithLogin{
		url:       url,
		username:  username,
		password:  password,
		csrfToken: "",
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
			Jar:     jar,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
	}
}

func (client *httpClientWithLogin) EnsureLoggedIn() error {
	client.criticalSection.Lock()
	defer client.criticalSection.Unlock()

	if client.csrfToken != "" {
		return nil
	}

	return client.loginNoLock()
}

func (client *httpClientWithLogin) Login() error {
	client.criticalSection.Lock()
	defer client.criticalSection.Unlock()

	if time.Since(client.lastLogin) < reLoginDelay {
		// Do not attempt a fast re-login
		return nil
	}

	return client.loginNoLock()
}

func (client *httpClientWithLogin) loginNoLock() error {
	// Wiping the cookie jar ensures we don't have stale/tainted session cookies
	jar, _ := cookiejar.New(nil)
	client.httpClient.Jar = jar
	client.csrfToken = ""

	loginURL := fmt.Sprintf("%s/api/auth/login", client.url)
	payload, _ := json.Marshal(map[string]string{
		"username": client.username,
		"password": client.password,
	})

	req, err := http.NewRequest(http.MethodPost, loginURL, bytes.NewBuffer(payload))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Referer", client.url)

	resp, err := client.httpClient.Do(req)
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
	client.csrfToken = resp.Header.Get("X-CSRF-Token")
	client.lastLogin = time.Now()

	log.Debug("Successfully logged in to UniFi controller")

	return nil
}

func (client *httpClientWithLogin) Do(req *http.Request) (*http.Response, error) {
	req.Header.Set("X-CSRF-Token", client.csrfToken)
	req.Header.Set("Referer", client.url)

	return client.httpClient.Do(req)
}
