package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"hikvision-control/internal/common"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

var testJWTKey = []byte("test_secret_key")

// MockChannelStatusProvider is a mock implementation of the ChannelStatusProvider interface
type MockChannelStatusProvider struct {
	mock.Mock
}

func (m *MockChannelStatusProvider) GetPortIDs() []string {
	args := m.Called()
	return args.Get(0).([]string)
}

func (m *MockChannelStatusProvider) GetPort(portID string) common.PortStatus {
	args := m.Called(portID)
	return args.Get(0).(common.PortStatus)
}

func (m *MockChannelStatusProvider) Set(channel string, active bool) error {
	args := m.Called(channel, active)
	return args.Error(0)
}

func setupTestRouter(username, password string) (*API, *MockChannelStatusProvider) {
	gin.SetMode(gin.TestMode)
	mockProvider := new(MockChannelStatusProvider)
	api := NewAPI(mockProvider, username, password, testJWTKey)
	return api, mockProvider
}

func generateValidToken(username string) string {
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(expirationTime),
		Subject:   username,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString(testJWTKey)
	return tokenString
}

func TestAPI_Login(t *testing.T) {
	t.Parallel()

	api, _ := setupTestRouter("admin", "password")

	tests := []struct {
		name         string
		payload      map[string]string
		expectedCode int
	}{
		{
			name: "Valid credentials",
			payload: map[string]string{
				"username": "admin",
				"password": "password",
			},
			expectedCode: http.StatusOK,
		},
		{
			name: "Invalid password",
			payload: map[string]string{
				"username": "admin",
				"password": "wrongpassword",
			},
			expectedCode: http.StatusUnauthorized,
		},
		{
			name: "Missing credentials",
			payload: map[string]string{
				"username": "admin",
			},
			expectedCode: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jsonValue, _ := json.Marshal(tt.payload)
			req, _ := http.NewRequest(http.MethodPost, "/login", bytes.NewBuffer(jsonValue))
			req.Header.Set("Content-Type", "application/json")

			w := httptest.NewRecorder()
			api.router.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedCode, w.Code)

			if tt.expectedCode == http.StatusOK {
				var response map[string]string
				err := json.Unmarshal(w.Body.Bytes(), &response)
				assert.NoError(t, err)
				assert.NotEmpty(t, response["token"])
			}
		})
	}
}

func TestAPI_ProtectedRoutes_Auth(t *testing.T) {
	t.Parallel()

	api, _ := setupTestRouter("admin", "password")

	req, _ := http.NewRequest(http.MethodGet, "/api/channels", nil)
	w := httptest.NewRecorder()
	api.router.ServeHTTP(w, req)

	// Missing token
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	// Invalid token
	req, _ = http.NewRequest(http.MethodGet, "/api/channels", nil)
	req.Header.Set("Authorization", "Bearer invalidtoken")
	w = httptest.NewRecorder()
	api.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAPI_GetChannels(t *testing.T) {
	t.Parallel()

	api, mockProvider := setupTestRouter("admin", "password")

	mockProvider.On("GetPortIDs").Return([]string{"1", "2"})

	token := generateValidToken("admin")
	req, _ := http.NewRequest(http.MethodGet, "/api/channels", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	api.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response []string
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.ElementsMatch(t, []string{"1", "2"}, response)
	mockProvider.AssertExpectations(t)
}

func TestAPI_GetChannelStatus(t *testing.T) {
	t.Parallel()

	api, mockProvider := setupTestRouter("admin", "password")
	token := generateValidToken("admin")

	// Success case
	mockProvider.On("GetPort", "3").Return(common.PortStatus{
		Name:   "Garden",
		PortID: "3",
		Active: true,
		Error:  "",
	})

	req, _ := http.NewRequest(http.MethodGet, "/api/channels/3", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	api.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var successResp common.PortStatus
	err := json.Unmarshal(w.Body.Bytes(), &successResp)
	assert.NoError(t, err)
	assert.Equal(t, "Garden", successResp.Name)
	assert.Equal(t, true, successResp.Active)

	// Not found case
	mockProvider.On("GetPort", "99").Return(common.PortStatus{
		PortID: "99",
		Name:   "unknown",
		Error:  fmt.Sprintf("port id %s not found", "99"),
	})

	req2, _ := http.NewRequest(http.MethodGet, "/api/channels/99", nil)
	req2.Header.Set("Authorization", "Bearer "+token)
	w2 := httptest.NewRecorder()
	api.router.ServeHTTP(w2, req2)

	assert.Equal(t, http.StatusNotFound, w2.Code)

	mockProvider.AssertExpectations(t)
}

func TestAPI_SetChannelStatus(t *testing.T) {
	t.Parallel()

	api, mockProvider := setupTestRouter("admin", "password")
	token := generateValidToken("admin")

	// Success case
	mockProvider.On("Set", "1", false).Return(nil)

	payload := map[string]interface{}{"active": false}
	jsonValue, _ := json.Marshal(payload)
	req, _ := http.NewRequest(http.MethodPost, "/api/channels/1", bytes.NewBuffer(jsonValue))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	api.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Error case
	mockProvider.On("Set", "2", true).Return(errors.New("API error"))

	payload2 := map[string]interface{}{"active": true}
	jsonValue2, _ := json.Marshal(payload2)
	req2, _ := http.NewRequest(http.MethodPost, "/api/channels/2", bytes.NewBuffer(jsonValue2))
	req2.Header.Set("Authorization", "Bearer "+token)
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	api.router.ServeHTTP(w2, req2)

	assert.Equal(t, http.StatusInternalServerError, w2.Code)

	mockProvider.AssertExpectations(t)
}
