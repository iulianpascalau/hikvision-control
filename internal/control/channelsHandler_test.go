package control

import (
	"testing"

	"unifi-control/internal/common"
	"unifi-control/internal/config"
	"unifi-control/internal/testsCommon"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewChannelsHandler(t *testing.T) {
	t.Parallel()

	t.Run("nil unifi handler should error", func(t *testing.T) {
		cfg := config.Config{}
		handler, err := NewChannelsHandler(cfg, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unifi handler is nil")
		assert.Nil(t, handler)
	})
	t.Run("no ports should not error", func(t *testing.T) {
		cfg := config.Config{}
		handler, err := NewChannelsHandler(cfg, &testsCommon.UnifiHandlerStub{})
		require.NoError(t, err)
		assert.NotNil(t, handler)
	})
	t.Run("should work with ports", func(t *testing.T) {
		cfg := config.Config{
			Ports: []config.PortConfig{
				{
					Name:       "Port 1",
					SwitchMAC:  "mac1",
					SwitchPort: 1,
				},
				{
					Name:       "Port 2",
					SwitchMAC:  "mac1",
					SwitchPort: 2,
				},
			},
		}
		handler, err := NewChannelsHandler(cfg, &testsCommon.UnifiHandlerStub{})
		require.NoError(t, err)
		assert.NotNil(t, handler)

		assert.Equal(t, []string{"0", "1"}, handler.GetPortIDs())
	})
}

func TestChannelsHandler_SetChannel(t *testing.T) {
	t.Parallel()

	t.Run("port not found should error", func(t *testing.T) {
		cfg := config.Config{
			Ports: []config.PortConfig{
				{
					Name:       "Port 1",
					SwitchMAC:  "mac1",
					SwitchPort: 1,
				},
			},
		}
		handler, _ := NewChannelsHandler(cfg, &testsCommon.UnifiHandlerStub{})

		err := handler.Set("missing", true)
		require.Error(t, err)
		require.Contains(t, err.Error(), "port missing not found")
	})
	t.Run("should work", func(t *testing.T) {
		cfg := config.Config{
			Ports: []config.PortConfig{
				{
					Name:       "Port 1",
					SwitchMAC:  "mac1",
					SwitchPort: 1,
				},
			},
		}
		setWasCalled := false
		handler, _ := NewChannelsHandler(cfg, &testsCommon.UnifiHandlerStub{
			SetPoeModeHandler: func(switchMAC string, portIdx int, on bool) error {
				require.Equal(t, "mac1", switchMAC)
				require.Equal(t, 1, portIdx)
				require.True(t, on)
				setWasCalled = true
				return nil
			},
		})

		err := handler.Set("0", true)
		require.Nil(t, err)
		assert.True(t, setWasCalled)
	})
}

func TestChannelsHandler_GetPort(t *testing.T) {
	t.Parallel()

	t.Run("port not found should error", func(t *testing.T) {
		cfg := config.Config{
			Ports: []config.PortConfig{
				{
					Name:       "Port 1",
					SwitchMAC:  "mac1",
					SwitchPort: 1,
				},
			},
		}
		handler, _ := NewChannelsHandler(cfg, &testsCommon.UnifiHandlerStub{})

		expectedStatus := common.PortStatus{
			Name:   unknownName,
			PortID: "missing",
			Active: false,
			Error:  "port id missing not found",
		}

		status := handler.GetPort("missing")
		assert.Equal(t, expectedStatus, status)
	})
	t.Run("should work", func(t *testing.T) {
		cfg := config.Config{
			Ports: []config.PortConfig{
				{
					Name:       "Port 1",
					SwitchMAC:  "mac1",
					SwitchPort: 1,
				},
			},
		}
		handler, _ := NewChannelsHandler(cfg, &testsCommon.UnifiHandlerStub{
			GetDeviceInfoHandler: func(mac string) (*common.UnifiDeviceData, error) {
				return &common.UnifiDeviceData{
					MAC: mac,
					PortTable: []common.UnifiPortStatus{
						{
							PortIdx:  1,
							PoeMode:  "auto",
							PoePower: "5.0",
						},
					},
				}, nil
			},
		})

		expectedStatus := common.PortStatus{
			Name:     "Port 1",
			PortID:   "0",
			Active:   true,
			PoePower: "5.0",
			Error:    "",
		}

		status := handler.GetPort("0")
		assert.Equal(t, expectedStatus, status)
	})
}
