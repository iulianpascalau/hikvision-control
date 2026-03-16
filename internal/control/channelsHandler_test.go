package control

import (
	"errors"
	"fmt"
	"testing"

	"hikvision-control/internal/common"
	"hikvision-control/internal/config"
	"hikvision-control/internal/testsCommon"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func getMockConfig() config.Config {
	return config.Config{
		Channels: []config.ChannelConfig{
			{
				Channel:      "6",
				OkIPAddress:  "192.0.2.1",
				NOKIPAddress: "192.1.2.1",
			},
		},
	}
}

func getMockResponse(channel string, name string, ip string) []byte {
	return []byte(fmt.Sprintf(`
<?xml version="1.0" encoding="UTF-8" ?>
<InputProxyChannel version="1.0" xmlns="http://www.hikvision.com/ver20/XMLSchema">
  <id>%s</id>
  <name>%s</name>
  <sourceInputPortDescriptor>
  <proxyProtocol>HIKVISION</proxyProtocol>
  <addressingFormatType>ipaddress</addressingFormatType>
  <ipAddress>%s</ipAddress>
  <managePortNo>8000</managePortNo>
  <srcInputPort>1</srcInputPort>
  <userName>admin</userName>
  <streamType>auto</streamType>
  <model>DS-2CD2T63G0-I5</model>
  <serialNumber>DS-2CD2T63G0-AABBCC</serialNumber>
  <firmwareVersion>V1.0.0 build 123456</firmwareVersion>
  <deviceID></deviceID>
  </sourceInputPortDescriptor>
  <enableAnr>false</enableAnr>
  <enableTiming>true</enableTiming>
  <devIndex>11111111-2222-3333-4444-555555555555</devIndex>
  <twoWayAudioChannelIDList>
    <twoWayAudioChannelID>6001</twoWayAudioChannelID>
  </twoWayAudioChannelIDList>
</InputProxyChannel>
`, channel, name, ip))
}

func getErrorResponse() error {
	return errors.New(`
unexpected status code: 401, body: <!DOCTYPE html>
<head>
    <title>Unauthorized</title>
    <link rel="shortcut icon" href="data:image/x-icon;," type="image/x-icon">
</head>
<body>
<h2>Access Error: 401 -- Unauthorized</h2>
<pre></pre>
</body>
</html>
`)
}

func TestNewChannelsHandler(t *testing.T) {
	t.Parallel()

	t.Run("no channels should not error", func(t *testing.T) {
		cfg := config.Config{}
		hikHandler := &testsCommon.HikvisionHandlerStub{}
		handler, err := NewChannelsHandler(cfg, hikHandler)
		require.NoError(t, err)
		assert.NotNil(t, handler)
	})
	t.Run("2 channels with the same channel value should error", func(t *testing.T) {
		cfg := config.Config{
			Channels: []config.ChannelConfig{
				{
					Channel: "1",
				},
				{
					Channel: "1",
				},
			},
		}
		hikHandler := &testsCommon.HikvisionHandlerStub{}
		handler, err := NewChannelsHandler(cfg, hikHandler)
		require.Error(t, err)
		require.Equal(t, "channel 1 was defined more than once", err.Error())
		assert.Nil(t, handler)
	})
	t.Run("nil hikvision handler should error", func(t *testing.T) {
		cfg := config.Config{}
		handler, err := NewChannelsHandler(cfg, nil)
		require.Error(t, err)
		require.Equal(t, "hikvision handler is nil", err.Error())
		assert.Nil(t, handler)
	})
	t.Run("should work", func(t *testing.T) {
		cfg := config.Config{
			Channels: []config.ChannelConfig{
				{
					Channel: "1",
				},
				{
					Channel: "2",
				},
			},
		}
		hikHandler := &testsCommon.HikvisionHandlerStub{}
		handler, err := NewChannelsHandler(cfg, hikHandler)
		require.NoError(t, err)
		assert.NotNil(t, handler)

		assert.Equal(t, []string{"1", "2"}, handler.GetChannels())
	})

}

func TestChannelsHandler_GetChannel(t *testing.T) {
	t.Parallel()

	t.Run("channel not found", func(t *testing.T) {
		hikHandler := &testsCommon.HikvisionHandlerStub{
			GetChannelConfigHandler: func(channel string) ([]byte, error) {
				require.Fail(t, "should not be called")
				return nil, nil
			},
		}
		handler, err := NewChannelsHandler(getMockConfig(), hikHandler)
		require.NoError(t, err)

		status := handler.GetChannel("7")
		expectedStatus := common.ChannelStatus{
			Name:    unknownName,
			Channel: "7",
			Active:  false,
			Error:   "channel 7 not found",
		}

		assert.Equal(t, expectedStatus, status)
	})
	t.Run("get channel errors", func(t *testing.T) {
		hikHandler := &testsCommon.HikvisionHandlerStub{
			GetChannelConfigHandler: func(channel string) ([]byte, error) {
				require.Equal(t, "6", channel)
				return nil, getErrorResponse()
			},
		}
		handler, err := NewChannelsHandler(getMockConfig(), hikHandler)
		require.NoError(t, err)

		status := handler.GetChannel("6")
		expectedStatus := common.ChannelStatus{
			Name:    unknownName,
			Channel: "6",
			Active:  false,
			Error:   getErrorResponse().Error(),
		}

		assert.Equal(t, expectedStatus, status)
	})
	t.Run("channel active", func(t *testing.T) {
		hikHandler := &testsCommon.HikvisionHandlerStub{
			GetChannelConfigHandler: func(channel string) ([]byte, error) {
				require.Equal(t, "6", channel)
				return getMockResponse(channel, "inside", "192.0.2.1"), nil
			},
		}
		handler, err := NewChannelsHandler(getMockConfig(), hikHandler)
		require.NoError(t, err)

		status := handler.GetChannel("6")
		expectedStatus := common.ChannelStatus{
			Name:    "inside",
			Channel: "6",
			Active:  true,
			Error:   "",
		}

		assert.Equal(t, expectedStatus, status)
	})
	t.Run("channel not active", func(t *testing.T) {
		hikHandler := &testsCommon.HikvisionHandlerStub{
			GetChannelConfigHandler: func(channel string) ([]byte, error) {
				require.Equal(t, "6", channel)
				return getMockResponse(channel, "inside", "192.0.0.1"), nil
			},
		}
		handler, err := NewChannelsHandler(getMockConfig(), hikHandler)
		require.NoError(t, err)

		status := handler.GetChannel("6")
		expectedStatus := common.ChannelStatus{
			Name:    "inside",
			Channel: "6",
			Active:  false,
			Error:   "",
		}

		assert.Equal(t, expectedStatus, status)
	})
}

func TestChannelsHandler_UpdateChannel(t *testing.T) {
	t.Parallel()

	expectedErr := errors.New("expected error")
	t.Run("channel not found", func(t *testing.T) {
		hikHandler := &testsCommon.HikvisionHandlerStub{
			GetChannelConfigHandler: func(channel string) ([]byte, error) {
				require.Fail(t, "should not be called")
				return nil, nil
			},
			UpdateChannelConfigHandler: func(channel string, payload []byte) error {
				require.Fail(t, "should not be called")
				return nil
			},
		}
		handler, err := NewChannelsHandler(getMockConfig(), hikHandler)
		require.NoError(t, err)

		err = handler.Set("7", true)
		assert.Error(t, err)
		assert.Equal(t, "channel 7 not found", err.Error())
	})
	t.Run("get channel config errors", func(t *testing.T) {
		hikHandler := &testsCommon.HikvisionHandlerStub{
			GetChannelConfigHandler: func(channel string) ([]byte, error) {
				return nil, expectedErr
			},
			UpdateChannelConfigHandler: func(channel string, payload []byte) error {
				require.Fail(t, "should not be called")
				return nil
			},
		}
		handler, err := NewChannelsHandler(getMockConfig(), hikHandler)
		require.NoError(t, err)

		err = handler.Set("6", true)
		assert.Equal(t, expectedErr, err)
	})
	t.Run("should set (true)", func(t *testing.T) {
		hikHandler := &testsCommon.HikvisionHandlerStub{
			GetChannelConfigHandler: func(channel string) ([]byte, error) {
				return getMockResponse(channel, "inside", "192.0.0.0"), nil
			},
			UpdateChannelConfigHandler: func(channel string, payload []byte) error {
				assert.Contains(t, string(payload), "192.0.2.1")
				return nil
			},
		}
		handler, err := NewChannelsHandler(getMockConfig(), hikHandler)
		require.NoError(t, err)

		err = handler.Set("6", true)
		assert.Nil(t, err)
	})
	t.Run("should set (false)", func(t *testing.T) {
		hikHandler := &testsCommon.HikvisionHandlerStub{
			GetChannelConfigHandler: func(channel string) ([]byte, error) {
				return getMockResponse(channel, "inside", "192.0.0.0"), nil
			},
			UpdateChannelConfigHandler: func(channel string, payload []byte) error {
				assert.Contains(t, string(payload), "192.1.2.1")
				return nil
			},
		}
		handler, err := NewChannelsHandler(getMockConfig(), hikHandler)
		require.NoError(t, err)

		err = handler.Set("6", false)
		assert.Nil(t, err)
	})
}
