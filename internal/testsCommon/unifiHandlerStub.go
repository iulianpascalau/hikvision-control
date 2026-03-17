package testsCommon

import (
	"unifi-control/internal/common"
)

type UnifiHandlerStub struct {
	LoginHandler         func() error
	SetPoeModeHandler    func(switchMAC string, portIdx int, on bool) error
	IsPoeOnHandler       func(switchMAC string, portIdx int) (bool, error)
	GetDeviceInfoHandler func(mac string) (*common.UnifiDeviceData, error)
	GetAllDevicesHandler func() ([]common.UnifiDeviceData, error)
}

func (stub *UnifiHandlerStub) Login() error {
	if stub.LoginHandler != nil {
		return stub.LoginHandler()
	}
	return nil
}

func (stub *UnifiHandlerStub) SetPoeMode(switchMAC string, portIdx int, on bool) error {
	if stub.SetPoeModeHandler != nil {
		return stub.SetPoeModeHandler(switchMAC, portIdx, on)
	}
	return nil
}

func (stub *UnifiHandlerStub) IsPoeOn(switchMAC string, portIdx int) (bool, error) {
	if stub.IsPoeOnHandler != nil {
		return stub.IsPoeOnHandler(switchMAC, portIdx)
	}
	return false, nil
}

func (stub *UnifiHandlerStub) GetDeviceInfo(mac string) (*common.UnifiDeviceData, error) {
	if stub.GetDeviceInfoHandler != nil {
		return stub.GetDeviceInfoHandler(mac)
	}
	return &common.UnifiDeviceData{}, nil
}

func (stub *UnifiHandlerStub) GetAllDevices() ([]common.UnifiDeviceData, error) {
	if stub.GetAllDevicesHandler != nil {
		return stub.GetAllDevicesHandler()
	}
	return []common.UnifiDeviceData{}, nil
}
