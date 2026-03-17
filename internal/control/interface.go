package control

import "unifi-control/internal/common"

type UnifiHandler interface {
	Login() error
	SetPoeMode(switchMAC string, portIdx int, on bool) error
	IsPoeOn(switchMAC string, portIdx int) (bool, error)
	GetDeviceInfo(mac string) (*common.UnifiDeviceData, error)
	GetAllDevices() ([]common.UnifiDeviceData, error)
}
