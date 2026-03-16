package testsCommon

type HikvisionHandlerStub struct {
	GetChannelConfigHandler    func(channel string) ([]byte, error)
	UpdateChannelConfigHandler func(channel string, payload []byte) error
}

func (stub *HikvisionHandlerStub) GetChannelConfig(channel string) ([]byte, error) {
	if stub.GetChannelConfigHandler != nil {
		return stub.GetChannelConfigHandler(channel)
	}

	return make([]byte, 0), nil
}

func (stub *HikvisionHandlerStub) UpdateChannelConfig(channel string, payload []byte) error {
	if stub.UpdateChannelConfigHandler != nil {
		return stub.UpdateChannelConfigHandler(channel, payload)
	}

	return nil
}
