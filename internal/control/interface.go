package control

type HikvisionHandler interface {
	GetChannelConfig(channel string) ([]byte, error)
	UpdateChannelConfig(channel string, payload []byte) error
}
