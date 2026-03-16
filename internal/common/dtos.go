package common

type ChannelStatus struct {
	Name    string `json:"name"`
	Channel string `json:"channel"`
	Active  bool   `json:"status"`
	Error   string `json:"error"`
}
