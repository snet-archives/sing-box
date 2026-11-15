package option

import "github.com/sagernet/sing/common/json/badoption"

type VLESSInboundOptions struct {
	ListenOptions
	Users []VLESSUser `json:"users,omitempty"`
	InboundTLSOptionsContainer
	Decryption *VLESSDecryptionOptions  `json:"decryption,omitempty"`
	Multiplex  *InboundMultiplexOptions `json:"multiplex,omitempty"`
	Transport  *V2RayTransportOptions   `json:"transport,omitempty"`
	Masquerade *Hysteria2Masquerade     `json:"masquerade,omitempty"`
}

type VLESSUser struct {
	Name        string   `json:"name,omitempty"`
	UUID        string   `json:"uuid"`
	Flow        string   `json:"flow,omitempty"`
	PaddingSeed []uint32 `json:"padding_seed,omitempty"`
}

type VLESSOutboundOptions struct {
	DialerOptions
	ServerOptions
	UUID    string      `json:"uuid"`
	Flow    string      `json:"flow,omitempty"`
	Network NetworkList `json:"network,omitempty"`
	OutboundTLSOptionsContainer
	Encryption     *VLESSEncryptionOptions   `json:"encryption,omitempty"`
	Multiplex      *OutboundMultiplexOptions `json:"multiplex,omitempty"`
	Transport      *V2RayTransportOptions    `json:"transport,omitempty"`
	PacketEncoding *string                   `json:"packet_encoding,omitempty"`
	PaddingSeed    []uint32                  `json:"padding_seed,omitempty"`
}

type VLESSDecryptionOptions struct {
	Enabled       bool               `json:"enabled,omitempty"`
	PrivateKey    string             `json:"private_key,omitempty"`
	MLKEM768Seed  string             `json:"mlkem768_seed,omitempty"`
	TicketSecret  string             `json:"ticket_secret,omitempty"`
	XorMode       string             `json:"xor_mode,omitempty" enum:"none,xor,random,http"`
	XorPSK        string             `json:"xor_psk,omitempty"`
	SessionMaxAge badoption.Duration `json:"session_max_age,omitempty"`
	HTTPHost      string             `json:"http_host,omitempty"`
	HTTPPath      string             `json:"http_path,omitempty"`
}

type VLESSEncryptionOptions struct {
	Enabled          bool                 `json:"enabled,omitempty"`
	PublicKey        string               `json:"public_key,omitempty"`
	MLKEM768EncapKey string               `json:"mlkem768_encap_key,omitempty"`
	Mode             string               `json:"mode,omitempty" enum:"native,zero_rtt"`
	XorMode          string               `json:"xor_mode,omitempty" enum:"none,xor,random,http"`
	XorPSK           string               `json:"xor_psk,omitempty"`
	HTTPHost         string               `json:"http_host,omitempty"`
	HTTPPath         string               `json:"http_path,omitempty"`
	HTTPHeaders      badoption.HTTPHeader `json:"http_headers,omitempty"`
}
