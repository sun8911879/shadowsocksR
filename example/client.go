package main

import (
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/sun8911879/shadowsocksR"
	"github.com/sun8911879/shadowsocksR/tools/leakybuf"
	"github.com/sun8911879/shadowsocksR/tools/socks"
)

var (
	readTimeout = 600 * time.Second
)

// SSInfo fields that shadowsocks/shadowsocksr used only
type SSInfo struct {
	SSRInfo
	EncryptMethod   string
	EncryptPassword string
}

// SSRInfo fields that shadowsocksr used only
type SSRInfo struct {
	Obfs          string
	ObfsParam     string
	ObfsData      interface{}
	Protocol      string
	ProtocolParam string
	ProtocolData  interface{}
}

// BackendInfo all fields that a backend used
type BackendInfo struct {
	SSInfo
	Address string
	Type    string
}

func main() {
	bi := &BackendInfo{
		Address: "www.domain.com:445",
		Type:    "ssr",
		SSInfo: SSInfo{
			EncryptMethod:   "aes-128-cfb",
			EncryptPassword: "password",
			SSRInfo: SSRInfo{
				Protocol:      "auth_aes128_sha1",
				ProtocolParam: "",
				Obfs:          "tls1.2_ticket_auth",
				ObfsParam:     "",
			},
		},
	}
	bi.Listen()
}

func (bi *BackendInfo) Listen() {
	listener, err := net.Listen("tcp", "0.0.0.0:2515")
	if err != nil {
		panic(err)
	}
	for {
		localConn, err := listener.Accept()
		if err != nil {
			continue
		}
		go bi.Handle(localConn)
	}
}

func (bi *BackendInfo) Handle(src net.Conn) {
	//直接访问google
	rawaddr := socks.ParseAddr("www.google.com.hk:443")

	dst, err := bi.DialSSRConn(rawaddr)
	if err != nil {
		panic(err)
	}
	go bi.Pipe(src, dst)
	bi.Pipe(dst, src)
	src.Close()
	dst.Close()
}

func (bi *BackendInfo) DialSSRConn(rawaddr socks.Addr) (net.Conn, error) {
	u := &url.URL{
		Scheme: bi.Type,
		Host:   bi.Address,
	}
	v := u.Query()
	v.Set("encrypt-method", bi.EncryptMethod)
	v.Set("encrypt-key", bi.EncryptPassword)
	v.Set("obfs", bi.Obfs)
	v.Set("obfs-param", bi.ObfsParam)
	v.Set("protocol", bi.Protocol)
	v.Set("protocol-param", bi.ProtocolParam)
	u.RawQuery = v.Encode()

	ssrconn, err := shadowsocksr.NewSSRClient(u)
	if err != nil {
		return nil, fmt.Errorf("connecting to SSR server failed :%v", err)
	}

	if bi.ObfsData == nil {
		bi.ObfsData = ssrconn.IObfs.GetData()
	}
	ssrconn.IObfs.SetData(bi.ObfsData)

	if bi.ProtocolData == nil {
		bi.ProtocolData = ssrconn.IProtocol.GetData()
	}
	ssrconn.IProtocol.SetData(bi.ProtocolData)

	if _, err := ssrconn.Write(rawaddr); err != nil {
		ssrconn.Close()
		return nil, err
	}
	return ssrconn, nil
}

// PipeThenClose copies data from src to dst, closes dst when done.
func (bi *BackendInfo) Pipe(src, dst net.Conn) error {
	buf := leakybuf.GlobalLeakyBuf.Get()
	for {
		src.SetReadDeadline(time.Now().Add(readTimeout))
		n, err := src.Read(buf)
		// read may return EOF with n > 0
		// should always process n > 0 bytes before handling error
		if n > 0 {
			// Note: avoid overwrite err returned by Read.
			if _, err := dst.Write(buf[0:n]); err != nil {
				break
			}
		}
		if err != nil {
			// Always "use of closed network connection", but no easy way to
			// identify this specific error. So just leave the error along for now.
			// More info here: https://code.google.com/p/go/issues/detail?id=4373
			break
		}
	}
	leakybuf.GlobalLeakyBuf.Put(buf)
	dst.Close()
	return nil
}
