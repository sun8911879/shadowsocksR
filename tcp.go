package shadowsocksr

import (
	"bytes"
	"fmt"
	"net"
	"sync"

	"github.com/sun8911879/shadowsocksR/obfs"
	"github.com/sun8911879/shadowsocksR/protocol"
	"github.com/sun8911879/shadowsocksR/tools/leakybuf"
)

// SSTCPConn the struct that override the net.Conn methods
type SSTCPConn struct {
	net.Conn
	sync.RWMutex
	*StreamCipher
	IObfs         obfs.IObfs
	IProtocol     protocol.IProtocol
	readBuf       []byte
	readDecodeBuf *bytes.Buffer
	readIndex     uint64
	readUserBuf   *bytes.Buffer
	writeBuf      []byte
	lastReadError error
}

func NewSSTCPConn(c net.Conn, cipher *StreamCipher) *SSTCPConn {
	return &SSTCPConn{
		Conn:          c,
		StreamCipher:  cipher,
		readBuf:       leakybuf.GlobalLeakyBuf.Get(),
		readDecodeBuf: bytes.NewBuffer(nil),
		readUserBuf:   bytes.NewBuffer(nil),
		writeBuf:      leakybuf.GlobalLeakyBuf.Get(),
	}
}

func (c *SSTCPConn) Close() error {
	leakybuf.GlobalLeakyBuf.Put(c.readBuf)
	leakybuf.GlobalLeakyBuf.Put(c.writeBuf)
	return c.Conn.Close()
}

func (c *SSTCPConn) GetIv() (iv []byte) {
	iv = make([]byte, len(c.iv))
	copy(iv, c.iv)
	return
}

func (c *SSTCPConn) GetKey() (key []byte) {
	key = make([]byte, len(c.key))
	copy(key, c.key)
	return
}

func (c *SSTCPConn) initEncryptor(b []byte) (iv []byte, err error) {
	if c.enc == nil {
		iv, err = c.initEncrypt()
		if err != nil {
			return nil, err
		}

		// should initialize obfs/protocol now, because iv is ready now
		obfsServerInfo := c.IObfs.GetServerInfo()
		obfsServerInfo.SetHeadLen(b, 30)
		obfsServerInfo.IV, obfsServerInfo.IVLen = c.IV()
		obfsServerInfo.Key, obfsServerInfo.KeyLen = c.Key()
		c.IObfs.SetServerInfo(obfsServerInfo)

		protocolServerInfo := c.IProtocol.GetServerInfo()
		protocolServerInfo.SetHeadLen(b, 30)
		protocolServerInfo.IV, protocolServerInfo.IVLen = c.IV()
		protocolServerInfo.Key, protocolServerInfo.KeyLen = c.Key()
		c.IProtocol.SetServerInfo(protocolServerInfo)
	}
	return
}

func (c *SSTCPConn) Read(b []byte) (n int, err error) {
	//先吐出已经解密后数据
	if c.readUserBuf.Len() > 0 {
		return c.readUserBuf.Read(b)
	}
	//未读取够长度继续读取并解码
	decodelength := c.readDecodeBuf.Len()
	if (decodelength == 0 || (c.readIndex != 0 && c.readIndex > uint64(decodelength))) && c.lastReadError == nil {
		n, c.lastReadError = c.Conn.Read(c.readBuf)
		//写入decode 缓存
		c.readDecodeBuf.Write(c.readBuf[0:n])
	}
	//无缓冲数据返回错误
	if c.lastReadError != nil && decodelength == 0 {
		return 0, c.lastReadError
	}
	decodelength = c.readDecodeBuf.Len()
	decodebytes := c.readDecodeBuf.Bytes()
	c.readDecodeBuf.Reset()
	for {
		decodedData, length, err := c.IObfs.Decode(decodebytes)

		if length == 0 && err != nil {
			return 0, err
		}

		//do send back
		if length == 1 {
			c.Write(make([]byte, 0))
			return 0, nil
		}

		//未读取完全数据
		if err != nil && length > 5 {
			if uint64(decodelength) > length {
				return 0, fmt.Errorf("data length: %d,decode data length: %d unknown panic", decodelength, length)
			}
			c.readIndex = length
			//c.readDecodeBuf.Write(decodebytes)
			break
		}
		//完全读取数据
		if length == 0 {
			c.readDecodeBuf.Write(decodedData)
			decodebytes = decodebytes[:0]
			decodelength = len(decodebytes)
			break
		}
		c.readDecodeBuf.Write(decodedData)
		decodebytes = decodebytes[length:]
		decodelength = len(decodebytes)
		if decodelength < 5 {
			break
		}
	}
	decodedData := c.readDecodeBuf.Bytes()
	decodelength = c.readDecodeBuf.Len()
	c.readDecodeBuf.Reset()
	c.readDecodeBuf.Write(decodebytes)
	//Protocol decrypt
	if c.dec == nil {
		iv := decodedData[0:c.info.ivLen]
		if err = c.initDecrypt(iv); err != nil {
			return 0, err
		}

		if len(c.iv) == 0 {
			c.iv = iv
		}
		decodelength -= c.info.ivLen
		decodedData = decodedData[c.info.ivLen:]
	}

	buf := make([]byte, decodelength)
	c.decrypt(buf, decodedData)

	postDecryptedData, err := c.IProtocol.PostDecrypt(buf)
	if err != nil {
		return 0, err
	}
	postDecryptedlength := len(postDecryptedData)
	blength := len(b)
	copy(b, postDecryptedData)
	if blength > postDecryptedlength {
		return postDecryptedlength, nil
	}
	c.readUserBuf.Write(postDecryptedData[len(b):])
	return blength, nil
}

func (c *SSTCPConn) preWrite(b []byte) (outData []byte, err error) {
	var iv []byte
	if iv, err = c.initEncryptor(b); err != nil {
		return
	}

	var preEncryptedData []byte
	preEncryptedData, err = c.IProtocol.PreEncrypt(b)
	if err != nil {
		return
	}
	preEncryptedDataLen := len(preEncryptedData)
	//c.encrypt(cipherData[len(iv):], b)
	encryptedData := make([]byte, preEncryptedDataLen)
	//! \attention here the expected output buffer length MUST be accurate, it is preEncryptedDataLen now!
	c.encrypt(encryptedData[0:preEncryptedDataLen], preEncryptedData)

	//common.Info("len(b)=", len(b), ", b:", b,
	//	", pre encrypted data length:", preEncryptedDataLen,
	//	", pre encrypted data:", preEncryptedData,
	//	", encrypted data length:", preEncryptedDataLen)

	cipherData := c.writeBuf
	dataSize := len(encryptedData) + len(iv)
	if dataSize > len(cipherData) {
		cipherData = make([]byte, dataSize)
	} else {
		cipherData = cipherData[:dataSize]
	}

	if iv != nil {
		// Put initialization vector in buffer before be encoded
		copy(cipherData, iv)
	}
	copy(cipherData[len(iv):], encryptedData)

	return c.IObfs.Encode(cipherData)
}

func (c *SSTCPConn) Write(b []byte) (n int, err error) {
	outData, err := c.preWrite(b)
	if err == nil {
		n, err = c.Conn.Write(outData)
	}
	return
}
