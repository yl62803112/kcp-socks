package main

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"github.com/akkuman/parseConfig"
	"github.com/golang/snappy"
	"github.com/pkg/errors"
	"github.com/uk0/kcp-socks/utils"
	"github.com/uk0/kcp-socks/utils/lowSocks"
	"github.com/urfave/cli"
	"github.com/xtaci/kcp-go"
	"github.com/xtaci/smux"
	"golang.org/x/crypto/pbkdf2"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"time"
)

var KEY_DES = "key"


// Config for client
type Config struct {
	LocalAddr    string `json:"localaddr"`
	RemoteAddr   string `json:"remoteaddr"`
	Key          string `json:"key"`
	Crypt        string `json:"crypt"`
	Mode         string `json:"mode"`
	Conn         int    `json:"conn"`
	AutoExpire   int    `json:"autoexpire"`
	ScavengeTTL  int    `json:"scavengettl"`
	MTU          int    `json:"mtu"`
	SndWnd       int    `json:"sndwnd"`
	RcvWnd       int    `json:"rcvwnd"`
	DataShard    int    `json:"datashard"`
	ParityShard  int    `json:"parityshard"`
	DSCP         int    `json:"dscp"`
	NoComp       bool   `json:"nocomp"`
	AckNodelay   bool   `json:"acknodelay"`
	NoDelay      int    `json:"nodelay"`
	Interval     int    `json:"interval"`
	Resend       int    `json:"resend"`
	NoCongestion int    `json:"nc"`
	SockBuf      int    `json:"sockbuf"`
	KeepAlive    int    `json:"keepalive"`
	Log          string `json:"log"`
	SnmpLog      string `json:"snmplog"`
	SnmpPeriod   int    `json:"snmpperiod"`
	Quiet        bool   `json:"quiet"`
}

func parseJSONConfig(config *Config, path string) error {
	file, err := os.Open(path) // For read access.
	if err != nil {
		return err
	}
	defer file.Close()

	return json.NewDecoder(file).Decode(config)
}


func parseJSONConfigByte(config *Config, data []byte) error {
	r := bytes.NewReader(data)
	return json.NewDecoder(r).Decode(config)
}

var (
	// VERSION is injected by buildflags
	VERSION = "v1"
	// SALT is use for pbkdf2 key expansion
	SALT = "G"
)

type compStream struct {
	conn net.Conn
	w    *snappy.Writer
	r    *snappy.Reader
}

func (c *compStream) Read(p []byte) (n int, err error) {
	return c.r.Read(p)
}

func (c *compStream) Write(p []byte) (n int, err error) {
	n, err = c.w.Write(p)
	err = c.w.Flush()
	return n, err
}

func (c *compStream) Close() error {
	return c.conn.Close()
}

func newCompStream(conn net.Conn) *compStream {
	c := new(compStream)
	c.conn = conn
	c.w = snappy.NewBufferedWriter(conn)
	c.r = snappy.NewReader(conn)
	return c
}

func handleClient(sess *smux.Session, p1 io.ReadWriteCloser, quiet bool) {
	if !quiet {
		log.Println("open")
		defer log.Println("close")
	}

	defer p1.Close()
	p2, err := sess.OpenStream()
	if err != nil {
		return
	}
	defer p2.Close()

	// start tunnel
	p1die := make(chan struct{})
	go func() { io.Copy(p1, p2); close(p1die) }()

	p2die := make(chan struct{})
	go func() { io.Copy(p2, p1); close(p2die) }()

	// wait for tunnel termination
	select {
	case <-p1die:
	case <-p2die:
	}
}

func checkError(err error) {
	if err != nil {
		log.Printf("%+v\n", err)
		os.Exit(-1)
	}
}

func PKCS5remove2(plaintext []byte) []byte {
	length := len(plaintext)
	num := int(plaintext[length-1])
	return plaintext[:(length - num)]
}
// 解密
func DecryptMode(fileName string,inkey []byte)[]byte{
	file,err:=os.Open(fileName)
	if err!=nil{
		fmt.Println("未找到待处理文件")
		os.Exit(0)
	}
	defer file.Close()
	//读取文件内容
	plain,_:=ioutil.ReadAll(file)
	arg1:=sha256.Sum224(inkey)
	key:=arg1[:24]
	block,_:=des.NewTripleDESCipher(key)

	DecryptMode:=cipher.NewCBCDecrypter(block,key[:8])
	plain,_=base64.StdEncoding.DecodeString(string(plain))
	DecryptMode.CryptBlocks(plain,plain)
	plain=PKCS5remove2(plain)
	return []byte(plain)
}


func main() {

	//go ss_start()
	go lowSocks.StartClientSocks()
	var config = parseConfig.NewData(DecryptMode("config.json",[]byte(KEY_DES)))

	//取数组
	var urls = config.Get2("socket_to_http_proxy").([]interface{})

	for _, v := range urls {
		go utils.Start(v.([]interface{})[1].(string), v.([]interface{})[0].(string))
	}

	rand.Seed(int64(time.Now().Nanosecond()))
	if VERSION == "v1" {
		// add more log flags for debugging
		log.SetFlags(log.LstdFlags | log.Lshortfile)
	}
	myApp := cli.NewApp()
	myApp.Name = ""
	myApp.Usage = ""
	myApp.Version = VERSION
	// -r 45.32.50.108:6500 -l :6500 -mode fast2 -crypt none -datashard 10-parityshard 3 -mtu 1350 -sndwnd 512 -rcvwnd 512 -dscp 46
	myApp.Action = func(c *cli.Context) error {
		config := Config{}
		//err := parseJSONConfig(&config, "config.json")
		err := parseJSONConfigByte(&config, DecryptMode("config.json",[]byte(KEY_DES)))
		checkError(err)
		// log redirect
		if config.Log != "" {
			f, err := os.OpenFile(config.Log, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
			checkError(err)
			defer f.Close()
			log.SetOutput(f)
		}

		switch config.Mode {
		case "normal":
			config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 0, 40, 2, 1
		case "fast":
			config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 0, 30, 2, 1
		case "fast2":
			config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 1, 20, 2, 1
		case "fast3":
			config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 1, 10, 2, 1
		}

		log.Println("version:", VERSION)
		addr, err := net.ResolveTCPAddr("tcp", config.LocalAddr)
		checkError(err)
		listener, err := net.ListenTCP("tcp", addr)
		checkError(err)

		pass := pbkdf2.Key([]byte(config.Key), []byte(SALT), 4096, 32, sha1.New)
		var block kcp.BlockCrypt
		switch config.Crypt {
		case "sm4":
			block, _ = kcp.NewSM4BlockCrypt(pass[:16])
		case "tea":
			block, _ = kcp.NewTEABlockCrypt(pass[:16])
		case "xor":
			block, _ = kcp.NewSimpleXORBlockCrypt(pass)
		case "none":
			block, _ = kcp.NewNoneBlockCrypt(pass)
		case "aes-128":
			block, _ = kcp.NewAESBlockCrypt(pass[:16])
		case "aes-192":
			block, _ = kcp.NewAESBlockCrypt(pass[:24])
		case "blowfish":
			block, _ = kcp.NewBlowfishBlockCrypt(pass)
		case "twofish":
			block, _ = kcp.NewTwofishBlockCrypt(pass)
		case "cast5":
			block, _ = kcp.NewCast5BlockCrypt(pass[:16])
		case "3des":
			block, _ = kcp.NewTripleDESBlockCrypt(pass[:24])
		case "xtea":
			block, _ = kcp.NewXTEABlockCrypt(pass[:16])
		case "salsa20":
			block, _ = kcp.NewSalsa20BlockCrypt(pass)
		default:
			config.Crypt = "aes"
			block, _ = kcp.NewAESBlockCrypt(pass)
		}


		log.Println("listening on:", listener.Addr())
		log.Println("encryption:", config.Crypt)
		log.Println("nodelay parameters:", config.NoDelay, config.Interval, config.Resend, config.NoCongestion)
		log.Println("remote address:", config.RemoteAddr)
		log.Println("sndwnd:", config.SndWnd, "rcvwnd:", config.RcvWnd)
		log.Println("compression:", !config.NoComp)
		log.Println("mtu:", config.MTU)
		log.Println("datashard:", config.DataShard, "parityshard:", config.ParityShard)
		log.Println("acknodelay:", config.AckNodelay)
		log.Println("dscp:", config.DSCP)
		log.Println("sockbuf:", config.SockBuf)
		log.Println("keepalive:", config.KeepAlive)
		log.Println("conn:", config.Conn)
		log.Println("autoexpire:", config.AutoExpire)
		log.Println("scavengettl:", config.ScavengeTTL)
		log.Println("snmplog:", config.SnmpLog)
		log.Println("snmpperiod:", config.SnmpPeriod)
		log.Println("quiet:", config.Quiet)


		smuxConfig := smux.DefaultConfig()
		smuxConfig.MaxReceiveBuffer = config.SockBuf
		smuxConfig.KeepAliveInterval = time.Duration(config.KeepAlive) * time.Second

		createConn := func() (*smux.Session, error) {
			kcpconn, err := kcp.DialWithOptions(config.RemoteAddr, block, config.DataShard, config.ParityShard)
			if err != nil {
				return nil, errors.Wrap(err, "createConn()")
			}
			kcpconn.SetStreamMode(true)
			kcpconn.SetWriteDelay(true)
			kcpconn.SetNoDelay(config.NoDelay, config.Interval, config.Resend, config.NoCongestion)
			kcpconn.SetWindowSize(config.SndWnd, config.RcvWnd)
			kcpconn.SetMtu(config.MTU)
			kcpconn.SetACKNoDelay(config.AckNodelay)

			if err := kcpconn.SetDSCP(config.DSCP); err != nil {
				log.Println("SetDSCP:", err)
			}
			if err := kcpconn.SetReadBuffer(config.SockBuf); err != nil {
				log.Println("SetReadBuffer:", err)
			}
			if err := kcpconn.SetWriteBuffer(config.SockBuf); err != nil {
				log.Println("SetWriteBuffer:", err)
			}

			// stream multiplex
			var session *smux.Session
			if config.NoComp {
				session, err = smux.Client(kcpconn, smuxConfig)
			} else {
				session, err = smux.Client(newCompStream(kcpconn), smuxConfig)
			}
			if err != nil {
				return nil, errors.Wrap(err, "createConn()")
			}
			// log.Println("connection:", kcpconn.LocalAddr(), "->", kcpconn.RemoteAddr())
			return session, nil
		}

		// wait until a connection is ready
		waitConn := func() *smux.Session {
			for {
				if session, err := createConn(); err == nil {
					return session
				} else {
					log.Println("re-connecting:", err)
					time.Sleep(time.Second)
				}
			}
		}

		numconn := uint16(config.Conn)
		muxes := make([]struct {
			session *smux.Session
			ttl     time.Time
		}, numconn)

		for k := range muxes {
			muxes[k].session = waitConn()
			muxes[k].ttl = time.Now().Add(time.Duration(config.AutoExpire) * time.Second)
		}

		chScavenger := make(chan *smux.Session, 128)
		go scavenger(chScavenger, config.ScavengeTTL)
		go snmpLogger(config.SnmpLog, config.SnmpPeriod)
		rr := uint16(0)
		for {
			p1, err := listener.AcceptTCP()
			if err != nil {
				log.Fatalln(err)
			}
			checkError(err)
			idx := rr % numconn

			// do auto expiration && reconnection
			if muxes[idx].session.IsClosed() || (config.AutoExpire > 0 && time.Now().After(muxes[idx].ttl)) {
				chScavenger <- muxes[idx].session
				muxes[idx].session = waitConn()
				muxes[idx].ttl = time.Now().Add(time.Duration(config.AutoExpire) * time.Second)
			}

			go handleClient(muxes[idx].session, p1, config.Quiet)
			rr++
		}
	}
	myApp.Run(os.Args)
}

type scavengeSession struct {
	session *smux.Session
	ts      time.Time
}

func scavenger(ch chan *smux.Session, ttl int) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var sessionList []scavengeSession
	for {
		select {
		case sess := <-ch:
			sessionList = append(sessionList, scavengeSession{sess, time.Now()})
			log.Println("session marked as expired")
		case <-ticker.C:
			var newList []scavengeSession
			for k := range sessionList {
				s := sessionList[k]
				if s.session.NumStreams() == 0 || s.session.IsClosed() {
					log.Println("session normally closed")
					s.session.Close()
				} else if ttl >= 0 && time.Since(s.ts) >= time.Duration(ttl)*time.Second {
					log.Println("session reached scavenge ttl")
					s.session.Close()
				} else {
					newList = append(newList, sessionList[k])
				}
			}
			sessionList = newList
		}
	}
}

func snmpLogger(path string, interval int) {
	if path == "" || interval == 0 {
		return
	}
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			// split path into dirname and filename
			logdir, logfile := filepath.Split(path)
			// only format logfile
			f, err := os.OpenFile(logdir+time.Now().Format(logfile), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
			if err != nil {
				log.Println(err)
				return
			}
			w := csv.NewWriter(f)
			// write header in empty file
			if stat, err := f.Stat(); err == nil && stat.Size() == 0 {
				if err := w.Write(append([]string{"Unix"}, kcp.DefaultSnmp.Header()...)); err != nil {
					log.Println(err)
				}
			}
			if err := w.Write(append([]string{fmt.Sprint(time.Now().Unix())}, kcp.DefaultSnmp.ToSlice()...)); err != nil {
				log.Println(err)
			}
			kcp.DefaultSnmp.Reset()
			w.Flush()
			f.Close()
		}
	}
}
