## kcp-socks


* 第一步 修改篇配置（不修改也可以）

```go
// 修改 lightsocks/cmd/config.go
// line 11 - 13
const (
	ConfigFileName    = "./token.json"
)
```


* 编译`server`端 go build ./
   
```bash
➜  server git:(master) ✗ ./server 
kcp.go:384: version: SELFBUILD
kcp.go:385: initiating key derivation
config.go:41: 从文件 ./token.json 中读取配置
config.go:35: 保存配置到文件 ./token.json 成功
server.go:44: 使用配置： 
本地监听地址 listen：
[::]:64809
密码 password：
hrAvV8b/YqzbSH7MZygUfV3vWopc6lN/HGMk6R6ZtsoJHXYO8eu/kDXWvIxbG57hNtEBs46+N+B4A5rdJhWxcxH1BqB8+fjkP9i9Mgv8CK4u395H2eiNClA9ImAnnHFquM4W1ADa7E/uZsF041F5VoWDa9XwzUPEOin+gnAE9gIxO8K7i3o8aFSSLFnLialkEKVplKRN920TyZcY7ZaqQLXHRuUjGlIzQqEgyIen19Oyt2VMDIArNP3zXvS5DVWPhEWrwCryop8ww07Suh9y3JMFoxJ1qD6YiGGRzxcHd5VBrdDFDzlfmy36Iabm4ntESvtub2y0GZ0454FJWCVLrw==
        
server.go:50: socks-server: 启动成功 监听在 [::]:64809
kcp.go:420: listening on: [::]:6443
kcp.go:421: target: 127.0.0.1:64809
kcp.go:422: encryption: none
kcp.go:423: nodelay parameters: 1 20 2 1
kcp.go:424: sndwnd: 2048 rcvwnd: 2048
kcp.go:425: compression: true
kcp.go:426: mtu: 1350
kcp.go:427: datashard: 10 parityshard: 3
kcp.go:428: acknodelay: false
kcp.go:429: dscp: 46
kcp.go:430: sockbuf: 4194304
kcp.go:431: keepalive: 10
kcp.go:432: snmplog: 
kcp.go:433: snmpperiod: 60
kcp.go:434: pprof: false
kcp.go:435: quiet: false
```

* 编译客户端（配置文件des加密）

```bash
# kcp-socks/utils/uncryptofile 里面有一个des加密工具类，还有未加密的文件，详情可以看源码
```

* 记得修改 `infileName` `outfileName` 

```bash
# 执行加密操作
文件已加密,务必记住加密key!
Process finished with exit code 0
# 加密完成会产生一个加密后的文件
➜  client git:(master) ✗ ls -al
total 12592
drwxr-xr-x   7 firshme  staff      224 Nov 21 16:10 .
drwxr-xr-x  11 firshme  staff      352 Nov 21 16:20 ..
-rwxr-xr-x   1 firshme  staff  6413240 Nov 21 12:48 client
-rwxr-xr-x   1 firshme  staff      492 Nov 21 16:19 config.json # 加密后的文件
-rw-r--r--   1 firshme  staff    11756 Nov 21 16:10 kcp.go
-rw-r--r--   1 firshme  staff      414 Nov 21 15:21 token.json

```

* 启动 client

```bash
./client
config.go:41: 从文件 ./token.json 中读取配置
2018/11/21 16:24:08 kcp.go:225: version: v1
2018/11/21 16:24:08 http_proxy.go:31: http <---::8198 ,socks5 :127.0.0.1:10899  
2018/11/21 16:24:08 config.go:35: 保存配置到文件 ./token.json 成功
2018/11/21 16:24:08 client.go:43: 使用配置： 
本地监听地址 listen：
[::]:10088
远程服务地址 remote：
127.0.0.1:10080
密码 password：
hrAvV8b/YqzbSH7MZygUfV3vWopc6lN/HGMk6R6ZtsoJHXYO8eu/kDXWvIxbG57hNtEBs46+N+B4A5rdJhWxcxH1BqB8+fjkP9i9Mgv8CK4u395H2eiNClA9ImAnnHFquM4W1ADa7E/uZsF041F5VoWDa9XwzUPEOin+gnAE9gIxO8K7i3o8aFSSLFnLialkEKVplKRN920TyZcY7ZaqQLXHRuUjGlIzQqEgyIen19Oyt2VMDIArNP3zXvS5DVWPhEWrwCryop8ww07Suh9y3JMFoxJ1qD6YiGGRzxcHd5VBrdDFDzlfmy36Iabm4ntESvtub2y0GZ0454FJWCVLrw==
        
2018/11/21 16:24:08 client.go:51: socks-local: 启动成功 监听在 [::]:10088
2018/11/21 16:24:08 kcp.go:264: listening on: [::]:10080
2018/11/21 16:24:08 kcp.go:265: encryption: none
2018/11/21 16:24:08 kcp.go:266: nodelay parameters: 1 20 2 1
2018/11/21 16:24:08 kcp.go:267: remote address: xxx.xx.xxx.xx:6443
2018/11/21 16:24:08 kcp.go:268: sndwnd: 1024 rcvwnd: 128
2018/11/21 16:24:08 kcp.go:269: compression: true
2018/11/21 16:24:08 kcp.go:270: mtu: 1350
2018/11/21 16:24:08 kcp.go:271: datashard: 10 parityshard: 10
2018/11/21 16:24:08 kcp.go:272: acknodelay: false
2018/11/21 16:24:08 kcp.go:273: dscp: 46
2018/11/21 16:24:08 kcp.go:274: sockbuf: 4194304
2018/11/21 16:24:08 kcp.go:275: keepalive: 10
2018/11/21 16:24:08 kcp.go:276: conn: 2
2018/11/21 16:24:08 kcp.go:277: autoexpire: 0
2018/11/21 16:24:08 kcp.go:278: scavengettl: 600
2018/11/21 16:24:08 kcp.go:279: snmplog: 
2018/11/21 16:24:08 kcp.go:280: snmpperiod: 0
2018/11/21 16:24:08 kcp.go:281: quiet: false

```

## 关于 socks5 to http 代理的实现已经写在http_proxy
* 相关配置如下（支持配置多个）

```json
"socket_to_http_proxy": [
  [
    "127.0.0.1:10899",
    ":8198"
  ]
]

```

## thanks

* 感谢以下两位大神开源出那么好用的东西。

```url

github.com/gwuhaolin

github.com/xtaci

```