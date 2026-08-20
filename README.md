# LocalSocks Docker

这是一个部署在Docker上的Socks5 (Over TLS) VPN服务端工具

## 使用

### 服务器端

使用这个命令在Docker上部署

```bash
sudo docker run -d \
--restart always \
-e USERNAME=<username> \
-e PASSWORD=<password> \
-e HOST=<host*> \
-v <crt_path**>:/app/crt \
-p <port>:3000 \
--name socks \
zhouc1230/local-socks:latest
```

\* host: 主机地址，你也可以填入IP地址（不推荐）  
\*\* crt_path: TLS证书存放位置，填入一个服务器中可读写的地址就可以

**HOST值示例**
- `example.com` -> `example.com`
- `proxy.example.com` -> `proxy.example.com`
- `proxy.example.com:8080` -> `proxy.example.com`

> [!IMPORTANT]
> TLS证书有效期为一年，在一年之内务必手动重启容器，并且建议重新设置用户名和密码

### 客户端

1. 使用一个支持Socks over TLS协议的VPN客户端添加一个代理服务器
2. 在这个代理中添加信任的TLS证书（注意是`.crt`文件而不是`.key`文件），有一些客户端显示为SHA256 (比如ShadowRocket)，那你应该填入的内容为docker logs输出的内容*

> [!IMPORTANT]
> 很多代理客户端会默认不使用代理访问局域网，可能需要你手动配置一下，配置可以参考本仓库的`tunnel.conf`文件

\* 你可以使用命令`sudo docker logs socks`查看，输出为
```
Generated TLS certificate: ./crt/server.crt
TLS private key: ./crt/server.key
SHA256 Fingerprint: 12:34:56:78:90:AB:...
Secure SOCKS5 over TLS server running on port 3000
```
你应该使用`12:34:56:78:90:AB:...`作为SHA256的值

## 更新

```bash
sudo docker pull zhouc1230/local-socks:latest &&
sudo docker stop socks &&
sudo docker rm socks &&
sudo docker run -d \
--restart always \
-e USERNAME=<username> \
-e PASSWORD=<password> \
-e HOST=<host> \
-v <crt_path*>:/app/crt \
-p <port>:3000 \
--name socks \
zhouc1230/local-socks:latest
```