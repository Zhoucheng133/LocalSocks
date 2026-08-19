# LocalSocks Docker

This is a Docker-based Socks5 (Over TLS) VPN for servers.  
这是一个部署在Docker上的Socks5 (Over TLS) VPN服务端工具

## Usage

Use this command to deploy with Docker  
使用这个命令在Docker上部署

```bash
sudo docker run -d \
--restart always \
-e USERNAME=<username> \
-e PASSWORD=<password> \
-e HOST=<host> \
-v <crt_path*>:/app/crt \
-p 8800:3000 \
--name socks \
zhouc1230/local-socks:latest
```

* crt_path: The path to your TLS certificate.

> [!WARNING]
> The TLS certificate **expires one year after installation**, so you need to restart it (or reinstall the container) annually. For enhanced security, consider changing your username and password periodically as well.  
> TLS证书将会在**一年之后过期**，这意味着你需要每年重启这个容器（或者添加一个新的容器）。但是更建议你在重启的时候顺便修改用户名和密码保证安全。

> [!IMPORTANT]
> Make sure your VPN client supports Socks5 Over TLS, and enable the **"Allow Insecure TLS"** option when adding the connection.  
> Some VPN clients block local traffic (localhost) through the VPN. Make sure your client is configured to allow access to localhost. You can refer to the `tunnel.config` rules in this repository for guidance.  
> 确保你的VPN客户端支持Socks5 Over TLS协议，并且在添加时注意设置 **“允许不安全的TLS”**。  
> 有一些VPN客户端的规则不允许通过VPN服务访问局域网地址，注意修改这些规则。你可以参考本仓库中的`tunnel.conf`配置

## Update

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
-p 8800:3000 \
--name socks \
zhouc1230/local-socks:latest
```