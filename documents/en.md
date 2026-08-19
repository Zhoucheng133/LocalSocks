# LocalSocks Docker

This is a Socks5 (Over TLS) VPN server tool deployed on Docker.

## Usage

### Server

Deploy on Docker using this command:

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

\* host: Host address. You can also enter an IP address (NOT recommended).  
\*\* crt_path: Location of the TLS certificate. Enter a writable address on the server.

**Example HOST value**

- `example.com` -> `example.com`
- `proxy.example.com` -> `proxy.example.com`
- `proxy.example.com:8080` -> `proxy.example.com`

> [!IMPORTANT]
> The TLS certificate is valid for one year. You must manually restart the container within one year, and it is recommended to reset the username and password.

### Client

1. Add a proxy server using a VPN client that supports the Socks over TLS protocol.
2. Add a trusted TLS certificate to this proxy (note that it is a `.crt` file, not a `.key` file). Some clients display SHA256 (e.g., ShadowRocket), in which case you should enter the content output by docker logs*.

> [!IMPORTANT]
> After restarting the container, you need to update the trusted TLS certificate.

\* You can use the command `sudo docker logs socks` to view the output, which is:

``` 
Generated TLS certificate: ./crt/server.crt
TLS private key: ./crt/server.key
SHA256 Fingerprint: 12:34:56:78:90:AB:...
Secure SOCKS5 over TLS server running on port 3000
```

You should use `12:34:56:78:90:AB:...` as the SHA256 value

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
-p <port>:3000 \
--name socks \
zhouc1230/local-socks:latest
```