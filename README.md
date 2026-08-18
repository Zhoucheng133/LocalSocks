# LocalSocks Docker

```bash
sudo docker run -d \
--restart always \
-e USERNAME=<username> \
-e PASSWORD=<password> \
-p 8800:3000 \
--name socks \
zhouc1230/local-socks:latest
```