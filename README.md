## 介绍

模仿[PPPoE-hijack](https://github.com/Karblue/PPPoE-hijack)的golang版本

原理: [解密古老又通杀的路由器攻击手法：从嗅探PPPoE到隐蔽性后门](http://www.freebuf.com/articles/wireless/163480.html)

## 用法

```bash
git clone https://github.com/hammerorz/pppoe-hijack-go.git
cd pppoe-hijack-go
go build main.go
./main -i 网卡
#例如
./main -i eth0
```
