# 吹着贝斯扫二维码 Writeup

## 解题步骤

flag压缩包需要密码才能解压，压缩包的备注有被加密的字符串。

`GNATOMJVIQZUKNJXGRCTGNRTGI3EMNZTGNBTKRJWGI2UIMRRGNBDEQZWGI3DKMSFGNCDMRJTII3TMNBQGM4TERRTGEZTOMRXGQYDGOBWGI2DCNBY`

除了压缩包外有36个文件，将文件名修改为jpg会发现是二维码是一部分。

对二维码的处理有两种方式：

1. 拿PS一个一个拼，顺序得慢慢尝试。
2. 使用010等工具查看每个图片的原数据，会发现图片的数据末尾有两个数字代表这个图片的位置，编写脚本或者使用ps等将二维码拼接好。

最终二维码为：

![QRcode.png](https://i.loli.net/2019/11/14/qyw28xgOPHsFSMT.png)

扫出来的内容为：

	BASE Family Bucket ??? 
	85->64->85->13->16->32

可以猜测压缩包备注的字符串应该是base加密，按照这个顺序反向base解密。

base32解码：

`3A715D3E574E36326F733C5E625D213B2C62652E3D6E3B7640392F3137274038624148`

base16解码：

`:q]>WN62os<^b]!;,be.=n;v@9/17'@8bAH`

这里的13并不是base编码，而是ROT13密码。

ROT13解密：

`:d]>JA62bf<^o]!;,or.=a;i@9/17'@8oNU`

base85解码：

`PCtvdWU4VFJnQUByYy4mK1lraTA=`

base64解码

`<+oue8TRgA@rc.&+Yki0`

base85解码：

`<+oue8TRgA@rc.&+Yki0`

得到解压密码：ThisIsSecret!233

解压后得到flag

base85编码：https://base85.io/
rot13：https://rot13.com/