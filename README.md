# TLV (Simple TLV)



## 写在前面

在当前IoT时代的大环境下，万物互联成为了主题，然而之前用过的很多的通讯协议不再是那么的贴切，注意到了TLV这个概念还是比较贴切的，所以，对TLV进行了必要的简化和再次的封装，以适用于大部分的IoT场合的通讯。



## 本项目特点

* HEX构建，ASCII传送

* 可选的3DES和AES加密

* 可选的密钥分散机制，支持双向全动态密钥传输

* 数据长度可变（可能这是废话）

* 自带CRC校验

* 为简化程序，和标准TLV协议对比，本项目的TAG只支持1个字节

* 本项目不支持协议嵌套，需要嵌套的可以自行在DATA段嵌套实现

  

## TLV struct 说明

```c
struct TLV_simple
{
	uint8_t				tag;
	tlvlensize			len;
	tlvaddsize  		addr;
	uint8_t				encrypt_mode;
	tlvlensize			effective_data_len;
	tlvcmdsize			cmd;
	uint32_t			crc;
	uint8_t				data[];
};
```

tag:	TLV中的T，标签，本设计仅用作通讯方的主从身份识别；

len:	TLV中的L，TLV串内容的长度，即V的长度；

其余部分都为V，V被分割成以下几个子项：

addr:	地址，0为保留字，全1为广播；

encrypt_mode：	加密模式，第0位为1时，进行3DES加密，第1位为1时，进行AES128的加密，第0位和第1位可同时为1，则先进行3DES加密，加密的结果再进行AES加密；

effective_data_len:	传输内容的有效长度，可以为0，即只有命令，没有内容；

cmd:	命令字，不能为0；（0被用作加密替代字，也就是如果选择了加密，命令字和传输内容都被加密，这里的cmd字段则变为0，当然，加解密过程已经完成了这些替换，最终从解析函数里返回的struct中，这个命令字已经被还原为明文的命令字了）

crc:	校验；

data:	传输内容；

```c
typedef uint16_t tlvlensize;
typedef uint16_t tlvaddsize;
typedef uint16_t tlvcmdsize;
```



对于重命名的三个数据类型：

tlvlensize:	长度的数据宽度；

tlvaddsize:	地址的数据宽度；

tlvcmdsize:	命令字的数据宽度；



## 操作集说明

```c
struct TLV_simple_Opr
{
	uint8_t				deskey[16];
	uint8_t				aeskey[16];
	uint8_t				defaulttag;
	tlvaddsize			defaultaddr;
	uint8_t				role;
	uint8_t				defaultencryptmode;
	uint8_t				key_scatter_factor[16];
	int					(*generate)(struct TLV_simple_Opr *, struct TLV_simple**, char **, uint32_t *);
	int					(*parse)(struct TLV_simple_Opr *, struct TLV_simple**, char **, uint32_t);
};
```



deskey:	顾名思义，不明白的可以猜一猜，猜不出的劝退3DES的使用；

aeskey:	彪悍的人生不需要解释；

defaulttag:	默认TAG，定义了这里以后，不用每次申请struct TLV_simple都定义TAG；注意，申请时，用calloc函数申请，如果用malloc申请的请先把结构体置0，只有在tag为0的情况下，defaulttag才会生效；

role:	角色，定义通讯发起方还是应答方，这个用在动态密钥里，应答方会把本次分散密钥的随机数放在结构体里以明文方式传给发起方；

defaultencryptmode: 根据上面的defaulttag，我知道你懂了；

key_scatter_factor:	密钥分散因子，用于动态密钥，前8个字节为应答方的随机数，后8个字节为发起方的随机数；

generate:	输入：struct TLV_simple，输出：被base64的struct TLV_simple (char *)；struct TLV_simple必须是可以释放的堆空间，函数执行后，就被强制释放。输出只需要给一个char类型的指针即可，函数会动态申请内存；

parse: 和generate反一反，输入：被base64的struct TLV_simple (char *)；输出：struct TLV_simple，同样，输入的char指针是要可以被释放的堆空间，struct TLV_simple为值为NULL的空指针，函数会完成申请动态内存过程。



未完待续......

标准TLV正在编码中......



## Authors and acknowledgment
鄭曾濤 (Zengtao Zheng)

E-mail: z_zt@msn.com

https://github.com/zhengzengtao/tlv.git



## License
GNU General Public License v3.0



