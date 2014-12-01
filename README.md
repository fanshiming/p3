p3
==
author  fanshiming 2014

这是一份用python3.4写的DES 3DES加密解密脚本
目的是练习：使用Python实现DES加密解密逻辑。


一份DES加密结果：
key = 7365637572697479		（7365表示 73H和65H,二进制表示为0111 0011 0110 0101）
plain_text =  636f6d7075746572
cipher 3B6C72B2710EB513

一份3DES加密结果：
秘钥   73656375726974797365637572697479
明文  636f6d7075746572
密文 3b6c72b2710eb513	

函数说明
des_encrypt(key, plain_text)
	DES加密函数
	参数key 表示加密秘钥。一个bytes对象，长度必须是8
	参数plain_text为明文。一个bytes对象，长度必须是8
	返回密文。一个bytes对象，长度为8
	
des_decrypt(key, bs)
	DES解密函数
	参数key 表示解密秘钥（DES加密解密使用相同的秘钥）。一个bytes对象，长度必须是8
	参数bs为待解密的密文。一个bytes对象，长度必须是8
	返回明文。一个bytes对象，长度为8

tdes_encrypt
	3DES加密。
	使用128位的秘钥。k1=k3, k2独立。
	对64位数据进行加密。
	返回64位密文。
tdes_decrypt
	参照tdes_encrypt



