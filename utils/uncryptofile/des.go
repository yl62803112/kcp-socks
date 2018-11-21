package main


import (
	"crypto/cipher"
	"crypto/des"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
)

var infileName = "/Users/zhangjianxin/home/GO_LIB/src/github.com/uk0/kcp-socks/utils/uncryptofile/";

var outfileName = "/Users/zhangjianxin/home/GO_LIB/src/github.com/uk0/kcp-socks/client/";

var KEY = "key";

func main() {

	start("config.json");
}

func start(fileName string) {
	var mode = false
	//表明是解密
	if mode {
		var plain = DecryptMode2(outfileName+fileName, []byte(KEY))
		err := ioutil.WriteFile(infileName+fileName, plain, 0777)
		if err != nil {
			fmt.Println("保存解密后文件失败!")
		} else {
			fmt.Println("文件已解密!")
		}
	} else {
		var plain = EncryptMode(infileName+fileName, []byte(KEY))
		err := ioutil.WriteFile(outfileName+fileName, plain, 0777)
		if err != nil {
			fmt.Println("保存加密后文件失败!")
		} else {
			fmt.Println("文件已加密,务必记住加密key!")
		}
	}
}

// 解密
func DecryptMode2(fileName string, inkey []byte) []byte {
	file, err := os.Open(fileName)
	if err != nil {
		fmt.Println("未找到待处理文件")
		os.Exit(0)
	}
	defer file.Close()
	//读取文件内容
	plain, _ := ioutil.ReadAll(file)
	arg1 := sha256.Sum224(inkey)
	key := arg1[:24]
	block, _ := des.NewTripleDESCipher(key)
	DecryptMode := cipher.NewCBCDecrypter(block, key[:8])
	plain, _ = base64.StdEncoding.DecodeString(string(plain))
	DecryptMode.CryptBlocks(plain, plain)
	plain = PKCS5remove(plain)
	return []byte(plain)
}

// 加密
func EncryptMode(fileName string, inkey []byte) []byte {
	file, err := os.Open(fileName)
	if err != nil {
		fmt.Println("未找到待处理文件")
		os.Exit(0)
	}
	defer file.Close()
	//读取文件内容
	plain, _ := ioutil.ReadAll(file)
	arg1 := sha256.Sum224(inkey)
	key := arg1[:24]
	block, _ := des.NewTripleDESCipher(key)
	EncryptMode := cipher.NewCBCEncrypter(block, key[:8])
	//明文补足PKCS5Padding
	plain = PKCS5append(plain)
	EncryptMode.CryptBlocks(plain, plain)
	return []byte(base64.StdEncoding.EncodeToString(plain))
}
func PKCS5append(plaintext []byte) []byte {
	num := 8 - len(plaintext)%8
	for i := 0; i < num; i++ {
		plaintext = append(plaintext, byte(num))
	}
	return plaintext
}
func PKCS5remove(plaintext []byte) []byte {
	length := len(plaintext)
	num := int(plaintext[length-1])
	return plaintext[:(length - num)]
}
