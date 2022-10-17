package secret

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
)

type RsaBitsType int

const (
	RsaBits512     RsaBitsType = 512
	RsaBits1024    RsaBitsType = 1024
	RsaBits2048    RsaBitsType = 2048
	RsaBits4096    RsaBitsType = 4096
	RsaDefaultBits             = RsaBits1024
)

const (
	RsaDefaultPublishKeyName = "publishKey"
	RsaDefaultPrivateKeyName = "privateKey"

	PublishKey = "PUBLIC KEY"
	PrivateKey = "RSA PRIVATE KEY"
)

type RsaEncrypt struct {
	Bits           RsaBitsType // 定位大小的 RSA 密钥对
	PublishKeyName string      // 公钥名字
	PrivateKeyName string      // 私钥名字
	PublishKeyPath string      // 公钥的输出路径
	PrivateKeyPath string      // 私钥的输出路径
}

var RsaBitsMap = map[RsaBitsType]int{
	RsaBits512:  512,
	RsaBits1024: 1024,
	RsaBits2048: 2048,
	RsaBits4096: 4096,
}

func formatPubAndPriKeyName(name string) string {
	return fmt.Sprintf("/%s.pem", name)
}

func NewDefaultRsaEncrypt() *RsaEncrypt {
	defaultPath, _ := os.Getwd()
	return &RsaEncrypt{
		Bits:           RsaDefaultBits,
		PublishKeyName: formatPubAndPriKeyName(RsaDefaultPublishKeyName),
		PrivateKeyName: formatPubAndPriKeyName(RsaDefaultPrivateKeyName),
		PublishKeyPath: defaultPath + formatPubAndPriKeyName(RsaDefaultPublishKeyName),
		PrivateKeyPath: defaultPath + formatPubAndPriKeyName(RsaDefaultPrivateKeyName),
	}
}

func NewRsaEncrypt(bits RsaBitsType, publishKeyName, publishKeyPath, privateKeyName, privateKeyPath string) *RsaEncrypt {
	obj := NewDefaultRsaEncrypt()
	if bits != 0 {
		obj.Bits = bits
	}

	if publishKeyName != "" {
		obj.PublishKeyName = formatPubAndPriKeyName(publishKeyName)
	}
	if publishKeyPath != "" {
		obj.PublishKeyPath = publishKeyPath + formatPubAndPriKeyName(publishKeyName)
	}
	if privateKeyName != "" {
		obj.PrivateKeyName = formatPubAndPriKeyName(privateKeyName)
	}
	if privateKeyPath != "" {
		obj.PrivateKeyPath = privateKeyPath + formatPubAndPriKeyName(privateKeyName)
	}
	return obj
}

// SaveRsaKey 保存生成的公钥和密钥
func (r *RsaEncrypt) SaveRsaKey() error {
	privateKey, err := rsa.GenerateKey(rand.Reader, RsaBitsMap[r.Bits])
	if err != nil {
		fmt.Println(err)
		return err
	}
	publicKey := privateKey.PublicKey
	// 使用x509标准对私钥进行编码，AsN.1编码字符串
	x509Privete := x509.MarshalPKCS1PrivateKey(privateKey)
	// 使用x509标准对公钥进行编码，AsN.1编码字符串
	x509Public := x509.MarshalPKCS1PublicKey(&publicKey)

	// 对私钥封装block 结构数据
	blockPrivate := pem.Block{Type: PrivateKey, Bytes: x509Privete}
	// 对公钥封装block 结构数据
	blockPublic := pem.Block{Type: PublishKey, Bytes: x509Public}

	// 创建存放私钥的文件
	privateFile, errPri := os.Create(r.PrivateKeyPath)
	if errPri != nil {
		return errPri
	}
	defer func(privateFile *os.File) {
		errClose := privateFile.Close()
		if errClose != nil {
			panic(errClose)
		}
	}(privateFile)
	err = pem.Encode(privateFile, &blockPrivate)
	if err != nil {
		return err
	}

	// 创建存放公钥的文件
	publicFile, errPub := os.Create(r.PublishKeyPath)
	if errPub != nil {
		return errPub
	}
	defer publicFile.Close()
	err = pem.Encode(publicFile, &blockPublic)
	if err != nil {
		return err
	}
	return nil
}

// RsaEncrypt 加密
func (r *RsaEncrypt) RsaEncrypt(src, filePath string) (string, error) {
	srcByte := []byte(src)
	// 打开文件
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}

	// 获取文件信息
	fileInfo, errInfo := file.Stat()
	if errInfo != nil {
		return "", errInfo
	}
	// 读取文件内容
	keyBytes := make([]byte, fileInfo.Size())
	// 读取内容到容器里面
	file.Read(keyBytes)
	// pem解码
	block, _ := pem.Decode(keyBytes)
	// x509解码
	publicKey, errPb := x509.ParsePKCS1PublicKey(block.Bytes)
	if errPb != nil {
		return "", errPb
	}
	// 使用公钥对明文进行加密
	retByte, errRet := rsa.EncryptPKCS1v15(rand.Reader, publicKey, srcByte)
	if errRet != nil {
		return "", errRet
	}
	return base64.StdEncoding.EncodeToString(retByte), nil
}

// RsaDecrypt 解密
func (r *RsaEncrypt) RsaDecrypt(srcByte []byte, filePath string) (string, error) {
	// 打开文件
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	// 获取文件信息
	fileInfo, errInfo := file.Stat()
	if errInfo != nil {
		return "", errInfo
	}
	// 读取文件内容
	keyBytes := make([]byte, fileInfo.Size())
	// 读取内容到容器里面
	_, _ = file.Read(keyBytes)
	// pem解码
	block, _ := pem.Decode(keyBytes)
	// x509解码
	privateKey, errPb := x509.ParsePKCS1PrivateKey(block.Bytes)
	if errPb != nil {
		return "", errPb
	}
	// 进行解密
	retByte, errRet := rsa.DecryptPKCS1v15(rand.Reader, privateKey, srcByte)
	if errRet != nil {
		return "", errRet
	}
	return base64.StdEncoding.EncodeToString(retByte), nil
}
