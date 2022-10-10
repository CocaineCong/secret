package secret

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

const (
	RsaDefaultBits           = 1024
	RsaDefaultPublishKeyName = "publishKey"
	RsaDefaultPrivateKeyName = "privateKey"

	PublishKey = "publish key"
	PrivateKey = "private key"
)

type RsaEncrypt struct {
	Bits           int    // 定位大小的 RSA 密钥对
	PublishKeyName string // 公钥名字
	PrivateKeyName string // 私钥名字
	PublishKeyPath string // 公钥的输出路径
	PrivateKeyPath string // 私钥的输出路径
}

func formatPubAndPriKeyName(name string) string {
	return fmt.Sprintf("%s.pem", name)
}

func NewDefaultRsaEncrypt() *RsaEncrypt {
	defaultPath, _ := os.Getwd()
	return &RsaEncrypt{
		Bits:           RsaDefaultBits,
		PublishKeyName: formatPubAndPriKeyName(RsaDefaultPublishKeyName),
		PrivateKeyName: formatPubAndPriKeyName(RsaDefaultPrivateKeyName),
		PublishKeyPath: defaultPath,
		PrivateKeyPath: defaultPath,
	}
}

func NewRsaEncrypt(bits int, publishKeyName, publishKeyPath, privateKeyName, privateKeyPath string) *RsaEncrypt {
	obj := NewDefaultRsaEncrypt()
	if bits != 0 {
		obj.Bits = bits
	}
	if publishKeyName != "" {
		obj.PublishKeyName = formatPubAndPriKeyName(publishKeyName)
	}
	if publishKeyPath != "" {
		obj.PublishKeyPath = publishKeyPath
	}
	if privateKeyName != "" {
		obj.PrivateKeyName = formatPubAndPriKeyName(privateKeyName)
	}
	if privateKeyPath != "" {
		obj.PrivateKeyPath = privateKeyPath
	}
	return obj
}

// SaveRsaKey 保存生成的公钥和密钥
func (r *RsaEncrypt) SaveRsaKey() error {
	privateKey, err := rsa.GenerateKey(rand.Reader, r.Bits)
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
	privateFile, errPri := os.Create(r.PrivateKeyPath + r.PrivateKeyName)
	if errPri != nil {
		return errPri
	}
	defer privateFile.Close()
	err = pem.Encode(privateFile, &blockPrivate)
	if err != nil {
		return err
	}

	// 创建存放公钥的文件
	publicFile, errPub := os.Create("publicKey.pem")
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

// RsaEncoding 加密
func (r *RsaEncrypt) RsaEncoding(src, filePath string) ([]byte, error) {
	srcByte := []byte(src)
	// 打开文件
	file, err := os.Open(filePath)
	if err != nil {
		return srcByte, err
	}

	// 获取文件信息
	fileInfo, errInfo := file.Stat()
	if errInfo != nil {
		return srcByte, errInfo
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
		return srcByte, errPb
	}
	// 使用公钥对明文进行加密
	retByte, errRet := rsa.EncryptPKCS1v15(rand.Reader, publicKey, srcByte)
	if errRet != nil {
		return srcByte, errRet
	}
	return retByte, nil
}

// RsaDecoding 解密
func (r *RsaEncrypt) RsaDecoding(srcByte []byte, filePath string) ([]byte, error) {
	// 打开文件
	file, err := os.Open(filePath)
	if err != nil {
		return srcByte, err
	}
	// 获取文件信息
	fileInfo, errInfo := file.Stat()
	if errInfo != nil {
		return srcByte, errInfo
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
		return keyBytes, errPb
	}
	// 进行解密
	retByte, errRet := rsa.DecryptPKCS1v15(rand.Reader, privateKey, srcByte)
	if errRet != nil {
		return srcByte, errRet
	}
	return retByte, nil
}
