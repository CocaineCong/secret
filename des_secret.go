package secret

import (
	"bytes"
	"crypto/des"
	"encoding/base64"
	"errors"
	"github.com/spf13/cast"
)

const DesKeyLength = 9

var DesBaseSpecialSign = "!@a%$bc.de,l%$fgqweruriskn&#@xl784zm321apgiw"
var DesBaseSpecialSignLength = len(DesBaseSpecialSign)

type DesEncrypt struct {
	SpecialSign string // 加解密都会基于这一串字符,如果没有会基于 DesBaseSpecialSign.
	Key         string // 密钥，建议是 5-8位的密钥
}

func NewDesEncrypt(specialSign, key string) (*DesEncrypt, error) {
	if specialSign == "" {
		specialSign = AesBaseSpecialSign
	}
	specialSignLength := len(specialSign)
	if len(specialSign) < DesKeyLength { // 小于8位填充
		if len(specialSign)%2 == 0 {
			specialSign += AesBaseSpecialSign[:DesKeyLength-specialSignLength]
		} else {
			specialSign += AesBaseSpecialSign[DesBaseSpecialSignLength-specialSignLength:]
		}
	} else if len(specialSign) > DesKeyLength { // 大于8位去除
		if len(specialSign)%2 == 0 {
			specialSign = specialSign[:DesKeyLength]
		} else {
			specialSign = specialSign[DesKeyLength-specialSignLength:]
		}
	}
	if key == "" {
		return nil, errors.New("need the key to encrypt, please add it. ")
	}
	return &DesEncrypt{
		SpecialSign: specialSign,
		Key:         key,
	}, nil
}

// GenerateAesKey 生成AES密钥
func (d *DesEncrypt) generateAesKey(id interface{}) []byte {
	idStr := cast.ToString(id)
	buf := make([]byte, 0, AesKeyLength)
	buf = append(buf, []byte(idStr)...)
	buf = append(buf, []byte(d.Key)...)
	return buf
}

// SecretEncrypt 加密
func (d *DesEncrypt) SecretEncrypt(secret interface{}, fields ...interface{}) (string, error) {
	srcByte := cast.ToString(secret)
	number := 0
	for i := range fields {
		number += fields[i].(int)
	}
	key := d.generateAesKey(number)
	block, err := des.NewCipher(key)
	if err != nil {
		return "", err
	}
	// 密码填充
	newSrcByte := PadPwd([]byte(srcByte), block.BlockSize())
	dst := make([]byte, len(newSrcByte))
	block.Encrypt(dst, newSrcByte)
	// base64编码
	pwd := base64.StdEncoding.EncodeToString(dst)
	return pwd, nil
}

// SecretDecrypt 解密
func (d *DesEncrypt) SecretDecrypt(secret interface{}, fields ...interface{}) (string, error) {
	number := 0
	for i := range fields {
		number += fields[i].(int)
	}
	src := cast.ToString(secret)
	pwdByte, err := base64.StdEncoding.DecodeString(src)
	if err != nil {
		return "", err
	}
	desKey := d.generateAesKey(number)
	block, errBlock := des.NewCipher(desKey)
	if errBlock != nil {
		return "", errBlock
	}
	dst := make([]byte, len(pwdByte))
	block.Decrypt(dst, pwdByte)
	// 填充的要去掉
	dst, _ = UnPadPwd(dst)
	return string(dst), nil
}

func UnPadPwd(dst []byte) ([]byte, error) {
	if len(dst) <= 0 {
		return dst, errors.New("长度有误")
	}
	// 去掉的长度
	unpadNum := int(dst[len(dst)-1])
	return dst[:(len(dst) - unpadNum)], nil
}

func PadPwd(srcByte []byte, blockSize int) []byte {
	padNum := blockSize - len(srcByte)%blockSize
	ret := bytes.Repeat([]byte{byte(padNum)}, padNum)
	srcByte = append(srcByte, ret...)
	return srcByte
}
