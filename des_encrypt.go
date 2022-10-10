package secret

import (
	"crypto/cipher"
	"crypto/des"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/spf13/cast"
)

const DesKeyLength = 8

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

// GenerateDesKey 生成DES密钥
func (d *DesEncrypt) generateDesKey(id interface{}) []byte {
	idStr := cast.ToString(id)
	buf := make([]byte, 0, DesKeyLength)
	buf = append(buf, []byte(idStr)...)
	buf = append(buf, []byte(d.Key)...)
	if len(buf) > DesKeyLength {
		buf = buf[:8]
	}
	return buf
}

// SecretEncrypt 加密
func (d *DesEncrypt) SecretEncrypt(secret interface{}, fields ...interface{}) (string, error) {
	number := 0
	for i := range fields {
		number += fields[i].(int)
	}
	if secret != "" {
		aesKey := d.generateDesKey(number)
		ans, err := d.desEncrypt(cast.ToString(secret), aesKey)
		if err != nil {
			return "", err
		}
		return ans, nil
	}
	return "", errors.New("need the secret to encrypt")
}

// SecretDecrypt 解密
func (d *DesEncrypt) SecretDecrypt(secret interface{}, fields ...interface{}) (string, error) {
	number := 0
	for i := range fields {
		number += fields[i].(int)
	}
	if secret != "" {
		aesKey := d.generateDesKey(number)
		b, err := d.desDecrypt(cast.ToString(secret), aesKey)
		if err != nil {
			return "", nil
		}
		return string(b), nil
	}
	return "", errors.New("need the secret to decrypt")
}

func (d *DesEncrypt) desEncrypt(origData string, key []byte) (string, error) {
	encodeByte := []byte(origData)

	block, err := des.NewCipher(key)
	if err != nil {
		return "", err
	}

	encodeByte = pkcs5Padding(encodeByte, block.BlockSize())
	blockMode := cipher.NewCBCEncrypter(block, key)

	crypted := make([]byte, len(encodeByte))
	blockMode.CryptBlocks(crypted, encodeByte)

	hexStr := fmt.Sprintf("%x", crypted)
	return hexStr, nil
}

func (d *DesEncrypt) desDecrypt(decodeStr string, key []byte) ([]byte, error) {
	decodeBytes, err := hex.DecodeString(decodeStr)
	if err != nil {
		return nil, err
	}
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, key)

	origData := make([]byte, len(decodeBytes))
	blockMode.CryptBlocks(origData, decodeBytes)

	origData = pkcs5UnPadding(origData)
	return origData, nil
}
