package secret

import (
	"crypto/cipher"
	"crypto/des"
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
	buf := make([]byte, 0, AesKeyLength)
	buf = append(buf, []byte(idStr)...)
	buf = append(buf, []byte(d.Key)...)
	return buf
}

func (d *DesEncrypt) SecretEncrypt(origData string, key []byte) (string, error) {
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

func (d *DesEncrypt) SecretDecrypt(crypted, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, key)
	origData := make([]byte, len(crypted))
	// origData := crypted
	blockMode.CryptBlocks(origData, crypted)
	origData = pkcs5UnPadding(origData)
	// origData = ZeroUnPadding(origData)
	return origData, nil
}
