package secret

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/spf13/cast"
)

const AesKeyLength = 16

var AesBaseSpecialSign = "!@a%$bc.de,l%$fgqweruriskn&#@xl784zm321apgiw"
var AesBaseSpecialSignLength = len(AesBaseSpecialSign)

type AesEncrypt16 struct {
	SpecialSign string // 加解密都会基于这一串字符,如果没有会基于 AesBaseSpecialSign.
	Key         string // 密钥，建议是 5-8位的密钥
}

func NewAesEncrypt16(specialSign, key string) (*AesEncrypt16, error) {
	if specialSign == "" {
		specialSign = AesBaseSpecialSign
	}
	if len(specialSign) < AesKeyLength {
		if len(specialSign)%2 == 0 {
			specialSign += AesBaseSpecialSign[:AesKeyLength-len(specialSign)]
		} else {
			specialSign += AesBaseSpecialSign[AesBaseSpecialSignLength-len(specialSign):]
		}
	}
	if key == "" {
		return nil, errors.New("need the key to encrypt, please add it. ")
	}
	return &AesEncrypt16{
		SpecialSign: specialSign,
		Key:         key,
	}, nil
}

// GetPrefix 根据长短来判断前缀
func (a *AesEncrypt16) getPrefix(length int) string {
	if len(a.SpecialSign)%2 == 0 {
		return a.SpecialSign[len(a.SpecialSign)-length:]
	}
	return a.SpecialSign[:length]
}

// GenerateAesKey 生成AES密钥
func (a *AesEncrypt16) generateAesKey(id interface{}) []byte {
	idStr := cast.ToString(id)
	length := AesKeyLength - len(idStr) - len(a.Key)
	buf := make([]byte, 0, AesKeyLength)
	prefix := a.getPrefix(length)
	buf = append(buf, []byte(prefix)...)
	buf = append(buf, []byte(idStr)...)
	buf = append(buf, []byte(a.Key)...)
	return buf
}

// SecretEncrypt 加密金额
func (a *AesEncrypt16) SecretEncrypt(secret interface{}, fields ...interface{}) string {
	number := 0
	for i := range fields {
		number += fields[i].(int)
	}
	if secret != "" {
		aesKey := a.generateAesKey(number)
		ans, _ := a.aesEncrypt(cast.ToString(secret), aesKey)
		return ans
	}
	return ""
}

// SecretDecrypt 解密
func (a *AesEncrypt16) SecretDecrypt(secret interface{}, fields ...interface{}) string {
	number := 0
	for i := range fields {
		number += fields[i].(int)
	}
	if secret != "" {
		aesKey := a.generateAesKey(number)
		b, _ := a.aesDecrypt(cast.ToString(secret), aesKey)
		return string(b)
	}
	return ""
}

// AesEncrypt AES加密
func (a *AesEncrypt16) aesEncrypt(encodeStr string, key []byte) (string, error) {
	encodeByte := []byte(encodeStr)
	// 根据key，生成密文
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	blockSize := block.BlockSize()
	encodeByte = pkcs5Padding(encodeByte, blockSize)

	blockMode := cipher.NewCBCEncrypter(block, key)
	crypted := make([]byte, len(encodeByte))
	blockMode.CryptBlocks(crypted, encodeByte)

	hexStr := fmt.Sprintf("%x", crypted)
	return hexStr, nil
}

// AesDecrypt AES 解密
func (a *AesEncrypt16) aesDecrypt(decodeStr string, key []byte) ([]byte, error) {
	decodeBytes, err := hex.DecodeString(decodeStr)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, key)
	origData := make([]byte, len(decodeBytes))

	blockMode.CryptBlocks(origData, decodeBytes)
	origData = pkcs5UnPadding(origData)
	return origData, nil
}

func pkcs5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padText...)
}

func pkcs5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}
