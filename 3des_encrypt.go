package secret

import (
	"crypto/cipher"
	"crypto/des"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/spf13/cast"
	"log"
)

const TripleDesKeyLength = 24
const TripleDesKeyBlock = 8

var TripleDesBaseSpecialSign = "!@abc$qwefgr.#n3@zmde,l%uri&%18$xl7g42askpiw"
var TripleDesBaseSpecialSignLength = len(TripleDesBaseSpecialSign)

type TripleDesEncrypt struct {
	SpecialSign string // 加解密都会基于这一串字符,如果没有会基于 TripleDesBaseSpecialSign.
	Key         string // 密钥，建议是 5-8位的密钥
}

func NewTripleDesEncrypt(specialSign, key string) (*TripleDesEncrypt, error) {
	if specialSign == "" {
		specialSign = TripleDesBaseSpecialSign
	}
	specialSignLength := len(specialSign)
	if specialSignLength+len(key) < TripleDesKeyLength { // 小于24位填充
		log.Printf("the length of specialSign and key less %v ", TripleDesKeyLength)
		if specialSignLength%2 == 0 {
			specialSign += TripleDesBaseSpecialSign[:TripleDesKeyLength-specialSignLength]
		} else {
			specialSign += TripleDesBaseSpecialSign[TripleDesBaseSpecialSignLength-specialSignLength:]
		}
	} else if specialSignLength > TripleDesKeyLength { // 大于24位去除
		if specialSignLength%2 == 0 {
			specialSign = specialSign[:TripleDesKeyLength+1]
		} else {
			specialSign = specialSign[specialSignLength-TripleDesKeyLength:]
		}
	}
	if key == "" {
		return nil, errors.New("need the key to encrypt, please add it. ")
	}
	return &TripleDesEncrypt{
		SpecialSign: specialSign,
		Key:         key,
	}, nil
}

// getPrefix 根据长短来判断前缀
func (t *TripleDesEncrypt) getPrefix(length int) string {
	if len(t.SpecialSign)%2 == 0 {
		return t.SpecialSign[len(t.SpecialSign)-length:]
	}
	return t.SpecialSign[:length]
}

// generateDesKey 生成3DES密钥
func (t *TripleDesEncrypt) generateTripleDesKey(id interface{}) []byte {
	idStr := cast.ToString(id)
	length := TripleDesKeyLength - len(idStr) - len(t.Key)
	buf := make([]byte, 0, TripleDesKeyLength)
	prefix := t.getPrefix(length)
	buf = append(buf, []byte(prefix)...)
	buf = append(buf, []byte(idStr)...)
	buf = append(buf, []byte(t.Key)...)
	if len(buf) > 24 {
		buf = buf[:TripleDesKeyLength+1]
	}
	return buf
}

// SecretEncrypt 加密
func (t *TripleDesEncrypt) SecretEncrypt(secret interface{}, fields ...interface{}) (string, error) {
	number := 0
	for i := range fields {
		number += fields[i].(int)
	}
	if secret != "" {
		desKey := t.generateTripleDesKey(number)
		ans, err := t.tripleDesEncrypt(cast.ToString(secret), desKey)
		if err != nil {
			return "", err
		}
		return ans, nil
	}
	return "", errors.New("need the secret to encrypt")
}

// SecretDecrypt 解密
func (t *TripleDesEncrypt) SecretDecrypt(secret interface{}, fields ...interface{}) (string, error) {
	number := 0
	for i := range fields {
		number += fields[i].(int)
	}
	if secret != "" {
		aesKey := t.generateTripleDesKey(number)
		b, err := t.tripleDesDecrypt(cast.ToString(secret), aesKey)
		if err != nil {
			return "", nil
		}
		return string(b), nil
	}
	return "", errors.New("need the secret to decrypt")
}

// tripleDesEncrypt 加密
func (t *TripleDesEncrypt) tripleDesEncrypt(origData string, key []byte) (string, error) {
	encodeByte := []byte(origData)
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return "", err
	}

	encodeByte = pkcs5Padding(encodeByte, block.BlockSize())
	blockMode := cipher.NewCBCEncrypter(block, key[:TripleDesKeyBlock])

	crypted := make([]byte, len(encodeByte))
	blockMode.CryptBlocks(crypted, encodeByte)

	hexStr := fmt.Sprintf("%x", crypted)
	return hexStr, nil
}

// tripleDesDecrypt 解密
func (t *TripleDesEncrypt) tripleDesDecrypt(decodeStr string, key []byte) ([]byte, error) {
	decodeBytes, err := hex.DecodeString(decodeStr)

	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, key[:TripleDesKeyBlock])
	origData := make([]byte, len(decodeBytes))
	blockMode.CryptBlocks(origData, decodeBytes)

	origData = pkcs5UnPadding(origData)
	return origData, nil
}
