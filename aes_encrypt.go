package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"log"

	"github.com/spf13/cast"
)

type AesKeyType uint64  // 密钥类型
type AesModeType string // 加密模式类型

const (
	// 密钥长度
	AesKeyLength128 = 16
	AesKeyLength192 = 24
	AesKeyLength256 = 32

	// IVLength 初始向量 16 字节
	IVLength = 16
)

// AES 密钥类型
const (
	AesEncrypt128 AesKeyType = 128
	AesEncrypt192 AesKeyType = 192
	AesEncrypt256 AesKeyType = 256
)

// AES 加密模式
const (
	AesModeTypeCBC AesModeType = "CBC" // Cipher Block Chaining
	AesModeTypeCFB AesModeType = "CFB" // Cipher FeedBack
	AesModeTypeCTR AesModeType = "CTR" // Counter
	AesModeTypeOFB AesModeType = "OFB" // Output FeedBack
)

var AesBaseSpecialSign = "!@a%$bc.de,l%$fgqweruriskn&#@xl784zm321apgiw"
var AesBaseSpecialSignLength = len(AesBaseSpecialSign)

type AesEncrypt struct {
	SpecialSign string // 加解密都会基于这一串字符,如果没有会基于 AesBaseSpecialSign.
	Key         string // 密钥，建议是 5-8位的密钥

	IV string // 初始向量 16 字节

	AesModeType AesModeType // 加密类型

	AesKeyType   AesKeyType // 加密类型
	AesKey       []byte     // AES 密钥
	AesKeyLength int        // 加密长度

	PlainTextLength int // 加密的长度
}

func NewAesEncrypt(specialSign, key, iv string, aesKeyType AesKeyType, aesModeType AesModeType) (*AesEncrypt, error) {
	if specialSign == "" {
		specialSign = AesBaseSpecialSign
	}

	var aesKeyLength int
	switch aesKeyType {
	case AesEncrypt128:
		aesKeyLength = AesKeyLength128
	case AesEncrypt192:
		aesKeyLength = AesKeyLength192
	case AesEncrypt256:
		aesKeyLength = AesKeyLength256
	default:
		return nil, errors.New("AES Key Type Error")
	}

	specialSignLength := len(specialSign)
	if specialSignLength+len(key) < aesKeyLength {
		log.Printf("【WARN】 the length of specialSign and key less %v ", aesKeyLength)
		if specialSignLength%2 == 0 {
			specialSign += AesBaseSpecialSign[:aesKeyLength-len(specialSign)]
		} else {
			specialSign += AesBaseSpecialSign[AesBaseSpecialSignLength-aesKeyLength:]
		}
	}
	if specialSignLength > aesKeyLength {
		if specialSignLength%2 == 0 {
			specialSign = specialSign[:aesKeyLength+1]
		} else {
			specialSign = specialSign[len(specialSign)-aesKeyLength:]
		}
	}
	if key == "" {
		return nil, errors.New("need the key to encrypt, please add it. ")
	}

	if iv == "" {
		iv = specialSign + key
	}

	if len(iv) > IVLength {
		iv = iv[:IVLength]
	}

	return &AesEncrypt{
		SpecialSign:  specialSign,
		Key:          key,
		IV:           iv,
		AesModeType:  aesModeType,
		AesKeyType:   aesKeyType,
		AesKeyLength: aesKeyLength,
	}, nil
}

// GetPrefix 根据长短来判断前缀
func (a *AesEncrypt) getPrefix(length int) string {
	if len(a.SpecialSign)%2 == 0 {
		return a.SpecialSign[len(a.SpecialSign)-length:]
	}
	return a.SpecialSign[:length]
}

// GenerateAesKey 生成AES密钥
func (a *AesEncrypt) generateAesKey() []byte {
	length := a.AesKeyLength - len(a.Key)
	buf := make([]byte, 0, a.AesKeyLength)
	prefix := a.getPrefix(length)
	buf = append(buf, []byte(prefix)...)
	buf = append(buf, []byte(a.Key)...)
	return buf
}

// SecretEncrypt 加密
func (a *AesEncrypt) SecretEncrypt(secret interface{}) string {
	if secret != "" {
		a.AesKey = a.generateAesKey()
		str := cast.ToString(secret)
		a.PlainTextLength = len(str)
		ans, _ := a.aesEncrypt(str)
		return ans
	}
	return ""
}

// SecretDecrypt 解密
func (a *AesEncrypt) SecretDecrypt(secret interface{}) string {
	if secret != "" {
		a.AesKey = a.generateAesKey()
		b, _ := a.aesDecrypt(cast.ToString(secret))
		return b
	}
	return ""
}

// AesEncrypt AES加密
func (a *AesEncrypt) aesEncrypt(encodeStr string) (string, error) {
	block, err := aes.NewCipher(a.AesKey)
	if err != nil {
		return "", err
	}

	switch a.AesModeType {
	case AesModeTypeCBC:
		return a.aesEncrypterCBC(encodeStr, block)
	case AesModeTypeCFB:
		return a.aesEncrypterCFB(encodeStr, block)
	case AesModeTypeCTR:
		return a.aesEncrypter(encodeStr, block, AesModeTypeCTR)
	case AesModeTypeOFB:
		return a.aesEncrypter(encodeStr, block, AesModeTypeOFB)
	}
	return "", nil
}

// AesDecrypt AES 解密
func (a *AesEncrypt) aesDecrypt(decodeStr string) (string, error) {
	decodeBytes, err := hex.DecodeString(decodeStr)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(a.AesKey)
	if err != nil {
		return "", err
	}

	switch a.AesModeType {
	case AesModeTypeCBC:
		return a.aesDecrypterCBC(decodeBytes, block)
	case AesModeTypeCFB:
		return a.aesDecrypterCFB(decodeBytes, block)
	case AesModeTypeCTR:
		return a.aesDecrypter(decodeBytes, block, AesModeTypeCTR)
	case AesModeTypeOFB:
		return a.aesDecrypter(decodeBytes, block, AesModeTypeOFB)
	}
	return "", nil
}

// aesEncrypterCBC CBC 模式的加密
func (a *AesEncrypt) aesEncrypterCBC(encodeStr string, block cipher.Block) (string, error) {
	encodeByte := []byte(encodeStr)
	encodeByte = pkcs5Padding(encodeByte, block.BlockSize())
	blockMode := cipher.NewCBCEncrypter(block, []byte(a.IV))
	crypted := make([]byte, len(encodeByte))
	blockMode.CryptBlocks(crypted, encodeByte)
	return hex.EncodeToString(crypted), nil
}

// aesDecrypterCBC CBC 模式的解密
func (a *AesEncrypt) aesDecrypterCBC(decodeBytes []byte, block cipher.Block) (string, error) {
	blockMode := cipher.NewCBCDecrypter(block, []byte(a.IV))
	blockMode.CryptBlocks(decodeBytes, decodeBytes)
	return string(pkcs5UnPadding(decodeBytes)), nil
}

// aesEncrypterCFB CFB 模式的加密
func (a *AesEncrypt) aesEncrypterCFB(encodeStr string, block cipher.Block) (string, error) {
	cipherText := make([]byte, a.PlainTextLength)
	cfb := cipher.NewCFBEncrypter(block, []byte(a.IV))
	copy(cipherText, encodeStr)
	cfb.XORKeyStream(cipherText, cipherText)
	return hex.EncodeToString(cipherText), nil
}

// aesDecrypterCFB CFB 模式的解密
func (a *AesEncrypt) aesDecrypterCFB(decodeBytes []byte, block cipher.Block) (string, error) {
	plaintextCopy := make([]byte, a.PlainTextLength)
	m := cipher.NewCFBDecrypter(block, []byte(a.IV))
	copy(plaintextCopy, decodeBytes)
	m.XORKeyStream(plaintextCopy, plaintextCopy)
	return string(plaintextCopy), nil
}

// aesEncrypter CTR OR OFB 模式的加密
func (a *AesEncrypt) aesEncrypter(encodeStr string, block cipher.Block, mode AesModeType) (string, error) {
	cipherText := make([]byte, a.PlainTextLength)
	m := cipher.NewCTR(block, []byte(a.IV))
	if mode == AesModeTypeCFB {
		m = cipher.NewOFB(block, []byte(a.IV))
	}
	copy(cipherText, encodeStr)
	m.XORKeyStream(cipherText, cipherText)
	return hex.EncodeToString(cipherText), nil
}

// aesDecrypter CTR OR OFB 模式的加密
func (a *AesEncrypt) aesDecrypter(decodeBytes []byte, block cipher.Block, mode AesModeType) (string, error) {
	m := cipher.NewCTR(block, []byte(a.IV))
	if mode == AesModeTypeCFB {
		m = cipher.NewOFB(block, []byte(a.IV))
	}
	plainTextCopy := make([]byte, a.PlainTextLength)
	copy(plainTextCopy, decodeBytes)
	m.XORKeyStream(plainTextCopy, plainTextCopy)
	return string(plainTextCopy), nil
}
