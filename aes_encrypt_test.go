package secret

import (
	"fmt"
	"testing"
)

func TestAesSecret(t *testing.T) {
	specialSign := "123ads12312adasdasda1"
	key := "458796" // key
	str := "this is a secret"
	a := AesEncodeOFB(specialSign, key, str)
	fmt.Println("a", a)
	b := AesDecodeOFB(specialSign, key, a)
	fmt.Println("b", b)
}

func AesEncodeCFB(specialSign, key, str string) string {
	aesEncrypt, _ := NewAesEncrypt(specialSign, key, "", AesEncrypt192, AesModeTypeCFB)
	return aesEncrypt.SecretEncrypt(str)
}

func AesDecodeCFB(specialSign, key, str string) string {
	aesEncrypt, _ := NewAesEncrypt(specialSign, key, "", AesEncrypt192, AesModeTypeCFB)
	return aesEncrypt.SecretDecrypt(str)
}

func AesEncodeCBC(specialSign, key, str string) string {
	aesEncrypt, _ := NewAesEncrypt(specialSign, key, "", AesEncrypt256, AesModeTypeCBC)
	return aesEncrypt.SecretEncrypt(str)
}

func AesDecodeCBC(specialSign, key, str string) string {
	aesEncrypt, _ := NewAesEncrypt(specialSign, key, "", AesEncrypt256, AesModeTypeCBC)
	return aesEncrypt.SecretDecrypt(str)
}

func AesEncodeOFB(specialSign, key, str string) string {
	aesEncrypt, _ := NewAesEncrypt(specialSign, key, "", AesEncrypt128, AesModeTypeOFB)
	return aesEncrypt.SecretEncrypt(str)
}

func AesDecodeOFB(specialSign, key, str string) string {
	aesEncrypt, _ := NewAesEncrypt(specialSign, key, "", AesEncrypt128, AesModeTypeOFB)
	return aesEncrypt.SecretDecrypt(str)
}
