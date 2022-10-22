package secret

import (
	"fmt"
	"testing"
)

func TestAesSecret(t *testing.T) {
	specialSign := "a1231243124124314vczxfda124sd"
	key := "458796" // key 密钥
	aesEncrypt, _ := NewAesEncrypt(specialSign, key, "", AesEncrypt128, AesModeTypeCTR)
	str := aesEncrypt.SecretEncrypt("this is a secret")
	fmt.Println(str)
	ans := aesEncrypt.SecretDecrypt(str)
	fmt.Println(ans)
}
