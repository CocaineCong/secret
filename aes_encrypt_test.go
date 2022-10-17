package secret

import (
	"fmt"
	"testing"
)

func TestAesSecret(t *testing.T) {
	specialSign := "asd"
	key := "458796" // key 密钥
	aesEncrypt, _ := NewAesEncrypt(specialSign, key)
	str := aesEncrypt.SecretEncrypt("this is a secret", 12)
	fmt.Println(str)
	ans := aesEncrypt.SecretDecrypt(str, 12)
	fmt.Println(ans)
}
