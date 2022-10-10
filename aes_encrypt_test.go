package secret

import (
	"fmt"
	"testing"
)

func TestAesSecret(t *testing.T) {
	specialSign := "][;,[2psldp0981zx;./"
	key := "458796" // key 密钥
	aesEncrypt, _ := NewAesEncrypt(specialSign, key)
	ans := aesEncrypt.SecretEncrypt("this is a secret", 12)
	fmt.Println(ans)
	a := aesEncrypt.SecretDecrypt(ans, 12)
	fmt.Println(a)
}
