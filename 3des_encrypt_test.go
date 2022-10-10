package secret

import (
	"fmt"
	"testing"
)

func Test3DesEncrypt(t *testing.T) {
	specialSign := "][;,[2psldp0981zx;./"
	key := "458796" // key 密钥
	tDesEncrypt, _ := NewTripleDesEncrypt(specialSign, key)
	ans, _ := tDesEncrypt.SecretEncrypt("this is a secret", 12)
	fmt.Println(ans)
	a, _ := tDesEncrypt.SecretDecrypt(ans, 12)
	fmt.Println(a)
}
