package secret

import (
	"fmt"
	"testing"
)

func TestDesSecret(t *testing.T) {
	specialSign := ""
	key := "458796" // key 密钥
	des, _ := NewDesEncrypt(specialSign, key)
	str, err := des.SecretEncrypt("this is a secret")
	if err != nil {
		fmt.Println("Err", err)
	}
	fmt.Println(str)
	ans, _ := des.SecretDecrypt(str)
	fmt.Println(ans)
}
