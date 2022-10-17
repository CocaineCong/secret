package secret

import (
	"fmt"
	"testing"
)

func TestRsaEncrypt(t *testing.T) {
	rsa := NewRsaEncrypt(RsaBits1024, "", "", "", "")
	_ = rsa.SaveRsaKey()
	secret, _ := rsa.RsaEncrypt("this is a secret", rsa.PublishKeyPath)
	fmt.Println("secret", secret)
	fmt.Println("secret", rsa.EncryptString(secret))
	ans, _ := rsa.RsaDecrypt(secret, rsa.PrivateKeyPath)
	fmt.Println("ans", ans)
	fmt.Println("ans", string(ans))
}
