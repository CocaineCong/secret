package secret

import (
	"fmt"
	"testing"
)

func TestRsaEncrypt(t *testing.T) {
	rsa := NewRsaEncrypt(RsaBits1024, "", "", "", "")
	_ = rsa.SaveRsaKey()
	secret, _ := rsa.RsaEncoding("this is a secret", rsa.PublishKeyPath)
	fmt.Println("secret", secret)
	ans, _ := rsa.RsaDecoding(secret, rsa.PrivateKeyPath)
	fmt.Println(string(ans))
}