package secret

import (
	"fmt"
	"testing"
)

func TestRsaEncrypt(t *testing.T) {
	rsa := NewRsaEncrypt(1024, "", "", "", "")
	rsa.SaveRsaKey()
	secret, _ := rsa.RsaEncoding("this is a secret", rsa.PublishKeyPath)
	fmt.Println(string(secret))
	ans, _ := rsa.RsaDecoding(secret, rsa.PrivateKeyPath)
	fmt.Println(string(ans))
}
