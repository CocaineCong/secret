package secret

import (
	"fmt"
	"testing"
)

func TestRsaEncrypt(t *testing.T) {
	rsa := NewRsaEncrypt(RsaBits1024, "", "", "", "")
	_ = rsa.SaveRsaKey()
	secret, _ := rsa.RsaEncrypt("this is a secret", rsa.PublishKeyPath)
	srcStr := rsa.EncryptString(secret)
	fmt.Println("src", srcStr)
	srcByte := rsa.DecryptByte(srcStr)
	ans, _ := rsa.RsaDecrypt(srcByte, rsa.PrivateKeyPath)
	fmt.Println("ans", ans)
}
