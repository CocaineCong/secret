package secret

import "testing"

/*
BenchmarkNewAesEncrypt
BenchmarkNewAesEncrypt-8          586963              1725 ns/op
BenchmarkNewDesEncrypt
BenchmarkNewDesEncrypt-8          250662              5068 ns/op
BenchmarkNew3DesEncrypt
BenchmarkNew3DesEncrypt-8          95594             12498 ns/op
*/
func BenchmarkNewAesEncrypt(b *testing.B) {
	specialSign := "][;,[2psldp0981zx;./"
	key := "458796" // key 密钥
	aesEncrypt, _ := NewAesEncrypt(specialSign, key, "", AesEncrypt192)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ans := aesEncrypt.SecretEncrypt("this is a secret")
		_ = aesEncrypt.SecretDecrypt(ans)
	}
	b.StopTimer()
}

func BenchmarkNewDesEncrypt(b *testing.B) {
	specialSign := "][;,[2psldp0981zx;./"
	key := "458796" // key 密钥
	desEncrypt, _ := NewDesEncrypt(specialSign, key)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ans, _ := desEncrypt.SecretEncrypt("this is a secret", 12)
		_, _ = desEncrypt.SecretDecrypt(ans, 12)
	}
	b.StopTimer()
}

func BenchmarkNew3DesEncrypt(b *testing.B) {
	specialSign := "][;,[2psldp0981zx;./"
	key := "458796" // key 密钥
	tDesEncrypt, _ := NewTripleDesEncrypt(specialSign, key)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ans, _ := tDesEncrypt.SecretEncrypt("this is a secret", 12)
		_, _ = tDesEncrypt.SecretDecrypt(ans, 12)
	}
	b.StopTimer()
}
