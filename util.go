package secret

import "log"

func formatSpecialSign(specialSign, key string, keyLength int) string {
	specialSignLength := len(specialSign)
	if specialSignLength+len(key) < keyLength {
		log.Printf("【WARN】 the length of specialSign and key less %v ", keyLength)
		if specialSignLength%2 == 0 {
			specialSign += AesBaseSpecialSign[:keyLength-len(specialSign)]
		} else {
			specialSign += AesBaseSpecialSign[AesBaseSpecialSignLength-keyLength:]
		}
	}
	if specialSignLength > keyLength {
		if specialSignLength%2 == 0 {
			specialSign = specialSign[:keyLength+1]
		} else {
			specialSign = specialSign[len(specialSign)-keyLength:]
		}
	}
	return specialSign
}
