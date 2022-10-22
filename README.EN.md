# Coding Make Secret Secret


![banner](https://img.shields.io/aur/maintainer/secret)
![go-version](https://img.shields.io/github/go-mod/go-version/CocaineCong/secret)
[![license](https://img.shields.io/github/license/CocaineCong/secret.svg)](LICENSE)
[![standard-readme compliant](https://img.shields.io/badge/readme%20style-standard-brightgreen.svg?style=flat-square)](https://github.com/RichardLitt/standard-readme)

# README

- zh_cn [简体中文](README.md)
- en [English](README.EN.md)

# Background
Provide the interface of symmetric encryption AES/DES/3DES and asymmetric encryption RSA, making your sensitive data easier to desensitize and store.

## Table of Contents

- [Install](#install)
- [Usage](#usage)
- [Contributing](#contributing)



## Install
You can install this package like this.
```go
go get github.com/CocaineCong/secret
```

## Usage
### AES
We can use a special string `special sign` and `key` in our code to construct our AES encryption object. \

In addition we can specify the length of AES encryption: AES-128, AES-192, AES-256. \
And the encryption mode: `BCB, CFB, CTR, OFB`. We will add more encryption modes in the future.

We input specialSign, key, iv (fixed 16 bits), select the encrypted key length, and select the encryption mode. \
If we don't want to input the iv initial vector, we default to 16 bits of the key.

```go
specialSign := "][;,[2psldp0981zx;./"
key := "458796" // key 
aesEncrypt, _ := NewAesEncrypt(specialSign, key, "", AesEncrypt128, AesModeTypeCTR)  //an aes encryption obj
```

We will perform a splicing to encrypt based on the `special sign and key` passed in. \
When decrypting, you only need to use the **same special sign and key** passed in.

```go
str := aesEncrypt.SecretEncrypt("this is a secret")
fmt.Println(str)
ans := aesEncrypt.SecretDecrypt(str)
fmt.Println(ans)
```

result:

```go
14be940cf428be2f5432018e3c885370029a0412d4b6be2d8fc96f33b02905f4
this is a secret
```

In this way, we have completed an encryption and decryption. \

### DES & 3DES
DES and 3DES do not support so many modes, **because these two algorithms are already insecure,** but they are here to provide you with more choices.

Relatively simple, pass in specialSign and key to construct a DES encryption object

```go
specialSign := "11111111111"
key := "458796" // key 密钥
des, _ := NewDesEncrypt(specialSign, key)
```

Encryption and decryption

```go
str, err := des.SecretEncrypt("this is a secret")
if err != nil {
    fmt.Println("Err", err)
}
fmt.Println(str)
ans, _ := des.SecretDecrypt(str)
fmt.Println(ans)
```

result:

```go
9c0e547c7eae91b2c7d84527fc3170af52ec01a914f9bf60
this is a secret
```


### RSA
RSA we need to specify `the length of the key`, can only select `the specified length of the key`, when building the object, you can input` the name and path of the public and private key`. If no name is input, the default `public key is publish.pem and the private key is private.pem`. If no path is passed in, it will `default to the path of the current working directory`

Specify an rsa encryption object and save the public and private keys

```go
rsa := NewRsaEncrypt(RsaBits1024, "", "", "", "")
_ = rsa.SaveRsaKey() // 保存公私钥
```

Encrypt this statement with the public key

```go
secret, _ := rsa.RsaEncrypt("this is a secret", rsa.PublishKeyPath)
fmt.Println("secret", secret)
```

Note that what we get after encryption is a `byte type`. If we want a string type, we need to execute the following code to convert it into a string type.

```go
srcStr := rsa.EncryptString(secret)
```

Of course, we also need to pass in byte type for encryption, so we need to convert this string type to byte type.

```go
srcByte := rsa.DecryptByte(srcStr)
```

After converting to byte type, we decrypt it

```go
ans, _ := rsa.RsaDecrypt(secret, rsa.PrivateKeyPath)
fmt.Println(ans)
```

It will return a string type.

result：
```go
src aUpVbJqOYvcDil7PmGRZ5iaOJ1oAhWE84uqlUZ5REqZFTW/p/enSTrA/dSGC9puHWuVesFTkYAl5dJtfNAHlCdODOP9xzj1gSQVSQblPFxUnRq1DwSgI3Y4ktApicuD26Pm5ViC5rYP9uCqNTo6Ewo1QQhs+c25EVNOzFHijYQ4=
ans this is a secret
```

## Contributing
We very much welcome interested developers to join and maintain this secret package together!




