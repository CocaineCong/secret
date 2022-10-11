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
We can use a special string `special sign` and `key` in our code to construct our AES encryption object. \

```go
specialSign := "][;,[2psldp0981zx;./"
key := "458796" // key 
aesEncrypt, _ := NewAesEncrypt(specialSign, key) //an aes encryption obj
```

We will perform a splicing to encrypt based on the `special sign and key` passed in. \
When decrypting, you only need to use the **same special sign and key** passed in.

```go
str := aesEncrypt.SecretEncrypt("this is a secret")
fmt.Println(str)
ans := aesEncrypt.SecretDecrypt(str)
fmt.Println(ans)
```

In this way, we have completed an encryption and decryption. \
DES and 3DES are also similar.



## Contributing
We very much welcome interested developers to join and maintain this secret package together!


Small note: If editing the Readme, please conform to the [standard-readme](https://github.com/RichardLitt/standard-readme) specification.



