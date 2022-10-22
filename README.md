# Coding Make Secret Secret

![banner](https://img.shields.io/aur/maintainer/secret)
![go-version](https://img.shields.io/github/go-mod/go-version/CocaineCong/secret)
[![license](https://img.shields.io/github/license/CocaineCong/secret.svg)](LICENSE)
[![standard-readme compliant](https://img.shields.io/badge/readme%20style-standard-brightgreen.svg?style=flat-square)](https://github.com/RichardLitt/standard-readme)

- zh_cn [简体中文](README.md)
- en [English](README.EN.md)

# 写在前面
提供 对称加密 AES、DES、3DES 以及非对称加密 RSA 的上层封装接口，让您的敏感数据更加容易脱敏并存储

# 使用说明
```go
go get github.com/CocaineCong/secret
```

## AES
我们可以在代码中先指定一段特殊字符串`special sign`，并且传入我们的密钥`key`，来构造我们的AES加密对象。\
我们会基于传进来的` special sign 和 key `进行一个`拼接来进行加密`，解密的时候，只需要用传入**相同的special sign和key**即可。

> ` specialSign 和 key 加起来的长度小于 对应所需要加密的密钥的长度 `，就会进行填充，并且`多于对应密钥的位数`，就会对根据密钥的长度是奇数还是偶数来判断，去除前缀还是后缀，来凑出对应密钥所需要的位数长度。

如果 specialSign 和 key 加起来的长度小于 对应所需要加密的密钥的长度 。**我们提醒，因为公开了部分密钥，容易被攻破有风险。**
```
the length of specialSign and key less 24 
```

另外我们可以指定AES加密的长度：AES-128、AES-192、AES-256。\
以及加密的模式：BCB、CFB、CTR、OFB。后续我们会新增更多的加密模式。

示例代码如下:\
我们传入 specialSign、key、iv(固定16位)、选择加密的密钥长度，选择加密的模式。\
如果不想传入 iv 初始向量，我们就默认是密钥的16位。

```go
specialSign := "][;,[2psldp0981zx;./"
key := "458796" // key 密钥
aesEncrypt, _ := NewAesEncrypt(specialSign, key, "", AesEncrypt128, AesModeTypeCTR)
```

具体加解密过程如下：

```go
str := aesEncrypt.SecretEncrypt("this is a secret")
fmt.Println(str)
ans := aesEncrypt.SecretDecrypt(str)
fmt.Println(ans)
```

结果如下：

```go
14be940cf428be2f5432018e3c885370029a0412d4b6be2d8fc96f33b02905f4
this is a secret
```

这样我们就完成了一次加解密了。
## DES & 3DES

DES、3DES 就没有支持那么多的模式了，**因为这两种算法其实都已经是不安全的了，** 但是为大家提供更多的选择，才放在这里的。

比较简约，传入 specialSign 和 key 就可以构造 DES加密对象 了　

```go
specialSign := "11111111111"
key := "458796" // key 密钥
des, _ := NewDesEncrypt(specialSign, key)
```

加解密

```go
str, err := des.SecretEncrypt("this is a secret")
if err != nil {
    fmt.Println("Err", err)
}
fmt.Println(str)
ans, _ := des.SecretDecrypt(str)
fmt.Println(ans)
```

结果如下:

```go
9c0e547c7eae91b2c7d84527fc3170af52ec01a914f9bf60
this is a secret
```

## RSA

RSA 我们需要指定密钥的长度，只能选择规定的密钥长度，在构建对象的时候，可以传入公私钥的名字和路径。如果没有传入名字，那么就是默认公钥是`publish.pem`，私钥是`private.pem`。如果没有传入路径，将会`默认放在当前工作目录的路径下`

指定rsa加密对象，并且保存公私钥

```go
rsa := NewRsaEncrypt(RsaBits1024, "", "", "", "")
_ = rsa.SaveRsaKey() // 保存公私钥
```

使用公钥对这条语句进行加密

```go
secret, _ := rsa.RsaEncrypt("this is a secret", rsa.PublishKeyPath)
fmt.Println("secret", secret)
```

注意加密过后的我们获取的是一个` byte 类型`，如果我们想要 string 类型，我们就需要执行下面一个代码进行转换，转成string类型。

```go
srcStr := rsa.EncryptString(secret)
```

当然我们加密同样也需要传入 byte 类型，所以要对这个 string 类型转成 byte 类型。

```go
srcByte := rsa.DecryptByte(srcStr)
```

转成byte类型之后，我们才进行解密

```go
ans, _ := rsa.RsaDecrypt(secret, rsa.PrivateKeyPath)
fmt.Println(ans)
```

这次返回的是string类型的了

结果如下：

```go
src aUpVbJqOYvcDil7PmGRZ5iaOJ1oAhWE84uqlUZ5REqZFTW/p/enSTrA/dSGC9puHWuVesFTkYAl5dJtfNAHlCdODOP9xzj1gSQVSQblPFxUnRq1DwSgI3Y4ktApicuD26Pm5ViC5rYP9uCqNTo6Ewo1QQhs+c25EVNOzFHijYQ4=
ans this is a secret
```

# 开源共建

**非常欢迎感兴趣的开发者一起加入，共同维护这个secret包！**

**`coding make secret secret`**


# 一些疑问？
## 1. 为什么会有这个包？
最主观的原因是没有找到符合我自己业务的加密包，每一次都要手写这些加密的方法，比如填充之类的。再者是想让用户输入的密钥少一点，因为我们的AES加密，如果密钥全部由用户来输入的话，至少要输入16位，所以我们打算在代码层面减少一些用户的负担。

## 2. 部分密钥写在代码里面？安全吗？
其实安全这种东西是相对的，为了便捷我们确实是需要舍弃一些安全，但是也不是完全不完全，毕竟代码是保护的很好的，加密的源代码一般是不会泄漏的，比如这个`special sign`是开发者定义的，可以每个函数方法都设置成不一样的，也能减少数据库被攻击，所造成的数据损失。再者，如果攻击者想真的锲而不舍地攻击的话，那什么加密方法都没用了。

## 3. 这个包适用哪些场景？
推荐在tob的业务使用，加密一些邮箱，手机，身份证等秘密信息，同样的，我们key可以使用数据库的字段，比如主键id来进行填入。


