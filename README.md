# coding make secret secret
提供 对称加密 AES、DES、3DES 以及非对称加密 RSA 的上层封装接口，让您的敏感数据更加容易脱敏并存储

# 使用说明

```go
go get github.com/CocaineCong/secret
```

## AES
我们可以在代码中先指定一段特殊字符串`special sign`，并且传入我们的密钥`key`，来构造我们的AES加密对象。\
我们会基于传进来的` special sign 和 key `进行一个`拼接来进行加密`，解密的时候，只需要用传入**相同的special sign和key**即可。

如以下代码:

```go
specialSign := "][;,[2psldp0981zx;./"
key := "458796" // key 密钥
aesEncrypt, _ := NewAesEncrypt(specialSign, key) // 构建一个aes加密器
```

再传入我们的所需要加密的对象即可,目前只封装了CBC模式,后续我们会支持更多的模式。

```go
str := aesEncrypt.SecretEncrypt("this is a secret")
fmt.Println(str)
ans := aesEncrypt.SecretDecrypt(str)
fmt.Println(ans)
```

这样我们就完成了一次加解密了。

DES、3DES也是类似的

# RSA

RSA 我们需要指定密钥的长度，只能选择规定的密钥长度，在构建对象的时候，可以传入公私钥的名字和路径。如果没有传入名字，那么就是，如果没有传入路径，将会`默认放在当前工作目录的路径下`

指定rsa加密对象，并且保存公私钥

```go
rsa := NewRsaEncrypt(RsaBits1024, "", "", "", "")
_ = rsa.SaveRsaKey() // 保存公私钥
```

对密钥进行加解密，最好存储byte类型，因为string之后可能会乱码。

```go
secret, _ := rsa.RsaEncoding("this is a secret", rsa.PublishKeyPath)
fmt.Println("secret", secret)
ans, _ := rsa.RsaDecoding(secret, rsa.PrivateKeyPath)
fmt.Println(string(ans))
```

# 开源共建

**我们非常欢迎感兴趣的同学一起加入，共同维护这个secret包！**

**`coding make secret secret`**


# 一些疑问？
## 1. 为什么会有这个包？
最主观的原因是没有找到符合我自己业务的加密包，每一次都要手写这些加密的方法，比如填充之类的。再者是想让用户输入的密钥少一点，因为我们的AES加密，如果密钥全部由用户来输入的话，至少要输入16位，所以我们打算在代码层面减少一些用户的负担。

## 2. 部分密钥写在代码里面？安全吗？
其实安全这种东西是相对的，为了便捷我们确实是需要舍弃一些安全，但是也不是完全不完全，毕竟代码是保护的很好的，加密的源代码一般是不会泄漏的，比如这个`special sign`是开发者定义的，可以每个函数方法都设置成不一样的，也能减少数据库被攻击，所造成的数据损失。再者，如果攻击者想真的锲而不舍地攻击的话，那什么加密方法都没用了。

## 3. 这个包适用哪些场景？
推荐在tob的业务使用，加密一些邮箱，手机，身份证等秘密信息，同样的，我们key可以使用数据库的字段，比如主键id来进行填入。


