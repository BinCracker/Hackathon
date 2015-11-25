##使用CBC-MAC进行哈希
有时人们尝试使用 CBC-MAC 作为哈希函数
这是一个坏主意，Matt Green 解释说：
> 为了使得一个长的信息变短：密码哈希函数是一个公开的函数(没有私钥)，并使它拥有碰撞抵抗的性质(找到两个拥有相同哈希值的不同消息是困难的)。
> 而 MAC 是一个使用密钥的函数，典型的，提供消息的不可伪造性，这是一种不同的性质，而且，它保证密钥必须是秘密的。

让我们进行一个简单的练习。  

哈希函数经常被用来进行代码验证，下面这个`JavaScript`代码片段：  
```JavaScript
alert('MZA who was that?');
```
使用 CBC-MAC 哈希值是`296b8d7cb78a243dda4d0a61d33bbdd1`，key 是`YELLOW SUBMARINE`，IV为0。  
伪造一个有效的JavaScript片段，来 alert "Ayo, the Wu is back!"，并且哈希出相同的哈希值。请确保你的代码可以运行在浏览器中。  
###额外的分数
编写 JavaScript 代码下载你的文件，检查它的 CBC-MAC，如果得到了期望的哈希值，就把它插入到 DOM 中。
