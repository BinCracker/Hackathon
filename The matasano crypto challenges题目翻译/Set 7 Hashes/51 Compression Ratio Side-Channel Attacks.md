##压缩比边信道攻击
互联网流量通常是压缩形式，以节省带宽。直到最近，这包括HTTPS头，以及响应的内容。  

为什么这很重要？  

如果你是一个攻击者，并且：  
1. 拥有部分明文的知识  
2. 可以控制部分明文  
3. 可以访问 oracle 压缩器(compression oracle)  

你就有很大的机会去还原出你不知道的明文信息。  

什么是 oracle 压缩器？你给它一些输入，它告诉你有多少完整的数据压缩，也就是，输出结果的长度。  

这同我们在 set 4 中进行的时间攻击很像，在 set 4 中我们使用边信道攻击来攻击密码机制自身以获得优势。  

方案：你运行中间人攻击偷取到了安全 session cookie，你可以注入恶意代码来使你可以产生任意请求并观察结果。(细节并不很重要，只需要大概)  

所以，写这样的 oracle 代码：  
`oracle(P) -> length(encrypt(compress(format_request(P))))`  

请求格式如下：  
```
POST / HTTP/1.1
Host: hapless.com
Cookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=
Content-Length: ((len(P)))
((P))
```
(假装你看不见这个 session id，你是攻击者。)  

使用 zlib 或是其他什么压缩。  

加密，实际上对于我们的目的无关紧要，不过这是一个游戏，仅仅使用流密码，假装是经销商的选择，对每一个 oracle 数据块使用随机的 key/IV 对。  

然后返回字节的长度。  

现在，这里的想法是使用压缩库来泄漏信息。一个 payload "sessionid=T" 应当比说 "sessionid=S" 要好一点。  

这里有一个复杂的因素，DEFLATE 算法操作单个的比特，但是最终的消息长度是字节，即使你找到了一个更好的压缩，也不得不跨越字节边界的不同，这是一个问题。  

你也许会收到一些偶然的误报。  

不要担心，我对你很有信心。  

使用 oracle 压缩器来还原出 session id。  

我会等你。  

做完了？好的。  

把流密码换成 CBC 再做一遍。
