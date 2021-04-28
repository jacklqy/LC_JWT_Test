# LC_JWT_Test
支持JWT对称加密HS256和非对称加密RS256鉴权授权

--加密算法主要是建立信任的基础-》证明来源

一、对称加密：同一个秘钥加密解密。必须有密码才能加密，必须有秘钥才能解密。如果token能被解密，就能证明来源，建立信任关系后，在通过token解密出来的东西，进行校验是否有效。
  
  a)对称速度快--秘钥不安全---内部用
  
  b)HS256 (带有 SHA-256 的 HMAC 是一种对称算法, 双方之间仅共享一个 密钥。由于使用相同的密钥生成签名和验证签名, 因此必须注意确保密钥不被泄密。
  
  c)防篡改：加密--解密，只要能解密，就能证明来源。解密后比对内容，看是否篡改。验签
  
  d)保证信息来自于张三，同时张三的信息没有被修改。

二、非对称加密：一组秘钥对(私钥加密+公钥解密)，由私钥加密的内容，提供公钥别人获取来解密，只要能解密，就能证明来源，建立信任关系后，在通过token解密出来的东西，进行校验是否有效。
  
  a)非对称速度慢--秘钥安全---第三方用
  
  b)RS256 (采用SHA-256 的 RSA 签名) 是一种非对称算法, 它使用公共/私钥对: 标识提供方采用私钥生成签名, JWT 的使用方获取公钥以验证签名。由于公钥 (与私钥相比) 不需要保护, 因此大多数标识提供方使其易于使用方获取和使用 (通常通过一个元数据URL)

原始版/加密版--》比对


token泄露怎么办？
  
  a)重放攻击，别人拿到请求后，重新请求
  
  b)修改密码了，希望token失效
  
  c)token滑动过期，如果token在用就延迟过期

问题很多，但是大部分解决不了，是由本质决定的，因为鉴权中心是独立的服务，没有和客户端实时交互。腾讯QQ和微信第三方登陆一样

解决方案：鉴权中心和相应客户端通过redis建立关联。

A：生成token是---除了生成token(含guid)---还生成一个guid+用户id---写入redis。验证token时---拿guid去redis校验

改密码---redis那一项数据---之前的token给删除掉/过期/无效

验证旧token---发现过期

验证新token就验证通过

这不就代表着，客户端和鉴权中心通信了，违背了JWT的设计初衷啦(去中心化)，但是没法，如果要实现这些，只能这样...

B：减少token有效期---降低伤害







