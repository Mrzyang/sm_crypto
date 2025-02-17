## 几种语言的国密算法合集
- 包括sm2，sm3，sm4，几种语言加密出来的一致性还没有测试
- openresty以及插件版本 openresty-1.27.1.1，openssl-3.4.1或Tongsuo-8.4.0（推荐），pcre2-10.45，zlib-1.3.1

## 问题反馈
于2025年2月16日发现，在用openssl-3.4.1连同编译openresty-1.27.1.1时，模块lua-resty-openssl在校验sm2公私钥时会出现无法识别秘钥类型，参考代码/sm_crypto/openresty/site/lualib/resty/openssl/pkey.lua第597行附近如下代码的最后一个子句C.EVP_PKEY_base_id(ctx)会抛异常，导致lua-resty-openssl模块无法正常识别PEM类型的sm2公私钥类型，lua-resty-openssl模块作者反馈是openssl-3.4.1的bug，目前还没有修复，将其替换成阿里巴巴的Tongsuo-8.4.0后，不再出现该问题。
``` lua
  local key_type = OPENSSL_3X and C.EVP_PKEY_get_base_id(ctx) or C.EVP_PKEY_base_id(ctx)
```