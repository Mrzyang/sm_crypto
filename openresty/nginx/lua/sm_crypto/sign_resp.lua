local resp_body = ngx.ctx.resp_body
if not resp_body then
    return
end

-- 加载 lua-resty-openssl
local openssl = require "resty.openssl"

-- SM4 加密
local sm4_key = "1234567890abcdef" -- 16 字节密钥
local sm4_iv = "1234567890abcdef" -- 16 字节 IV
local mode = "sm4-cbc"
local cipher = require("resty.openssl.cipher").new(mode)
local encrypted_body = cipher:encrypt(sm4_key, sm4_iv, resp_body, false)

-- 将加密后的报文存储到 ngx.ctx 中,供 body_filter 阶段捕获响应体并替换为密文 使用
ngx.ctx.encrypted_body = encrypted_body

-- SM2 签名
local sm2_private_key_pem = [[
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQg8HLOQ9PlccsWBgNp
ForNIOvr0pFRp7jzUrNj78RbIuahRANCAASeMvuRVyaRFFkFCkrTHEo2xqKvIzp3
sfJjNNf5jyB7m9EVuiz0RpQqNfEk2PP1EpC40stZ351d6cYida6BGT7u
-----END PRIVATE KEY-----
]]

local pkey = require "resty.openssl.pkey"
local digest = require "resty.openssl.digest"

local priv_key, err = pkey.new(sm2_private_key_pem, {
    type = "pr",
    format = "PEM"
})
if not priv_key then
    ngx.say("Failed to load private key: ", err)
    return
end

-- 计算数据的 SM3 哈希值
local hashed = digest.new("sm3"):final(resp_body)

-- 使用私钥对哈希值进行签名
local signature, err = priv_key:sign(hashed, "sm3")
if not signature then
    ngx.say("Failed to sign data: ", err)
    return
end

-- 将签名值插入到 HTTP 响应头中
ngx.header["X-Signature"] = ngx.encode_base64(signature)
