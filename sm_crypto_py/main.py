from gmssl import sm2, sm3, func
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT
import gmalg
# https://github.com/py-gmssl/py-gmssl 这个项目用的人多，推荐
# https://github.com/ww-rm/gmalg 这里仅仅提取了sm2公司钥生成算法
# 当你生成 SM2 公钥时，如果它显示为 130 个十六进制字符，这通常是因为你使用的是 非压缩公钥格式，而 SM2 的公钥通常包含了压缩格式和非压缩格式两种表示方式。
#
# 1. 非压缩公钥格式
# 在 SM2 和其他椭圆曲线加密算法中，公钥通常由两个坐标 x 和 y 组成，且采用 非压缩格式 时，会在公钥的前面加一个标识符字节，以指示它是一个非压缩格式的公钥。
#
# 非压缩公钥格式：公钥由 x 和 y 坐标的 64 字节组成（32 字节用于 x，32 字节用于 y），再加上一个前导字节 0x04，表示这是非压缩公钥。因此，最终的长度是：
# 1 (前导字节) + 64 (x 和 y 坐标) = 65 字节，也就是 130 个十六进制字符。
# 2. 压缩公钥格式
# 压缩公钥格式在表示公钥时，只使用 x 坐标和一个标志字节（表示 y 坐标的符号，0x02 表示 y 坐标为正，0x03 表示 y 坐标为负）。因此，压缩格式的公钥长度为：
#
# 1 (前导字节) + 32 (x 坐标) = 33 字节，即 66 个十六进制字符。
# 3. 总结
# 非压缩公钥格式：65 字节（130 个十六进制字符），以 0x04 开头。
# 压缩公钥格式：33 字节（66 个十六进制字符），以 0x02 或 0x03 开头。
# 如果你看到的公钥是 130 个十六进制字符，那么它应该是 非压缩格式的公钥。
#
# 代码中如何获取压缩格式公钥
# 如果你想要压缩公钥，你需要确保生成公钥时使用的是压缩格式。例如，在使用 gmssl 或其他加密库时，可以显式地选择压缩公钥格式。如果你自己实现密钥生成，你可以通过以下方式来生成压缩格式的公钥：
#
# # 压缩公钥格式
# compressed_public_key = public_key.get_encoded(True)  # `True` 表示压缩
# 如果使用非压缩格式生成公钥，那么它将自动包含一个 0x04 字节，导致公钥长度为 130 个十六进制字符。

sk, pk = gmalg.SM2().generate_keypair()
#16进制的公钥和私钥
sm2_private_key = sk.hex()
sm2_public_key = pk.hex()
print("sm2私钥：",sm2_private_key)
print("sm2公钥：",sm2_public_key)
private_key = sk.hex()
public_key = pk.hex()
sm2_crypt = sm2.CryptSM2(
    public_key=sm2_public_key, private_key=sm2_private_key)
# 对接java 时验签失败可以使用
# sm2_crypt = sm2.CryptSM2(
#     public_key=public_key, private_key=private_key, asn1=True)
data = b"111" # bytes类型
random_hex_str = func.random_hex(sm2_crypt.para_len)
sign = sm2_crypt.sign(data, random_hex_str) #  16进制
print(sm2_crypt.verify(sign, data))
#assert sm2_crypt.verify(sign, data) #  16进制

# sign_with_sm3和verify_with_sm3
data = b"111" # bytes类型
sign = sm2_crypt.sign_with_sm3(data) #  16进制
assert sm2_crypt.verify_with_sm3(sign, data) #  16进制

# SM3算法
sm3_hash = sm3.sm3_hash(func.bytes_to_list(b"abc"))
print(sm3_hash)

# SM4算法-ECB模式 没有iv，不够安全，iv为128bit，16字节
key = b'3l5butlj26hvv313'
value = b'111'
iv = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
crypt_sm4 = CryptSM4(padding_mode=3) #默认pkcs#7填充

crypt_sm4.set_key(key, SM4_ENCRYPT)
encrypt_value = crypt_sm4.crypt_ecb(value)
print("加密后:"+encrypt_value.hex())
crypt_sm4.set_key(key, SM4_DECRYPT)
decrypt_value = crypt_sm4.crypt_ecb(encrypt_value)
print("解密后:" + decrypt_value.decode('utf-8'))
assert value == decrypt_value

# SM4算法-CBC模式 有iv，安全
crypt_sm4.set_key(key, SM4_ENCRYPT)
encrypt_value = crypt_sm4.crypt_cbc(iv , value)
print("加密后:" + encrypt_value.hex())
crypt_sm4.set_key(key, SM4_DECRYPT)
decrypt_value = crypt_sm4.crypt_cbc(iv , encrypt_value)
print("解密后:" + decrypt_value.decode('utf-8'))
assert value == decrypt_value