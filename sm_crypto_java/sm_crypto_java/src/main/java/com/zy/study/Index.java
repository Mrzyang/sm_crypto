package com.zy.study;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.*;

public class Index {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws Exception {
        // 1. SM2 密钥对生成
        AsymmetricCipherKeyPair keyPair = generateSM2KeyPair();
        ECPrivateKeyParameters privateKey = (ECPrivateKeyParameters) keyPair.getPrivate();
        ECPublicKeyParameters publicKey = (ECPublicKeyParameters) keyPair.getPublic();

        System.out.println("SM2 私钥: " + Hex.toHexString(privateKey.getD().toByteArray()));
        System.out.println("SM2 公钥: " + Hex.toHexString(publicKey.getQ().getEncoded(false)));

        // 2. SM2 签名与验签
        String message = "Hello, SM2!";
        byte[] signature = sm2Sign(privateKey, message.getBytes());
        System.out.println("SM2 签名: " + Hex.toHexString(signature));

        boolean verifyResult = sm2Verify(publicKey, message.getBytes(), signature);
        System.out.println("SM2 验签结果: " + verifyResult);

        // 3. SM3 哈希摘要
        byte[] sm3Hash = sm3Hash(message.getBytes());
        System.out.println("SM3 哈希值: " + Hex.toHexString(sm3Hash));

        // 4. SM4 密钥和 IV 生成
        byte[] sm4Key = generateSM4Key();
        byte[] iv = generateIV();
        System.out.println("SM4 密钥: " + Hex.toHexString(sm4Key));
        System.out.println("SM4 IV: " + Hex.toHexString(iv));

        // 5. SM4 对称加密与解密 (CBC 模式，PKCS#7 填充)
        byte[] encrypted = sm4Encrypt(sm4Key, iv, message.getBytes());
        System.out.println("SM4 加密结果: " + Hex.toHexString(encrypted));

        byte[] decrypted = sm4Decrypt(sm4Key, iv, encrypted);
        System.out.println("SM4 解密结果: " + new String(decrypted));
    }

    // 生成 SM2 密钥对
    public static AsymmetricCipherKeyPair generateSM2KeyPair() {
        ECKeyPairGenerator generator = new ECKeyPairGenerator();
        ECKeyGenerationParameters keyGenParams = new ECKeyGenerationParameters(
                new ECDomainParameters(SM2Util.CURVE, SM2Util.G, SM2Util.N, SM2Util.H),
                new SecureRandom());
        generator.init(keyGenParams);
        return generator.generateKeyPair();
    }

    // SM2 签名
    public static byte[] sm2Sign(ECPrivateKeyParameters privateKey, byte[] data) throws CryptoException {
        SM2Signer signer = new SM2Signer();
        signer.init(true, privateKey);
        signer.update(data, 0, data.length);
        return signer.generateSignature();
    }

    // SM2 验签
    public static boolean sm2Verify(ECPublicKeyParameters publicKey, byte[] data, byte[] signature) {
        SM2Signer signer = new SM2Signer();
        signer.init(false, publicKey);
        signer.update(data, 0, data.length);
        return signer.verifySignature(signature);
    }

    // SM3 哈希摘要
    public static byte[] sm3Hash(byte[] data) throws NoSuchAlgorithmException, NoSuchProviderException {
        MessageDigest digest = MessageDigest.getInstance("SM3", "BC");
        return digest.digest(data);
    }

    // 生成 SM4 密钥
    public static byte[] generateSM4Key() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("SM4", "BC");
        keyGenerator.init(128); // SM4 密钥长度为 128 位
        SecretKey secretKey = keyGenerator.generateKey();
        return secretKey.getEncoded();
    }

    // 生成 IV
    public static byte[] generateIV() {
        byte[] iv = new byte[16]; // IV 长度为 16 字节
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    // SM4 加密 (CBC 模式，PKCS#7 填充)
    public static byte[] sm4Encrypt(byte[] key, byte[] iv, byte[] data) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(key, "SM4");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance("SM4/CBC/PKCS7Padding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
        return cipher.doFinal(data);
    }

    // SM4 解密 (CBC 模式，PKCS#7 填充)
    public static byte[] sm4Decrypt(byte[] key, byte[] iv, byte[] encryptedData) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(key, "SM4");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance("SM4/CBC/PKCS7Padding", "BC");
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        return cipher.doFinal(encryptedData);
    }
}

// SM2 参数工具类
class SM2Util {
    public static final ECCurve CURVE = new ECCurve.Fp(
            new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16),
            new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16),
            new BigInteger("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16));
    public static final ECPoint G = CURVE.createPoint(
            new BigInteger("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16),
            new BigInteger("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16));
    public static final BigInteger N = new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16);
    public static final BigInteger H = BigInteger.valueOf(1);
}