package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/sm3"
	"github.com/tjfoc/gmsm/sm4"
	"io"
)

// 生成SM2公私钥对
func generateSM2KeyPair() (*sm2.PrivateKey, *sm2.PublicKey, error) {
	privateKey, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	publicKey := &privateKey.PublicKey
	return privateKey, publicKey, nil
}

// SM2签名
func sm2Sign(privateKey *sm2.PrivateKey, data []byte) ([]byte, error) {
	signature, err := privateKey.Sign(rand.Reader, data, nil)
	if err != nil {
		return nil, err
	}
	return signature, nil
}

// SM2验签
func sm2Verify(publicKey *sm2.PublicKey, data, signature []byte) bool {
	return publicKey.Verify(data, signature)
}

// SM3哈希摘要
func sm3Hash(data []byte) string {
	hash := sm3.New()
	hash.Write(data)
	return hex.EncodeToString(hash.Sum(nil))
}

// 生成SM4密钥和IV
func generateSM4KeyAndIV() ([]byte, []byte, error) {
	key := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, nil, err
	}

	iv := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, nil, err
	}

	return key, iv, nil
}

// SM4 CBC模式加密 (PKCS#7填充)
func sm4EncryptCBC(key, iv, data []byte) ([]byte, error) {
	err := sm4.SetIV(iv) //设置SM4算法实现的IV值,不设置则使用默认值
	if err != nil {
		fmt.Println("sm4 setIV error:%s", err)
		return nil, err
	}
	encryptedData, err := sm4.Sm4Cbc(key, data, true) //sm4Ecb模式pksc7填充加密
	if err != nil {
		fmt.Println("sm4 enc error:%s", err)
		return nil, err
	}
	fmt.Printf("ecbMsg = %x\n", encryptedData)
	return encryptedData, nil
}

// SM4 CBC模式解密 (PKCS#7填充)
func sm4DecryptCBC(key, iv, encryptedData []byte) ([]byte, error) {
	err := sm4.SetIV(iv) //设置SM4算法实现的IV值,不设置则使用默认值
	if err != nil {
		fmt.Println("sm4 setIV error:%s", err)
		return nil, err
	}
	decrypted, err := sm4.Sm4Cbc(key, encryptedData, false) //sm4Ecb模式pksc7填充解密
	if err != nil {
		fmt.Println("sm4 dec error:%s", err)
		return nil, err
	}
	fmt.Printf("cbcDec = %x\n", decrypted)

	return decrypted, nil
}

func main() {
	// 生成SM2公私钥对
	privateKey, publicKey, err := generateSM2KeyPair()
	if err != nil {
		fmt.Println("生成SM2公私钥对失败:", err)
		return
	}
	fmt.Println("SM2私钥:", hex.EncodeToString(privateKey.D.Bytes()))
	fmt.Println("SM2公钥:", hex.EncodeToString(publicKey.X.Bytes())+hex.EncodeToString(publicKey.Y.Bytes()))

	// SM2签名和验签
	data := []byte("Hello, SM2!")
	signature, err := sm2Sign(privateKey, data)
	if err != nil {
		fmt.Println("SM2签名失败:", err)
		return
	}
	fmt.Println("SM2签名:", hex.EncodeToString(signature))

	isValid := sm2Verify(publicKey, data, signature)
	fmt.Println("SM2验签结果:", isValid)

	// SM3哈希摘要
	hash := sm3Hash(data)
	fmt.Println("SM3哈希:", hash)

	// 生成SM4密钥和IV
	sm4Key, sm4IV, err := generateSM4KeyAndIV()
	if err != nil {
		fmt.Println("生成SM4密钥和IV失败:", err)
		return
	}
	fmt.Println("SM4密钥:", hex.EncodeToString(sm4Key))
	fmt.Println("SM4 IV:", hex.EncodeToString(sm4IV))

	// SM4 CBC模式加密
	encryptedData, err := sm4EncryptCBC(sm4Key, sm4IV, data)
	if err != nil {
		fmt.Println("SM4加密失败:", err)
		return
	}
	fmt.Println("SM4加密结果:", hex.EncodeToString(encryptedData))

	// SM4 CBC模式解密
	decryptedData, err := sm4DecryptCBC(sm4Key, sm4IV, encryptedData)
	if err != nil {
		fmt.Println("SM4解密失败:", err)
		return
	}
	fmt.Println("SM4解密结果:", string(decryptedData))
}
