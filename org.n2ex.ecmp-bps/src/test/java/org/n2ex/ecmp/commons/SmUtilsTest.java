package org.n2ex.ecmp.commons;


import org.apache.commons.codec.DecoderException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import org.apache.commons.codec.binary.Hex;

import java.security.KeyPair;

import static org.n2ex.ecmp.commons.Sm2Utils.*;

public class SmUtilsTest   {

    @Test
    @DisplayName("Sm2UtilsTest")
    void Sm2UtilsTest() {
        try {
            KeyPair keyPair = generateSm2KeyPair();
        String privateKeyHex = Hex.encodeHexString(keyPair.getPrivate().getEncoded()).toUpperCase();
        String publicKeyHex  =Hex.encodeHexString(keyPair.getPublic().getEncoded()).toUpperCase();
        String data = "{\"daId\":\"123456\"}";
        String encryptedJsonStr =  Hex.encodeHexString(encrypt(data, publicKeyHex)) + "";//16进制字符串
        String decryptedJsonStr = null;

            decryptedJsonStr = decrypt(Hex.decodeHex(encryptedJsonStr.toCharArray()), privateKeyHex);

        String sign = Hex.encodeHexString(sign(data, privateKeyHex).getBytes()).toUpperCase();
        boolean flag = verify(Hex.encodeHexString(data.getBytes()), sign, publicKeyHex);
        System.out.println("privateKey:" + privateKeyHex);
        System.out.println("publicKey:" + publicKeyHex);
        System.out.println("加密前数据:" + data);
        System.out.println("公钥加密后16进制字符串:" + encryptedJsonStr);
        System.out.println("私钥解密后数据：" + decryptedJsonStr);
        System.out.println("私钥加签后数据(16进制)：" + sign);
        System.out.println("公钥验签结果：" + flag); } catch ( Exception e) {
            throw new RuntimeException(e);
        }
    }
    @Test
    @DisplayName("Sm3UtilsTest")
    public static void Sm3UtilsTest() {
        //  Test 2: json
        String json = "{\"name\":\"Marydon\",\"website\":\"http://www.cnblogs.com/Marydon20170307\"}";
        String hex = Sm3Utils.encrypt(json);
        System.out.println(hex);// 0b0880f6f2ccd817809a432420e42b66d3772dc18d80789049d0f9654efeae5c
        //  Verify that the encrypted hexadecimal string is the same as the one before encryption
        boolean flag = Sm3Utils.verify(json, hex);
        System.out.println(flag);// true

    }

    @Test
    @DisplayName("Sm4UtilsTest")
    public static void Sm4UtilsTest() {
        String SRC_DATA = "你好";
        byte[] sm4key = Sm4Utils.generateKey();
        String key = Hex.encodeHexString(sm4key);
        System.out.println("SM4密钥:" + key);
        byte[] iv = Sm4Utils.generateKey();
        String ivStr = Hex.encodeHexString(iv);
        System.out.println("iv偏移量密钥:" + ivStr);
        String cipherText;

        /*********************ECB加解密*************************/
        cipherText = Sm4Utils.encryptEcbPadding(key, SRC_DATA);
        System.out.println("SM4 ECB Padding 加密结果16进制:\n" + cipherText);
        String decryptedData;
        decryptedData = Sm4Utils.decryptEcbPadding(key, cipherText);
        System.out.println("SM4 ECB Padding 解密结果:\n" + decryptedData);
//        Assert.assertEquals(SRC_DATA, decryptedData);

        /*********************CBC加解密*************************/
        cipherText = Sm4Utils.encryptCbcPadding(key, ivStr, SRC_DATA);
        System.out.println("SM4 CBC Padding 加密结果16进制:\n" + cipherText);
        decryptedData = Sm4Utils.decryptCbcPadding(key, ivStr, cipherText);
        System.out.println("SM4 CBC Padding 解密结果:\n" + decryptedData);

    }
}