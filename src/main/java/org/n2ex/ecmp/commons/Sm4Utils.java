package org.n2ex.ecmp.commons;

import com.sun.org.slf4j.internal.Logger;
import com.sun.org.slf4j.internal.LoggerFactory;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.SecureRandom;
import java.security.Security;

/**
 * 对称加密算法,只有一个密钥
 */

public class Sm4Utils {
    private static final Logger logger
            = LoggerFactory.getLogger(Sm4Utils.class);
    static {
        //加入BouncyCastleProvider的支持 BouncyCastle->开源密码包，扩充密码算法支持
        Security.addProvider(new BouncyCastleProvider());
    }

    //算法名称
    public static final String ALGORITHM_NAME = "SM4";

    //ECB P5填充
    public static final String ALGORITHM_NAME_ECB_PADDING = "SM4/ECB/PKCS5Padding";

    //CBC P5填充
    public static final String ALGORITHM_NAME_CBC_PADDING = "SM4/CBC/PKCS5Padding";

    //密钥长度
    public static final int DEFAULT_KEY_SIZE = 128;


    /**
     * 获取密钥
     * @return 密钥
     * @throws Exception 异常
     */

    public static byte[] generateKey() {
        try {
            return generateKey(DEFAULT_KEY_SIZE);
        } catch (Exception e) {
            logger.error(e.getMessage());
        }
        return null;
    }

    /**
     * 获取指定长度密钥
     * @param keySize 密钥的长度
     * @return 密钥
     * @throws Exception 异常
     */

    public static byte[] generateKey(int keySize) {
        try {
            KeyGenerator kg = KeyGenerator.getInstance(ALGORITHM_NAME,
                    BouncyCastleProvider.PROVIDER_NAME);
            kg.init(keySize, new SecureRandom());
            return kg.generateKey().getEncoded();
        } catch (Exception e) {
            logger.error(e.getMessage() );
        }
        return null;
    }

    /**
     * ECB P5填充加密
     * 优点:简单，利于并行计算，误差不会被传递
     * 缺点：加密模式易被确定
     * @param key 密钥
     * @param data 明文数据
     * @return 加密结果
     * @throws Exception 异常
     */
    public static String encryptEcbPadding(String key, String data) {
        try {
            Cipher cipher = generateEcbCipher(ALGORITHM_NAME_ECB_PADDING, Cipher.ENCRYPT_MODE,
                   Hex.decodeHex(key.toCharArray()));
            byte[] encryptBytes = cipher.doFinal(data.getBytes("UTF-8"));
            return Hex.encodeHexString(encryptBytes);
        } catch (Exception e) {
            logger.error(e.getMessage());
        }
        return null;
    }

    /**
     * ECB P5填充解密
     * @param key 密钥
     * @param cipherText 加密后的数据
     * @return 解密结果
     */

    public static String decryptEcbPadding(String key, String cipherText) {
        try {
            Cipher cipher = generateEcbCipher(ALGORITHM_NAME_ECB_PADDING, Cipher.DECRYPT_MODE,
                    Hex.decodeHex(key.toCharArray()));
            byte[] decryptBytes = cipher.doFinal(Hex.decodeHex(cipherText.toCharArray()));
            return new String(decryptBytes);
        } catch (Exception e) {
            logger.error(e.getMessage());
        }
        return null;
    }

    /**
     * CBC P5填充加密
     * 优点：安全性高
     * 缺点：不利于并行计算，误差传递，需要初始化向量iv
     * @param key 密钥
     * @param iv 偏移量，CBC每轮迭代会和上轮结果进行异或操作，由于首轮没有可进行异或的结果，
     *           所以需要设置偏移量，一般用密钥做偏移量
     * @param data 明文数据
     * @return 加密结果
     */

    public static String encryptCbcPadding(String key, String iv, String data) {
        try {
            Cipher cipher = generateCbcCipher(ALGORITHM_NAME_CBC_PADDING, Cipher.ENCRYPT_MODE,
                    Hex.decodeHex(key.toCharArray()), Hex.decodeHex(iv.toCharArray()));
            byte[] encryptBytes = cipher.doFinal(data.getBytes("UTF-8"));
            return Hex.encodeHexString(encryptBytes);
        } catch (Exception e) {
            logger.error(e.getMessage());
        }
        return null;
    }

    /**
     * CBC P5填充解密
     * @param key 密钥
     * @param iv 偏移量，CBC每轮迭代会和上轮结果进行异或操作，由于首轮没有可进行异或的结果，
     *           所以需要设置偏移量，一般用密钥做偏移量
     * @param cipherText 加密数据
     * @return 解密结果
     */
    public static String decryptCbcPadding(String key, String iv, String cipherText) {
        try {
            Cipher cipher = generateCbcCipher(ALGORITHM_NAME_CBC_PADDING, Cipher.DECRYPT_MODE,
                    Hex.decodeHex(key.toCharArray()), Hex.decodeHex(iv.toCharArray()));
            byte[] decryptBytes = cipher.doFinal(Hex.decodeHex(cipherText.toCharArray()));
            return new String(decryptBytes);
//            return Hex.encodeHexString(decryptBytes);
        } catch (Exception e) {
            logger.error(e.getMessage());
        }
        return null;
    }

    /**
     * ECB P5填充加解密Cipher初始化
     * @param algorithmName 算法名称
     * @param mode 1 加密  2解密
     * @param key 密钥
     * @return Cipher
     */
    private static Cipher generateEcbCipher(String algorithmName, int mode, byte[] key) {
        try {
            Cipher cipher = Cipher.getInstance(algorithmName, BouncyCastleProvider.PROVIDER_NAME);
            Key sm4Key = new SecretKeySpec(key, ALGORITHM_NAME);
            cipher.init(mode, sm4Key);
            return cipher;
        } catch (Exception e) {
            logger.error(e.getMessage());
        }
        return null;
    }

    /**
     * CBC P5填充加解密Cipher初始化
     * @param algorithmName 算法名称
     * @param mode 1 加密  2解密
     * @param key 密钥
     * @param iv 偏移量，CBC每轮迭代会和上轮结果进行异或操作，由于首轮没有可进行异或的结果，
     *           所以需要设置偏移量，一般用密钥做偏移量
     * @return Cipher
     */
    private static Cipher generateCbcCipher(String algorithmName, int mode, byte[] key, byte[] iv) {
        try {
            Cipher cipher = Cipher.getInstance(algorithmName, BouncyCastleProvider.PROVIDER_NAME);
            Key sm4Key = new SecretKeySpec(key, ALGORITHM_NAME);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            cipher.init(mode, sm4Key, ivParameterSpec);
            return cipher;
        } catch (Exception e) {
            logger.error(e.getMessage());
        }
        return null;
    }
    public  static void main(String... args){
        //明文数据
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
//        Assert.assertEquals(SRC_DATA, decryptedData);
    }

}
