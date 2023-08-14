package org.n2ex.ecmp.commons;

import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;

import java.io.UnsupportedEncodingException;
import java.security.Security;
import java.util.Arrays;

/**
 * 这个是类似MD5，SHA256的摘要算法。通过一系列的位运算来获得一个256bit的大数。
 * 注意，是摘要算法，不是加密算法
 */
public class Sm3Utils {

        private static final String ENCODING = "UTF-8";
        static {
            Security.addProvider(new BouncyCastleProvider());
        }


    /**
     * sm3 algorithm encryption
     * @explain
     * @param paramStr
     * String to be encrypted
     * @return returns a hexadecimal string of fixed length=32 after encryption
     */
    public static String encrypt(String paramStr){
        // Convert the returned hash value into a hexadecimal string
        String resultHexString = "";
        try {
            // Convert the string into a byte array
            byte[] srcData = paramStr.getBytes(ENCODING);
            // call hash()
            byte[] resultHash = hash(srcData);
            // Convert the returned hash value into a hexadecimal string
            resultHexString = ByteUtils.toHexString(resultHash);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return resultHexString;
    }

    /**
     * Return a byte array with length=32
     * @explain generates the corresponding hash value
     * @param srcData
     * @return
     */
    public static byte[] hash(byte[] srcData) {
        SM3Digest digest = new SM3Digest();
        digest.update(srcData, 0, srcData.length);
        byte[] hash = new byte[digest.getDigestSize()];
        digest.doFinal(hash, 0);
        return hash;
    } 

    /**
     * Encrypted by key
     * @explain specifies the key for encryption
     * @param key
     * Key
     * @param srcData
     * The encrypted byte array
     * @return
     */
    public static byte[] hmac(byte[] key, byte[] srcData) {
        KeyParameter keyParameter = new KeyParameter(key);
        SM3Digest digest = new SM3Digest();
        HMac mac = new HMac(digest);
        mac.init(keyParameter);
        mac.update(srcData, 0, srcData.length);
        byte[] result = new byte[mac.getMacSize()];
        mac.doFinal(result, 0);
        return result;
    } 

    /**
     * Determine whether the source data is consistent with the encrypted data
     * @explain verifies whether the original array and the generated hash array are the same array to verify whether the two are the same data
     * @param srcStr
     * Original string
     * @param sm3HexString
     * Hexadecimal string
     * @return verification result
     */
    public static boolean verify(String srcStr, String sm3HexString) {
        boolean flag = false;
        try {
            byte[] srcData = srcStr.getBytes(ENCODING);
            byte[] sm3Hash = ByteUtils.fromHexString(sm3HexString);
            byte[] newHash = hash(srcData);
            if (Arrays.equals(newHash, sm3Hash))
                flag = true;
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return flag;
    } 

}
