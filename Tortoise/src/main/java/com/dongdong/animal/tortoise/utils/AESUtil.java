package com.dongdong.animal.tortoise.utils;

import android.os.Build;
import android.security.keystore.KeyProperties;
import android.text.TextUtils;
import android.util.Base64;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Aes加解密工具类
 * Created by dongdongzheng on 2017/2/24.
 */

public class AESUtil {

    private static final String AES_MODE_OAEP = "AES/CBC/PKCS5Padding";
    private final static String ALGORITHM = "SHA1PRNG";
    private static final String CRYPTO = "Crypto";
    private static final String HEX = "0123456789ABCDEF";


    /**
     * AES加密算法加密
     *
     * @param seed   种子
     * @param intext 原文
     * @return 密文
     */
    public static String encode(String seed, String intext) {
        try {
            byte[] rawKey = getAesKey(seed).getEncoded();
            return encode(rawKey, intext);
        } catch (Exception e) {
            e.printStackTrace();
            return intext;
        }


    }

    /**
     * AES加密算法加密
     *
     * @param key    key
     * @param intext 原文
     * @return 密文
     */
    public static String encode(SecretKeySpec key, String intext) {
        if (key == null) {
            return intext;
        }
        try {
            byte[] rawKey = key.getEncoded();
            return encode(rawKey, intext);
        } catch (Exception e) {
            e.printStackTrace();
            return intext;
        }

    }


    private static String encode(byte[] raw, String cleartext) {
        try {
            byte[] result = encrypt(raw, cleartext.getBytes(StandardCharsets.UTF_8));
            return Base64.encodeToString(result, Base64.NO_WRAP);
        } catch (Exception e) {
            return cleartext;
        }
    }

    /**
     * @return AES加密算法加密
     * @throws Exception
     */
    private static byte[] encrypt(byte[] raw, byte[] clear) throws Exception {
        SecretKeySpec skeySpec = new SecretKeySpec(raw, KeyProperties.KEY_ALGORITHM_AES);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(raw);
        Cipher cipher = Cipher.getInstance(AES_MODE_OAEP);
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivParameterSpec);
        return cipher.doFinal(clear);
    }


    /**
     * AES解密算法解密
     *
     * @param seed      种子
     * @param encrypted 密文
     * @return 原文
     */
    public static String decode(String seed, String encrypted) {
        try {
            byte[] rawKey = getAesKey(seed).getEncoded();
            return encode(rawKey, encrypted);
        } catch (Exception e) {
            e.printStackTrace();
            return encrypted;
        }

    }

    /**
     * AES解密算法解密
     *
     * @param key       key
     * @param encrypted 密文
     * @return 原文
     */
    public static String decode(SecretKeySpec key, String encrypted) {
        if (key == null) {
            return encrypted;
        }
        try {
            byte[] rawKey = key.getEncoded();
            return decode(rawKey, encrypted);
        } catch (Exception e) {
            e.printStackTrace();
            return encrypted;
        }
    }

    public static String decode(byte[] raw, String encrypted) {
        try {
            byte[] enc = Base64.decode(encrypted, Base64.NO_WRAP);
            byte[] result = decrypt(raw, enc);
            return new String(result);
        } catch (Exception e) {
            return encrypted;
        }
    }


    private static byte[] decrypt(byte[] raw, byte[] encrypted)
            throws Exception {
        SecretKeySpec skeySpec = new SecretKeySpec(raw, KeyProperties.KEY_ALGORITHM_AES);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(raw);
        Cipher cipher = Cipher.getInstance(AES_MODE_OAEP);
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, ivParameterSpec);
        return cipher.doFinal(encrypted);
    }


    private static String toHex(byte[] buf) {
        if (buf == null) {
            return "";
        }
        StringBuilder result = new StringBuilder(2 * buf.length);
        for (int i = 0; i < buf.length; i++) {
            result.append(HEX.charAt((buf[i] >> 4) & 0x0f)).append(
                    HEX.charAt(buf[i] & 0x0f));
        }
        return result.toString();
    }


    private static byte[] toByte(String hexString) {
        int len = hexString.length() / 2;
        byte[] result = new byte[len];
        for (int i = 0; i < len; i++) {
            result[i] = Integer.valueOf(hexString.substring(2 * i, 2 * i + 2),
                    16).byteValue();
        }
        return result;
    }

    public static SecretKeySpec getAesKey(String seed) {
        if (TextUtils.isEmpty(seed)) {
            return null;
        } else {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                return createKeyUpP(seed);
            } else {
                return createKeyDownP(seed);
            }
        }

    }


    private static SecretKeySpec createKeyDownP(String seed) {
        KeyGenerator kgen = null;
        try {
            kgen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES);
            // SHA1PRNG 强随机种子算法, 要区别4.2以上版本的调用方法
            SecureRandom sr = null;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
                sr = SecureRandom.getInstance(ALGORITHM, new CryptoProvider());
            } else {
                sr = SecureRandom.getInstance(ALGORITHM);
            }
            sr.setSeed(seed.getBytes(StandardCharsets.UTF_8));
            kgen.init(128, sr);
            return new SecretKeySpec(kgen.generateKey().getEncoded(), KeyProperties.KEY_ALGORITHM_AES);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }


    }

    private static SecretKeySpec createKeyUpP(String password) {
        byte[] rawKey = InsecureSHA1PRNGKeyDerivator.deriveInsecureKey(password.getBytes(), 16);
        return new SecretKeySpec(rawKey, KeyProperties.KEY_ALGORITHM_AES);
    }
}
