package com.util;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

public abstract class RSACoder {
    //非对称加密密钥算法
    public  static  final  String KEY_ALGORITHM = "RSA";
    //公钥
    public  static  final  String PUBLIC_KEY = "RSAPublicKey";
    //私钥
    public  static  final  String PRIVATE_KEY = "RSAPrivateKey";
    //解密数据长度
    public static  final int MAX_DECRYPT_BLOCK = 128;
    /**
     * RSA密钥长度
     * 默认1024位
     * 密钥长度必须是64的倍数
     * 范围在512-65536位之间
     */
    public static  final int KEY_SIZE = 1024;

    /**
     * 初始化密钥
     * @return Map 密钥Map
     *@throws  NoSuchAlgorithmException
     */
    public static Map<String,Object> initKey() throws NoSuchAlgorithmException {
        //实例化密钥对生成器
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
        //初始化密钥对生成器
        keyPairGenerator.initialize(KEY_SIZE);
        //生成密钥对
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        //公钥
        RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
        //私钥
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
        //封装密钥
        Map<String,Object> keyMap = new HashMap<String, Object>(2);
        keyMap.put(PUBLIC_KEY,rsaPublicKey);
        keyMap.put(PRIVATE_KEY,rsaPrivateKey);
        return keyMap;
    }
    /**
     * 公钥加密
     * @param  data 待加密数据
     * @param  key 公钥
     * @return byte[] 加密数据
     */
    public static byte[] encryptByPublicKey(byte[] data,byte[] key) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        //获取公钥
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(key);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
        //数据加密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE,publicKey);
        return cipher.doFinal(data);
    }
    /**
     * 私钥解密
     * @param  data 待解密数据
     * @param  key 私钥
     * @return byte[] 解密数据
     */
    public static  byte[] decryptByPrivateKey(byte[] data,byte[] key) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, IOException {
        //取得私钥
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(key);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        //生成私钥
        PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        //对数据进行解密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE,privateKey);
        //分段解密
        int inputLen = data.length;
        //开始点
        int offSet = 0;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        while (inputLen-offSet > 0) {
            if(inputLen - offSet > MAX_DECRYPT_BLOCK) {
                out.write(cipher.doFinal(data,offSet,MAX_DECRYPT_BLOCK));
            }else {
                out.write(cipher.doFinal(data,offSet,inputLen-offSet));
            }
            offSet=offSet+MAX_DECRYPT_BLOCK;
        }
        byte[] decryptedData = out.toByteArray();
        out.close();
        return decryptedData;
    }

    /**
     * 获取私钥
     * @param keyMap 密钥Map
     * @return byte[]  私钥
     */
    public static byte[] getPrivateKey(Map<String,Object> keyMap){
        Key key = (Key) keyMap.get(PRIVATE_KEY);
        return  key.getEncoded();
    }
    /**
     * 获取公钥
     * @param keyMap 密钥Map
     * @return byte[]  公钥
     */
    public static byte[] getPublicKey(Map<String,Object> keyMap){
        Key key = (Key) keyMap.get(PUBLIC_KEY);
        return  key.getEncoded();
    }


}
