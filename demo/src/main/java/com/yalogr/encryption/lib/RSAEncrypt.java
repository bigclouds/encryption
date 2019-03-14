package com.yalogr.encryption.lib;

import javax.crypto.Cipher;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import org.apache.commons.codec.binary.Base64;
import java.util.HashMap;
import java.util.Map;

public class RSAEncrypt {
	//定义加密方式
	private static final String KEY_RSA = "RSA";
	//定义公钥关键词
    public static final String KEY_RSA_PUBLICKEY = "RSAPublicKey";
    //定义私钥关键词
    public static final String KEY_RSA_PRIVATEKEY = "RSAPrivateKey";
	//定义签名算法
    private final static String KEY_RSA_SIGNATURE = "MD5withRSA";
	/** 
	 * 随机生成密钥对 
	 * @throws NoSuchAlgorithmException 
	 */  
	public static Map<Integer, String> genKeyPair() throws NoSuchAlgorithmException {
		Map<Integer, String> keyMap = new HashMap<Integer, String>();
	
		// KeyPairGenerator类用于生成公钥和私钥对，基于RSA算法生成对象  
		KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");  
		// 初始化密钥对生成器，密钥大小为96-1024位  
		keyPairGen.initialize(1024,new SecureRandom());  
		// 生成一个密钥对，保存在keyPair中  
		KeyPair keyPair = keyPairGen.generateKeyPair();  
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();   // 得到私钥  
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();  // 得到公钥  
		String publicKeyString = new String(Base64.encodeBase64(publicKey.getEncoded()));  
		// 得到私钥字符串  
		String privateKeyString = new String(Base64.encodeBase64((privateKey.getEncoded())));  
		// 将公钥和私钥保存到Map
		keyMap.put(0,publicKeyString);  //0表示公钥
		keyMap.put(1,privateKeyString);  //1表示私钥
		
		return keyMap;
	}  
	/** 
	 * RSA公钥加密 
	 *  
	 * @param str 		明文字符串
	 * @param publicKey	公钥 
	 * @return str		密文	base64 
	 * @throws Exception	加密过程中的异常信息
	 */  
	public static String encryptByPublicKey(String str, String key) throws Exception{
		//base64编码的公钥
		byte[] decoded = Base64.decodeBase64(key);
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decoded);
		RSAPublicKey pubKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(keySpec);
		//RSA加密
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, pubKey);
		String outStr = Base64.encodeBase64String(cipher.doFinal(str.getBytes("UTF-8")));
		return outStr;
	}
	
	/** 
	 * RSA私钥加密 
	 *  
	 * @param str 		明文字符串
	 * @param publicKey	私钥 
	 * @return str		密文	base64 
	 * @throws Exception	加密过程中的异常信息
	 */  
	public static String encryptByPrivateKey(String str, String key) throws Exception{
		//base64编码的私钥
		byte[] decoded = Base64.decodeBase64(key);
		PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(decoded);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		RSAPrivateKey priKey = (RSAPrivateKey) keyFactory.generatePrivate(pkcs8KeySpec);
		//RSA加密
		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
		cipher.init(Cipher.ENCRYPT_MODE, priKey);
		String outStr = Base64.encodeBase64String(cipher.doFinal(str.getBytes("UTF-8")));
		return outStr;
	}
	
	/** 
	 * RSA私钥解密
	 *  
	 * @param str  		加密字符串 base64
	 * @param privateKey	私钥
	 * @return str		明文
	 * @throws Exception	解密过程中的异常信息 
	 */  
	public static String decryptByPrivateKey(String str, String key) throws Exception{
		//64位解码加密后的字符串
		byte[] inputByte = Base64.decodeBase64(str.getBytes("UTF-8"));
		//base64编码的私钥
		byte[] decoded = Base64.decodeBase64(key);  
		PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(decoded);
        RSAPrivateKey priKey = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(pkcs8KeySpec);  
		//RSA解密
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, priKey);
		String outStr = new String(cipher.doFinal(inputByte));
		return outStr;
	}
	
	/** 
	 * RSA公钥解密
	 *  
	 * @param str  		加密字符串 base64
	 * @param Key		公钥
	 * @return str		明文
	 * @throws Exception	解密过程中的异常信息 
	 */  
	public static String decryptByPublicKey(String str, String key) throws Exception{
		//base64编码的加密后的字符串
		byte[] inputByte = Base64.decodeBase64(str.getBytes("UTF-8"));
		//base64编码的公钥
		byte[] decoded = Base64.decodeBase64(key);
		X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(decoded);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_RSA);
        RSAPublicKey publicK = (RSAPublicKey) keyFactory.generatePublic(x509KeySpec);
		//RSA解密
		Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
		cipher.init(Cipher.DECRYPT_MODE, publicK);
		String outStr = new String(cipher.doFinal(inputByte));
		return outStr;
	}
	
	/**
     * 用私钥对加密数据进行签名
     * @param encryptedStr	加密字符串 base64
     * @param privateKey		私钥 base64
     * @return 字符串的签字	base64
     */
    public static String signByPrivateKey(String encryptedStr, String privateKey) {
        String str = "";  
        try {
            //将私钥加密数据字符串转换为字节数组
            byte[] data = Base64.decodeBase64(encryptedStr);
            // 解密由base64编码的私钥  
            byte[] bytes = Base64.decodeBase64(privateKey);  
            // 构造PKCS8EncodedKeySpec对象  
            PKCS8EncodedKeySpec pkcs = new PKCS8EncodedKeySpec(bytes);  
            // 指定的加密算法  
            KeyFactory factory = KeyFactory.getInstance(KEY_RSA);  
            // 取私钥对象  
            PrivateKey key = factory.generatePrivate(pkcs);  
            // 用私钥对信息生成数字签名  
            Signature signature = Signature.getInstance(KEY_RSA_SIGNATURE);  
            signature.initSign(key);  
            signature.update(data);  
            str = Base64.encodeBase64String(signature.sign());  
        } catch (Exception e) {  
            e.printStackTrace();  
        }  
        return str;  
    }
    
    /**
     * 用公钥校验数字签名 
     * @param encryptedStr	加密字符串 base64
     * @param publicKey		公钥 base64
     * @param sign			密文的签字 base64
     * @return 校验成功返回true，失败返回false
     */
    public static boolean verifyByPublicKey(String encryptedStr, String publicKey, String sign) {  
        boolean flag = false;
        try {
            //将私钥加密数据字符串转换为字节数组
            byte[] data = Base64.decodeBase64(encryptedStr);
            // 解密由base64编码的公钥  
            byte[] bytes = Base64.decodeBase64(publicKey);  
            // 构造X509EncodedKeySpec对象  
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(bytes);  
            // 指定的加密算法
            KeyFactory factory = KeyFactory.getInstance(KEY_RSA);  
            // 取公钥对象  
            PublicKey key = factory.generatePublic(keySpec);  
            // 用公钥验证数字签名  
            Signature signature = Signature.getInstance(KEY_RSA_SIGNATURE);  
            signature.initVerify(key);  
            signature.update(data);  
            flag = signature.verify(Base64.decodeBase64(sign));
        } catch (Exception e) {  
            e.printStackTrace();  
        }
        return flag;  
    }
}
