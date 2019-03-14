package com.yalogr.encryption.demo;

import java.util.Map;
import com.yalogr.encryption.lib.RSAEncrypt;

public class TestRSAEncrypt {
	public static void main(String[] args) throws Exception {
		//生成公钥和私钥
		Map<Integer, String> keyMap = RSAEncrypt.genKeyPair();
		//加密字符串
		String message = "df723820你好";
		System.out.println("----公钥加密-私钥解密-----------------");
		System.out.println("随机生成的公钥为:" + keyMap.get(0));
		System.out.println("随机生成的私钥为:" + keyMap.get(1));
		// 公钥加密
		String messageEn = RSAEncrypt.encryptByPublicKey(message,keyMap.get(0));
		System.out.println(message + " \t公钥加密后的字符串为:" + messageEn);
		// 私钥解密
		String messageDe = RSAEncrypt.decryptByPrivateKey(messageEn,keyMap.get(1));
		System.out.println("私钥解密后的字符串为:" + messageDe);
		// 私钥签字
		String sign = RSAEncrypt.signByPrivateKey(messageEn, keyMap.get(1));
		System.out.println("加密后的字符串的签字:" + sign);
		// 公钥验证
		System.out.println("签字验证:" + RSAEncrypt.verifyByPublicKey(messageEn, keyMap.get(0), sign));
		
		System.out.println("-----私钥加密-公钥解密----------------");
		// 私钥加密
		messageEn = RSAEncrypt.encryptByPrivateKey(message, keyMap.get(1));
		System.out.println(message + " \t私钥加密后的字符串为:" + messageEn);
		// 公钥解密
		messageDe = RSAEncrypt.decryptByPublicKey(messageEn, keyMap.get(0));
		System.out.println("公钥解密后的字符串为:" + messageDe);
	}
}
