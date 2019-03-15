package com.yalogr.encryption.demo;

import java.util.Map;
import com.yalogr.encryption.lib.DSASignature;

public class TestDSASignature {
	public static void main(String[] args) throws Exception{
		String inputStr = "abc123456你好"; 
		byte[] data = inputStr.getBytes(); 

		// 构建密钥 
		Map<String, Object> keyMap = DSASignature.initKey(); 

		// 获得密钥 
		String publicKey = DSASignature.getPublicKey(keyMap); 
		String privateKey = DSASignature.getPrivateKey(keyMap); 

		System.out.println("公钥:" + publicKey); 
		System.out.println("私钥:" + privateKey); 

		// 产生签名 
		String sign = DSASignature.sign(data, privateKey); 
		System.out.println(inputStr +" 签名:" + sign); 

		// 验证签名 
		boolean status = DSASignature.verify(data, publicKey, sign); 
		System.out.println("状态:" + status); 
	}
}
