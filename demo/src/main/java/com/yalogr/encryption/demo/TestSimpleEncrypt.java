package com.yalogr.encryption.demo;

import com.yalogr.encryption.lib.SimpleAESEncrypt;

/**
 * Hello world!
 *
 */
public class TestSimpleEncrypt 
{
	public static void main(String[] args) throws Exception {
		 
        String password = "mypassword";
        String passwordEnc = SimpleAESEncrypt.encrypt(password);
        String passwordDec = SimpleAESEncrypt.decrypt(passwordEnc);
 
        System.out.println("Plain Text : " + password);
        System.out.println("Encrypted : " + passwordEnc);
        System.out.println("Decrypted : " + passwordDec);
    }
}
