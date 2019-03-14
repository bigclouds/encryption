package com.yalogr.encryption.demo;

import com.yalogr.encryption.lib.SaltAESEncrypt;

public class TestSaltEncrypt {
	public static void main(String[] args) throws Exception {
        String password = "mypassword";
        String salt = "this is a simple clear salt";
        String passwordEnc = SaltAESEncrypt.encrypt(password, salt);
        String passwordDec = SaltAESEncrypt.decrypt(passwordEnc, salt);
 
        System.out.println("Salt Text : " + salt);
        System.out.println("Plain Text : " + password);
        System.out.println("Encrypted : " + passwordEnc);
        System.out.println("Decrypted : " + passwordDec);
    }
}
