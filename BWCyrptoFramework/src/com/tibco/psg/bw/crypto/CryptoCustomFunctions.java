package com.tibco.psg.bw.crypto;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.codec.binary.Base64;

public class CryptoCustomFunctions {

	static final String RSA_ALGORITHM = "RSA";
	static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
	
	
	/**
	 * Signs the given content based on SHA256withRSA algorithm.
	 * 
	 * @param privateKeyPath RSA Key
	 * @param content Content to be signed
	 * 
	 * @return String Generated Signature
	 * @author Sachin Roham
	 * 
	 */
	
	public static String signSHA256withRSA(String privateKeyPath,String content) {
		
		try {
			String privateKeyContent = new String(Files.readAllBytes(Paths.get(privateKeyPath)));
			privateKeyContent = privateKeyContent.replaceAll("\\n", "").replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "");
			
			
			KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
	        
			PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.decodeBase64(privateKeyContent));
	        RSAPrivateKey privateKey = (RSAPrivateKey)keyFactory.generatePrivate(keySpecPKCS8);
	        System.out.println("Private Key: "+ Base64.encodeBase64URLSafeString(privateKey.getEncoded()));

			Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
			signature.initSign(privateKey);
			signature.update(content.getBytes("UTF-8"));
			
			return Base64.encodeBase64URLSafeString(signature.sign());
			
		} catch (IOException e) {
			System.err.println("IOException : "+ e.getMessage());
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			System.err.println("NoSuchAlgorithmException : "+ e.getMessage());
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			System.err.println("InvalidKeySpecException : "+ e.getMessage());
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			System.err.println("InvalidKeyException : "+ e.getMessage());
			e.printStackTrace();
		} catch (SignatureException e) {
			System.err.println("SignatureException : "+ e.getMessage());
			e.printStackTrace();
		}
		return null;  	
		
	}
	
	/**
	 * Verify a SHA256withRSA Signature.
	 * 
	 * @param publicKeyPath RSA Key
	 * @param signatureContent Signature
	 * @param content Orignal Content
	 * 
	 * @return boolean GVerification result
	 * @author Sachin Roham
	 * 
	 */
	
	public static boolean verifySHA256withRSA(String publicKeyPath, String signatureContent, String content){
		
		try {
			String publicKeyContent = new String(Files.readAllBytes(Paths.get(publicKeyPath)));
			publicKeyContent = publicKeyContent.replaceAll("\\n", "").replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "");;
			
			KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
	        X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.decodeBase64(publicKeyContent));
	        RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(keySpecX509);
	        System.out.println("Public Key: "+ Base64.encodeBase64URLSafeString(publicKey.getEncoded()));        
	
			Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
			signature.initVerify(publicKey);
			signature.update(content.getBytes("UTF-8"));
			boolean verifies = signature.verify(Base64.decodeBase64(signatureContent));
			return verifies;
	        
	        
		} catch (IOException e) {
			System.err.println("IOException : "+ e.getMessage());
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			System.err.println("NoSuchAlgorithmException : "+ e.getMessage());
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			System.err.println("InvalidKeySpecException : "+ e.getMessage());
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			System.err.println("InvalidKeyException : "+ e.getMessage());
			e.printStackTrace();
		} catch (SignatureException e) {
			System.err.println("SignatureException : "+ e.getMessage());
			e.printStackTrace();
		}
		return false;
		
	}
	
	
	/**
	 * Encrypts the given content based on a RSA cipher
	 * 
	 * @param keyPath RSA Key
	 * @param content Orignal Content
	 * 
	 * @return String Encrypted content
	 * @author Sachin Roham
	 * 
	 */
	public static String encryptRSACipher(String keyPath, String content){
		
		
		try {
			String publicKeyContent = new String(Files.readAllBytes(Paths.get(keyPath)));
			publicKeyContent = publicKeyContent.replaceAll("\\n", "").replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "");;
			
			KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
	        X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.decodeBase64(publicKeyContent));
	        RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(keySpecX509);
	        System.out.println("Public Key: "+ Base64.encodeBase64URLSafeString(publicKey.getEncoded()));      

	        byte[]  encryptionData = content.getBytes();
			System.out.println("encryptionData"+encryptionData);
	        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
	        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
	        byte[] encryptedText = cipher.doFinal(encryptionData);
	        System.out.println("encryptedText::::::"+Base64.encodeBase64String(encryptedText));
	        return Base64.encodeBase64String(encryptedText);
		} catch (IOException e) {
			System.err.println("IOException : "+ e.getMessage());
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			System.err.println("NoSuchAlgorithmException : "+ e.getMessage());
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			System.err.println("InvalidKeySpecException : "+ e.getMessage());
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			System.err.println("NoSuchPaddingException : "+ e.getMessage());
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			System.err.println("InvalidKeyException : "+ e.getMessage());
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			System.err.println("IllegalBlockSizeException : "+ e.getMessage());
			e.printStackTrace();
		} catch (BadPaddingException e) {
			System.err.println("BadPaddingException : "+ e.getMessage());
			e.printStackTrace();
		}
		return null;
		
	}
	
	
	/**
	 * Decrypt the given content based on a RSA cipher
	 * 
	 * @param keyPath RSA Key
	 * @param encryptedContent Encrypted Content
	 * 
	 * @return String Decrypted content
	 * @author Sachin Roham
	 * 
	 */
	public static String decryptRSACipher(String keyPath, String encryptedContent){
		
		try {
			String privateKeyContent = new String(Files.readAllBytes(Paths.get(keyPath)));
			privateKeyContent = privateKeyContent.replaceAll("\\n", "").replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "");
			
			
			KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
	        
			PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.decodeBase64(privateKeyContent));
	        RSAPrivateKey privateKey = (RSAPrivateKey)keyFactory.generatePrivate(keySpecPKCS8);
	        System.out.println("Private Key: "+ Base64.encodeBase64URLSafeString(privateKey.getEncoded()));
	
	        
	        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
	        cipher.init(Cipher.DECRYPT_MODE, privateKey);
	        byte[] decryptedText = cipher.doFinal(Base64.decodeBase64(encryptedContent));
	        System.out.println("decryptedText::::::"+new String(decryptedText));
	        return new String(decryptedText);
	        
		} catch (IOException e) {
			System.err.println("IOException : "+ e.getMessage());
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			System.err.println("NoSuchAlgorithmException : "+ e.getMessage());
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			System.err.println("InvalidKeySpecException : "+ e.getMessage());
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			System.err.println("InvalidKeyException : "+ e.getMessage());
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			System.err.println("NoSuchPaddingException : "+ e.getMessage());
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			System.err.println("IllegalBlockSizeException : "+ e.getMessage());
			e.printStackTrace();
		} catch (BadPaddingException e) {
			System.err.println("BadPaddingException : "+ e.getMessage());
			e.printStackTrace();
		}
     		
		return null;
		
	}
	
	/**
	 * The following is a two-dimensional array that provides the online help
	 * for functions in this class. Declare an array named HELP_STRINGS.
	 */
	public static final String[][] HELP_STRINGS = {
			{ "signSHA256withRSA", "Sign the content based on the private key provided", "Example",
					"signSHA256withRSA(\"c:/tmp/private_key_pkcs8.pem\",\"content\")" },
			{ "verifySHA256withRSA", "Verifies the signature based on the public key provided", "Example",
					"verifySHA256withRSA(\"c:/tmp/public_key.pem\",\"signatureContent\",\"content\")" },
			{ "encryptRSACipher", "Encrypts data based on the RSA key provided", "Example",
					"encryptRSACipher(\"c:/tmp/public_key.pem\",\"content\")" },
			{ "decryptRSACipher", "Verifies the signature based on the public key provided", "Example",
					"decryptRSACipher(\"c:/tmp/private_key_pkcs8.pem\",\"encryptedContent\")" }};
}
