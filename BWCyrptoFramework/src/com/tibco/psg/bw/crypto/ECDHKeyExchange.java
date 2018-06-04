package com.tibco.psg.bw.crypto;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;

import org.apache.commons.codec.binary.Base64;

public class ECDHKeyExchange {

	private final String ELLIPTICAL_CURVE_NAME="prime256v1";
	private final String BOUNTY_CASTLE="BC";
	private final String ELLIPTICAL_CURVE_DIFFIE_HELLMAN = "ECDH";
	private final String AES_256 = "AES-256";
	
	
	
	/**
	 * Generate Private and Public Keys based on ECDH Algorithm
	 * 	
	 * @return String[0]-Private Key ,String[1]-Public Key
	 *  
	 * @author Sachin Roham
	 * @throws NoSuchAlgorithmException 
	 * @throws NoSuchProviderException 
	 * @throws InvalidAlgorithmParameterException 
	 */

	public String[] generateECDHKeys() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException{
			
			try {
				ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec(ELLIPTICAL_CURVE_NAME);
				KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ELLIPTICAL_CURVE_DIFFIE_HELLMAN, BOUNTY_CASTLE);
				keyPairGenerator.initialize(ecGenParameterSpec, new SecureRandom());
				
				KeyPair keyPair = keyPairGenerator.generateKeyPair();
				PrivateKey privateKey  =  keyPair.getPrivate();
				PublicKey  publicKey = keyPair.getPublic();
				
				String[] keys = new String[2];
				keys[0]=Base64.encodeBase64URLSafeString(privateKey.getEncoded());
				keys[1]=Base64.encodeBase64URLSafeString(publicKey.getEncoded());
				
				System.out.println("Private Key :" +keys[0]);
				System.out.println("Public Key :" +keys[1]);
				
				return keys;
			} catch (NoSuchAlgorithmException e) {
				System.err.println("NoSuchAlgorithmException : "+ e.getMessage());
				e.printStackTrace();
				throw e;
			} catch (NoSuchProviderException e) {
				System.err.println("NoSuchProviderException : "+ e.getMessage());
				e.printStackTrace();
				throw e;
			} catch (InvalidAlgorithmParameterException e) {
				System.err.println("InvalidAlgorithmParameterException : "+ e.getMessage());
				e.printStackTrace();
				throw e;
			}			
	
	}

	/**
	 * Generate ECDH Secret based on provided keys
	 * 
	 * @param privateKeyContent Base64 encoded private key
	 * @param publicKeyContent Base64 encoded public key
	 * 
	 * @return secret The generated ECDH secret key
	 * @author Sachin Roham
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeySpecException 
	 * @throws InvalidKeyException 
	 */
	
	public String generateECDHSecret(String privateKeyContent, String publicKeyContent) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException{
		
     	try {
			KeyFactory keyFactory = KeyFactory.getInstance(ELLIPTICAL_CURVE_DIFFIE_HELLMAN, BOUNTY_CASTLE);
			
	        PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.decodeBase64(privateKeyContent));
	        PrivateKey privateKey = keyFactory.generatePrivate(keySpecPKCS8);

	        X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.decodeBase64(publicKeyContent));
	        PublicKey publicKey =  keyFactory.generatePublic(keySpecX509);
	
			System.out.println("Private Key :" +Base64.encodeBase64URLSafeString(privateKey.getEncoded()));
			System.out.println("Public Key :" +Base64.encodeBase64URLSafeString(publicKey.getEncoded()));

			KeyAgreement keyAgreement = KeyAgreement.getInstance(ELLIPTICAL_CURVE_DIFFIE_HELLMAN);
			keyAgreement.init(privateKey);	

			keyAgreement.doPhase(publicKey, true);
			
			SecretKey secret = keyAgreement.generateSecret(AES_256);
			System.out.println("secret Key :" +Base64.encodeBase64URLSafeString(secret.getEncoded()));
			return Base64.encodeBase64URLSafeString(secret.getEncoded());
			
		} catch (NoSuchAlgorithmException e) {
			System.err.println("NoSuchAlgorithmException : "+ e.getMessage());
			e.printStackTrace();
			throw e;
		} catch (InvalidKeySpecException e) {
			System.err.println("InvalidKeySpecException : "+ e.getMessage());
			e.printStackTrace();
			throw e;
		} catch (NoSuchProviderException e) {
			System.err.println("NoSuchProviderException : "+ e.getMessage());
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			System.err.println("InvalidKeyException : "+ e.getMessage());
			e.printStackTrace();
			throw e;
		}
    	


		return null;
	
	}
	
	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, InvalidKeySpecException {
		ECDHKeyExchange generateECDHKeys = new ECDHKeyExchange();
		String[] keys = generateECDHKeys.generateECDHKeys();
		System.out.println(keys[0]);
		System.out.println(keys[1]);
		
		String secret = generateECDHKeys.generateECDHSecret(keys[0], keys[1]);
		
		System.out.println(secret);

	}

}
