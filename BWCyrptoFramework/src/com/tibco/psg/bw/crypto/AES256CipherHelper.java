package com.tibco.psg.bw.crypto;



import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

public class AES256CipherHelper {
	
	static final String CIPHER_ALGORITHM = "AES/ECB/PKCS5Padding";
	static final String SECRET_KEY_ALGORITHM = "AES";
	


	/**
	 * Encrypts a file based on AES256 Algorithm
	 * 
	 * @param secretKeyContent AES Secret Key
	 * @param filePath File to be encrypted
	 * 
	 * @return String Filepath of the encrypted file
	 * @author Sachin Roham
	 * @throws GeneralSecurityException, IOException 
	 */
	
	public String encryptAES256ForFile(String secretKeyContent, String filePath) throws GeneralSecurityException, IOException{
		
		try {
		
			File file = new File(filePath);
			FileInputStream fileInputStream = new FileInputStream(file);
			File encryptedFile = new File(file.getAbsolutePath().substring(0, file.getAbsolutePath().indexOf("."))+".enc");
			FileOutputStream fileOutputStream = new FileOutputStream(encryptedFile);
			
			SecretKeySpec key = new SecretKeySpec(Base64.decodeBase64(secretKeyContent),0,32, SECRET_KEY_ALGORITHM);
			Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
			
			cipher.init(Cipher.ENCRYPT_MODE,key);
			
			CipherInputStream cipherInputStream = new CipherInputStream(fileInputStream, cipher);
			byte[] bytes = new byte[1024];
			int numBytes;
			while ((numBytes = cipherInputStream.read(bytes)) != -1) {
				fileOutputStream.write(bytes, 0, numBytes);
			}
			fileOutputStream.flush();
			fileOutputStream.close();			
			cipherInputStream.close();            
					
			return encryptedFile.getAbsolutePath();
			
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			System.err.println("NoSuchAlgorithmException : "+ e.getMessage());
			e.printStackTrace();
			throw e;
		} catch (FileNotFoundException e) {
			System.err.println("FileNotFoundException : "+ e.getMessage());
			e.printStackTrace();
			throw e;
		} catch (IOException e) {
			System.err.println("IOException : "+ e.getMessage());
			e.printStackTrace();
			throw e;
		}

		
	}

	/**
	 * Decrypts a file based on AES256 Algorithm
	 * 
	 * @param secretKeyContent AES Secret Key
	 * @param encryptedFilePath File to be decrypted
	 * 
	 * @return String Filepath of the decrypted file
	 * @author Sachin Roham
	 * @throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IOException, IllegalBlockSizeException, BadPaddingException
	 */	
	public String decryptAES256ForFile(String secretKeyContent, String encryptedFilePath) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IOException, IllegalBlockSizeException, BadPaddingException{
		
		try {
			
			File file = new File(encryptedFilePath);
			FileInputStream fileInputStream = new FileInputStream(file);
			File decryptedFile = new File(file.getAbsolutePath().substring(0, file.getAbsolutePath().indexOf("."))+".zip");
			FileOutputStream fileOutputStream = new FileOutputStream(decryptedFile);
			
			SecretKeySpec key = new SecretKeySpec(Base64.decodeBase64(secretKeyContent),0,32, SECRET_KEY_ALGORITHM);
			Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
			cipher.init(Cipher.DECRYPT_MODE,key);
			
			CipherOutputStream cipherOutputStream =  new CipherOutputStream(fileOutputStream, cipher);
			byte[] bytes = new byte[1024];
			int numBytes;
			while ((numBytes = fileInputStream.read(bytes)) != -1) {
				cipherOutputStream.write(bytes, 0, numBytes);
			}
			cipherOutputStream.flush();
			cipherOutputStream.close();
			fileInputStream.close();
			
			return decryptedFile.getAbsolutePath();
			
		} catch (NoSuchAlgorithmException e) {
			System.err.println("NoSuchAlgorithmException : "+ e.getMessage());
			e.printStackTrace();
			throw e;
		} catch (InvalidKeyException e) {
			System.err.println("InvalidKeyException : "+ e.getMessage());
			e.printStackTrace();
			throw e;
		} catch (NoSuchPaddingException e) {
			System.err.println("NoSuchPaddingException : "+ e.getMessage());
			e.printStackTrace();
			throw e;
		} catch (FileNotFoundException e) {
			System.err.println("FileNotFoundException : "+ e.getMessage());
			e.printStackTrace();
			throw e;
		} catch (IOException e) {
			System.err.println("IOException : "+ e.getMessage());
			e.printStackTrace();
			throw e;
		}
		
	}
}
