package com.tibco.psg.bw.crypto;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SHA512DigestHelper {
	private final String SHA_512="SHA-512";

	
	/**
	 * Generate a SHA256 digest for given file
	 * 
	 * @param filePath Input file path
	 * 
	 * @return String Generated Digest
	 * @author Sachin Roham
	 * @throws NoSuchAlgorithmException, IOException 
	 */
	
	public String generateSHA512ForFile(String filePath) throws NoSuchAlgorithmException, IOException{
		
		try {
			File file = new File(filePath);
			FileInputStream fileInputStream = new FileInputStream(file);
			
			BufferedInputStream bufferedInputStream = new BufferedInputStream(fileInputStream);

			MessageDigest messageDigest = MessageDigest.getInstance(SHA_512);
		
			byte[] buffer = new byte[1024];
			int length=0;
			while (bufferedInputStream.available() != 0) {
				length = bufferedInputStream.read(buffer);
				messageDigest.update(buffer,0,length);
			}

			bufferedInputStream.close();
			fileInputStream.close();

			File outputFile = new File(file.getAbsolutePath().substring(0, file.getAbsolutePath().indexOf("."))+".sha512");
			outputFile.createNewFile();
            FileOutputStream fileOutputStream = new FileOutputStream(outputFile);
            fileOutputStream.write(messageDigest.digest());
            fileOutputStream.flush();
            fileOutputStream.close();		
            return outputFile.getAbsolutePath();
		} catch (FileNotFoundException e) {
			System.err.println("FileNotFoundException : "+ e.getMessage());
			e.printStackTrace();
			throw e;
		} catch (NoSuchAlgorithmException e) {
			System.err.println("NoSuchAlgorithmException : "+ e.getMessage());
			e.printStackTrace();
			throw e;
		} catch (IOException e) {
			System.err.println("IOException : "+ e.getMessage());
			e.printStackTrace();
			throw e;
		}
		
	}
	
	/**
	 * Verify a SHA256 digest for given file
	 * 
	 * @param digestFilePath Digest file path
	 * @param actualFilePath Orignal file path
	 * 
	 * @return boolean Verification result
	 * @author Sachin Roham
	 * @throws NoSuchAlgorithmException, IOException 
	 */
	
	public boolean verifySHA512ForFile(String digestFilePath, String actualFilePath) throws NoSuchAlgorithmException, IOException{
	
		try {
			File actualFile = new File(actualFilePath);
			FileInputStream fileInputStream = new FileInputStream(actualFile);
			
			BufferedInputStream bufferedInputStream = new BufferedInputStream(fileInputStream);

			MessageDigest messageDigest = MessageDigest.getInstance(SHA_512);
		
			byte[] buffer = new byte[1024];
			int length=0;
			while (bufferedInputStream.available() != 0) {
				length = bufferedInputStream.read(buffer);
				messageDigest.update(buffer,0,length);
			}

			bufferedInputStream.close();
			fileInputStream.close();
			
			File digestFile = new File(digestFilePath);
			fileInputStream = new FileInputStream(digestFile);
			
			byte[] inputBytes = new byte[(int) digestFile.length()];
			fileInputStream.read(inputBytes);
			fileInputStream.close();
			
			return MessageDigest.isEqual(messageDigest.digest(), inputBytes);
			
			
		} catch (FileNotFoundException e) {
			System.err.println("FileNotFoundException : "+ e.getMessage());
			e.printStackTrace();
			throw e;
		} catch (NoSuchAlgorithmException e) {
			System.err.println("NoSuchAlgorithmException : "+ e.getMessage());
			e.printStackTrace();
			throw e;
		} catch (IOException e) {
			System.err.println("IOException : "+ e.getMessage());
			e.printStackTrace();
			throw e;
		}
	
	}
}
