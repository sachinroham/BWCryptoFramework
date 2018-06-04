# BWCryptoFramework
A Cryptography Framework for Tibco Businessworks

## Custom Functions:

 ###	
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
  - String signSHA256withRSA(String privateKeyPath,String content)
  
  ###	
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
  - boolean verifySHA256withRSA(String publicKeyPath, String signatureContent, String content)
  
  ###	
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
  - String encryptRSACipher(String keyPath, String content)
  
   ###	
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
  - String decryptRSACipher(String keyPath, String encryptedContent)
    
## Java Methods:
###    
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
  - String encryptAES256ForFile(String secretKeyContent, String filePath)
  
  ###    
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
  - String decryptAES256ForFile(String secretKeyContent, String encryptedFilePath)
  
  ###   
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
  - String[] generateECDHKeys()
  
  ###	
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
  - String generateECDHSecret(String privateKeyContent, String publicKeyContent) 
  
  ###	
  	/**
	 * Generate a SHA256 digest for given file
	 * 
	 * @param filePath Input file path
	 * 
	 * @return String Generated Digest
	 * @author Sachin Roham
	 * @throws NoSuchAlgorithmException, IOException 
	 */
  - String generateSHA512ForFile(String filePath)
  
  ###	
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
  - boolean verifySHA512ForFile(String digestFilePath, String actualFilePath)
  
  ###	
  	/**
	 * Create a Zip File out of the supplied files
	 * 
	 * @param zipFilePath Full path of the zip file
	 * @param filePaths Array of file paths
	 * 
	 * @return boolean Result of the Zip Operation
	 * @author Sachin Roham
	 * @throws IOException 
	 */
  - boolean zipFiles(String zipFilePath, String[] filePaths)
  
  ###	
  	/**
	 * Extacts the contents of the given zip file
	 * 
	 * @param zipFilePath Full path of the zip file
	 *  
	 * @return String[] filePaths Array of extracted files 
	 * @author Sachin Roham
	 * @throws IOException 
	 */
  - String[] unzipFiles(String zipFilePath)  
