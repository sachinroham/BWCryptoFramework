# BWCryptoFramework
A Cryptography Framework for Tibco Businessworks

## Custom Functions:
  - String signSHA256withRSA(String privateKeyPath,String content)
  - boolean verifySHA256withRSA(String publicKeyPath, String signatureContent, String content)
  - String encryptRSACipher(String keyPath, String content)
  - String decryptRSACipher(String keyPath, String encryptedContent)
    
## Java Methods:
  - String encryptAES256ForFile(String secretKeyContent, String filePath)
  - String decryptAES256ForFile(String secretKeyContent, String encryptedFilePath)
  - String[] generateECDHKeys()
  - String generateECDHSecret(String privateKeyContent, String publicKeyContent) 
  - String generateSHA512ForFile(String filePath)
  - boolean verifySHA512ForFile(String digestFilePath, String actualFilePath)
  - boolean zipFiles(String zipFilePath, String[] filePaths)
  - String[] unzipFiles(String zipFilePath)  
