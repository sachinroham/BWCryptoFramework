package com.tibco.psg.bw.zip;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

public class ZipUtility {

	final byte[] buffer = new byte[1024];

	
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
	public boolean zipFiles(String zipFilePath, String[] filePaths) throws IOException{
        try {

        	ZipOutputStream zipOutputStream = new ZipOutputStream(new FileOutputStream(zipFilePath));
			
			for(String currentFile:filePaths){
				File file =  new File(currentFile);
				FileInputStream fileInputStream =  new FileInputStream(file);
				
				zipOutputStream.putNextEntry(new ZipEntry(file.getName()));
				int length;
	    		while ((length = fileInputStream.read(buffer)) > 0) {
	    			zipOutputStream.write(buffer, 0, length);
	    		}

	    		fileInputStream.close();
	    		zipOutputStream.closeEntry();
           
	    	}
			zipOutputStream.close();
			return true;
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

	public String[] unzipFiles(String zipFilePath) throws IOException{
		try {
			
			File zipFile =  new File(zipFilePath);
			ZipInputStream zipInputStream =  new ZipInputStream(new FileInputStream(zipFile));
			ZipEntry zipentry = null;
			
			ArrayList<String> extractedFiles = new ArrayList<String>();
			
			while( (zipentry = zipInputStream.getNextEntry())!=null ){
	
				File currentFile = new File(zipFile.getParent() + File.separator + zipentry.getName());
				FileOutputStream fileOutputStream = new FileOutputStream(currentFile);
				
	            int length;
	            while ((length = zipInputStream.read(buffer)) > 0) {
	            	fileOutputStream.write(buffer, 0, length);
	            }
	        	
	            fileOutputStream.close();
	            zipInputStream.closeEntry();
	            extractedFiles.add(currentFile.getCanonicalPath());
			}
			
			zipInputStream.close();
			
			String[] extractedFilePath =  new String[extractedFiles.size()]; 
			
			for (int i = 0; i < extractedFiles.size(); i++) {
				extractedFilePath[i] = extractedFiles.get(i);
			}
			
			return extractedFilePath;
			
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
	
	
	public static void main(String[] args) throws IOException {
		ZipUtility zipUtility = new ZipUtility();
		String zipFilePath = "C:/tmp/document.zip";
		String[] filePaths = new String [3];
		filePaths[0] = "C:/tmp/document.sha512";
		filePaths[1] = "C:/tmp/document.enc";
		filePaths[2] = "C:/tmp/document.pdf";
		boolean result = zipUtility.zipFiles(zipFilePath, filePaths);
		
		System.out.println("Zip File Result :" + result);
		
		
		String[] extractedFiles = zipUtility.unzipFiles(zipFilePath);
		for(String file : extractedFiles){
			System.out.println("Extracted File :" + file);
		}
		

	}

}
