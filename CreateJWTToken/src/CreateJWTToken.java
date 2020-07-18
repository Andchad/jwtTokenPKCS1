import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.Base64;
import java.util.Enumeration;
import java.util.Map;
import java.util.Properties;
import java.util.Scanner;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import sun.security.util.DerInputStream;
import sun.security.util.DerValue;

public class CreateJWTToken {

	@SuppressWarnings({ "unchecked", "rawtypes" })
	public static void main(String[] args) throws Exception {
		
		System.out.println("Please insert configuration file full path: ");
		
		Scanner in = new Scanner(System.in);
        String configurationFilePath = in.nextLine();
        in.close();
   
        Properties properties = readPropertiesFile(configurationFilePath);
        
        //check file for validity
        if(!properties.contains("private.key")) {
        	System.out.println("Please add a private key value to your properties file with key : private.key");
        	return;
        }
        
        //add claims 
        Claims claims = Jwts.claims();
        
        Enumeration<String> enums = (Enumeration<String>) properties.propertyNames();
        System.out.println("======================================");
        System.out.println("Claims : ");
        while (enums.hasMoreElements()) {
          String key = enums.nextElement();
          String value = properties.getProperty(key);
          if(!key.equals("private.key")) {
        	  claims.put(key, value);
          }
          System.out.println(key + " : " + value);
        }
        System.out.println("Claims end");
        System.out.println("======================================");
        
        //get private key
        String privateKeyString =  properties.getProperty("private.key");
        
		
		SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.RS256;
		
		Header header = Jwts.header();
		header.setType("JWT");
		
		String result = null;
		try {
			PrivateKey privKey = readPrivateKeyPKCS1PEM(privateKeyString);
            result = Jwts.builder().setClaims(claims).setHeader((Map<String, Object>)header).signWith(signatureAlgorithm, privKey).compact();
		} catch (NoClassDefFoundError e) {
			System.out.println(e.getMessage());
		}
		
		System.out.println("JWT : " + result);
		
	}
	
	public static PrivateKey readPrivateKeyPKCS1PEM(String content) throws Exception {
		
        content = content.replaceAll("\\n", "").replace("-----BEGIN RSA PRIVATE KEY-----", "").replace("-----END RSA PRIVATE KEY-----", "");
        content = content.replaceAll("\\s+","");
        
        byte[] bytes = Base64.getDecoder().decode(content);

        DerInputStream derReader = new DerInputStream(bytes);
        DerValue[] seq = derReader.getSequence(0);
        // skip version seq[0];
        BigInteger modulus = seq[1].getBigInteger();
        BigInteger publicExp = seq[2].getBigInteger();
        BigInteger privateExp = seq[3].getBigInteger();
        BigInteger prime1 = seq[4].getBigInteger();
        BigInteger prime2 = seq[5].getBigInteger();
        BigInteger exp1 = seq[6].getBigInteger();
        BigInteger exp2 = seq[7].getBigInteger();
        BigInteger crtCoef = seq[8].getBigInteger();

        RSAPrivateCrtKeySpec keySpec =
                new RSAPrivateCrtKeySpec(modulus, publicExp, privateExp, prime1, prime2, exp1, exp2, crtCoef);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
        
        return privateKey;
        
    }
	
	public static Properties readPropertiesFile(String fileName) throws IOException {
	      FileInputStream fis = null;
	      Properties prop = null;
	      try {
	         fis = new FileInputStream(fileName);
	         prop = new Properties();
	         prop.load(fis);
	      } catch(FileNotFoundException fnfe) {
	         fnfe.printStackTrace();
	      } catch(IOException ioe) {
	         ioe.printStackTrace();
	      } finally {
	         fis.close();
	      }
	      return prop;
	   }
	
}
