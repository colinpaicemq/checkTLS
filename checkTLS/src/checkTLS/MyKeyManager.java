package checkTLS;
//MIT License
//
//Copyright (c) 2020 Stromness Software Solutions.
//
//Permission is hereby granted, free of charge, to any person obtaining a copy
//of this software and associated documentation files (the "Software"), to deal
//in the Software without restriction, including without limitation the rights
//to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//copies of the Software, and to permit persons to whom the Software is
//furnished to do so, subject to the following conditions:
//
//The above copyright notice and this permission notice shall be included in all
//copies or substantial portions of the Software.
//
//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//SOFTWARE.
//
//* Contributors:
//*   Colin Paice - Initial Contribution

/*
 * My key manager manages the key manager containing the private key to be used 
 */


import java.io.FileInputStream;
import java.io.IOException;
import java.net.Socket;
// import java.security.AlgorithmConstraints;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
// import javax.net.ssl.SSLSocket;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509KeyManager;
/**
 * @author colinpaice
 *
 */
// base it on the Sun provided key manager
public class MyKeyManager extends X509ExtendedKeyManager  {
	X509KeyManager myKeyManager;
	int count = 0;
	KeyStore keyStore;
	CheckCert cc = new CheckCert();
	int printedCAIssuer = 0;

	KeyStore myTrustStore =  MyTrustManager.getTrustManager() ;
	Parameters parms = null; 
	

	/**
	 * Constructor to set up the key manager 
	 * <p> 
	 *
	 * @param  none 	 * @param  name the location of the image, relative to the url argument
	 * @throws Exception 
	 * 
	 */

	public MyKeyManager(Parameters p) throws Exception {
		parms = p;
		KeyManager[] keymanager = null;  
		int printKeyManager = parms.getPrintKeyStore(); // if the key store should be printed
		String  keyStoreName = parms.getKeystoreName();
		String  keyStorePassword = parms.getKeyStorePassword();
		String  keyStoreType = parms.getKeystoreType();
		
		System.out.println("==KeyManager KeyStore name:" +keyStoreName + ", type:" + keyStoreType );
		// AlgorithmConstraints a = new AlgorithmConstraints();
		try {
			// standard stuff 
			keyStore = KeyStore.getInstance(keyStoreType );
			keyStore.load(new FileInputStream(keyStoreName), keyStorePassword.toCharArray());
			
			System.out.println("==KeyManager provider:" + keyStore.getProvider().toString());
			// list all of the names in the keystore 
			if (printKeyManager > 0 )
				printKeyStore(printKeyManager);
		//	summariseKeyStore();
			// set it up - standard stuff
			KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());

			// read the file into the key manager factory
			keyManagerFactory.init(keyStore, keyStorePassword.toCharArray());
			keymanager = keyManagerFactory.getKeyManagers();
		} catch (NoSuchAlgorithmException  e) {
			// TODO Auto-generated catch block
			System.out.println("NoSuchAlgorithmException EXCEPTION:" + e);
			// e.printStackTrace();
			throw e;
		} catch (UnrecoverableKeyException e) {
			// TODO Auto-generated catch block
			System.out.println("UnrecoverableKeyException EXCEPTION:" + e);
			// e.printStackTrace();
			throw e;
		} catch (KeyStoreException  | CertificateException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw e;
		}
		myKeyManager = (X509KeyManager) keymanager[0];
	}

//	void summariseKeyStore() {
//		try {
//			Enumeration<String> enumeration = keyStore.aliases();
//		
//			while(enumeration.hasMoreElements()) {
//				String alias = enumeration.nextElement();
//				X509Certificate x509 =   (X509Certificate) keyStore.getCertificate(alias);
//				String subject = x509.getSubjectX500Principal().toString() ;
//			  String alg = x509.getSigAlgName();
//			  keyStoreSummary.put(subject,alg);
//			  System.out.println("Summarise keystore added "+alias +" " +subject +":"+alg);
//			}
//		} catch (KeyStoreException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
//		
//	}
	/**
	 * @param printKeyManager 
	 * 
	 */
	void	printKeyStore(int printKeyManager)
	{
		//  We can only go thorugh it by listing the aliases
		//  then getting the certificate for each alias
		
		// if (!parms.checkKS.equals("")) // not the default
		if (printKeyManager > 0)
		try {
			Enumeration<String> enumeration = keyStore.aliases();
			System.out.println("==KEYSTORE CONTENTS ===");
			while(enumeration.hasMoreElements()) {
				String alias = enumeration.nextElement();
				String title = "====KeyManager.Clients keystore has alias name: " + alias;
				// System.out.println(title );
				X509Certificate x509 =   (X509Certificate) keyStore.getCertificate(alias);
				if (printKeyManager == 1)
					System.out.printf("== %-12s %-30s Issuer: %-30s %n", alias,x509.getSubjectX500Principal().toString(),x509.getIssuerX500Principal( ) ) ;
				if (printKeyManager > 1 && cc.check(myTrustStore, x509,  title))
					Util.SAN(title ,x509) ;
			}
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println("==========END OF KEYSTORE CONTENTS ============");
	}
	/**
	 * Return a list of alias names matching the list
	 * of Issuers(signers) 
	 * 
	 * @param  key type RSA
	 * @param  List of DNs 
	 */
	public String[] getClientAliases(String keyType,
			Principal[] issuers) {

		System.out.println("keytype"+keyType);
		System.out.println("==KeyManager.getClientAliases: keytype"+keyType);
		for (Principal p  : issuers)
			System.out.println("issuers"+p);
		return  myKeyManager. getClientAliases(keyType, issuers);

	}
	/**
	 * Returns the certificate for a client when passed the alias name
	 *  
	 * @param alias
	 * @return x509 certificate
	 * @throws KeyStoreException
	 */

	X509Certificate getCertAlias(String alias) throws KeyStoreException
	{
		X509Certificate x509 = (X509Certificate) keyStore.getCertificate(alias);
		return x509;
	}
	/**
	 * Returns an alias from the keystore which matches the list of 
	 * CAs, and the socket 
	 * 
	 * @param type eg RSA, EC
	 * @parma issuer - the list of DNs
	 * @param the socket ( unused as far as I can tell)
	 */
	public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
		// System.out.println("==KeyManager.  Choose Client Alias from client keystore");
		/* print out the list of keytypes */
	
		if (printedCAIssuer == 0)
		{
			printedCAIssuer =1;
			if (issuers != null)
			{
				System.out.println("==KeyManager.List of acceptable CA issuer subject names:");
				for (Principal p  : issuers)
				{
					System.out.println("==KeyManager.   "+p);
				}}
			else 
				System.out.println("==KeyManager.There was no list of acceptable CAs. Any issuer can be used");
		}
		
		String keyNames = "";
		for (String s : keyType)
			keyNames += s +" ";

		// System.out.println("==KeyManager.Choose Client Alias from client keystore key ==algorithms:"+keyNames);
		// ask super to chose
		String s = myKeyManager.chooseClientAlias(keyType, issuers, socket);
		// and print what was chosen
		if (s ==null)
		{
			System.out.println("==KeyManager.  No client certificate found matching CA and key type:" + keyNames);
		}
		else 
			{
			  System.out.println("==KeyManager.Alias found with matching CA and key type:" + keyNames + " ==>: " +s);
			 if (keyType[0].equals("RSASSA-PSS"))
				 System.out.println("==KeyManager: WARNING RSASSA-PSS may not be supported and cause bad certificate errors ");
			}
		return s;
	}

	/**
	 *  Returns the certificate for a server when passed the alias name
	 *  
	 * @param alias
	 * @return x509 certificate
	 * @throws KeyStoreException
	 */
	@Override
	public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {

	//	count = count + 1;
		// if the user did specify an alias then use what they passed else find one  
		if (!parms.alias.equals(""))
				return parms.alias; 
		// so use the Sun version 
		String ret = myKeyManager.chooseServerAlias(keyType, issuers, socket);
		String printRet = ret;
		if (printRet == null)  
			printRet = "null";
		// build the issuer (is)
		String is = "";
		if ( issuers == null)
			is = " :Issuer CA names :none";
		else {
			is = "Issuer CA names:";
			for ( Principal i : issuers) {
				is = is +" "+ i;
			}
		}
		System.out.println("==KeyManager.chooseServerAlias keytype:" + keyType +is + "  returned " + printRet);
		if ( issuers != null)
			for (Principal p  : issuers)
				System.out.println("issuers"+p);
		// build a list of key types which some browsers complain about
		 List<String> list = Arrays.asList("RSASSA-PSS");
		 if (list.contains(keyType))
			 System.out.println("==KeyManager: WARNING This may not be supported and cause bad certificate errors ");
		return ret;
	}
	/**
	 * 
	 */
	public X509Certificate[] getCertificateChain(String alias) {

		System.out.println("==KeyManager.  Get CertificateChain for " + alias);
		X509Certificate[] x = myKeyManager.getCertificateChain(alias);
		int count = 0;
		if ( x != null)
			for (X509Certificate x509 : x)
			{
				try {
					validate(x509, "==getCertificateChain");
				} catch (CertificateException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				Util.SAN("==KeyManager.  GetCertificateChain number["+count+"]",x509);
				count ++;
			}
		else 
			System.out.println("==KeyManager. No keystore CertificateChain for " + alias);
		return x;
	}

	/**
	 * Given an alias return the private key
	 */
	public PrivateKey getPrivateKey(String alias) {
    if (alias != null)
		  System.out.println("==KeyManager.  Get private key for " + alias);
		PrivateKey pk =  myKeyManager.getPrivateKey(alias);
		return pk;
	}

	/**
	 * the key manager is serially reused
	 * This routine resets it
	 */

	public void reset() {
		count = 0;
	}

	/**
	 * List all of the names in the keystore
	 */
	public String[] getServerAliases(String keyType, Principal[] issuers) {
		System.out.println("==KeyManager.getServerAliases");
		for (Principal p  : issuers)
			System.out.println("  issuers"+p);

		System.out.println("==KeyManager.getServerAliases.Keytype:"+keyType);
		
		return myKeyManager.getServerAliases(keyType, issuers) ;
	}

	void validate(X509Certificate x509Cert,String title) throws CertificateException {
		cc.check(myTrustStore ,x509Cert, title);
	}
}