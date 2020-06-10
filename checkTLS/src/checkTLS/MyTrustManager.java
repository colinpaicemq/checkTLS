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
//LIABILITY, WHETHER IN AN ACTION OF CONTRACT

/**
 * This class defines a trust manager.
 * A trust manager is used to check an incoming certificate has a CA entry in the trust store etc
 * 
 */

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Principal;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

public final class MyTrustManager implements X509TrustManager {
 // standard stuff for processing a key store
	int count = 0;

	X509TrustManager myTrustManager = null;
	FileInputStream myKeysStream = null;
	TrustManagerFactory myTrustManagerFactory = null;
	static KeyStore myTrustStore = null;
	CheckCert cc = new CheckCert();
	Parameters parms = null;
	int printTrustStore   = 0;

//	public MyTrustManager(X509TrustManager myTrustManager) {
//		this.myTrustManager = myTrustManager;
//		System.err.println("WE GOT TO X509TrustManager 41 ");
//	}
	/**
	 * From key manager
	 * @return
	 */

	public static KeyStore getTrustManager() {	
		return myTrustStore;
	}
	/*
	 * create the trust manager, and save the user specified parameters 
	 */
 
	public MyTrustManager(Parameters p) throws Exception {
		parms = p;
		printTrustStore = parms.getPrintTrustStore();
		myTrustStore =  openTrustStore();

	}
/**
 * Validate the certificates in the keystore and print them if there is a problem
 */
	void print() throws KeyStoreException, CertificateException {
		//	if (traceTrust > 0 )
		boolean check ;
		if (parms.checkKS.equals("") ||  parms.checkKS.equals("0"))
			check = false;
		else 
			check = true;
		int counter  = 0;
	  if (check)
			for (Enumeration<String> e = myTrustStore.aliases(); e.hasMoreElements();)
			{
				String elem = e.nextElement();
				X509Certificate x509 = (X509Certificate) myTrustStore.getCertificate(elem);

				String title = "==TrustManager:Certificate("+counter+") from trust store: ==Alias:"+ elem;
				if (cc.check(myTrustStore, x509, title  ))  // if it worked  - then print it
				{
					if (check)
						Util.SAN(title ,x509) ;
				}
				counter ++;
			}
	}
	/**
	 * Print a one line summary of the contents of the trust store.
	 */
	static void printTrustStoreSummary() {
		System.out.println("== Summary of Trust Store ");
		try {
			for (Enumeration<String> e = myTrustStore.aliases(); e.hasMoreElements();)
			{
				String elem = e.nextElement();
				X509Certificate x509;
        x509 = (X509Certificate) myTrustStore.getCertificate(elem);
				System.out.printf("== %-12s %-30s Issuer: %-30s %n", elem,x509.getSubjectX500Principal().toString(),x509.getIssuerX500Principal( ) ) ;
			} 
		} catch (KeyStoreException e) {
			System.err.println("KEYSTORE EXCEPTION"+e.toString());
		}

	}

/**
 * Routine is passed in the DN of a signer(CA) certificate
 * Iterate over the keystore looking for the certificate with the same DN
 * @param DN
 * @return
 * @throws KeyStoreException
 */

	X509Certificate getIssuerCertFromMyTrustStore(Principal DN) throws KeyStoreException
	{
		X509Certificate x509 = null;	
		Enumeration<String> ee = myTrustStore.aliases();
		boolean found = false;
		if (ee != null)
			for (Enumeration<String> e = myTrustStore.aliases(); e.hasMoreElements();)
			{
				String elem = e.nextElement();
				x509 = (X509Certificate) myTrustStore.getCertificate(elem);
				if (x509.getSubjectX500Principal().equals(DN))
				{
					found = true;
					break;
				}
			}
		if ( found == true) 
			return x509;
		else 
			return null;
	}

/**
 * Use the trust store parameters to open the file, load it and close it
 * @return
 * @throws Exception
 */
	KeyStore openTrustStore() throws Exception{
    // standard stuff 
		String  trustStoreName = parms.getTruststoreName();
		String  trustStorePassword = parms.getTrustStorePassword();
		String  trustStoreType = parms.getTrustStoreType();
    //  all of the examples on the web do the following
		try {
			myKeysStream = new FileInputStream(trustStoreName);
			myTrustStore = KeyStore.getInstance(trustStoreType);
			myTrustStore.load(myKeysStream, trustStorePassword.toCharArray());
			myKeysStream.close();
			
			myTrustManagerFactory = TrustManagerFactory
					.getInstance(TrustManagerFactory.getDefaultAlgorithm());

			myTrustManagerFactory.init(myTrustStore);

			myTrustManager = null;
			for (TrustManager tm : myTrustManagerFactory.getTrustManagers()) {
				if (tm instanceof X509TrustManager) { myTrustManager = (X509TrustManager) tm;
					break;
				}
			}

		} catch (FileNotFoundException e1) {
			System.out.println("==TrustManager: You must specify a valid -Djavax.net.ssl.trustStore=value");
			e1.printStackTrace();
			throw new Exception("==TrustManager:No trust manager");

		} catch (Exception e1) {
			System.out.println("==TrustManager: You must specify a valid -Djavax.net.ssl.trustStore=value");
			e1.printStackTrace();
			throw new Exception("==TrustManager:No trust manager");
		}
		if (myTrustManager == null) throw new Exception("==TrustManager:No trust manager");
		return  myTrustStore; 
	}
	@Override
	/*
	 * Get the list of CA's (and self signed) from the key store and display them
	 */
	public X509Certificate[] getAcceptedIssuers() 
	{
		// call super object
		X509Certificate[] chain= myTrustManager.getAcceptedIssuers();
		if (printTrustStore > 0 )
		{
			System.out.println("==TrustManager:Certificate authority certificates received which are trusted for authenticating peers." + chain.length);
			for (int j=0; j<chain.length; j++)
			{
				Util.SAN("  ==TrustManager:Trusted:(" + j + ")",chain[j]) ;
			}
			// System.out.println("After getAcceptedIssuers() ");
			System.out.println("==TrustManager:End Certificate authority certificates received which are trusted for authenticating peers.");
		}
		return chain;
	}

	@Override
	/*
	 * Check a certificate (chain) to make sure the CAs etc ar valid
	 */
	public void checkServerTrusted(X509Certificate[] chain,
			String authType) throws CertificateException {
		int certNumber = 0;
		String issuer = "Unknown";
		String serial = "Unknown";
		String subject = "Unknown";
		
		validate(chain[0]); // the first in the list ignoring any included CAs
		
		for (int j=0; j<chain.length; j++)
		{
			subject = chain[j].getSubjectDN().toString();
			issuer = 	chain[j].getIssuerDN().toString();
			serial = chain[j].getSerialNumber().toString();
			Util.SAN("==TrustManager:Certificate sent from server["+ String.valueOf(certNumber) +"] :",chain[j]) ;
			certNumber ++;
		}
		// do basic checks on the server certificate
		if ( chain.length > 0)
		{
			Collection<List<?>> san = chain[0].getSubjectAlternativeNames();
			if ( san == null || san.size() == 0)
				System.err.println("==TrustManager:Server certicate does not have SubjectAlternativeNames");

			if (Util.checkEKU (chain[0], "1.3.6.1.5.5.7.3.1" ) == true) //  TLS Web server authentication
				System.out.println("==TrustManager:Server certicate has serverAuth");
			else
				System.err.println("==TrustManager:Server certicate does not have serverAuth Extended Key Usage");
		}
		
		System.out.println("==TrustManager:key exchange algorithm from server:" + authType);
		try { // pass it to the super to do the real work
			myTrustManager.checkServerTrusted(chain, authType);
		} catch (Exception e) {
			System.err.println("==TrustManager:checkServer certificate catch.  Subject:"+ subject + " Serial:" + serial);
			System.err.println("==TrustManager:checkServer certificate catch.  Issuer:"+ issuer);
			Throwable rootCause = e;
			for ( int i = 0;i < 10;i++)
			{
				System.err.println("==TrustManager:checkServer:root cause: " + rootCause.toString());
				if (rootCause.getCause() == null) break;
				rootCause = rootCause.getCause();
			}
			throw e;
		}
	}

	void validate(X509Certificate x509Cert) throws CertificateException {

		List<X509Certificate> x509 = new ArrayList<X509Certificate>();
		x509.add(x509Cert);
		X509Certificate lx509Cert = x509Cert;
		// start with the certificate passed to us, and extract the issuer name
		// then check in our trust store for that certificate and check again 
		// until we get to the root where issuer=subject
		// we only go 10 deep.
		
		for ( int i = 0; i < 10; i++)
		{
			Principal issuerDN  = lx509Cert .getIssuerX500Principal( );
			Principal subjectDN = lx509Cert .getSubjectX500Principal( );

			if ( issuerDN.equals(subjectDN)) 
				break;  // stop when you get to root of signing certificates
			//		System.out.println("==Sent to me: About to do check of issuer:"+ issuerDN.toString());

			try {
				lx509Cert = getIssuerCertFromMyTrustStore(issuerDN); // from my trust store
				if (lx509Cert != null)
				x509.add(lx509Cert);
			} catch (KeyStoreException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			if (lx509Cert == null) break;
		}

		Collections.reverse(x509); // do from CA down to certificate

		for (X509Certificate x: x509)
		{
			cc.check(myTrustStore,  x,  "==TrustManager: Check the certificate chain");
		}
	}
	@Override
	/*
	 * Check the client certificate sent from client looks OK
	 * Has clientauth
	 * A
	 */
	public void checkClientTrusted(X509Certificate[] chain,
			String authType) throws CertificateException{

		validate(chain[0]);

		X509Certificate issuer = null;
		for (int j=0; j<chain.length; j++)
		{
			Util.SAN("==TrustManager: Certificate sent from client[" +j +"]" ,chain[j]) ;				
		}

		try {
			issuer = getIssuerCertFromMyTrustStore(chain[0]. 	getIssuerX500Principal() );
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		if (issuer == null) 
		{
			System.err.println("==Issuer for certificate sent from client " + chain[0].getSubjectX500Principal( ) + 
					"  ==issuer CANNOT find the issuer " + chain[0].getIssuerX500Principal( ) +" in the trust store");
			System.err.flush();
			throw new CertificateException("Trust store is missing entry for " + chain[0].getIssuerX500Principal( ) );
		}
		else
			System.out.println("==Trust Manager. For certificate sent from client " + chain[0].getSubjectX500Principal( )
					+ ";  found the issuer " + chain[0].getIssuerX500Principal( ) + " in the trust store ");

		// if it is self signed then do not check the EKU
		if (! chain[0].getSubjectX500Principal().equals( chain[0].getIssuerX500Principal()))
		{
			//  \u2714\u274c\
			if (Util.checkEKU (chain[0], "1.3.6.1.5.5.7.3.2" ) == true) // (1.3.6.1.5.5.7.3.2) -- TLS Web client authentication
				System.out.println("==TrustManager: \u2714 Client certicate has clientAuth");
			else
				System.err.println("==TrustManager: \u274c Client certicate does not have clientAuth Extended Key Usage");
		}
		// System.out.println("==TrustManager: Certificate sent from client is ?trusted. Authtype:" + authType);
		myTrustManager.checkClientTrusted(chain, authType);
		System.out.println("==TrustManager: ===" );
	}
}