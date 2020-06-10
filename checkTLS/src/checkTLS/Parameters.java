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

/*
 * Collect and process input parameters.
 * Parameters can be passed as arguments - or in a file 
 */
import java.security.Security;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Properties;

import javax.naming.ConfigurationException;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;


public class Parameters {
	int printTrustStore = 0;   // dump the trust store when processing requests
	int printKeyManager = 0; // dump the key store when processing requests

	String keyStoreName;
	String keyStoreType;
	String keyStorePassword;
	String trustStoreName;
	String trustStoreType;
	String trustStorePassword;
	String checkTS;  // display Trust Store at startup
	String alias;    // which certificat - if any to use in the key store - default use the first/only
	String checkKS;  // Display Key store at startup
	String host;
	int port = 0;	
	Properties prop;  // this contains the properties set by the user 
	
	// send is an array of what data is sent up by a clients
	// the format is send0=...
	//               send1=...
	List<String> send = new ArrayList<String>();

	// specify methods for getting parameters, with/without default, and convert to int
	public String getStringParm(String name) { 
		String value =  System.getProperty(name,"");
		if (value.equals(""))
			value = prop.getProperty(name, "");			
		return value ;
		}
	public String getStringParm(String name,String defaultValue) { 
		String value = getStringParm(name);
		if (value.equals(""))
			value = defaultValue;
		return value ;
		}
	public int getIntParm(String name) {
		int iValue = 0;
		String value = getStringParm(name);
		if (value.equals(""))
			value = "0";
		try {
		  iValue = Integer.parseInt(value);
		}
		catch (NumberFormatException e)
		{
		  System.err.println("Invalid integer value for:"+name+"="+ value);
		}
		return iValue;
		}
	
	public Parameters(String  type) throws IOException, ConfigurationException
	{
		int errors = 0;
		prop = new Properties();
		String propertyFile =  System.getProperty("propertyFile","");
		// 
		// See if the user specified a parameter file, if so process it
		//
		if (! propertyFile.equals(""))
			try 
			{
				File file = new File(propertyFile);
				System.out.println("Using property file:"+ propertyFile + " -> "+  file.getAbsolutePath());
				InputStream input = new FileInputStream(propertyFile);
				// load a properties file
				prop.load(input);
				System.out.println("Contents of propery file:");
				Enumeration<Object> e = prop.keys();
				// take the parameters and display them in sorted order
				//  by default properties are in hash order so 
				// send0 and send1 are not adjacent
				List<String> ll = new ArrayList<String>();
				while (e.hasMoreElements()) {
					ll.add( (String) e.nextElement());  
				}
				Collections.sort(ll); 
				// and display the sorted list
				for (String l : ll) {
					System.out.println("  "+ l+ ":"+prop.getProperty(l));
				}   

			} catch (FileNotFoundException ex) {
				throw  ex;
			} catch (IOException ex) {
				throw ex;
			} 
		
		
		printTrustStore =  getIntParm("printTrustStore");
		printKeyManager  =  getIntParm("printKeyManager");
		checkKS = getStringParm("checkKS"); // can be none if not specified
		checkTS = getStringParm("checkTS"); // can be none if not specified

		if (type == "Client")
		{
			host = getStringParm("host");
			if (host == null)
			{
				host = "localhost";
				System.err.println("host missing - set to " + host);
			}
		}


		String sPort = getStringParm("port","8443");
		try {
			port = Integer.parseInt(sPort);
		} catch (Exception e) {
			System.err.println("Invalid -Dport value");
			throw e;
		}

		//
		// keystore processing 
		//
		keyStoreName = getStringParm("javax.net.ssl.keyStore");
		if (keyStoreName == null)
		{
			throw new IllegalArgumentException("==KeyManager. You must specify a valid -Djavax.net.ssl.keyStore=value");
		}

		keyStorePassword = getStringParm("javax.net.ssl.keyStorePassword");
		if (keyStorePassword == null)
		{
			throw new IllegalArgumentException("==KeyManager.  You must specify a valid -Djavax.net.ssl.keyStorePassword=value");
		}

		File ks = new File(keyStoreName);
		if ( ! ks.exists())
		{
			    System.out.println("keyStore "+ keyStoreName +" does not exist");
			    errors ++;
		}
		else
		if ( ! ks.canRead())
		{
				    System.out.println("keyStore "+ keyStoreName +" is not readable");
				    errors ++;
		}
		
		keyStoreType = getStringParm("javax.net.ssl.keyStoreType");	
		if (keyStoreType == null)
		  	throw new IllegalArgumentException("==KeyManager.  You must specify a valid -Djavax.net.ssl.keyStoreType=value");
			
		//
		// trust store processing
		//
		trustStoreName = getStringParm("javax.net.ssl.trustStore");
		if (trustStoreName == null)
		{
			throw new IllegalArgumentException("==KeyManager. You must specify a valid -Djavax.net.ssl.keyStore=value");
		}

		File ts = new File(trustStoreName);
		if ( ! ts.exists())
		{
			    System.out.println("trustStore "+ trustStoreName +" does not exist");
			    errors ++;
		}
		else
		if ( ! ts.canRead())
		{
				    System.out.println("trustStore "+ trustStoreName +" is not readable");
				    errors ++;
		}
		trustStoreType = getStringParm("javax.net.ssl.trustStoreType");		
		if (trustStoreType == null)
		{
			throw new IllegalArgumentException("==trustManager.  You must specify a valid -Djavax.net.ssl.trustStoreType=value");
		}

		trustStorePassword = getStringParm("javax.net.ssl.trustStorePassword");
		if (trustStorePassword == null)
		{
			throw new IllegalArgumentException("==trustManager.  You must specify a valid -Djavax.net.ssl.trustStorePassword=value");
		}

		//
		// Allow the selection of a key from the key store
		//
		alias = getStringParm("alias","");

		//
		//
		//
		//System.out.println("  jdk.tls.server.protocols="+getStringParm("jdk.tls.server.protocols"));
		//System.out.println("  jdk.tls.client.protocols="+getStringParm("jdk.tls.client.protocols"));

	  //
		// display the parameter we have
		//
		System.out.println("==Parameters");
		System.out.println("  Keystore name:"+ keyStoreName +" type:" + keyStoreType 
				+" password:...") ;
		System.out.println("  Truststore name:"+ trustStoreName +" type:" + trustStoreType 
				+" password:..." );
		System.out.println("  Keystore Alias:"+ alias);
		System.out.println("  traceTrust: " + printTrustStore +" traceKeyStore: " + printKeyManager );
		// get local + security parameters display and update
		SecurityProperties("jdk.tls.disabledAlgorithms");
		SecurityProperties("jdk.certpath.disabledAlgorithms");

		//		String certpath_disabledAlgorithms = getStringParm("jdk.certpath.disabledAlgorithms","");
		//		System.out.println("==jdk.tls.disabledAlgorithms = "
		//				+ Security.getProperty("jdk.tls.disabledAlgorithms"));
		//		System.out.println("==jdk.certpath.disabledAlgorithms = "
		//				+ Security.getProperty("jdk.certpath.disabledAlgorithms"));
		//		
		//System.err.println("==jdk.tls.client.cipherSuites = "
		//		+ getStringParm("==jdk.tls.client.cipherSuites",""));
		System.out.println("==jdk.tls.client.cipherSuites = "
				+ getStringParm("jdk.tls.client.cipherSuites",""));

		//		System.err.println("==javax.net.ssl.keyStore = "
		//				+ getStringParm("javax.net.ssl.keyStore",""));
		//		System.out.println("==javax.net.ssl.keyStore = "
		//				+ getStringParm("javax.net.ssl.keyStore",""));
		if (errors > 0)
			throw new ConfigurationException("errors detected");
	}

	//
	// Update the security policy if they have specified the local parameters
	// 
	void SecurityProperties(String what)
	{
		String local = getStringParm(what,"");
		String javas = Security.getProperty(what);
		if (local.equals(""))
		{
			System.out.println("  Using Security."+what + ":"+javas);
		}
		else
		{
			System.out.println("  Updating Security."+what + ":"+javas + " with " + local);
			Security.setProperty(what, javas +"," +local);	
		}
	}


	public String getKeystoreName() {
		return keyStoreName;
	}
	public String getKeystoreType() {
		return keyStoreType;
	}
	public String getKeyStorePassword() {
		return keyStorePassword;
	}

	public int getPrintTrustStore	()
	{
		return printTrustStore;
	}
	public int getPrintKeyStore()
	{
		return printKeyManager;
	}
	public String getTruststoreName() {
		return trustStoreName;

	}
	public String getTrustStorePassword() {
		return trustStorePassword;
	}
	public String getTrustStoreType() {
		return trustStoreType;
	}
	public void display() {
		// TODO Auto-generated method stub

	}
	//
	// This defaults to TLS v.12
	//
	public String getTLS(String string) {
		
		String  tls;
		if (string.equals("Server"))
			tls = getStringParm("jdk.tls.server.protocols");
		else
		tls = getStringParm("jdk.tls.client.protocols");
		if (tls == null || tls.length() == 0)
			tls= "TLSv1.2";
		else
		{
			tls = tls.replace(","," ").replace(";"," ");
			String stls[] = tls.split(" ");
			tls = stls[0];
		}
		if (string.equals("Server"))
		  System.out.println(" 2 jdk.tls.server.protocols="+tls );
		else 
			System.out.println(" 2  jdk.tls.client.protocols="+tls );
		return tls;
	}

}
