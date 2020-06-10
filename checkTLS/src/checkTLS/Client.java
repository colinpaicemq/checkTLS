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


/**
 * Program to act as a client to a web server and display certificate sent down,
 * and sent up.
 * Basic checks are done
 * 
 * We need: 
 * a key store holding the certificate and private key 
 * a trust manager holding the public keys to validate certificate send to client
 * 
 * Get a connection and try to connect to the server
 */

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.SocketException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

import javax.naming.ConfigurationException;
import javax.net.SocketFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;


public class Client {
	SSLParameters sslp;
	public static void main(String args[]) {
		Client start = new Client();
		try {
			start.dowork(args);
		} catch (Exception e) {
			// TODO Auto-generated catch block		port = 19443;
			e.printStackTrace();
		}
		return ;
	}

	public void dowork(String args[]) throws Exception  {
		String host = "localhost";
		int port = 8443;	
		SSLContext sc;
		sc = null;
		// process the parameters
		Parameters params; 
		try {
		  params = new Parameters("Client");
		} catch (ConfigurationException | IOException e2) {
			// TODO Auto-generated catch block
			return;
		}
		host = params.host;
		port = params.port;
		System.out.println("CLIENT: using "+host+":"+port);

		String  tls = params.getTLS("Client");  // the version of TLS eg TLSv1.2
		X509TrustManager customTrustManager = new MyTrustManager(params);

		System.out.println("Loaded trust manager successfully");
		
		try {
			sc = SSLContext.getInstance(tls);
			MyKeyManager myKeyManager = new MyKeyManager(params);
			sc.init(new MyKeyManager[] {myKeyManager }  , 
		    			new TrustManager[] { customTrustManager }, 
				    	new java.security.SecureRandom()
					);

		} catch (NoSuchAlgorithmException e2) {
			// TODO Auto-generated catch block
			e2.printStackTrace();
			return;
		}
		
		catch (KeyManagementException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return;
		}
		
		// display the contents - it checks to see if print is needed
		((MyTrustManager)customTrustManager).print();

		SocketFactory factory = sc.getSocketFactory(); 
		SSLSession ss = null;

		try (Socket connection = factory.createSocket(host, port)) 
		{
			// protocols could be TLSV1.2 or TLSV1.3
			((SSLSocket) connection).setEnabledProtocols(	new String[] { tls });

			// display the signatures
			Util.PeerSupportedSignatureAlgorithms(ss);
			long start  = System.currentTimeMillis();
			//  we need to define an SSLParameters so we can get them
			// SSLParameters sslParams = new SSLParameters();
			//(SSLSocket) connection).setSSLParameters(sslParams);

			sslp = ((SSLSocket) connection).getSSLParameters();
			displayCipherSuites();
			BufferedReader input = new BufferedReader(
				new InputStreamReader(connection.getInputStream()));
					
			Util.displayProtocols(((SSLSocket) connection).getSSLParameters(), 
			                      "No protocol found.  Check  -Djdk.tls.client.protocols=...");
						
			// start the connection and do the handshake
			ss =  ((SSLSocket) connection). getSession();
			if (! ss.isValid()) 
			{
				System.out.println("==!! ");    
				System.out.println("==!! connection is not valid");
				System.out.println("==!! ");
				//throw new SocketException("!!Connection is not valid");
         return;
			}
		//	displayCipherSuites();

			ss =  ((SSLSocket) connection). getSession();
			Util.PeerSupportedSignatureAlgorithms(ss);
		//	if (! ss.isValid()) 
			
			// Open connection so we can write to it
			PrintWriter out = new PrintWriter(connection.getOutputStream(), true);
			String sendData = "";
			// check to see if there is data to be sent as in send0, send1, etc parameters
			if (params.prop.containsKey("send0"))// we had some parameters to send  
				for (int i = 0;;i++)
				{
					String key = "send"+i;
					if (!params.prop.containsKey(key))  // not found - it was the last one
						break;
					sendData =params.prop.getProperty(key);
					System.out.println("SEND: "+key +":"+sendData);
					out.println(sendData);  // send the data
				}
			else  // no data specified by the user
			{
				sendData = "xxxxy";
				out.println(sendData);  // send the data 
				System.out.println("SEND: send"+sendData);
				out.println(""); // send end of data
			}
			// the end of transmission is a null line, so send one if required
			if (!sendData.equals(""))
				out.println("");

			System.out.println("Data from server:"+ input.readLine());
			System.out.println("Request took:" + (System.currentTimeMillis()- start)+ " milliseconds");
			Util.displayConnection(ss,"as seen by the client");
		} catch (SocketException e) {
			// we can get here for many reasons

			Throwable rootCause = e;
			for ( int i = 0;i < 10;i++)  // only display the first few elements in the stack
			{
				System.err.println("Client:root cause: " + rootCause.toString());
				if (rootCause.getCause() == null) break;  // end of root cause stack
				rootCause = rootCause.getCause();
			}
			e.printStackTrace();
		}
		catch (Exception e) {

			Throwable rootCause = e;
			for ( int i = 0;i < 10;i++)  // only display the first few elements in the stack
			{
				System.err.println("Client:root cause: " + rootCause.toString());
				if (rootCause.getCause() == null) break;
				rootCause = rootCause.getCause();
			}
			e.printStackTrace();
		}
		return;
	}
	/*
	 * Display the cipher suites available to the client.
	 */
	void displayCipherSuites()
	{
		// display the cipher suites.   It returns the count of them.  If count = 0 this
		// is a problems
		if (Util.displayCipherSuites(sslp.getCipherSuites()) == 0 )
		{
			System.out.println("==No cipher suites for client connection");
			System.out.println("  Check  -Djdk.tls.client.protocols -Djdk.tls.client.cipherSuites combination");
			throw new IllegalArgumentException("No cipher suites for client connection.  Check  -Djdk.tls.client.protocols -Djdk.tls.client.cipherSuites combination"); 
		}
	}
}