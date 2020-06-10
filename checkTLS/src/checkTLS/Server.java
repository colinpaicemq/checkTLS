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
 *  This program acts as a TLS/SSL server and prints out information about
 *  TLS requests.  For example when a browser connects to the port, information
 *  about the certificate, and its validity are displayed.
 */

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;

import javax.naming.ConfigurationException;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;


public class Server {
	public static void main(String args[]) throws IOException {
  		Server start = new Server();
//		Set<String> a  = new  HashSet<>(Security.getAlgorithms("Signature"));
//		for ( String s : a)
//		System.out.println("Signature"+ s  );
//		
//		a  = new  HashSet<>(Security.getAlgorithms("MessageDigest"));
//		for ( String s : a)
//		System.out.println("MessageD "+ s  );
//		
//		a  = new  HashSet<>(Security.getAlgorithms("Mac"));
//		for ( String s : a)
//		System.out.println("Mac "+ s  );
//		
//		a  = new  HashSet<>(Security.getAlgorithms("Cipher"));
//		for ( String s : a)
//		System.out.println("Cipher "+ s  );
//		
//		a  = new  HashSet<>(Security.getAlgorithms("KeyStore"));
//		for ( String s : a)
//		System.out.println("KeyStore "+ s  );
//		System.out.println(Security.getProviders("AlgorithmParameters.EC")[0]
//		    .getService("AlgorithmParameters", "EC").getAttribute("SupportedCurves"));
		
		start.dowork(args);
		return ;
	}
	/**
	 * Key things are 
	 * - the keystore holding the certificate to identify the server
	 * - the trust store holding the certificates to validate any certificate sent 
	 *   to the server
	 * - session
	 * - connection 
	 * @param args
	 * @throws IOException
	 */

	public void dowork(String args[]) throws IOException  {
		MyKeyManager myKeyManager = null;
		X509TrustManager customTrustManager = null;
		SSLServerSocketFactory factory = null;

		SSLContext serverContext = null;
		Parameters parms;
		// read and validate the parameters
		try {
			parms = new Parameters("Server");
		} catch (ConfigurationException | IOException e2) {
			// TODO Auto-generated catch block
			return;
		}

		int port = parms.port;
		System.out.println("Starting server on "+ port);
		// set up the trust manager 

		String  tls = parms.getTLS("Server");  // for example TLSv1.2

		try {
			serverContext  = SSLContext.getInstance(tls);
			customTrustManager = new MyTrustManager(parms);
			System.out.println("Loaded trust manager successfully");

			myKeyManager = new MyKeyManager(parms);
			// this code copied from the web.
			serverContext.init(new MyKeyManager[] {myKeyManager }  , 
					new TrustManager[] { customTrustManager }, 
					new java.security.SecureRandom()
					);
			factory = (SSLServerSocketFactory)serverContext.getServerSocketFactory();
		} catch (NoSuchAlgorithmException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		// print the trust store contents
		if (!parms.checkTS.equals("")) // not the default
			try {
				((MyTrustManager)customTrustManager).print();
			} catch (KeyStoreException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (CertificateException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}

		SSLServerSocket sslListener = null;
		try (ServerSocket listener = factory.createServerSocket(port)) {
			sslListener = (SSLServerSocket) listener;
			sslListener.setNeedClientAuth(true);
			sslListener.setEnabledProtocols(	new String[] { tls });
			System.out.println("=== after set enabled:"+tls);
			//	The following section looked interesting, but was always null
			// AlgorithmConstraints a = sslListener.getSSLParameters().getAlgorithmConstraints();
			// 	System.out.println("====AG"+a);

			//
			// This does the work
			//
			while (true) {
				System.out.println("<-------------- new connection -------------->");
				myKeyManager.reset();// set counter to 0;
				//
				// wait for a connection connects to the server
				//
				try (Socket socket = sslListener.accept()) {
					System.out.println("==Socket: Local port" + socket.getLocalPort() +" Remote port:" +socket.getPort());
					SSLParameters sslp = ((SSLSocket) socket).getSSLParameters();
		   		// the protocols can change depending on the client
					Util.displayProtocols(sslp,"No protocol found. Check -Djdk.tls.server.protocols=...");

					System.out.println("==Enabled cipher suites for server connection");
					if (Util.displayCipherSuites(sslListener.getEnabledCipherSuites()) == 0 )
					{
						System.out.println("==No cipher suites for server connection");
						System.out.println("  Check  -Djdk.tls.server.protocols -Djdk.tls.server.cipherSuites combination");
						throw new IllegalArgumentException("No cipher suites for server connection.  Check  -Djdk.tls.server.protocols -Djdk.tls.server.cipherSuites combination"); 
					}
							
					((SSLSocket) socket).startHandshake();//  this instruction causes any certificate exceptions

					SSLSession  ss = ((SSLSocket) socket). getSession();

          System.out.println("PROOTOCLA:"+ss.getProtocol());
//					System.out.println("==Enabled cipher suites for server connection");
//					if (Util.displayCipherSuites(sslListener.getEnabledCipherSuites()) == 0 )
//					{
//						System.out.println("==No cipher suites for server connection");
//						System.out.println("  Check  -Djdk.tls.server.protocols -Djdk.tls.server.cipherSuites combination");
//						throw new IllegalArgumentException("No cipher suites for server connection.  Check  -Djdk.tls.server.protocols -Djdk.tls.server.cipherSuites combination"); 
//					}			

					// Start handling application content
					// we read from the input stream, and write to the output stream 
					InputStream inputStream = ((SSLSocket)socket).getInputStream();
					OutputStream outputStream = ((SSLSocket)socket).getOutputStream();

					BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
					
					String line = null;
					while((line = bufferedReader.readLine()) != null){
						System.out.println("Input received from client: "+line);
						// keep going until we get a null record indicating end of flow
						if(line.trim().isEmpty()){
							break;
						}
					}
					// we have finished with the input
					String value = Util.displayConnection(ss,"As seen by the server") ;
				  // now send the reply
					PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
					DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
					Calendar cal = Calendar.getInstance();
					String now = dateFormat.format(cal.getTime());
					out.println("HTTP/1.1 200 OK");
					out.println("Set-Cookie: colin=colincookietime"+now+ "; Expires=Thu, 01 Dec 2021 16:00:00 GMT; Path=/; Secure; HttpOnly");
					// out.println("Set-Cookie: colin=\"\"; Expires=Thu, 01 Dec 2021 15:00:00 GMT; Path=/; Secure; HttpOnly");

					//					out.println("Set-Cookie: colin=colincookietime2; Expires=Thu,01 Dec 1994 16:00:00; Path=/; Secure; HttpOnly");
					////				out.println("HTTP/1.1 200 OK");
					////				out.println("Set-Cookie: colin=colincookietime; Expires=Thu,01 Dec 1994 16:00:00");
					////				out.println("X-Content-Type-Options: nosniff");
					////				out.println("X-Frame-Options: SAMEORIGIN");
					////				out.println("Content-Security-Policy: default-src 'none'; manifest-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; connect-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; font-src 'self' https://fonts.gstatic.com");
					////				out.println("Cache-Control: no-cache, no-store, no-transform, max-age=0");
					////				out.println("Content-Language: en-GB");
					////				out.println("Content-Length: 0");
					//					
					//				out.println("X-XSS-Protection: 1;mode=block");
					//				out.println("X-Content-Type-Options: nosniff");
					//				out.println("X-Frame-Options: SAMEORIGIN");
					//				out.println("Content-Security-Policy: default-src 'none'; manifest-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; connect-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; font-src 'self' https://fonts.gstatic.com");
					//				out.println("Date: Mon, 11 May 2020 11:11:18 GMT");
					//				
					//				out.println("Expires: Thu, 01 Dec 1994 16:00:00 GMT");
					//				out.println("Content-Type: text/html");
					//				out.println("Last-Modified: Tue, 24 Mar 2020 09:13:30 GMT");
					//				out.println("Content-Language: en-GB");
					//			//	out.println("Content-Length: 0");
					//				out.println("Cache-Control: no-cache=\"set-cookie, set-cookie2\"");

					out.println(""); // emptyline after any cookies
					// send back the information we collected
					out.println(value);
					outputStream.close();

					bufferedReader.close(); 
					ss.invalidate();
					socket.close();
				}
				catch (SSLHandshakeException e) {
					System.err.println("==SERVER SSLHandshakeException:" + e);
					handleException(e);
				} 
				catch (CertPathValidatorException e) {
					System.err.println("==SERVER CertPathValidatorException:" + e);
					handleException(e);
				} 
				catch (Exception e) {
					System.err.println("==SERVER Exception:" + e);
					handleException(e);
					e.printStackTrace();
				} 
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 
	}
	void handleException( Throwable rootCause)
	{	
		for ( int i = 0;i < 2;i++)
			//	while (rootCause.getCause() != null)
		{
			System.err.println("==Server problem:root cause: " + rootCause.toString());
			if (rootCause.getCause() == null) break;
			rootCause = rootCause.getCause();
		}
	}
}
