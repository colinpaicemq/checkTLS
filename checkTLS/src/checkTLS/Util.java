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
// Good definition of tls terms in 
// https://docs.oracle.com/javase/9/docs/specs/security/standard-names.html
/**
 * setof utility methods for processing certificates etc.  They are common to client
 * and to server
 */

import java.io.IOException;

import java.security.PublicKey;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Dictionary;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.List;
import java.util.Set;

import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSession;

public class Util {
	// for printing, using Value print
	static ValuePrint vp = new ValuePrint();
	/**
	 * Convert key usage bits into an List - so it can be displayed
	 * @param bits
	 * @return
	 */
	static List<String> getKeyUsage( boolean[] bits)
	{
		String[] keyUsage = 
			{"digitalSignature ", //        (0),
					"nonRepudiation ", //          (1),
					"keyEncipherment ", //         (2),
					"dataEncipherment ",//        (3),
					"keyAgreement ",//            (4),
					"keyCertSign ",//             (5),
					"cRLSign ",//                 (6),
					"encipherOnly ",//            (7),
					"decipherOnly " //            (8) 
			};
		List<String> listA = new ArrayList<String>();

		if (bits == null) 
			return listA;
		for (int i = 0;i< bits.length;i++)
		{
			if (bits[i] == true)
				listA.add(keyUsage[i]);
		}
		return listA;
	}

	// check certificate has basic constraints
	// the only one I could find is CA. - and what depth it can sign for
	// see https://tools.ietf.org/html/rfc5280#section-4.2.1.9
	// 	
	static boolean hasBasicConstraints 	(X509Certificate in, String what) {
		int basicConstraints = 0;
		basicConstraints = in.getBasicConstraints();
		if (basicConstraints >= 0)  
			return true;
		else return false;
	}
	/**
	 * 
	 * @param in certificate
	 * @param what sring like 1.3.6.1.5.5.7.3.2 ( tls web client))
	 * @return
	 */
	static Boolean checkEKU (X509Certificate in, String what) {
		try {
			List<String> eku = in.getExtendedKeyUsage();
			if ( eku == null) return false;
			if (eku.isEmpty()) 
				return false;

			for (String c : eku )
				if (c.equals(what)) // (1.3.6.1.5.5.7.3.1) -- TLS Web server authentication )
					return true;

		} catch (CertificateParsingException e) {
			Throwable rootCause = e;
			for ( int i = 0;i < 10;i++)
				//	while (rootCause.getCause() != null)
			{
				// System.err.println("root cause:" + rootCause.getMessage());
				System.err.println("CertificateParsingException:" + rootCause.toString());
				if (rootCause.getCause() == null) break;
				rootCause = rootCause.getCause();
			}
		}
		return false	;	
	}

	/*
	 * Subject Alternative Name  eg servers IP address 127.0.0.1 or localhost
	 */
	static String SAN (String label,X509Certificate in) {
		String value = "";
		//	ValuePrint vp = new ValuePrint();
		// vp.print vp = new vp.print();
		String subject = "unknown ";
		try {
			value =  vp.print(label);

			doSubjectAlternativeNames( in.getSubjectAlternativeNames());

			subject = in.getSubjectX500Principal().toString() ;

			value += vp.print("  Subject DN:"  + subject);
			value += vp.print("  Issuer  DN:"  + in.getIssuerX500Principal( ));
			value += vp.print("  Serial number:"  + in.getSerialNumber());
			value += vp.print("  Signature algorithm:"  + in.getSigAlgName());
			value += vp.print("  Certificate version:"  + in.getVersion());
			boolean hasBasicSection = hasBasicConstraints(in,"unused");
			boolean iskeyCertSign = false;
			doEKU(in.getExtendedKeyUsage());

			List<String>  lKeyusage = Util.getKeyUsage(in.getKeyUsage());
			String keyUsage = "";
			for (String l : lKeyusage) 
			{
				keyUsage += l+" ";
				if  (l.equals("keyCertSign ") ) // needs the blank  
					iskeyCertSign = true;
			}
			vp.print("  keyUsage:" + keyUsage);
			if (hasBasicSection  && !iskeyCertSign)// not allowed
			{
				vp.print("  This is a certificate, but does not have keyCertSign key usage attribute");
				System.err.println("==" + subject  +  "is a certificate,but does not have keyCertSign key usage attribute");
			}

			value += vp.print("  Not before:" + in.getNotBefore());
			value += vp.print("  Not after :" + in.getNotAfter());

			in.checkValidity() ;  // throw exception if problem
			PublicKey pk =  in.getPublicKey();
			// vp.print("  Public key:" + getKeyLength(pk));
			value += vp.print("  Public key:" + pk.toString() );
			checkPublicKey(pk);
			//	System.out.println("  Public key:" + pk.getFormat() );
		} catch (CertificateParsingException e) {
			both("==CertificateParsingException:" + subject  + " " +  e);
			//		e.printStackTrace();
		} catch (CertificateExpiredException e) {
			both("==CertificateExpiredException:" + subject +" " + e );
		} catch (CertificateNotYetValidException e) {
			both("==CertificateNotYetValidException:" + subject + " " +  e);
		}
		vp.print("");
		return value;
	}
	private static void both(String s) {
		System.err.println(s);
		System.err.flush();
		System.out.println(s );
		System.out.flush();
	}

	/*
	 * extract the location eg 127.0.0.0 or localhost - depending on
	 * what is specified
	 */
	private static void doSubjectAlternativeNames(Collection<List<?>> altNames) {
		// System.out.println("============MYTM:"+ label);
		String[] stype = 
			{"otherName", //                       [0]     OtherName,
					"rfc822Nam ", //                      [1]     IA5String,
					"DNSName", //                         [2]     IA5String,
					"x400Address",  //                   [3]     ORAddress,
					"directoryNam ",  //                 [4]     Name,
					"ediPartyName",    //                [5]     EDIPartyName,
					"uniformResourceIdentifier", //       [6]     IA5String,
					"iPAddress",                //       [7]     OCTET STRING,
					"registeredID"              //      [8]     OBJECT IDENTIFIER}
			};
		if (altNames != null) {
			String answer = "";
			String pad = "";
			for (List<?> altName : altNames) {
				int i=Integer.parseInt(String.valueOf(altName.get(0) ) );			
				answer += pad +  altName.get(1) + " (" +stype[i]+ ")" ;
				pad = ", ";  // for second and later times
			}
			System.out.println("  " + "SubjectAlternativeNames:" + answer );   
		}
		else
			System.out.println("  SubjectAlternativeNames: none"); 
	}
	/**
	 * display the Extended Keys information as a string 
	 * @param eku
	 */


	private static void doEKU(List<String> eku) {
		Dictionary<String,String>  EKU  = new Hashtable<String,String>(); 
		EKU.put("1.3.6.1.5.5.7.3.1","serverAuth ");// (1.3.6.1.5.5.7.3.1) -- TLS Web server authentication
		EKU.put("1.3.6.1.5.5.7.3.2","clientAuth");// (1.3.6.1.5.5.7.3.2) -- TLS Web client authentication
		EKU.put("1.3.6.1.5.5.7.3.3","codeSigning ");// (1.3.6.1.5.5.7.3.3) -- Code signing
		EKU.put("1.3.6.1.5.5.7.3.4","emailProtection ");// (1.3.6.1.5.5.7.3.4) -- E-mail protection
		EKU.put("1.3.6.1.5.5.7.3.8","timeStamping "); // (1.3.6.1.5.5.7.3.8) -- Timestamping
		EKU.put("1.3.6.1.5.5.7.3.9","ocspSigning "); // (1.3.6.1.5.5.7.3.9) -- OCSPstamping 

		String ekuString = "";
		if (eku != null)
			if (eku.size()> 0 )
				for (String c : eku)
					if (EKU.get(c)!= null)
						//vp.print("  ExtendedKeyUsage: "+ EKU.get(c));
						ekuString += EKU.get(c);
					else;
			else; // vp.print("  No ExtendedKeyUsage: ");
		else;
		vp.print("  ExtendedKeyUsage: "+ ekuString);
	}

	/**
	 * Send to the end user the information about the certificates
	 * @param ss
	 * @param title
	 * @return
	 * @throws Exception
	 */
	static public String displayConnection( SSLSession  ss,String title ) throws Exception
	{
		//  get time now so they end user can see it change when they repeat the requst
		DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
		Calendar cal = Calendar.getInstance();
		System.out.println(dateFormat.format(cal.getTime()));
		String value = vp.print(title+":"+ dateFormat.format(cal.getTime())); 

		vp.print("==Summary of connection details "+ dateFormat.format(cal.getTime()));
		try {
			if ( ss != null) 
			{	
				X509Certificate[] x509 = (X509Certificate[]) ss.getLocalCertificates();
				if (x509 != null)
				{
					int count = 0;
					for (X509Certificate xx509 : x509)
					{
						value = value + Util.SAN("Local Certificate used in handshake[" + count + "]:",xx509) ;
						count ++;
					}
					x509 = (X509Certificate[])ss.getPeerCertificates();
					count = 0;
					value += vp.print("");
					for (X509Certificate xx509 : x509)
					{
						value = value +	Util.SAN("Peer certificate used in handshake[" + count + "]:",xx509) ;
						count ++;
					}					
				}
				printSupportedSignatureAlgorithms(ss);
				value += vp.print("");
				value += vp.print( " %-20s %-20s","peerPrincipal:" ,ss.getPeerPrincipal().toString() );
				value += vp.print( " %-20s %-20s","clientPrincipal:" ,ss.getLocalPrincipal().toString()  );
				value += vp.print( " %-20s %-20s","cipherSuite used:" ,ss.getCipherSuite()    );
				value += vp.print( " %-20s %-20s ","peer host:" ,ss.getPeerHost()  );
				;
			}
			else
				System.out.println("== SSLSession is null"); 

		} catch (IOException e) {
			Throwable rootCause = e;
			for ( int i = 0;i < 10;i++)
			{
				// System.err.println("root cause:" + rootCause.getMessage());
				System.err.println("==Util.displayConnectiont:root cause: " + rootCause.toString());
				if (rootCause.getCause() == null) break;
				rootCause = rootCause.getCause();
			}
			//	e.printStackTrace();
		}
		return value;
	}

	public static void PeerSupportedSignatureAlgorithms(SSLSession ss) throws Exception {
		if (ss instanceof ExtendedSSLSession) {
			printSupportedSignatureAlgorithms(ss);
		}
	}
	/** 
	 * List the agreed signature algorithms and compare the remote and the local 
	 * so we can see what is different in the two ends
	 * @param ss session
	 * @throws Exception 
	 */
	private  static void printSupportedSignatureAlgorithms(SSLSession ss) throws Exception {
		if (ss instanceof ExtendedSSLSession) {
			ExtendedSSLSession extSession = (ExtendedSSLSession)ss;

			Set<String> peerSupportedSignatureAlgorithms = new HashSet<String>(); 

			for (String s : extSession.getPeerSupportedSignatureAlgorithms() )
				peerSupportedSignatureAlgorithms.add(s);

			Set<String> localSupportedSignatureAlgorithms = new HashSet<String>(); 
			for (String s : extSession.getLocalSupportedSignatureAlgorithms() )
				localSupportedSignatureAlgorithms.add(s);
			//	int sizePeer  = peerSupportedSignatureAlgorithms.size();

			int sizeLocal  = localSupportedSignatureAlgorithms.size();
			String peer = "peer " + peerSupportedSignatureAlgorithms.size();
			String local = "local " + localSupportedSignatureAlgorithms.size();
			vp.print("Compare supported signature algorithms");
			vp.print("  : %-20s %-20s",local,peer);
			if (sizeLocal > 0 )
				for (String s : localSupportedSignatureAlgorithms ) {
					if (peerSupportedSignatureAlgorithms.contains(s))
						vp.print("  : %-20s %-20s",s,s);
					//System.out.println("  "+ s +  "  " + s);
					else 
						//	System.out.println("  "+ s +  "  ");
						vp.print("  : %-20s %-20s",s,"not found");
				}	
			else
			{
				System.out.println("==No algorithms found");
			}
			// this is usually empty
			String[] vn = ss.getValueNames();
			if (vn.length > 0 )
				for (String s :  vn)
					vp.print("==  get application value names "+ s +"=" +ss.getValue(s) );
		}
		return;
	}
	/**
	 * display a set as a string 
	 * @param s
	 * @param set
	 */

	static void printSet(String s, Set<String> set) {
		String o = "";
		String pad = " ";
		for (String ss : set)
		{
			o = o + pad +  ss ;
			pad = ", ";
		}
		System.out.println(s+ o);
	}

	/**
	 * this takes the cipher specs, breaks them down into the constituents and
	 * displays the summary
	 * @param sl
	 * @return
	 */
	public static int displayCipherSuites(String[] sl) {
		if (sl.length > 0)
		{
			int others = 0; 
			Set<String> first  = new HashSet<String>();
			Set<String> second = new HashSet<String>();
			Set<String> third  = new HashSet<String>();
			System.out.println("==Cipher suites available count " + sl.length +" :");
			// display the standard format ones first 
			// then the ones which dont have "with"...
			for (String s : sl )
			{
				System.out.println("  " +  s );
				if (s.contains("_WITH_"))
				{
					String[] splits = s.split("_WITH_");
					first.add(splits[0].substring(4));
					String[] splits2  = splits[1].split("_");
					second.add(splits2[0]+"_" + splits2[1]);
					third.add(splits2[2]+"_" + splits2[3]);
				}
				else 
					others ++; //  System.out.println("  " +  s );
			}
			// print out the info
			printSet("  Key Exchange Algorithms_Authentication/Digital Signature Algorithms: ",first);
			printSet("  Bulk encryption algorithm:",second);
			printSet("  Hashing algorithms:  ",third);
			// print any left over
			if (others > 0)
			{	
				System.out.println("  Others:");
				for (String s : sl )
				{
					if (!  s.contains("_WITH_"))
						System.out.println("    " +  s );
				}
			}
		} 
		return sl.length;
	}

	/**
	 * Some certificate are created with options that are no longer supported so 
	 * check the value belows have been used in Elliptic Curves - eg sect571k1
	 * @param pk
	 */

	public static void checkPublicKey(final PublicKey pk) {
		// see https://www.java.com/en/configure_crypto.html for list of weak stuff
		// Set demonstration using HashSet Constructor 

		Set<String> weakEC = new HashSet<>(Arrays.asList(
				"secp112r1", "secp112r2", "secp128r1", "secp128r2", 
				"secp160k1", "secp160r1", "secp160r2", "secp192k1",
				"secp192r1", "secp224k1", "secp224r1", "secp256k1", 
				"sect113r1", "sect113r2", "sect131r1", "sect131r2",
				"sect163k1", "sect163r1", "sect163r2", "sect193r1", 
				"sect193r2", "sect233k1", "sect233r1", "sect239k1",
				"sect283k1", "sect283r1", "sect409k1", "sect409r1", 
				"sect571k1", "sect571r1", "X9.62 c2tnb191v1",
				"X9.62 c2tnb191v2", "X9.62 c2tnb191v3", "X9.62 c2tnb239v1", 
				"X9.62 c2tnb239v2", "X9.62 c2tnb239v3",
				"X9.62 c2tnb359v1", "X9.62 c2tnb431r1", "X9.62 prime192v2", 
				"X9.62 prime192v3", "X9.62 prime239v1",
				"X9.62 prime239v2", "X9.62 prime239v3", "brainpoolP256r1", 
				"brainpoolP320r1", "brainpoolP384r1", "brainpoolP512r1" 
				)); 

		if (pk instanceof RSAPublicKey) {
			//final RSAPublicKey rsapub = (RSAPublicKey) pk;
			//	String	answer = "RSA " + rsapub.getModulus().bitLength();
			System.err.println("RSA" +pk.toString());
		} else if (pk instanceof ECPublicKey) {
			final ECPublicKey ecpriv = (ECPublicKey) pk;
			final java.security.spec.ECParameterSpec spec = ecpriv.getParams();
			if (spec != null) {
				// spec.toString is like sect409k1 [NIST K-409] (1.3.132.0.36)
				String ecCurve[] = spec.toString().split(" ",2);
				if (weakEC.contains(ecCurve[0]))
					System.out.println(" !!Certificate is weak and may not be accepted:" + spec.toString() );
				//				System.out.println("???+EC Certificate" + spec.toString());
				//			System.out.println("???+EC Certificate" + spec.getCurve().toString());
				//			answer = "EC " + spec.getOrder().bitLength(); // does this really return something we expect?
			} else {
				// We support the key, but we don't know the key length
				//	answer = "EC ??? ";
			}
		} else if (pk instanceof DSAPublicKey) {
			//			final DSAPublicKey dsapub = (DSAPublicKey) pk;
			//			if ( dsapub.getParams() != null ) {
			//				answer = "DSA " + dsapub.getParams().getP().bitLength();
			//			} else {
			//				answer = "DSA " + dsapub.getY().bitLength();
			//			}
		} else {
			System.err.println("Unknown public key type" +pk.toString());
		}
		return;
	}


	public static void displayProtocols(SSLParameters sslp,String errMsg) {
		String [] sl;  // string list
		sl = sslp.getProtocols();
		if (sl.length > 0)
		{  
			String o = "==SSLParameters protocols available: ";
			// loopCounter++;
			for (String s : sl )
				o = o +  " " + s+ " ";
			o = o+ ";";
			System.out.println(o);
		}
		else
		{
			System.out.println("==No SSLParameter protocols");
			throw new IllegalArgumentException(errMsg);
		}
	}
}
