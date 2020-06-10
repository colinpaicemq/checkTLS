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
 * This class checks the validity of a certificate
 * It uses the super validate function, captures any exception and augments the reason
 */

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.PKIXReason;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

// import sun.security.util.DisabledAlgorithmConstraints;
// TLSV1.3 cipher specs defined in https://tools.ietf.org/html/rfc8446#appendix-B.4

public class CheckCert {

	public boolean  check(KeyStore trustStore, X509Certificate x509cert, String title) throws CertificateException {
		//  The following  code does not produce any useful data
		//
		// DisabledAlgorithmConstraints
		// certPathDefaultConstraints = new DisabledAlgorithmConstraints(
		// DisabledAlgorithmConstraints.PROPERTY_CERTPATH_DISABLED_ALGS);
		//  This gives null...  System.out.println(certPathDefaultConstraints .disabledAlgorithms);
		// Set demonstration using HashSet Constructor
		//
		// do not dump the certificate if obvious problem like expired
		// See https://docs.oracle.com/javase/7/docs/api/java/security/cert/CertPathValidatorException.BasicReason.html
		Set<String> dontDump = new HashSet<>(Arrays.asList(
					"EXPIRED","NOT_YET_VALID"
				)); 

		boolean value = true;
		try {
			/*
			The CertificateFactory class defines the functionality of a certificate factory, 
			which is used to generate certificate, certification path (CertPath) and certificate 
			revocation list (CRL) objects from their encodings.

			... Use generateCertPath when you want to generate a 
			CertPath (a certificate chain) and subsequently validate it with a CertPathValidator.
			See  https://docs.oracle.com/javase/7/docs/api/java/security/cert/CertificateFactory.html 
			*/
			// specify which validator we need - use the default
			CertPathValidator validator = CertPathValidator.getInstance("PKIX");
			CertificateFactory factory = CertificateFactory.getInstance("X509");
			CertPath certPath = factory.generateCertPath(Arrays.asList(x509cert));
			
			// PKIXParameters requires the "most trusted CAs".  We specify the trust store
			// so it can go and get what it wants
			PKIXParameters params = new PKIXParameters(MyTrustManager.myTrustStore);
			params.setRevocationEnabled(false);
			validator.validate(certPath, params);
			} 
		catch (CertPathValidatorException e) {
			value = false;
			// if it failed - then display it
			Util.SAN(title + " FAILED"  ,x509cert) ;	
			Throwable rootCause = e;
			String reason = rootCause.toString();
			String cause[] = e.toString().split(":");
			System.out.println("Exception reason:"+ e.getReason());
			if ( e.getReason() ==   PKIXReason.NO_TRUST_ANCHOR)
			{
				System.err.println("==Problems with the issuer in the keystore.  Issuer:"
			  + x509cert.getIssuerX500Principal().toString() );
			}
			if (!dontDump.contains(e.getReason().toString()) && e.getCertPath() != null)
			{
				System.out.println("Dump of Certificate path");
				System.out.println(e.getCertPath().toString());
				System.out.println("/Dump of Certificate path");
			}
			if (cause[1].equals(" Path does not chain with any of the trust anchors"))
			{
				reason = " Not found in the trust store ";
				MyTrustManager.printTrustStoreSummary(); 
			}
			System.out.println(cause[1]);
			for ( int i = 0;i < 1;i++)  // print stack trace - depth 1
			{
				String report = "  " +  x509cert.getSubjectX500Principal().toString() +".  Issuer:"+ x509cert.getIssuerX500Principal().toString()  + " root cause:("+i+")" + reason;
				System.err.println("!"+report);
				System.out.println(" "+ report);
				System.err.println("");
				System.out.println("");
				if (rootCause.getCause() == null) break;
				rootCause = rootCause.getCause();
			}
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		System.out.println(" " );
		return value;
	}
}
