package org.globus.grid.cert;

import java.io.*;
import java.util.ResourceBundle;
import java.util.StringTokenizer;
import java.util.Vector;
import java.security.*;
import java.security.cert.*;

import org.globus.gsi.CertUtil;

import org.globus.util.Base64;

import org.globus.grid.gsi.GSIProperties;

// Classes for cert rq generation
// Implemented in puretls.jar
import COM.claymoresystems.cert.CertRequest;
import COM.claymoresystems.cert.X509Name;

// Cryptix utility classes 
// Implemented in Cryptix32.jar
import cryptix.util.mime.Base64OutputStream;

import org.globus.gsi.bc.BouncyCastleOpenSSLKey;
import org.globus.gsi.OpenSSLKey;

// Import log4j classes.
import org.apache.log4j.Logger;

// Legion of the Bouncy Castle JCE classes
// Implemented in jce-jdk13-117.jar
import org.bouncycastle.jce.X509V3CertificateGenerator;


/**
 * A class to automate the Globus Proxy creation and certificate
 * installation. Emulates: grid-proxy-init, install-certs, etc...
 * Usage:
 * 			<pre>
 * 			// proxy creation...
 *			CertGenerator generator = new CertGenerator("Vladimir SIlva","IBMGrid");
 *			generator.generateCertAndKey("2p2dkdt");
 *
 *			GlobusCredential cred = generator.gridProxyInit("2p2dkdt", 512, 12);
 *			System.out.println(cred.toString());
 *
 *			// save creds...
 *			generator.saveCertificates("c:\\temp\\usercert.pem", "c:\\temp\\userkey.pem");
 *			generator.saveProxy(cred, "c:\\temp\\proxy.pem");
 *			</pre>
 */
public class CertGenerator {
	static Logger logger = Logger.getLogger(CertGenerator.class);

	private String _certPEM = null;
	private String _keyPEM = null;
	private String _certRQPEM = null;


	/* Cert gen subject */
	X509Name _subject = null;
	
	private int _strength = 1024;
	private ResourceBundle _resBundle = GSIProperties.getResBundle();
		
	/**
	 * Certificate Generation engine
	 * @param subject Certificate subject (e.g C=US,O=Grid,OU=OGSA,CN=John Doe)
	 * @throws Exception if an error occurs
	 */	
	public CertGenerator(String subject )   
		throws Exception 
	{
		_subject = makeCertDN(subject);
		_strength = Integer.parseInt(GSIProperties.getString(GSIProperties.CERT_STRENGTH));
		logger.debug("Constructor Subject:" + subject);
	}
	/**
	 * Certificate Generation engine
	 * @param subject subject Certificate subject (e.g C=US,O=Grid,OU=OGSA,CN=John Doe)
	 * @param strength engine stren (e.g 1024)
	 * @throws Exception
	 */
	public CertGenerator(String subject, int strength )   
		throws Exception 
	{
		_subject = makeCertDN(subject);
		_strength = strength;
		logger.debug("Constructor Subject:" + subject + " stren=" + strength);
	}

	/**
	* generateCertAndKey Creates a Signed User certificate and a private key
	* by generating a self signed user certificate. Private key is encrypted w/ Pwd
	* Certificates are kept internally. (CN and OU are given to the contructor)
	* @param Pwd = Challenge pwd (used to encrypt pirv key)
	* @throws FileNotFoundException
	* @throws IOException
	*/
	public void generateSelfSignedCertAndKey( String Pwd )
	        throws NoSuchAlgorithmException, Exception
	{
		if ( _subject == null) 
			throw new Exception(_resBundle.getString(GSIProperties.MSG_DN_INFO_REQUIRED));
			
		if ( Pwd == null ) 
			throw new Exception(_resBundle.getString(GSIProperties.MSG_INVALID_PWD));
		
		logger.debug("generateSelfSignedCertAndKey Cert subject: " + _subject.getNameString() + " Strength=" + _strength + " Pwd=" + Pwd); 

		// Generate A Cert RQ
		StringWriter sw  	= new StringWriter(); // wil contain the priv key PEM
		BufferedWriter bw 	= new BufferedWriter(sw);

		KeyPair kp 			= CertRequest.generateKey("RSA", _strength, Pwd, bw, true); // gen pub/priv keys

		// certs are valid for 1 year: 31536000 secs
		byte[] certBytes 	= CertRequest.makeSelfSignedCert(kp, _subject, 31536000);
		
		// Private key
		_keyPEM = sw.toString();
		logger.debug("CertKeyGenerator: Private key PEM\n" + _keyPEM);

		// cert in PEM format
  		//_certPEM = "Certificate:\n" + 
  		//		(CertUtil.loadCertificate(new ByteArrayInputStream(certBytes))).toString() + "\n" +
		_certPEM =	writePEM(certBytes,
					"-----BEGIN CERTIFICATE-----\n",
					"-----END CERTIFICATE-----\n");
		
		logger.debug("CertKeyGenerator: Signed Cert RQ . signedUserCert\n" + _certPEM);

	}


	/**
	 * createCertRequest: Create a certificate request PEM encoded string
	 * @param bits Certificate strenght in bits (e.g 512)
	 * @param Pwd passphrase used to encrypt the private key 
	 * @return PEM encoded cert rq string
	 * @throws IOException
	 * @throws NoSuchProviderException
	 * @throws NoSuchAlgorithmException
	 */	
	public synchronized void createCertRequest( int bits, String Pwd)  
		throws IOException, NoSuchProviderException, 
				NoSuchAlgorithmException, GeneralSecurityException
	{
		// Pwd cannot be null
		if ( Pwd == null ) throw new GeneralSecurityException("Invalid NULL password");
		
		/*
		 * Generate A Cert RQ. Using the CertRequest utility class
		 * implemented in puretls.jar 
		 */ 
		logger.debug("createCertRequest: Creating a cert request Subject:" + _subject.getNameString() + " bits=" + bits + " pwd=" + Pwd);
		
		StringWriter sw  	= new StringWriter(); // wil contain the priv key PEM
		BufferedWriter bw 	= new BufferedWriter(sw);

		/*
		 * Generate public/private keys
		 */
		KeyPair kp 			= CertRequest.generateKey("RSA", bits, Pwd, bw, true); 
		byte[] req 			= CertRequest.makePKCS10Request(kp, _subject);

		/*
		 * Save data in PEM format
		 */		
		_certRQPEM 	= buildRequestInfoHeader(
							_subject.getNameString()) +
							writePEM(req,"-----BEGIN CERTIFICATE REQUEST-----\n", 
							"-----END CERTIFICATE REQUEST-----\n"
							);
							
		_keyPEM 	=  sw.toString();
	
		logger.debug("createCertRequest: Cert RQ\n" + _certRQPEM + "Key\n" + _keyPEM); 
	}
	
	/* Cert RQ info header */
	private String buildRequestInfoHeader(String subject) {
		StringBuffer buff = new StringBuffer("This is a Certificate Request file:\nIt should be mailed to to a CA for signature");
		buff.append("\n===============================================================");
		buff.append("\nCertificate Subject:\n\t");
		buff.append(subject);
		buff.append("\n\n");
		return buff.toString();
	}

	/**
	 * Write certficate bytes into a PEM encoded string 
	 */
	public static String writePEM (byte[] bytes, String hdr, String ftr)
			throws IOException
	{
		ByteArrayOutputStream bos=new ByteArrayOutputStream();
		Base64OutputStream b64os=new Base64OutputStream(bos);
		b64os.write(bytes);
		b64os.flush();
		b64os.close();

		ByteArrayInputStream bis=new ByteArrayInputStream(bos.toByteArray());
		InputStreamReader irr=new InputStreamReader(bis);
		BufferedReader r=new BufferedReader(irr);

		StringBuffer buff = new StringBuffer();
		String line;
		buff.append(hdr); 

		while((line=r.readLine())!=null){
			buff.append(line + "\n");
		}
		buff.append(ftr); 
		return buff.toString();

	}

	/*
	 * makeCertDN: Creates an X509 Identity based on a string subject
	 * e.g:  "C=US,O=Grid,OU=OGSA,OU=Foo,CN=John Doe"
	 */
	private static X509Name makeCertDN(String subject) throws Exception 
	{
		Vector tdn = new Vector();
//		Vector elems = new Vector();
		StringTokenizer st = new StringTokenizer(subject,",");
		
		for (; st.hasMoreTokens() ;) {
			String s = st.nextToken(); // [key=value]
			if (  s.indexOf("=") == -1 ) 
				throw new Exception("Invalid subject format: " + subject + " Offending value: " + s);
			
			String key = s.substring(0, s.indexOf("=")).trim();
			String val = s.substring(s.indexOf("=") + 1).trim();
			
			if ( val == null || val.equals(""))
				throw new Exception("Invalid subject format: " + subject + " Offending value: " + s);
			
			//logger.debug(key + "=" + val);
			String[] temp = {key, val};
			tdn.addElement(temp);
		}
		// COM.claymoresystems.cert (puretls.jar)
		return CertRequest.makeSimpleDN(tdn);
	}
	
	/**
	 * Creates an X509 version3 certificate
	 * @param algorithm (e.g RSA, DSA, etc...)
	 * @param bits Cet strength e.g 1024
	 * @param issuer Issuer string e.g "O=Grid,OU=OGSA,CN=ACME"
	 * @param subject Subject string e.g "O=Grid,OU=OGSA,CN=John Doe"
	 * @param months time to live
	 * @param outPrivKey OutputStream to the private key in PKCS#8 format (Note: this key will not be encrypted)
	 * @return X509 V3 Certificate
	 * @throws GeneralSecurityException
	 */
	public static X509Certificate createX509Cert(
				String algorithm, 
				int bits, 
				String issuer, 
				String subject, 
				int months, 
				OutputStream outPrivKey,
				String sigAlg,
				String pwd
				) 
		throws GeneralSecurityException, IOException
	{
		//String sigAlg = "SHA1WithRSAEncryption";
		
		// Priv key is in PKCS#8 format
		KeyPair kp 	= CertUtil.generateKeyPair(algorithm, bits);

		// must convert from PKCS#8 to PKCS#1 to encrypt with BouncyCastleOpenSSLKey
		// Priv key must be DER encoded key data in PKCS#1 format to be encrypted.
		OpenSSLKey PKCS_8key = new BouncyCastleOpenSSLKey(kp.getPrivate());

		long serial= 0;

		logger.debug("createX509Cert Alg: " + algorithm + " bits:" + bits + " Issuer: " + issuer + " Subject: " + subject);
		logger.debug("createX509Cert Sig alg:" + sigAlg + " Priv key format:"  + PKCS_8key.getPrivateKey().getFormat());		
		
		//if ( pwd != null && ! PKCS_8key.isEncrypted()) 
		//	PKCS_8key.encrypt(pwd);
		
		// write private key		
		PKCS_8key.writeTo(outPrivKey);
		
		// return X509 Cert
		return createX509V3Certificate(kp.getPublic(), 
					kp.getPrivate(),
					months, issuer, subject, 
					serial, sigAlg);

	}
	
	/* Cert creation engine */
	private static synchronized X509Certificate createX509V3Certificate(
			PublicKey pubKey, 
			PrivateKey privKey,
			int ttlMonths,
			String issuerDN, String subjectDN, 
			long serial, String signAlgoritm
			) 
	throws GeneralSecurityException
	{
		X509V3CertificateGenerator  certGenerator = new X509V3CertificateGenerator();
		certGenerator.reset();

		certGenerator.setSerialNumber(java.math.BigInteger.valueOf(serial));
		certGenerator.setIssuerDN(new org.bouncycastle.asn1.x509.X509Name(issuerDN));
		certGenerator.setNotBefore(new java.util.Date(System.currentTimeMillis()));
		certGenerator.setNotAfter(new java.util.Date(System.currentTimeMillis() + ttlMonths *(1000L * 60 * 60 * 24 * 30)));
		certGenerator.setSubjectDN(new org.bouncycastle.asn1.x509.X509Name(subjectDN));
		certGenerator.setPublicKey(pubKey);
		certGenerator.setSignatureAlgorithm(signAlgoritm);

		X509Certificate cert = certGenerator.generateX509Certificate(privKey,"BC",new java.security.SecureRandom());
		cert.checkValidity(new java.util.Date());
		cert.verify(pubKey);

		return cert;
	}
	
	
	/**
	 * readPEM: Read a PEM encoded base64 stream and decode it
	 * @param is Base64 PEM encoded stream
	 * @param hdr Header delimeter (e.g. ----------CERTIFICATE---------)
	 * @param ftr Footer delimeter (e.g. ----------END CERTIFICATE---------)
	 * @return decoded DER bytes
	 * @throws IOException if a read error occurs
	 */
	public static byte[] readPEM (InputStream is, String hdr, String ftr)
					throws IOException
	{
			logger.debug("Reading PEM hdr:" + hdr + " ftr:" + ftr);
			is.reset();
			InputStreamReader irr=new InputStreamReader(is);
			BufferedReader r=new BufferedReader(irr);

			StringBuffer buff = new StringBuffer();
			String line;
			boolean read = false;

			while((line=r.readLine())!=null){
			  if ( line.equals(hdr) ) { read = true; continue; }
			  if ( line.equals(ftr) ) read = false;
			  if (read ) buff.append(line);

			}
			return Base64.decode(buff.toString().getBytes());
	}
	
	/**
	 * Test if a X509 key is encryped
	 * @param inKey X509 key stream
	 * @return true if encrypted e;se flase
	 * @throws IOException
	 * @throws GeneralSecurityException
	 */
	public static boolean isKeyEncrypted(InputStream inKey)
		throws IOException, GeneralSecurityException
	{
		return (new BouncyCastleOpenSSLKey(inKey)).isEncrypted();
	}
	
	/* getter methods */
	public String getCertPEM() { return _certPEM; }
	public String getKeyPEM() { return _keyPEM; }
	public String getCertRQPEM() { return _certRQPEM; }

	public X509Name getSubject() { return _subject; }
	
	
	/* setter(mutator) mthods */
	public void setCertPEM(String certPEM) { _certPEM = certPEM; }
	public void setKeyPEM(String keyPEM) { _keyPEM = keyPEM; }

	public String toString() {
		return "\nCert Request:\n" + _certRQPEM + "\nCertificate:\n" + _certPEM + "\nKey:\n" + _keyPEM;
	}
}
