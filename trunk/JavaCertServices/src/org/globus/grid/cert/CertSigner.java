/*
 * Created on Aug 16, 2003
 */
package org.globus.grid.cert;

import java.io.*;
import java.util.*;
import java.security.*;
import java.security.cert.*;

import java.math.BigInteger;

//Bouncycastle provider (jce-jdk13-117.jar)
import org.bouncycastle.jce.X509V3CertificateGenerator;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERInputStream;
import org.bouncycastle.asn1.x509.*;

import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.globus.gsi.*;

// Import log4j classes.
import org.apache.log4j.Logger;


import org.globus.gsi.bc.BouncyCastleOpenSSLKey;
import org.globus.gsi.OpenSSLKey;

/**
 * A Class to sign certificate requests.
 * It uses the Legion of The Boucy Castle JCE provider (jce-jdk13-117.jar)
 * available at http://www.bouncycastle.org/
 * @author Vladimir Silva
 */

public class CertSigner {

	static Logger logger = Logger.getLogger(CertSigner.class);

	static X509V3CertificateGenerator  _v3CertGenerator = new X509V3CertificateGenerator();
	private X509Certificate _signedCert = null;

	/**
	 * CertSigner Construcor: Reads a cert request and signs it with a set of CA certs 
	 * @param certRqPath Full path to the CSR (Cert request)
	 * @param caCertPath Full path to the CA cert (PEM)
	 * @param caKeyPath Full path to the CA key (PEM)
	 * @param caPwd CA password
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws InvalidKeyException
	 * @throws GeneralSecurityException
	 */
	public CertSigner(String certRqPath,
							 String caCertPath,
							 String caKeyPath,
							 String caPwd)
		throws IOException, NoSuchAlgorithmException,
		NoSuchProviderException, InvalidKeyException, GeneralSecurityException
	{
  	
		loadKeysAndSign(	new FileInputStream(certRqPath), 
					new FileInputStream(caCertPath),
					new FileInputStream(caKeyPath),
					caPwd );
	}

	/**
	 * Signs a Cert request (CSR)
	 * @param inCertRq CSR Input stream
	 * @param inCACert CA Cert stream
	 * @param inCAKey CA key iStream
	 * @param caPwd CA password
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws InvalidKeyException
	 * @throws GeneralSecurityException
	 */
	public CertSigner( InputStream inCertRq,
			InputStream inCACert,
			InputStream inCAKey,
			String caPwd
	)
		throws IOException, NoSuchAlgorithmException,
		NoSuchProviderException, InvalidKeyException, GeneralSecurityException
	{
  	
		loadKeysAndSign( inCertRq, inCACert, inCAKey ,	caPwd );
	}

	public CertSigner(PublicKey rqPubKey, PublicKey caPub, PrivateKey caPriv,
		String caIssuer, String rqIssuer, long serial, int months, String sigAlg)
		throws IOException, GeneralSecurityException 
	{
		_signedCert = signCert(rqPubKey, caPub, caPriv, caIssuer, rqIssuer, serial, months, sigAlg);	
	}
	
	/* getters */
	public X509Certificate getSignedCert() {
		return _signedCert;
	}
	
	/**
	 * Load A CSR and sign it using CA cert/key and password 
	 * @param inRq CSR request input stream
	 * @param inCACert CA Cert input stream
	 * @param inCAKey CA key input stream
	 * @param caPwd CA key password
	 * @throws IOException if an IO error occurs
	 * @throws NoSuchAlgorithmException if Security error
	 * @throws NoSuchProviderException
	 * @throws InvalidKeyException
	 * @throws GeneralSecurityException
	 */
	private void loadKeysAndSign(InputStream inRq,
						InputStream inCACert,
						InputStream inCAKey,
						String caPwd)
						
	throws IOException, NoSuchAlgorithmException,
			NoSuchProviderException, InvalidKeyException, GeneralSecurityException
	{	
		byte[] derArray = null;
		PKCS10CertificationRequest rqDer = null;
		
		try {
			derArray = CertGenerator.readPEM(inRq,
					  "-----BEGIN CERTIFICATE REQUEST-----",
					  "-----END CERTIFICATE REQUEST-----");
			rqDer 	= new PKCS10CertificationRequest(derArray);
			
		} catch (IllegalArgumentException e) {
			logger.error(e);
			derArray = null;
			derArray = CertGenerator.readPEM(inRq,
					  "-----BEGIN NEW CERTIFICATE REQUEST-----",
					  "-----END NEW CERTIFICATE REQUEST-----");
			rqDer 	= new PKCS10CertificationRequest(derArray);
		}
		
		// extract pub key from rq
		PublicKey  rqPubKey 				= rqDer.getPublicKey();

		// 
		X509Certificate caCert 	= CertUtil.loadCertificate(inCACert);
		OpenSSLKey key  		= new BouncyCastleOpenSSLKey(inCAKey);

		// Get request issuer
		String rqIssuer	= rqDer.getCertificationRequestInfo().getSubject().toString();
		
		// cert lifetime
	  	int months		= 12; 

	  	String alg 			= caCert.getSigAlgName();
	  	PublicKey caPubKey	= caCert.getPublicKey();
		//String caIssuer 	= decodeX509Subject(caCert.getSubjectDN().toString());
		String caIssuer 	= caCert.getSubjectDN().toString();
	  
		// decrypt ca priv key	
		if (key.isEncrypted()) {
			try {
				if (caPwd == null) 
					throw new GeneralSecurityException("A CA password is required"); 
				
				key.decrypt(caPwd);
			} 
			catch(GeneralSecurityException e) {
				//e.printStackTrace();
				throw new GeneralSecurityException("Wrong CA password or other security error: " + e.getMessage());
			}
		}
	
		PrivateKey caPrivKey	= key.getPrivateKey();
		long serial 			= PrivateKey.serialVersionUID;
	
	
		logger.debug("Constructor: Request Info - Issuer=" + rqIssuer + " alg=" + alg + " lifetime(months)=" + months);
		logger.debug("Constructor: CA Info - Priv key serial=" + serial + " Issuer=" + caIssuer +  " Encrypted=" + key.isEncrypted() );
	
		// sign
		_signedCert = signCert(rqPubKey, caPubKey, caPrivKey, caIssuer, rqIssuer, serial, months, alg);
	}

	/**
	 * Save a signed certificate (PEM encoded)
	 * @param os Stream where the cert is to be saved
	 * @throws IOException if a save error occurs
	 * @throws CertificateEncodingException if a PEM encoding error occurs
	 */
	public void save(OutputStream os )
		throws IOException , CertificateEncodingException
	{
	  String s = CertGenerator.writePEM(_signedCert.getEncoded(),
									"-----BEGIN CERTIFICATE-----\n",
									"-----END CERTIFICATE-----\n");
	  logger.debug("save: Signed cert PEM\n" + s);
	  os.write(s.getBytes());
	}

	/**
	 * Sign a certificate
	 * @param rqPubKey USer request public key
	 * @param caPubKey Certificate authority (CA) pub key
	 * @param caPrivKey CA private key
	 * @param caIssuer CA Issuer string (e.g /O=Grid/O=Globus/OU=simpleCA....
	 * @param rqIssuer Request issuer
	 * @param serial Private key serial number
	 * @param lifeTimeMonths Cert lifetime in months
	 * @param signAlgoritm Signature Algorithm (e.g sha1WithEncryption)
	 * @return signed X509Certificate
	 * @throws GeneralSecurityException
	 * @throws IOException
	 */
	private static X509Certificate signCert(PublicKey rqPubKey,
						 PublicKey caPubKey,
						 PrivateKey caPrivKey,
						 String caIssuer,
						 String rqIssuer,
						 long serial,
						 int lifeTimeMonths,
						 String signAlgoritm 
						 )
	 throws GeneralSecurityException, IOException
	{
	  
	  _v3CertGenerator.reset();

	  _v3CertGenerator.setSerialNumber(BigInteger.valueOf(serial));
	  _v3CertGenerator.setIssuerDN(new X509Name(caIssuer));
	  _v3CertGenerator.setNotBefore(new Date(System.currentTimeMillis()));
	  _v3CertGenerator.setNotAfter(new Date(System.currentTimeMillis() + lifeTimeMonths *(1000L * 60 * 60 * 24 * 30)));
	  _v3CertGenerator.setSubjectDN(new X509Name(rqIssuer));
	  _v3CertGenerator.setPublicKey(rqPubKey);
	  _v3CertGenerator.setSignatureAlgorithm(signAlgoritm);

	  // cert extensions
	  
	  _v3CertGenerator.addExtension(X509Extensions.SubjectKeyIdentifier,
							 false,
							 createSubjectKeyId(rqPubKey));
	  _v3CertGenerator.addExtension(X509Extensions.AuthorityKeyIdentifier,
							 false,
							 createAuthorityKeyId(caPubKey));

	  _v3CertGenerator.addExtension(X509Extensions.BasicConstraints,
							 false,
							 new BasicConstraints(false));

	  _v3CertGenerator.addExtension(X509Extensions.KeyUsage,
							 false,
							 new KeyUsage(KeyUsage.dataEncipherment | KeyUsage.digitalSignature ) );

	  X509Certificate cert = _v3CertGenerator.generateX509Certificate(caPrivKey,"BC",new java.security.SecureRandom());

	  cert.checkValidity(new Date());
	  cert.verify(caPubKey);

	  return cert;
	}

	/**
	 * 
	 * @param pubKey
	 * @return
	 */
	private static SubjectKeyIdentifier createSubjectKeyId(PublicKey pubKey) {
		try {
			ByteArrayInputStream bIn =
					new ByteArrayInputStream( pubKey.getEncoded() );

			SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(
				 (ASN1Sequence)new DERInputStream(bIn).readObject()
			);

			return new SubjectKeyIdentifier(info);
		}
		catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * 
	 * @param pubKey
	 * @param name
	 * @param sNumber
	 * @return
	 * @throws IOException
	 */
	private static AuthorityKeyIdentifier createAuthorityKeyId(PublicKey pubKey,
		X509Name name, int sNumber) throws IOException
	{
			ByteArrayInputStream bIn = new ByteArrayInputStream(
			pubKey.getEncoded());
			SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(
			(ASN1Sequence)new DERInputStream(bIn).readObject());

			GeneralName genName = new GeneralName(name);

			//DERConstructedSequence seq = new DERConstructedSequence();
			ASN1Sequence seq = ASN1Sequence.getInstance(genName);

			//seq.addObject(genName);

			return new AuthorityKeyIdentifier( info, new GeneralNames(seq), BigInteger.valueOf(sNumber));
	}

	/**
	 * 
	 * @param pubKey
	 * @return
	 * @throws IOException
	 */
	private static AuthorityKeyIdentifier createAuthorityKeyId(PublicKey pubKey)
		throws IOException
	{
			ByteArrayInputStream    bIn = new ByteArrayInputStream(
			pubKey.getEncoded());
			SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(
				 (ASN1Sequence)new DERInputStream(bIn).readObject()
			);
			return new AuthorityKeyIdentifier(info);
	}


	/* For debuging only!
	public static void main(String[] args) {
	  try {
		Logger.getRootLogger().setLevel(Level.DEBUG);

		String rqPath 		= "C:\\Documents and Settings\\Administrator\\.globus\\usercert_request.pem";
		String userKeyPath 	= "C:\\Documents and Settings\\Administrator\\.globus\\userkey.pem";
		String caCertPath 	= "C:\\Documents and Settings\\Administrator\\.globus\\simpleCA\\cacert.pem";
		String caKeyPath 	= "C:\\Documents and Settings\\Administrator\\.globus\\simpleCA\\cakey.pem";
		String signedCertPath = "C:\\Documents and Settings\\Administrator\\.globus\\usercert.pem";
		
		String subject = "O=Grid,OU=GlobusTest,OU=simpleCA-vladimir.pok.ibm.com,OU=pok.ibm.com,CN=vsilva";
		//String subject = GSIProperties.getString(GSIProperties.LOCAL_USER_SUBJECT)  + ",CN=Vladimir Silva";

		CertGenerator generator = new CertGenerator(subject);
		CertManager mgr = new CertManager(generator);
				
		mgr.createCertRequest(1024, "2p2dkdt");
		mgr.saveCertRequest(rqPath, userKeyPath);
		
		// sign rq
		CertSigner signer = new CertSigner(rqPath, caCertPath, caKeyPath, "2p2dkdt");
		signer.save(new FileOutputStream(signedCertPath));
		
		logger.debug("CA Cert\n" + CertUtil.loadCertificate(GSIProperties._defCACert).toString());
	  }
	  catch (Exception ex) {
		ex.printStackTrace();
	  }
	}
	*/
}
