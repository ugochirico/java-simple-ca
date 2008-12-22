/*
 * Created on Aug 13, 2003
 */
package org.globus.grid.cert;
import java.io.*;
import java.util.ResourceBundle;
import java.security.*;
import java.security.cert.*;

import org.globus.gsi.OpenSSLKey;
import org.globus.gsi.CertUtil;

import org.globus.gsi.bc.*;

// Import log4j classes.
import org.apache.log4j.Logger;

import org.globus.grid.gsi.GSIProperties;

/**
 * CertManager: Class used to manage certificates and Globus proxies: load, save, init
 * @author Vladimir Silva
 * <br>Sample Usage:
 * 			<pre>
 *			if ( CertManager.localCertsInstalled() ) {
 *				if (! ProxyManager.isLocalProxyValid() ) {
 *					System.out.println("Creating proxy...");
 *					GlobusCredential c = ProxyManager.gridProxyInit("certpwd");
 *					ProxyManager.saveAsLocalProxy(c);
 *					System.out.println("proxy=" + c );	
 *				}
 *				else {
 *					System.out.println("Loading local proxy");
 *					System.out.println(ProxyManager.loadLocalProxy());				
 *				}
 *			}
 *			else {
 *				System.out.println("Local certs not installed.");
 * 				CertGenerator generator = new CertGenerator("C=US,O=Grid,OU=OGSA,CN=Jon Doe");
 *				CertManager mgr = new CertManager(generator);
 *				// install certs here
 * 			}
 *			</pre>
 */
public class CertManager {
	static Logger logger = Logger.getLogger(CertManager.class);

	private CertGenerator _generator = null;
	
	private int _strength = 1024;	
	private ResourceBundle _resBundle = GSIProperties.getResBundle();

	/**
	 * CertManager: Manages certificate loading and validation
	 * loads certificates from $HOME/.globus 
	 * looks for the files: (userser.pem, userkey.pem, x509up_[$USER_NAME])
	 * @param gen a Certificate generator class (CertGenerator)
	 * used to generate user certs and keys
	 * @throws Exception
	 */			
	public CertManager(CertGenerator gen) throws Exception {
		_generator = gen;
		// def stren
		_strength = Integer.parseInt(GSIProperties.getString(GSIProperties.CERT_STRENGTH));
		logger.debug("Constructor: stren=" + _strength); 
	}
	
	/**
	 * Uses a CertificateGenerartor to generate a user cert and private key
	 * @param pwd password used to encrypt the private key
	 * @throws NoSuchAlgorithmException
	 * @throws Exception
	 */
	public void generateSelfSignedCertificates(String pwd) 
		throws NoSuchAlgorithmException, Exception 
	{
		_generator.generateSelfSignedCertAndKey(pwd);
	}
	
	
	/**
	 * loadCertificates: Loads user certificates from $HOME/.globus
	 * User cert file is usercert.pem, Key: userkey.pem
	 * Proxy: userproxy.pem
	 */
	public void loadLocalCertificates() {
		// load cert, key & proxy
		String certPath = GSIProperties._defUsercert; 
		String keyPath = GSIProperties._defUserKey; 
		String proxyPath = GSIProperties._defUserProxy; 
		logger.debug("loadCertificates: Loading user cert from:" + certPath);
		logger.debug("loadCertificates: Loading user key from:" + keyPath);
		logger.debug("loadCertificates: Loading proxy from:" + proxyPath);
		
		String _certPEM = GSIProperties.readFile(certPath);
		String _keyPEM = GSIProperties.readFile(keyPath);
		
		// send PEMS to gen engine
		_generator.setCertPEM(_certPEM);
		_generator.setKeyPEM(_keyPEM);
	}

	/**
	 * certsInstalled Check if globus certificates are installed for the
	 * current user's home directory (The user that starts the java process).
	 * $HOME/.globus directory will be checked for: usercer.pem & userkey.pem
	 * @return boolean value (true if certs exist in user's home else false)
	 */
	public static boolean localCertsInstalled() 
		throws IOException, GeneralSecurityException
	{
		String _certPath	= GSIProperties._defUsercert; 
		String _keyPath		= GSIProperties._defUserKey; 
		boolean bool 		= false;

		CertUtil.loadCertificate(_certPath);
		new BouncyCastleOpenSSLKey(_keyPath);
		bool = true;

		logger.debug("localCertsInstalled: Checking if certs are installed in: " + GSIProperties._certsHome + " Installed: " + bool);
		return bool;
	}

	/**
	 * Check if Local CA certs are installed in the defaul locations
	 * Cert: $HOME/.globus/simpleCA/cacert.pem
	 * Key: $HOME/.globus/simpleCA/cakey.pem
	 * @return true if installed else false
	 */
	public static boolean localCACertsInstalled() {
		try {
			new FileInputStream(GSIProperties._defCACert);
			new FileInputStream(GSIProperties._defCAKey);
			return true;
		} catch (Exception e) {
			return false;
		}
	}

	/**
	 * saveCertificates: Save generated certificates into the user's
	 * home directory as: $HOME/usercert.pem and $HOME/userkey.pem
	 * @throws IOException if certificates cannot be saved by some reason
	 */
	public void saveLocalCertificates()
		throws IOException 
	{
		String certPath =  GSIProperties._defUsercert; // _certsHome + "/usercert.pem";
		String keyPath = GSIProperties._defUserKey; // _certsHome + "/userkey.pem";
		saveCertificates(certPath, keyPath);		  
	}
	
	/**
	 * Save user certificate & private key into specified files (PEM encoded)
	 * @param certPath Full path to the cert file to save (e.g $HOME/.globus/.usercert.pem)
	 * @param keyPath Full path to the key file to save (e.g $HOME/.globus/.userkey.pem)
	 * @throws IOException if an error occurs
	 */
	public synchronized void saveCertificates(String certPath, String keyPath)
		throws IOException 
	{
	  
		FileOutputStream fos0 = new FileOutputStream(certPath);
		FileOutputStream fos1 = new FileOutputStream(keyPath);
		
		logger.debug("saveCertificates: Saving cred to: " + certPath + " Key: " + keyPath );
		
		String _certPEM = _generator.getCertPEM();
		String _keyPEM = _generator.getKeyPEM();
		
		if ( _certPEM == null || _keyPEM == null ) 
			throw new IOException("No user cert and private key have been generated.");
		
		fos0.write(_certPEM.getBytes());
		fos1.write(_keyPEM.getBytes());
		fos0.close(); fos1.close();
	}
	

	/**
	 * Save an X509 Certificate
	 * @param cert X509 certificate to be saved
	 * @param out save Output stream
	 * @throws GeneralSecurityException
	 * @throws IOException
	 */
	public static void saveX509Cert(X509Certificate cert, OutputStream out) 
		throws GeneralSecurityException, IOException
	{
		// "Certificate:\n" + cert.toString() + "\n\n" +
		String pem = 
			CertGenerator.writePEM(cert.getEncoded(),
				"-----BEGIN CERTIFICATE-----\n",
				"-----END CERTIFICATE-----\n");
		out.write(pem.getBytes());
		out.close();
	}
	

	/* getter methods */
	public String getCertPEM() { return  _generator.getCertPEM(); } //_certPEM; }
	public String getKeyPEM() { return _generator.getKeyPEM(); }
	
	public String toString() {
		return "Certificate\n" + _generator.getCertPEM() + "Key\n" + _generator.getKeyPEM() ; // + "Proxy\n" + _proxyPEM;
	}
	
	/**
	 * signCertificateRequest: Sign the local certificate request
	 * on the user's home dir
	 * 		Request Path: (e.g. $HOME/.globus/usercert_request.pem)
	 *		Signed cert path (e.g. $HOME/.globus/usercert.pem)
	 * CA certs are under : $HOME/.globus/simpleCA
	 * 
	 * @param caPwd Password of the cert authority
	 * @throws IOException If IO error occurs
	 * @throws FileNotFoundException
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws GeneralSecurityException
	 */
	
	public void signLocalCertRequest(String caPwd) 
		throws IOException, FileNotFoundException, InvalidKeyException,
			NoSuchAlgorithmException, GeneralSecurityException
	{
		//String caHome = GSIProperties._caHome;
		String caCertPath 		= GSIProperties._defCACert; 
		String caKeyPath 		= GSIProperties._defCAKey; 
		String rqPath 			= GSIProperties._defUserCertRq; 
		String signedCertPath 	= GSIProperties._defUsercert;
				
		CertSigner signer = new CertSigner(rqPath, caCertPath, caKeyPath , caPwd);
		signer.save(new FileOutputStream(signedCertPath));
	}
	
	/**
	 * createCertRequest: Create a cert rq on user's home directory $HOME/.globus
	 * @param pwd Request password
	 * @throws IOException if an io error occurs
	 * @throws GeneralSecurityException
	 */
	public void createCertRequest(int bits, String pwd)
		throws IOException, GeneralSecurityException
	{
		_generator.createCertRequest(bits, pwd);

	}
	
	public void saveLocalCertRequest()
			throws FileNotFoundException, IOException 
	{
		String rqPath 	= GSIProperties._defUserCertRq;
		String keyPath	= GSIProperties._defUserKey;
		
		logger.debug("saveCertRequest: Saving rq to: " + rqPath + " key: " + keyPath);
		saveCertRequest(rqPath, keyPath);
	}	
	
	/**
	 * saveCertRequest: Save certificate request. Rq must be generated first
	 * by calling createCertRequest(...)
	 * @param rqPath Full Path to the cert rq file (e.g $HOME/.globus/usercert_request.pem)
	 * @throws FileNotFoundException
	 * @throws IOException
	 */
	public synchronized void saveCertRequest(String rqPath, String keyPath)
		throws FileNotFoundException, IOException 
	{
		if (rqPath == null) throw new IOException("Invalid cert request path");
		FileOutputStream fos0 = new FileOutputStream(rqPath);
		
		// save priv key too...
		//String keyFilePath = GSIProperties._certsHome + "/" + _props.getProperty(GSIProperties.USER_KEY_FILENAME);
		FileOutputStream fos1 = new FileOutputStream(keyPath);

		// check if cert has been generated
		if ( _generator.getCertRQPEM() == null ) 
			throw new IOException(_resBundle.getString(GSIProperties.MSG_NO_CERT_RQ));
			
		fos0.write(_generator.getCertRQPEM().getBytes());
		fos1.write(_generator.getKeyPEM().getBytes());
		fos0.close(); fos1.close();
	}
	
	/**
	 * Install certificates in the user's home directory
	 * @param certPwd Certificate passphrasse
	 * @param caPwd Certificate authority passphrasse
	 * @throws IOException
	 * @throws GeneralSecurityException
	 * @throws Exception
	 */
	public void installLocalCertificates(String certPwd, String caPwd)
		throws IOException, GeneralSecurityException, Exception
	{
		// create  local CA certs
		String caSubject 	= GSIProperties.getString(GSIProperties.LOCAL_CA_SUBJECT);
		String caCertPath 	= GSIProperties._defCACert;
		String caKeyPath 	= GSIProperties._defCAKey;
		
		// Initialize cert locatrions: $HOME/.globus (Create folders if they don't exist)
		GSIProperties.initCertLocations();
		
		logger.debug("installLocalCertificates: Creating a CA with subject:" + caSubject + " Cert: " + caCertPath + " Key:" + caKeyPath + " CA pwd=" + caPwd);
		
		// Create CA cert + key (unencrypted)
		FileOutputStream outCAKey 	= new FileOutputStream(caKeyPath);
		FileOutputStream outCACert	= new FileOutputStream(caCertPath);
		String sigAlg 				= "SHA1WithRSAEncryption";
		int months 					= 12;
		
		// self-signed CA cert
		X509Certificate caCert = CertGenerator.createX509Cert("RSA", 1024 , caSubject, caSubject, months, outCAKey, sigAlg, certPwd);
		CertManager.saveX509Cert(caCert, outCACert);
				
		// create a user cert rq, encrypted private key & save
		int bits = Integer.parseInt(GSIProperties.getString(GSIProperties.CERT_STRENGTH));
		createCertRequest(bits, certPwd);
		saveLocalCertRequest();	// save rq + key
		
		// sign + save signbed cert
		signLocalCertRequest(caPwd); // caPwd is not needed cuz CA key is not encrypted
	}

	/**
	 * 
	 * @param capwd
	 * @throws GeneralSecurityException
	 * @throws IOException
	 */
	public static void checkCAPassword(String capwd) throws GeneralSecurityException, IOException 
	{
		// check 4 CA pwd (if any)
		if ( ! capwd.equals("") ) {
			OpenSSLKey key = new BouncyCastleOpenSSLKey(GSIProperties._defCAKey);
					
			// is CA key enc?
			if ( key.isEncrypted() ) {
				try {
					key.decrypt(capwd);
				} 
				catch(GeneralSecurityException e) {
					throw new GeneralSecurityException("Wrong CA password or other security error: " + e.getMessage());
				}
			}
		}
		else
			throw new GeneralSecurityException("Invalid CA password.");
	}
	
	
	/* for debugging only! */
	/*	
	public static void main(String[] args) {
		org.apache.log4j.Logger.getRootLogger().setLevel(org.apache.log4j.Level.DEBUG);
		
		try {
			CertGenerator g = new CertGenerator("O=IBM,OU=Globus,CN=vsilva");
			g.createCertRequest(1024, "foo");
			
			ByteArrayInputStream bis = new ByteArrayInputStream(g.getKeyPEM().getBytes()); 
			BouncyCastleOpenSSLKey k = new BouncyCastleOpenSSLKey(bis);
			
			System.err.println("k verif is enc=" + k.isEncrypted() + " k=" + k.getPrivateKey()); 
		} catch (Exception e) {
			e.printStackTrace();
			System.err.println(e);
		}
		
	}
	*/

}
