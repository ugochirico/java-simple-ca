/*
 * Created on Aug 17, 2003
 */
package org.globus.grid.ca;

import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.Properties;
import java.util.ResourceBundle;

// Certificate manipulation classes
import org.globus.grid.gsi.GSIProperties;
import org.globus.grid.cert.CertGenerator;
import org.globus.grid.cert.CertManager;
import org.globus.grid.cert.CertSigner;

// Globus Certificate Utility Class from the Java COG Kit
// Infile cog-jglobus.jar
import org.globus.gsi.CertUtil;
import org.globus.gsi.OpenSSLKey;
import org.globus.gsi.bc.BouncyCastleOpenSSLKey;

import java.io.OutputStream;
import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.io.ByteArrayInputStream; 
import java.io.ByteArrayOutputStream; 


// Import log4j classes.
import org.apache.log4j.Level;
import org.apache.log4j.Logger;


/**
 * Simple CA: A clas to emulate simple CA functionality.
 * Functionality includes
 * <ul>
 * 		<li>Creating certificat requests (CSR) (e.g jcs req -keyout userkey.pem -out user-rq.pem -pwd test)
 * 		<li>Signing certificate requets (e.g jcs ca -rq /tmp/rq.pem -out /tmp/usercert.pem -capwd globus)
 * 		<li>Displaying certificate information
 * </ul>
 * Certificate Authority (CA) Certs are stored in: $HOME/.globus/CA
 * 
 * @author Vladimir Silva
 *
 */
public class SimpleCA 
{
	static Logger logger = Logger.getLogger(SimpleCA.class);
	
	private ResourceBundle _bundle 	= GSIProperties.getResBundle();
	private String _class 			= this.getClass().getName();
	private Properties _props 		= GSIProperties.load();
	
	public SimpleCA () {}

	
	public String getProperty(String key) {
		return _props.getProperty(key);
	}
	
	/**
	 * Simple CA usage
	 *
	 */
	public void usage() {
		StringBuffer buff = new StringBuffer("USAGE: " + _class + " [service] [options]");
		buff.append("\nService values are: ");
		buff.append("\n\treq\t- to create a cert request");
		buff.append("\n\thost\t- to create a host certificate");
		buff.append("\n\tca\t- to sign a request");
		buff.append("\n\tx509\t- to display certificate info");

		buff.append("\n\nreq (Certificate Request) options:");
		buff.append("\n\t-out\t(Required) [path to the request PEM]");
		buff.append("\n\t-keyout\t(Required) [path to the private key PEM]");
		buff.append("\n\t-pwd\t(Required) [passphrase used to encrypt the key]");
		buff.append("\n\t-dn\t(Optional) [Certificate identity. e.g: C=US,O=Grid,OU=OGSA,CN=John Doe]");
		buff.append("\n\t-bits\t(optional) [Certificate strength]");
		buff.append("\n\t-debug\t(Optional) [display debug msgs]");

		buff.append("\n\nca (Certificate signature) options:");
		buff.append("\n\t-rq\t(Required) [path to the request PEM file to be signed]");
		buff.append("\n\t-out\t(Required) [path to the signed certificate e.g $HOME/.globus/usercert.pem]");
		buff.append("\n\t-cacert\t(optional) [path to the CA certificate PEM]");
		buff.append("\n\t-cakey\t(optional) [path to the CA private key PEM file]");
		buff.append("\n\t-capwd\t(optional) [CA passphrase]");

		buff.append("\n\nhost (Create a Host Certificate) options:");
		buff.append("\n\t-out\t(Required) [Out path to the host cert PEM]");
		buff.append("\n\t-keyout\t(Required) [Out path to the private key PEM]");
		buff.append("\n\t-capwd\t(Required) [CA passphrase]");
		buff.append("\n\t-dn\t(Optional) [Certificate identity. e.g: C=US,O=Grid,OU=OGSA,CN=John Doe]");

		buff.append("\n\nx509 (Certificate info) options:");
		buff.append("\n\t-in\t(Required) [path to the X509 certificate PEM file]");
		buff.append("\n\t-info\t(Required) [Flag used to display cert info]");
		System.out.println(buff.toString());
	}
	
	/**
	 * Long usage
	 *
	 */
	public void longUsage() {
		usage();
		System.out.println("\nSamples:\nCertificate Request:");
		System.out.println("\tjava " + _class + " " + _bundle.getString("MSG_SAMPLES0"));
		System.out.println("\nCertificate signature:"); 
		System.out.println("\tjava " + _class + " " + _bundle.getString("MSG_SAMPLES1"));
	}

	/**
	 * Create a certificate request and encrypted private key
	 * @param rqPath Path to the NEW Certificate request file in PEM format
	 * @param keyPath path to the private key pem
	 * @param subject Requeter subject (e.g: "o=grid,uo=acme,cn=John doe")
	 * @param bits CSR strength in bits (e.g 512, 1024,...)
	 * @param pwd Certificate passphrase
	 * @throws Exception if an error occurs
	 */
	private void buildCertRequest(String rqPath, String keyPath, String subject, int bits, String pwd) 
	{
		try {
			logger.debug("Creating a cert request RQ Path=" + rqPath + " Key Path=" + keyPath + " Subject:" + subject + " bits:" + bits + " Passphrase:" + pwd);

			if (pwd == null ) {
				throw new Exception("A passphrase is required");
			}

			CertGenerator _gen 	= new CertGenerator(subject);
			CertManager _mgr 	= new CertManager(_gen);
				
			_mgr.createCertRequest(bits, pwd);
			_mgr.saveCertRequest(rqPath, keyPath);
			
		} catch (Exception e) {
			System.err.println("An error has occured generating a cert request: " + e.getMessage());
			//usage();
		}
	}
	
	/**
	 * Create a Host Certificate with unencrypted key.
	 * @param certPath Full Path to the cert
	 * @param keyPath Full path to the key
	 * @param subject Cert subject (e.g: "o=grid,uo=acme,cn=host/myhost.com")
	 * @param bits cert strength (e.g: 1024)
	 */
	private void buildHostCert(String certPath, String keyPath, String subject, int bits, String capwd) 
	{
		try {
			// Load BC provider if missing (cog-jglobus.jar) 
			CertUtil.init();
			
			// CA pwd is required to proceed. (An error will be thrown if wrong pwd)..
			CertManager.checkCAPassword(capwd);
			
			System.out.println("WARNING: Private key will not be encrypted!");

			// Create a Cert request (CSR) + Encrypted key
			CertGenerator gen = new CertGenerator(subject);
			gen.createCertRequest(bits, "dummy");
			
			// Here is the encrypted key
			String keyPEM = gen.getKeyPEM();

			// load CA streams (used for signature)
			ByteArrayInputStream inRQ 	= new ByteArrayInputStream(gen.getCertRQPEM().getBytes());
			FileInputStream inCACert	= new FileInputStream(GSIProperties._defCACert); 
			FileInputStream inCAKey 	= new FileInputStream(GSIProperties._defCAKey);
			OutputStream outCert 		= new FileOutputStream(certPath);

			// sign CSR and save it
			CertSigner signer = new CertSigner(inRQ, inCACert, inCAKey, capwd);
			signer.save(outCert);
			outCert.close();
			
			// Load encrypted key
			OpenSSLKey key = new BouncyCastleOpenSSLKey(new ByteArrayInputStream(keyPEM.getBytes()));
				
			// decrypt & assign back to keyPEM
			ByteArrayOutputStream outKey = new ByteArrayOutputStream();
			key.decrypt("dummy");
			key.writeTo(outKey);
			keyPEM = outKey.toString();
			
			// save priv key
			new FileOutputStream(keyPath).write(keyPEM.getBytes());
			
/*				
			// Get CA Cert issuer 
			String issuer = org.globus.gsi.CertUtil.loadCertificate(GSIProperties._defCACert).getIssuerDN().toString();

			// Create a X509 cert + unencrypted key (host)
			String sigAlg 				= "SHA1WithRSAEncryption";
			FileOutputStream fosKey 	= new FileOutputStream(keyPath);
			X509Certificate cert 		= CertGenerator.createX509Cert("RSA", bits, issuer, subject, 12, fosKey, sigAlg);
				
			// close key file & save cert
			fosKey.close();
			CertManager.saveX509Cert(cert, new FileOutputStream(certPath));
*/			
			
		} catch (Exception e) {
			System.err.println("An error has occured creating a host cert: " + e.getMessage());
		}
	}
	
	/**
	 * Sign a Certificate Request (CSR) . All input files must be PEM encoded.
	 * @param rqPath Full path to the CSR PEM file
	 * @param caCertPath Full path to the CA certificate used for signature
	 * @param caKeyPath Full path to the CA key file used for signature
	 * @param signedPath Full path to the output signed certificate
	 * @param caPwd CA passphrase
	 */
	private void signCertRequest(String rqPath, String caCertPath, String caKeyPath, String signedPath, String caPwd)
	{
		logger.debug("Signing cert rq. Rq Path=" + rqPath + " CA Cert=" + caCertPath + " CA key=" + caKeyPath + " Signed path=" + signedPath + " CA pwd=" + caPwd);
		
		try {
			
			CertSigner signer = new CertSigner(rqPath, caCertPath, caKeyPath , caPwd);
			signer.save(new FileOutputStream(signedPath));
			
		} catch (GeneralSecurityException e) {
			System.err.println(e.getMessage());
			usage();
		}
		catch (Exception e1) {
			System.err.println("An error has occured signing a cert request: " + e1.getClass().getName() + ": " + e1.getMessage());
			//e1.printStackTrace();
		}
		
	}

	/**
	 * Deal with host certificates option
	 * @param args
	 */
	private void handleHostCert(String[] args) throws Exception
	{
		String certPath = null, keyPath = null;
		String caPwd = null, subject = null, msg = null;
		boolean error = false, debug = false;

		//Logger.getRootLogger().setLevel(Level.DEBUG);
						
		for (int i = 1; i < args.length; i++) {
			String arg = args[i];
					
			if ( arg.equalsIgnoreCase("-out")) {
				certPath = args[++i];
			}
			else if (arg.equalsIgnoreCase("-keyout")) {
				keyPath = args[++i];
			}
			else if (arg.equalsIgnoreCase("-capwd")) {
				caPwd = args[++i];
			}
			else if (arg.equalsIgnoreCase("-dn") ) {
				subject = args[++i];
			}
					
		}
		if ( subject == null ) 
			subject = GSIProperties.getString(GSIProperties.LOCAL_USER_SUBJECT) + ",CN=" + GSIProperties._userName;
				
		// validations
		if ( certPath == null || keyPath == null || caPwd == null ) { error = true; msg ="ERROR: -out, -keyout, -capwd are required"; }
		 
		//System.out.println("Host certPath=" + certPath + " keyPath=" + keyPath + " subject=" + subject + " caPwd=" + caPwd + " error=" + error);				
		
		if ( error ) throw new Exception(msg);
		 
		if (debug) { Logger.getRootLogger().setLevel(Level.DEBUG);} 
		buildHostCert(certPath, keyPath, subject, 1024, caPwd);
	}
	
	/**
	 * SimplaCA main function
	 * @param args
	 */
	public static void main(String[] args) {
		SimpleCA simpleCA = new SimpleCA();
		String msg	= null;

		if ( args.length == 0) { simpleCA.longUsage(); return; } 
			
		String service = args[0];
		
		boolean error = false;
		boolean debug = false;
		
		String rqPath = null;
		String keyPath = null;
		
		
		try {		
			// create a cert request
			if ( service.equalsIgnoreCase("req") ) {
				// 
				String subject = null;
				String passPhrase = null;
				int bits = 1024;
				
				for (int i = 1; i < args.length; i++) {
					String arg = args[i];
					if ( arg.equalsIgnoreCase("-out")) {
						rqPath = args[++i];
				   	}
				   	else if (arg.equalsIgnoreCase("-keyout") ) {
						keyPath = args[++i];
				   	}
					else if (arg.equalsIgnoreCase("-pwd") ) {
						passPhrase = args[++i];
					}
					else if (arg.equalsIgnoreCase("-bits") ) {
						bits = Integer.parseInt(args[++i]);
					}
					else if (arg.equalsIgnoreCase("-dn") ) {
						subject = args[++i];
					}
					else if (arg.equalsIgnoreCase("-debug") ) {
						debug = true;
					}
				   	else {error = true;  msg = "Invalid option: " + args[i-1];} 
				}
				
				// if empty subject build a default
				if ( subject == null )  {
					subject = GSIProperties.getString(GSIProperties.LOCAL_USER_SUBJECT) + ",CN=" + GSIProperties._userName;
					
					System.out.println("Using default subject: " + subject);
				}
				else {
					System.out.println("Using subject: " + subject);
				}
				
				// validations
				if ( rqPath == null || keyPath == null || passPhrase == null ) { error = true; msg ="ERROR: -out, -keyout, -pwd are required"; } 
				
				if ( !error ) {
				 	if (debug) { Logger.getRootLogger().setLevel(Level.DEBUG);} 
					simpleCA.buildCertRequest(rqPath, keyPath, subject, bits, passPhrase);
				}
			}
			// certificate signature
			else if ( service.equalsIgnoreCase("ca")) {
				String caHome 		= GSIProperties._caHome;
				String caPwd 		= null;
				String signedPath 	= null;
				
				String caCertPath 	= caHome + "/" + simpleCA.getProperty(GSIProperties.CA_CERT_FILENAME);
				String caKeyPath 	= caHome + "/" + simpleCA.getProperty(GSIProperties.CA_KEY_FILENAME);
	
				for (int i = 1; i < args.length; i++) {
				   	String arg = args[i];
					
					if ( arg.equalsIgnoreCase("-rq")) {
						rqPath = args[++i];
				   	}
				   	else if ( arg.equalsIgnoreCase("-caCert")) {
						caCertPath = args[++i];
				   	}
					else if ( arg.equalsIgnoreCase("-caKey")) {
						caKeyPath = args[++i];
					}
				   	else if (arg.equalsIgnoreCase("-out") ) {
						signedPath = args[++i];
				   	}
				   	else if (arg.equalsIgnoreCase("-capwd") ) {
						caPwd = args[++i];
				   	}
					else if (arg.equalsIgnoreCase("-debug") ) {
						debug = true;
					}
				   	else { error = true; msg = "Invalid option: " + args[i-1];} 
				}

				// validations
				if ( rqPath == null || signedPath == null ) { error = true; msg ="ERROR: -rq, -out are required"; } 

				if ( !error ) {
					if (debug) Logger.getRootLogger().setLevel(Level.DEBUG);
				   	simpleCA.signCertRequest(rqPath, caCertPath, caKeyPath, signedPath, caPwd);
				}
			
			}
			// X509 functions
			else if ( service.equalsIgnoreCase("x509")) {
				boolean info = false;

				for (int i = 1; i < args.length; i++) {
					String arg = args[i];
				
					if ( arg.equalsIgnoreCase("-in")) {
						rqPath = args[++i];
					}
					else if ( arg.equalsIgnoreCase("-info")) {
						info = true;
					}
				}
				// validate opts
				if ( ( rqPath == null) || !info ) {
					error = true;
					msg = "Invalid options: Certificate path and -info required.";
				}
				if ( ! error) {
					X509Certificate cert = org.globus.gsi.CertUtil.loadCertificate(rqPath);
					System.out.println("Subject:" + cert.getSubjectDN() + "\nHash:" + cert.hashCode());
				}
			}
			// Initialize cert locations $HOME/.globus
			else if ( service.equalsIgnoreCase("setup")) {
				if (args[1].equalsIgnoreCase("-debug")) Logger.getRootLogger().setLevel(Level.DEBUG);
				
				logger.debug("Setting up cert locations.");
				GSIProperties.initCertLocations();
			}
			else if ( service.equalsIgnoreCase("host")) {
				simpleCA.handleHostCert(args);
			}
			else {
				simpleCA.longUsage();
			}
			
			if ( error ){
				System.err.println(msg); // error msg
				//simpleCA.usage();
			}
			
		}
		catch (InternalError e0) {
			System.err.println("Internal Error: " + e0.getMessage());
		}
		catch (Exception e1) {
			System.err.println(e1.getMessage());
		}
	}
}
