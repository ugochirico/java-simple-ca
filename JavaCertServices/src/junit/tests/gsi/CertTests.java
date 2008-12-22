/*
 * Created on Aug 13, 2003
 *
 * To change the template for this generated file go to
 * Window&gt;Preferences&gt;Java&gt;Code Generation&gt;Code and Comments
 */
package junit.tests.gsi;

/**
 * @author Vladimir Silva
 *
 * Junit tests
 */
import junit.framework.*;


import org.globus.grid.cert.CertGenerator;
import org.globus.grid.cert.CertManager;

import java.io.FileOutputStream;

import java.security.cert.X509Certificate;



public class CertTests extends TestCase {
	protected CertGenerator _gen	= null;
	protected CertManager _mgr 		= null;
	
	public static final String _certPwd = "certpwd";
	public static final String _caPwd 	= "globus"; 
	
	protected int _stren = 1024;
	
	// CA params
	protected String _caCertPath = "C:\\Documents and Settings\\Administrator\\.globus\\simpleCA\\cacert.pem";
	protected String _caKeyPath = "C:\\Documents and Settings\\Administrator\\.globus\\simpleCA\\cakey.pem";
	protected String _ca_subject = "O=Grid,OU=GlobusTest,OU=simpleCA-vladimir.pok.ibm.com,OU=pok.ibm.com,CN=Globus Simple CA";
	
	// User cert params
	protected String _rqPath = "C:\\Documents and Settings\\Administrator\\.globus\\usercert_request.pem";
	protected String _signedCertPath = "C:\\Documents and Settings\\Administrator\\.globus\\usercert.pem";
	protected String _rq_subject = "O=Grid,OU=GlobusTest,OU=simpleCA-vladimir.pok.ibm.com,OU=pok.ibm.com,CN=vsilva";
	

	public static Test suite() {
		return new TestSuite(CertTests.class);
	}
	
	protected void setUp() throws Exception {
		_gen = new CertGenerator(_rq_subject) ; 
		_mgr = new CertManager(_gen);
	}
	

	// Sign RQ from user's home $HOME/.globus/usercert_request.pem
	public void testLocalRequestSignature() throws Exception {
		_mgr.signLocalCertRequest(_caPwd);
	}
	
	//	Create a cert rq & save it in the user's home dir $HOME/.globus
	public void testCreateHomeCertRq() throws Exception {
		_mgr.createCertRequest(_stren, _certPwd);
		_mgr.saveLocalCertRequest();
	}
	
	// create CA certs & save them in default loc: $HOME/.globus/simpleCA/user{cer,key}.pem
	public void testCACertGenerationAndSave() throws Exception {
		FileOutputStream outKey = new FileOutputStream(_caKeyPath);
		FileOutputStream outCert = new FileOutputStream(_caCertPath);
		X509Certificate cert = CertGenerator.createX509Cert("RSA", _stren, _ca_subject, _ca_subject, 12, outKey, "SHA1WithRSAEncryption", null);
		CertManager.saveX509Cert(cert, outCert);
	}
	
	// Create a self-signed (Root CA cert) & save	
	public void testSelfSignedCertGenerationAndSave() throws Exception {			
		CertGenerator gen = new CertGenerator(_rq_subject); 
		CertManager mgr = new CertManager(gen);
			
		mgr.generateSelfSignedCertificates(_certPwd);
		mgr.saveCertificates("c:\\temp\\cert.pem", "c:\\temp\\key.pem");
	}
	
	// test if CA certs installed in def loc. (Install if not)	
	public void testCACertInstall() throws Exception {
		if ( ! CertManager.localCACertsInstalled()) {
			_mgr.installLocalCertificates(_certPwd, _caPwd);			
		}
		assertTrue(CertManager.localCACertsInstalled() == true);
	}

/*
	public void testUserPasswordMatch()
		throws Exception	
	{
		String uname = "globus";
		String pwd = "globus1";
		
		CryptUtil.pwd_entry pw_ent = null;
		CryptUtil c 	= new CryptUtil();
		int[] maxUID 	= { -1 };
		
		pw_ent = c.getUserEntry(uname, maxUID);
			
		if ( pw_ent != null ) {
			String h0 = pw_ent.ent_pwd;
			String h1 =	c.hash(pwd);

			assertTrue("Password hash mismatch error H:" + h0 + " H':" + h1, h0.equals(h1));
		}
		else
			throw new Exception("No such user: " + uname + " in pwd table");
	}
*/	
	
	
	public static void main(String[] args) {
		//org.apache.log4j.Logger.getRootLogger().setLevel(org.apache.log4j.Level.DEBUG);
		junit.textui.TestRunner.run (suite());

		
	}
}
