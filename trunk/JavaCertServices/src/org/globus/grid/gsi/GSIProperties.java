/*
 * Created on Aug 7, 2003
 *
 * To change the template for this generated file go to
 * Window&gt;Preferences&gt;Java&gt;Code Generation&gt;Code and Comments
 */
package org.globus.grid.gsi;

import java.security.Provider;
import java.security.Security;
import java.util.Properties;
import java.util.ResourceBundle;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.RandomAccessFile;

// Import log4j classes.
import org.apache.log4j.Logger;

import COM.claymoresystems.ptls.LoadProviders;

/**
 * Default Application properties
 * @author Vladimir Silva
 *
 */
public class GSIProperties extends Properties 
{
	private static final long serialVersionUID = -4325760122489221903L;

	static Logger logger = Logger.getLogger(GSIProperties.class);
	
	private static final String props_file_name = "gsi.properties";
	
	// DB Connection args
	public static final String GSI_CA_ID 	= "GSI_CA_ID";
	public static final String GSI_DB_URL 	= "GSI_DB_URL";
	public static final String GSI_DB_JNDI 	= "GSI_DB_JNDI";
	
	// 
	public static final String DB2_DRIVER 	= "DB2_DRIVER";
	public static final String DB2_USER 	= "DB2_USER";
	public static final String DB2_PWD		= "DB2_PWD";
	
	// Messages
	public static final String MSG_DN_INFO_REQUIRED = "MSG_DN_INFO_REQUIRED";
	public static final String MSG_INVALID_PWD 		= "MSG_INVALID_PWD";
	public static final String MSG_NO_CERT_RQ 		= "MSG_NO_CERT_RQ";
	public static final String MSG_NO_CERTS_FOUND 	= "MSG_NO_CERTS_FOUND";
	
	// User certs and CA dirs	
	public static final String USER_CERTS_DIR 	= "USER_CERTS_DIR";
	public static final String CA_CERTS_DIR 	= "CA_CERTS_DIR";
	public static final String TRUSTED_DIRS 	= "TRUSTED_DIRS";
	
	// default filenames
	public static final String USER_CERT_FILENAME	= "USER_CERT_FILENAME";
	public static final String USER_KEY_FILENAME	= "USER_KEY_FILENAME";
	public static final String CA_CERT_FILENAME		= "CA_CERT_FILENAME";
	public static final String CA_KEY_FILENAME		= "CA_KEY_FILENAME";
	public static final String USER_CERT_RQ_FILENAME = "USER_CERT_RQ_FILENAME";
	
	// local CA values (for installing certs)
	public static final String LOCAL_CA_SUBJECT 	=  "LOCAL_CA_SUBJECT";
	
	public static final String LOCAL_USER_SUBJECT 	= "LOCAL_USER_SUBJECT";
	
	// def cert strength
	public static final String CERT_STRENGTH = "CERT_STRENGTH";

	private static Properties _props = null;
	static {
		_props = load();
	}
	
	// globals
	public static final String _os 			= System.getProperty("os.name");
	public static final String _userHome 	= System.getProperty("user.home");
	public static final String _tmpDir		= System.getProperty("java.io.tmpdir");
	public static final String _userName	= System.getProperty("user.name");
	public static final String _fileSep		= System.getProperty("file.separator");
	
	public static final boolean isWin32		= (_os.indexOf("Windows") != -1);
	
	// certs/CA home		
	public static String _certsHome 		= _userHome +  _fileSep + _props.getProperty(GSIProperties.USER_CERTS_DIR);
	public static String _caHome 			= _certsHome + _fileSep + _props.getProperty(GSIProperties.CA_CERTS_DIR);
		
	// defaults
	public static String _defCACert 	= _caHome + _fileSep + _props.getProperty(GSIProperties.CA_CERT_FILENAME);
	public static String _defCAKey 		= _caHome + _fileSep + _props.getProperty(GSIProperties.CA_KEY_FILENAME);
	public static String _defUsercert 	= _certsHome + _fileSep +  _props.getProperty(GSIProperties.USER_CERT_FILENAME);
	public static String _defUserKey 	= _certsHome + _fileSep +  _props.getProperty(GSIProperties.USER_KEY_FILENAME);
	public static String _defUserCertRq = _certsHome + _fileSep + _props.getProperty(GSIProperties.USER_CERT_RQ_FILENAME);
	
	public static String _defUserProxy 	= GSIProperties.guessProxyName();
	//public static String _defUserProxy 	= _tmpDir + _fileSep + "x509up_u_" + _userName.toLowerCase();
	
	public static String _defTrustedCertsLoc = (isWin32) ? _certsHome :  _certsHome + "," + _props.getProperty(GSIProperties.TRUSTED_DIRS);

	
	public GSIProperties() {}
	
	/**
	 * Load default properties
	 * @return Application properties
	 */
	public synchronized static Properties load() //throws Exception
	{
		if ( _props != null ) return _props;
		GSIProperties gsiProps = new GSIProperties();
		Properties props = new Properties();
		try {		
			props.load(gsiProps.getClass().getResourceAsStream("/" + props_file_name));
			return props;
		}
		catch (Exception e) {
			try {
				props.load(gsiProps.getClass().getResourceAsStream(props_file_name));
				return props;				
			} catch (Exception e1) {
				//throw new Exception("Unable to find GSI properties file: " + props_file_name + " Message: " + e1.getClass().getName());
				System.err.println("Unable to find GSI properties file: " + props_file_name + " Message: " + e1.getClass().getName());
				return null;
			}
		}
	}
	
	/**
	 * Get a property value from gsi.properties file
	 * @param key Name of the search key 
	 * @return Propety value as string
	 */
	public static String getString(String key) {
		return _props.getProperty(key);
	}
	
	/**
	 * Returns GSI propeties hash table
	 * @return properties for GSI
	 */
	public static Properties getProperties() {
		return _props;
	}
	
	/**
	 * Read a file. Used for testing
	 */
	public static String readFile(String path) {
		try {
			RandomAccessFile f = new RandomAccessFile (path, "r");
			byte[] b = new byte[(int)f.length()];
			f.read(b);
			return new String(b);
		}
		catch (Exception ex) {
			  logger.error("GSIProperties::readFile Error: " + ex.getMessage() );
			  return null;
		}
	}
	
	/**
	 * installBCProvider: Install the BouncyCastle JCE provider
	 *
	 */
	public static void installBCProvider() {
		logger.debug("Instaling Bouncy Castle Crypto provider");
		
		//LoadProviders.init();
		if ( java.security.Security.getProvider("BC") == null )
			java.security.Security.insertProviderAt(new org.bouncycastle.jce.provider.BouncyCastleProvider(), 1);
	}

	public static void dumpJCEproviders () {
		Provider[] providers =  Security.getProviders();
		for (int i = 0; i < providers.length; i++) {
			System.out.println(providers[i]);
		}
	}
	
	/**
	 * getResBundle: Get app res bundle messages
	 * @return Application messages res bundle
	 */
	public static ResourceBundle getResBundle() {
		return ResourceBundle.getBundle("org.globus.grid.gsi.messages"); 
	}
	
	/**
	 * Create directory
	 * @param path Full path to the folder
	 */
	public static void createDir(String path) {
		File f = new File(path);
		try {
			if ( !f.exists() ) {
				logger.debug("createDir: Creating folder: " + path);
				f.mkdirs();	
			}
			else logger.debug("createDir: " + path + " already exists.");
		} 
		catch (Exception e) {
			System.err.println("GSIProperties::createDir: Unable to create folder: " + path + ". " + e.getMessage());
		}
	}
	
	/**
	 * Initialize cert locations. Creates folders for certificates
	 * under $HOME/.globus and $HOME/.globus/simpleCA
	 */
	public static void initCertLocations() {
			createDir(_certsHome);
			createDir(_caHome);
	}
	
	/**
	 * Execute an OS native process
	 * @param cmd Full path to an executable as an array of strings
	 * @param stdout Standard out
	 * @param stderr Standard err
	 * @throws IOException if exec not found
	 */
	public static void runProcess(String[] cmd, StringBuffer stdout, StringBuffer stderr)
		throws IOException 
	{
		Process p  = null;
		String s = ""; 
		for (int i = 0; i < cmd.length; i++) {
			s += cmd[i];
		}
		try {
			p = Runtime.getRuntime().exec(cmd);	
		} catch (IOException e) {
			throw new IOException("Command " + s + " not found.");
		}
		
				
		BufferedReader in0  = new BufferedReader(new InputStreamReader(p.getInputStream()));
		BufferedReader in1  = new BufferedReader(new InputStreamReader(p.getErrorStream()));

		String line = null;
				
		while ( (line = in0.readLine()) != null) {
			stdout.append(line);
		}
		while ( (line = in1.readLine()) != null) {
			stderr.append(line);
		}
		logger.debug("runProcess cmd: " + s + " stdout: " + stdout + " stderr: " + stderr);
	}
	
	/**
	 * Guess the proxy file name from Win32 or Linux
	 * Win32: x509up_u_[USER_NAME]
	 * Unix: x509up_u[USER_ID]
	 * @return Proxy file name
	 */
	public static String guessProxyName() 
	{
		
		String name = _tmpDir + _fileSep + "x509up_u_" + _userName.toLowerCase();
		
		// Get the userid for a given user from the passwd file
		String[] cmd1 =  { "awk", "-F:", "{ if ( $1 == \"" + _userName + "\" ) print $3}", "/etc/passwd" };

		StringBuffer userName = new StringBuffer("");				
		StringBuffer stderr = new StringBuffer("");				
		
		if ( !GSIProperties.isWin32) {
			// assume Linux/Unix
			try {
				runProcess(cmd1, userName, stderr);	
			} 
			catch (IOException e) {
				logger.error("guessProxyName Unable to run: " + cmd1 + " :" + e.getMessage());
			}
			
			if ( userName.toString().length() > 0 ) {
				name = _tmpDir + _fileSep  + "x509up_u" + userName; 
			}
		}
		logger.debug("guessProxyName OS:" + _os + " Is Win32:" + isWin32 + " Proxy name: " + name);

		return name;
	}
	
	/* for debuging only */
	public static void main(String[] args) {
		try {
//			String[] cmd = {"c:\\winnt\\system32\\xcopy.exe",  "/?" };
//			
//			StringBuffer stdout = new StringBuffer("");				
//			StringBuffer stderr = new StringBuffer("");				
//			GSIProperties.runProcess(cmd, stdout, stderr);
//				
//			System.out.println("os=" + GSIProperties._os);
//			System.out.println("Is win32=" + GSIProperties.isWin32);
//			
//			System.out.println("stdout:" + stdout);	
//			System.err.println("stderr:" + stderr);	
//			
//			System.out.println(GSIProperties._defUserProxy);
			
			installBCProvider();
			
			dumpJCEproviders();

		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
