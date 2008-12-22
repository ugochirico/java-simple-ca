<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<!--
*****************************************************************
* Java Certificate Services
* A web tool implementation for the creation and manipulation of:
* Author: Vladimir Silva
*
*	1) X509 Certificate requests,
*	2) User or Host certificates and private keys
* 	3) Self-signed certificates
*
* Requires the Java Cog Kit 1.1 + utility classes
*
*****************************************************************
-->
<HTML>
<HEAD>
<%@ page 
	language="java"
	contentType="text/html; charset=ISO-8859-1"
	import="org.globus.grid.cert.*,
			java.io.*,
			java.security.GeneralSecurityException,
			org.globus.gsi.CertUtil,
			org.globus.gsi.bc.BouncyCastleOpenSSLKey,
			org.globus.gsi.OpenSSLKey,
			java.security.cert.X509Certificate,
			org.globus.grid.gsi.GSIProperties"

%>
<%! 
	
	public void jspInit() {
       
	}
%>
<META http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<META name="GENERATOR" content="IBM WebSphere Studio">
<META http-equiv="Content-Style-Type" content="text/css">
<LINK href="../../theme/Master.css" rel="stylesheet"
	type="text/css">

<TITLE>User/Host Certificates</TITLE>

<%
	//OutputStream outKey = new ByteArrayOutputStream();
	OutputStream outCert 	= new ByteArrayOutputStream();
	X509Certificate cert 	= null;
	CertGenerator gen 		= null;
	String keyPEM			= null;
	
	String action 	= request.getParameter("action");
	String msg 		= request.getParameter("msg");

	boolean caCertsFound 	= true;
	boolean caKeyEncrypted 	= false;
	boolean _error			= false;
		
	X509Certificate caCert 			= null;
	BouncyCastleOpenSSLKey caKey 	= null;
	
	if ( action == null ) {
		// check 4 CA certs
		try {
			caCert 				= org.globus.gsi.CertUtil.loadCertificate(GSIProperties._defCACert);
			FileInputStream fis = new FileInputStream(GSIProperties._defCAKey);
			caKeyEncrypted 		= CertGenerator.isKeyEncrypted(fis);
		}
		catch (Exception e ) {
			//msg = "CA certs are required." + e.getMessage();
			caCertsFound = false;
		}
	}
	else {
		try {
			// Form args
			String cn = request.getParameter("CN");
			String ou = request.getParameter("OU");
			String o0 = request.getParameter("O");
			String L = request.getParameter("L");
			String C = request.getParameter("C");
			String pwd 		= request.getParameter("PWD");
			String capwd 	= request.getParameter("CAPWD");
			
			int bits 	= Integer.parseInt(request.getParameter("ST"));
			int months 	= Integer.parseInt(request.getParameter("MONTHS"));
			
			String subject = "C=" + C + ",L=" + L + ",O=" + o0 + ",OU=" + ou + ",CN=" + cn; // "LOC=" + lo + 
			//System.out.println("userhost.jsp: Subject:" + subject + " st=" + bits + " months=" + months + " pwd=" + pwd + " ca pwd=" + capwd);

			// X509 cert generator
			gen = new CertGenerator(subject);
			
			// Create a Cert request (CSR) + Encrypted key
			gen.createCertRequest(bits, pwd);
			
			// Here is the encrypted key
			keyPEM = gen.getKeyPEM();

			// CSR as a stream
			ByteArrayInputStream inRQ 	= new ByteArrayInputStream(gen.getCertRQPEM().getBytes());
				
			// CA stream cert files (used for signature)
			FileInputStream inCACert	= new FileInputStream(GSIProperties._defCACert); 
			FileInputStream inCAKey 	= new FileInputStream(GSIProperties._defCAKey);

			// sign CSR
			CertSigner signer = new CertSigner(inRQ, inCACert, inCAKey, capwd);
			signer.save(outCert);
			outCert.close();

			// get cert info (for user display)
			cert = org.globus.gsi.CertUtil.loadCertificate(new ByteArrayInputStream(outCert.toString().getBytes()));
			
			// HOST CERT (empty pwd):  decrypt the key(keyPEM) above...
			if ( (pwd == null) || pwd.equals("") ) {
				
				// Load encrypted key
				OpenSSLKey key = new BouncyCastleOpenSSLKey(new ByteArrayInputStream(keyPEM.getBytes()));
				
				// decrypt & assign back to keyPEM
				ByteArrayOutputStream outKey = new ByteArrayOutputStream();
				key.decrypt(pwd);
				key.writeTo(outKey);
				keyPEM = outKey.toString();

			}
/*
			else {
				
				ByteArrayInputStream inRQ 	= new ByteArrayInputStream(gen.getCertRQPEM().getBytes());
				
				// CA cert files (used for signature)
				FileInputStream inCACert	= new FileInputStream(GSIProperties._defCACert); 
				FileInputStream inCAKey 	= new FileInputStream(GSIProperties._defCAKey);
			
				// sign CSR
				CertSigner signer = new CertSigner(inRQ, inCACert, inCAKey, capwd);
				signer.save(outCert);
						
				outCert.close();
				
				// get cert info (for user display)
				cert = org.globus.gsi.CertUtil.loadCertificate(new ByteArrayInputStream(outCert.toString().getBytes()));
			}
*/
		}
		catch (Exception e0 ) 
		{
			// A fatal error has occured. Redirect w/ an error message
			_error	= true;
			msg 	= e0.getMessage().replace(' ','+');
			
			response.sendRedirect("userhost.jsp?msg=" + e0.getClass().getName() + "-" + msg);
		}
	}
%>
<SCRIPT language="Javascript">
	function OnLoad() {
		if (document.F1 && document.F1.CN) 
			document.F1.CN.focus();
		status = "Done.";
	}
	
	function OnSubmit() {
		var f = document.F1;
		var caKeyEnc = <%=caKeyEncrypted%>;
		
		if (  !f.CN.value || !f.OU.value || !f.O.value || ( caKeyEnc && !f.CAPWD.value)
				|| !f.C.value || !f.L.value
			) 
		{
				alert("All fields are required.");
				f.elements[0].focus();
				return false;
		}
		status = "Working. Please wait.";
		if ( document.all ) f.SUBMIT.disabled = true;
		return true;
	}
</SCRIPT>

</HEAD>
<BODY onload="OnLoad()">
<H1>User/Host Certificates</H1>
<a href="../../">Home</a>
<hr>


<% if ( !caCertsFound) { %>
	<P>CA Certificates must be installed first</p>
		<UL>
			<LI><%=GSIProperties._defCACert%></LI>
			<LI><%=GSIProperties._defCAKey%></LI>
		</UL>
	
<% } else if ( action == null ) { %>

	<% if ( msg != null ) { %>
		<P><FONT color="blue"><b><%=msg%></b></FONT></P>
	<% } %>

	<FIELDSET>
		<LEGEND>CA Information</LEGEND>
		<TABLE>
			<TR>
				<TD><b>Issuer</b></TD>
				<td><%=caCert.getIssuerDN()%></td>
			</TR>
			<TR>
				<TD><b>Subject</b></TD>
				<td><%=caCert.getSubjectDN()%></td>
			</TR>
			<TR>
				<TD><b>Signature Algorithm</b></TD>
				<td><%=caCert.getSigAlgName()%></td>
			</TR>
			<% if ( ! caKeyEncrypted ) { %>
			<TR>
				<TD><b>CA Key</b></TD>
				<td><img src="../../img/information.gif"> CA key is not encrypted</td>
			</TR>
			<%} %>
		</TABLE>
	</FIELDSET>

	<P>All fields are required. Output will be PEM encoded. (Save output files in your certs folder)</P>

	<FORM method="POST" name="F1" action="userhost.jsp?action=create" onsubmit="return OnSubmit()">
		<TABLE align="left">
			<TR>
				<TD>Common Name</TD>
				<TD><INPUT name="CN" size="30" maxlength="50"> </TD>
			</TR>
			<TR>
				<TD>Organization Unit</TD>
				<TD><INPUT name="OU" size="30" maxlength="50"> </TD>
			</TR>
			<TR>
				<TD>Organization</TD>
				<TD><INPUT name="O" size="30" maxlength="50"> </TD>
			</TR>
			<TR>
				<TD>City/Locality</TD>
				<TD><INPUT name="L" size="30" maxlength="50"> </TD>
			</TR>
			<TR>
				<TD>Country (2 char)</TD>
				<TD><INPUT name="C" size="3" maxlength="2" value="US"> </TD>
			</TR>
			<TR>
				<TD colspan="2"><hr></TD>
			</TR>
			<TR>
				<TD colspan="2"><b>Crypto Options<b></TD>
			</TR>
			<TR>
				<TD colspan="2"><font color=blue>Note: leave "Cert Password" blank for an unencrypted key (Useful in Host/LDAP certs).</font></TD>
			</TR>
			<TR>
				<TD colspan="2">&nbsp;</TD>
			</TR>
			<TR>
				<TD>Strength</TD>
				<TD>
					<SELECT name="ST">
						<OPTION value="512">512</OPTION>
						<OPTION value="1024">1024</OPTION>
					</SELECT>
				</TD>
			</TR>
			<TR>
				<TD>Lifetime (months)</TD>
				<TD>
					<SELECT name="MONTHS">
						<OPTION value="12">12</OPTION>
						<OPTION value="24">24</OPTION>
						<OPTION value="36">36</OPTION>
					</SELECT>
				</TD>
			</TR>
			<TR>
				<TD>Cert Password </TD>
				<TD><INPUT type="password" name="PWD" size="30" maxlength="20"> </TD>
			</TR>
			<% if (  caKeyEncrypted ) { %>
			<TR>
				<TD>CA Password (for signature)</TD>
				<TD><INPUT type="password" name="CAPWD" size="30" maxlength="20"> </TD>
			</TR>
			<% } %>
			<TR>
				<TD colspan="2" align="right"><INPUT name="SUBMIT" type="submit" value="Submit"></TD>
			</TR>
		</TABLE>


	</FORM>
<% } else if ( ! _error ) { %>

<P>Here is your Certificate</P>
	<TABLE>
		<tr>
		<td><b>Subject</b></td><td><%=cert.getSubjectDN()%> </td>
		</tr>
		<tr>
		<td><b>Issuer</b></td><td><%=cert.getIssuerDN()%> </td>
		</tr>
	</TABLE>
	
	<P>
	<FORM name="F1">
		<TEXTAREA rows="10" style="width:100%"><%=outCert.toString()%> </TEXTAREA>
	
		<P>Private Key</P>
		<TEXTAREA rows="10" style="width:100%"><%=keyPEM%> </TEXTAREA>
	</FORM>
	
<% } %>	

</BODY>
</HTML>
