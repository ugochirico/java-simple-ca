<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<!--
*****************************************************************
* Java Certificate Services
* A web tool implementation for the creation and manipulation of:
* Author: Vladimir Silva
*
*	1) X509 Certificate requests,
*	2) User or Host certs and private keys
* 	3) Self-signed certs
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
			org.globus.grid.gsi.GSIProperties,
			java.io.*,java.security.cert.X509Certificate"

%>
<META http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<META name="GENERATOR" content="IBM WebSphere Studio">
<META http-equiv="Content-Style-Type" content="text/css">
<LINK href="../../theme/Master.css" rel="stylesheet"
	type="text/css">
<TITLE>CA Certificate</TITLE>

<SCRIPT language="Javascript">
	function OnLoad() {
		if ( document.F1 && document.F1.CN)
			document.F1.CN.focus();
		status = "Done.";
	}
	
	function OnSubmit() {
		var f = document.F1;
		if (  !f.CN.value || !f.OU.value || !f.O.value || !f.PWD.value 
				|| !f.C.value || !f.L.value
			) 
		{
				alert("All fields are required.");
				f.CN.focus();
				return false;
		}
		status = "Working. Please wait.";
		
		if ( document.all ) f.SUBMIT.disabled = true;
		return true;
	}
</SCRIPT>
<%
	OutputStream outKey = new ByteArrayOutputStream();
	OutputStream outCert = new ByteArrayOutputStream();
	X509Certificate cert = null;

	String action 	= request.getParameter("action");
	String msg 		= request.getParameter("msg");
	String setup 	= ( request.getParameter("setup") != null ) ? request.getParameter("setup") : "";

	// Used for redirection, if a fatal error occurs
	boolean _error	= false;	
		
	if ( action != null ) {

		try {
			String cn = request.getParameter("CN");
			String ou = request.getParameter("OU");
			String o0 = request.getParameter("O");
			String L = request.getParameter("L");
			String C = request.getParameter("C");
			String pwd 	= request.getParameter("PWD");
			int bits 	= Integer.parseInt(request.getParameter("ST"));
			int months 	= Integer.parseInt(request.getParameter("MONTHS"));
			
			String subject = "C=" + C + ",L=" + L + ",O=" + o0 + ",OU=" + ou + ",CN=" + cn; // "LOC=" + lo + 
			//System.out.println("Subject:" + subject + " st=" + bits + " pwd=" + pwd);
			
			// setup CA certs			
			if ( setup != null && !setup.equals("") ) {
				// install CA certs
				System.out.println("Installing ca certs...");
				
				// Create CA cert + key (unencrypted)
				FileOutputStream outCAKey = new FileOutputStream(GSIProperties._defCAKey);
				FileOutputStream outCACert = new FileOutputStream(GSIProperties._defCACert);
				
				try {
					// key will be saved here				
					cert = CertGenerator.createX509Cert("RSA", 1024 , subject, subject, months, outCAKey, "SHA1WithRSAEncryption", pwd);
					
					// save cert
					CertManager.saveX509Cert(cert, outCACert); 
				}
				catch (Exception e) {
					new File(GSIProperties._defCAKey).delete();
					new File(GSIProperties._defCACert).delete();
				}
				
				// redirect back to home
				outCACert.close(); outCAKey.close();
				response.sendRedirect("../../main.jsp?msg=CA+installed.");
			}

			// create self-signed certs
			cert = CertGenerator.createX509Cert("RSA", bits , subject, subject, months, outKey, "SHA1WithRSAEncryption", pwd);
			CertManager.saveX509Cert(cert, outCert);
			
			outCert.close();
			outKey.close();
		}
		catch (Exception e0 ) {
			//e0.printStackTrace();
			
			_error	= true;
			msg 	= e0.getMessage().replace(' ','+');
			response.sendRedirect("self-sign.jsp?msg=" + msg);
		}
	}
%>

</HEAD>
<BODY onload="OnLoad()">
<H1>CA Certificate</H1>
<a href="../../">Home</a>
<hr>

<% if ( msg != null ) { %>
	<P><font color=blue><%=msg%></font></P>
<% } %>

<P>All fields are required. Output will be PEM encoded. (Save these files in your certs folder)</P>


<% if ( action == null ) { %>
	<FORM method="POST" name="F1"  action="self-sign.jsp?action=create" onsubmit="return OnSubmit()">
		<INPUT type="hidden" name="setup" value="<%=setup%>">
		
		<TABLE align="center" width="80%">
			<TR>
				<TD>Common Name</TD>
				<TD><INPUT name="CN" size="40" maxlength="50"> </TD>
			</TR>
			<TR>
				<TD>Organization Unit</TD>
				<TD><INPUT name="OU" size="40" maxlength="50"> </TD>
			</TR>
			<TR>
				<TD>Organization</TD>
				<TD><INPUT name="O" size="40" maxlength="50"> </TD>
			</TR>
			<TR>
				<TD>City/Locality</TD>
				<TD><INPUT name="L" size="40" maxlength="50"> </TD>
			</TR>
			<TR>
				<TD>Country (2 char)</TD>
				<TD><INPUT name="C" size="3" maxlength="2" value="US"> </TD>
			</TR>
			<TR>
				<TD colspan="2"><hr></TD>
			</TR>
			<TR>
				<TD colspan="2">Crypto Options</TD>
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
			<!-- Not supported -->
			<!--  
			<TR>
				<TD>Key Password</TD>
				<TD><INPUT type="password" name="PWD" size="30" maxlength="20"> </TD>
			</TR>
			-->
			<TR>
				<TD colspan="2" align="right"><INPUT name="SUBMIT" type="submit" value="Submit"></TD>
			</TR>
		</TABLE>


	</FORM>
<% } else if ( ! _error ) { %>

<FORM name="F1">
<P>Here is your CA Certificate</P>
	<b>Subject:</b> <%=cert.getSubjectDN().toString()%>
	<br>
	<b>Issuer:</b> <%=cert.getIssuerDN().toString()%>
	<P>
	<TEXTAREA rows="10" style="width:100%"><%=outCert.toString()%> </TEXTAREA>

<P>Private Key</P>
	<TEXTAREA rows="10" style="width:100%"><%=outKey.toString()%> </TEXTAREA>
</FORM>

<% } %>	


</BODY>
</HTML>
