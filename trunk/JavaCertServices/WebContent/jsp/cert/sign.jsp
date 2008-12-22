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
import="org.globus.grid.gsi.GSIProperties,
		org.globus.grid.cert.*,
		com.jspsmart.upload.*,
		java.io.InputStream,java.io.FileInputStream,
		java.io.ByteArrayInputStream,java.io.ByteArrayOutputStream"
%>
<%! 
		String caCertPath = GSIProperties._defCACert;
		String caKeyPath = GSIProperties._defCAKey;

%>
<META http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<META name="GENERATOR" content="IBM WebSphere Studio">
<META http-equiv="Content-Style-Type" content="text/css">
<LINK href="../../theme/Master.css" rel="stylesheet"
	type="text/css">
<TITLE>Sign a cert request</TITLE>


<%
	String action 	= request.getParameter("action");
	String msg 		= request.getParameter("msg");
	String signedCert = null;
		
	java.security.cert.X509Certificate caCert = null;
	boolean caCertFound 	= true; 
	boolean caKeyEncrypted 	= false;

	try {
		if ( caCertPath != null && action == null ) {
			try {
				caKeyEncrypted 	= CertGenerator.isKeyEncrypted(new FileInputStream(caKeyPath));
				caCert 			= org.globus.gsi.CertUtil.loadCertificate(caCertPath);
			}
			catch (Exception e ) {
				caCertFound = false;
			}
		}
		if ( action != null && action.equals("create") ) 
		{
			/* JSP Smart upload*/
			SmartUpload mySmartUpload = new SmartUpload();
			
			// Initialization
			mySmartUpload.initialize(config,request,response);
			
			// Upload
			mySmartUpload.upload();
			
			// get  file
			File rqFile = mySmartUpload.getFiles().getFile(0);
			
			String rqPEM = rqFile.getContentString();
			String caPwd = mySmartUpload.getRequest().getParameter("CAPWD");
			
			java.io.InputStream inRq = new ByteArrayInputStream(rqPEM.getBytes());
			
			// sign rq
			CertSigner signer = new CertSigner(
				inRq, 
				new FileInputStream(caCertPath), 
				new FileInputStream(caKeyPath) , 
				caPwd);
			
			// save to OS
			ByteArrayOutputStream rqOs = new ByteArrayOutputStream();
			signer.save(rqOs);
			
			signedCert = rqOs.toString();
			msg = "Done.";
		}
		//else
		//	msg = null;
	}
	catch (Exception e0 ) {
		e0.printStackTrace();
		msg = e0.getMessage();
		response.sendRedirect("sign.jsp?action=init&msg=" + msg);
	}
/*
	catch (InternalError e1 ) {
		//e1.printStackTrace();
		msg = e1.getMessage();
		response.sendRedirect("sign.jsp?action=init&msg=" + msg);
	}
*/
%>
<SCRIPT language="Javascript">
	function OnLoad() {
		if (document.F1) document.F1.RQ.focus();
		status = "Done.";
	}
	
	function OnSubmit() {
		var f = document.F1;
		var caKeyEnc = <%=caKeyEncrypted%>;
		
		if (  !f.RQ.value  || ( caKeyEnc && !f.CAPWD.value) ) {
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
<h2>Certificate Signature</h2>
<a href="../../">Home</a>
<hr>

<% if ( msg != null ) { %>
	<P><font color="blue"><%=msg%></font></P>
<% } %>

<% if ( caCert != null && signedCert == null) { %>
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
			<TR>
				<TD><b>Serial Number</b></TD>
				<td><%=caCert.getSerialNumber()%></td>
			</TR>
			<% if ( ! caKeyEncrypted ) { %>
			<TR>
				<TD><b>CA Key</b></TD>
				<td><img src="../../img/information.gif"> CA key is not encrypted</td>
			</TR>
			<%} %>
		</TABLE>
	</FIELDSET>

<P>
<h3>Request</h3>
<P>Enter the full path to your cert request file (PEM encoded)</P>
<hr>
	<FORM method="post" name="F1" action="sign.jsp?action=create" onsubmit="return OnSubmit()" ENCTYPE="multipart/form-data">
		<TABLE>
			<TR>
				<TD>Certificate request</TD>
				<TD>
			   		<INPUT TYPE="FILE" NAME="RQ" SIZE="60" maxlength="50"><BR>
				</TD>
			</TR>
			<% if (  caKeyEncrypted ) { %>
			<TR>
				<TD>CA password</TD>
				<td><INPUT type="password" name="CAPWD" size="30" maxlength="20"> </td>
			</TR>
			<% } %>
		</table>	
		<INPUT type="submit" value="Submit" name="SUBMIT">
	</FORM>

<% } else if ( signedCert != null ) { %>

	<P>Signed Certificate: Save this file to you certificates folder</P>
	
	<TEXTAREA name="RQ" rows="20" style="width:100%"><%=signedCert%></TEXTAREA>

<% } else  if ( !caCertFound) { %>
	<b>CA Certificates must be installed first.</b>
	<UL>
		<li><%=caCertPath%>
		<li><%=caKeyPath%>
	</UL>
<% } %>

</BODY>
</HTML>
