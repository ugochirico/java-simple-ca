<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<HTML>
<HEAD>
<%@ page 
	language="java"
	contentType="text/html; charset=ISO-8859-1"
	import="org.globus.grid.cert.*"
%>

<%
	String msg 		= request.getParameter("msg");
	
	// create $HOME/.globus & $HOME/.globus/[CA_DIR]
	org.globus.grid.gsi.GSIProperties.initCertLocations();
	
	if ( !CertManager.localCACertsInstalled() ) {
		response.sendRedirect("jsp/cert/self-sign.jsp?setup=yes&msg=CA+setup:root+certificates+must+be+created+first+for+signature.");
	}
%>

<META http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<META name="GENERATOR" content="IBM WebSphere Studio">
<META http-equiv="Content-Style-Type" content="text/css">
<LINK href="theme/Master.css" rel="stylesheet" type="text/css">
<TITLE>Java Certificate Services</TITLE>
</HEAD>
<BODY>
<img src="img/cert.gif" align="right"><H2>Java Certificate Services</H2>
<HR>

<% if ( msg != null ) { %>
	<P><font color=blue><%=msg%></font></P>
<% } %>

	<UL>
		<LI><A href="jsp/cert/certrq.jsp">Certificate Request</A>  
			<BLOCKQUOTE>Create a downloadable certificate request and private key</BLOCKQUOTE> 
			</LI>
		<LI><A href="jsp/cert/sign.jsp">Sign a Certificate Request</A>  
			<BLOCKQUOTE>Upload a request for signature. </BLOCKQUOTE>
		</LI>
		<LI><A href="jsp/cert/userhost.jsp">User/Host Certificates</A>  
			<BLOCKQUOTE>Create a user or host certificates and private key.</BLOCKQUOTE>
		</LI>
		<LI><A href="jsp/cert/self-sign.jsp">Self-signed certificate and private key</A>  
			<BLOCKQUOTE>Create a self-signed or CA certificate and private key</BLOCKQUOTE>
		</LI>

	</UL>
</BODY>
</HTML>
