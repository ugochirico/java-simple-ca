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



<%@page import="org.globus.grid.gsi.GSIProperties"%><HTML>
<HEAD>

<%@ page 
	language="java"
	contentType="text/html; charset=ISO-8859-1"
	import="org.globus.grid.cert.*"
%>

<META http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<META name="GENERATOR" content="IBM WebSphere Studio">
<META http-equiv="Content-Style-Type" content="text/css">
<LINK href="../../theme/Master.css" rel="stylesheet"
	type="text/css">
<TITLE>Certificate Request</TITLE>

<SCRIPT language="Javascript">
	function OnLoad() {
		document.F1.elements[0].focus();
		status = "Done.";
	}
	
	function OnSubmit() {
		var f = document.F1;
		if (  !f.CN.value || !f.OU.value || !f.O.value || !f.PWD.value 
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
<%!
	static {
		GSIProperties.installBCProvider();
	}
%>
<%

	String action 	= request.getParameter("action");
	String msg 		= request.getParameter("msg");
	CertGenerator gen = null;
	
	boolean _error 	= false;
	
	if ( action != null ) {
		try {
			String cn = request.getParameter("CN");
			String ou = request.getParameter("OU");
			String o0 = request.getParameter("O");
			String L = request.getParameter("L");
			String C = request.getParameter("C");
			String pwd 	= request.getParameter("PWD");
			int bits 	= Integer.parseInt(request.getParameter("ST"));
			
			String subject = "C=" + C + ",L=" + L + ",O=" + o0 + ",OU=" + ou + ",CN=" + cn; 
			
			gen = new CertGenerator(subject);
			gen.createCertRequest(bits, pwd);
			
		}
		catch (Exception e0 ) {
			GSIProperties.dumpJCEproviders();
			
			e0.printStackTrace();
			
			msg 	= e0.toString().replace(' ','+');
			_error 	= true;
			response.sendRedirect("certrq.jsp?msg=" + msg);
		}
	}
%>
<BODY onload="OnLoad()">
<h2>Certificate Request (RSA)</h2>
<a href="../../">Home</a>
<hr>
<P>All fields are required. Output will be PEM encoded. (Save these files in your certs folder)</P>

<% if ( msg != null ) { %>
	<P><b><%=msg%></b></P>
<% } %>

<% if ( action == null ) { %>
	<FORM method="POST" name="F1" action="certrq.jsp?action=create" onsubmit="return OnSubmit()">
		<TABLE align="center" width="80%">
			<TR>
				<TD>Common Name</TD>
				<TD><INPUT name="CN" size="40" maxlength="100"> </TD>
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
				<TD>Password</TD>
				<TD><INPUT type="password" name="PWD" size="30" maxlength="20"> </TD>
			</TR>
			<TR>
				<TD colspan="2" align="right"><INPUT name="SUBMIT" type="submit" value="Submit"></TD>
			</TR>
		</TABLE>


	</FORM>
<% } else if ( ! _error ) { %>

<P>Here is your Certificate request</P>
<FORM name="F1"> 
	Subject: <%=gen.getSubject().getNameString()%>
	<P>
	<TEXTAREA rows="10" style="width:100%"><%=gen.getCertRQPEM()%> </TEXTAREA>

<P>Private Key</P>
	<TEXTAREA rows="10" style="width:100%"><%=gen.getKeyPEM()%> </TEXTAREA>
</FORM>
<% } %>	
</BODY>
</HTML>
