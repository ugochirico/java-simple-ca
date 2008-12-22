
Java Certificate Services 
=========================

1. Introduction

   The Java Certificate Services provides an implementation of the simple
   ca services in java. It contains some of the functionality of the
   openssl program. It also includes a handly web application that can
   be access from anybody in your intranet to request certificates 
   and sign them

2. Installation

   2.1 Requirements

       2.2.1 Java

	     The Java Certificate Services requires J2SE version 1.3.1 or higher.
             It is assumed that Java is properly installed and that the Java bin/ directory 
             has been included in the user's path.


       2.2.3 JCS_ROOT variable

	     The JCS_ROOT environment variable must be set
	     before any of the scripts included with the Java Certificate Services
	     will work. This variable points to where the Java Certificate Services 
             is installed. (For example: C:\jCertServices-1.1)
	   
	2.2.4 Webtool Tomcat Deployment 
	
		The webtool provides the same functionality as the command line one. To deploy it in tomcat 4.1.2.27 use the following command from the JCS_INTALL_PATH folder:

			1. Type ant -Dtomcat.dir=<tomcat root> deployTomcat 
			2. Replace tomcat.dir with your tomcat root install folder 	   
			
   2.3 Configuration

       2.3.1 Prerequisites
  
	     This software uses modified versions of the Bouncy Castle provider
	     and Criptix 3.2. This code has been modiefied to work under an 
	     application such as WebSphere. This code has been fully tested
	     with Websphere AppServer 4.x/5.x.
	     Changes to the JCE providers allow to bypass imcompatibilities
	     of multiple JCE providers runing on an application server.
	     
       2.3.2 Setup
		 Unzip the binary distribution on your hard disk and create
		 the environment variable JCS_ROOT to point to the install
		 folder

    2.4. Samples
    	
	USAGE: jcs [service] [options]
	Service values are: 
		req  - to create a cert request
		ca  - to sign a request
	
	req (Certificate Request) options are:
	
		-out	(Required) [path to the request PEM]
		-keyout	(Required) [path to the private key PEM]
		-pwd	(Required) [passphraseused to encrypt the key]
		-dn	(Optional) [Certificate identity. e.g: C=US,O=Grid,OU=OGSA,CN=John Doe]
		-debug	(Optional) [display debug msgs]
	
	ca (Certificate signature) options are:
	
		-rq	(Required) [path to the request PEM file to be signed]
		-out	(Required) [path to the signed certificate e.g $HOME/.globus/usercert.ppem]
		-cacert	(optional) [path to the CA certificate PEM]
		-cakey	(optional) [path to the CA private key PEM file]
		-capwd	(optional) [CA passphrase]
	
	Samples:
	
	Creating a Certificate Request:
		jcs -keyout $HOME/.globus/userkey.pem -out $HOME/.gobus/user-rq.pem -pwd test -debug 
	
	Certificate signature:
		jcs ca -rq c:\temp\rq.pem -out c:\temp\usercert.pem -capwd globus -debug

	Display usage:
		jcs or jcs help


3. Features

   What's new in version 1.1?

   o Command line tool to create cert requests and private keys
   o Command line tool to sign certificate request
   o Web Application tool for the above functionality
   o Creation of CA(self-signed) certificates

   Using the Web tool

   o Under construction


4. More Information

   4.1 Bugs, suggestions, contributions

       No support is provided for this software. Feel free to modify it
       at your leisure.


   4.2 Contacts

       Vladimir Silva       Developer              vsilva@us.ibm.com
       Jarek Gawor          Developer              gawor@mcs.anl.gov
       Gregor von Laszewski Supervisor/Developer   gregor@mcs.anl.gov
  
5. Globus website

	http://www.globus.org/