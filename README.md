Copyright (c) 2013-2016 SURFnet bv

All rights reserved. This software is distributed under a BSD-style
license. For more information, see LICENSE

1. INTRODUCTION
===============

DNS-based Authentication of Named Entities (DANE) is a mechanism that
allows the Domain Name System (DNS) to be used to furnish authenticated
information about hosts. RFC 6698 specifies the DANE TLSA record type
that can be used to store information about relating to the certificate
used to secure TLS connections to a specific service on a host.

To make optimal use of this new facility, the danish tool helps users
by generating TLSA or SMIMEA records and by checking certain properties of
certificates. The tool was specifically designed to be integrated into
an automated DNS zone generation chain. Apart from being able to
generate TLSA and SMIMEA records from X.509 certificates danish is also 
able to:

 - Check if a certificate has expired
 - Check if the hostname for which a TLSA record is created matches
   with the certificate
 - Check if the e-mail address for which an SMIMEA record is created
   matches with the certificate
 - Check if a certificate matches with the certificate signing request
   (CSR) used to to request the certificate from a certificate
   authority

2. PREREQUISITES
================

To build the program:

 - POSIX compliant build system
 - OpenSSL (>= 0.9.8), the Open Source toolkit for SSL/TLS

3. BUILDING
===========

To build the danish tool, execute the following commands:

    ./autogen.sh
    ./configure
    make

4. INSTALLING
=============

To install the library as a regular user, run:

    sudo make install

If you are root (administrative user), run:

    make install

5. USING THE TOOL
=================

For more information on the danish tool, please consult the manual
page by executing:

	man 1 danish
	
6. INTEGRATING THE TOOL WITH YOUR SCRIPTS
=========================================

The danish tool was designed with integration in a DNS zone publication
tool chain in mind. To this end, it can run certain checks on the
certificates for which it generates TLSA records. Depending on which
checks were run and the outcome of those checks, danish will set its 
exit status. This can be used to make decisions about whether or not to
include a TLSA record in a DNS zone. The danish tool supports 4 checks
listed in section 1 of this README document.

Depending on the outcome of these checks danish may return a combination
of one or more of the following exit status values:

 - CERT_NOT_VALID 	(0x00000001)
   This exit status is set if the certificate has expired
 - CERT_NAME_MISMATCH 	(0x00000002)
   This exit status is set if the hostname for which the TLSA record
   is created does not match any of the names specified in the subject
   or subjectAltName of the certificate
 - CERT_CSR_MISMATCH	(0x00000004)
   This exit status is set if the certificate does not match the
   certificate signing request specified on the command-line
 - CERT_ADDR_MISMATCH	(0x00000008)
   This exit status if set if the specified e-mail address for which the
   SMIMEA record is created does not match any of the e-mail addresses
   in the subject or subjectAltName of the certificate
 - CERT_FATAL_ERROR	(0x80000000)
   This exit status is set if danish encountered a blocking issue while
   checking the certificate or generating the TLSA record
   
Multiple exit statuses may be combined using a logical OR operation;
thus, if a certificate has expired and the certificate does not match
the certificate signing request danish will return:

	CERT_NOT_VALID | CERT_CSR_MISMATCH = 0x00000005

7. CONTACT
==========

Questions/remarks/suggestions/praise regarding this tool can be sent to:

Roland van Rijswijk-Deij <roland.vanrijswijk@surfnet.nl>
