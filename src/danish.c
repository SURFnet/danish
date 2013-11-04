/*
 * Copyright (c) 2013 SURFnet bv
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of SURFnet bv nor the names of its contributors 
 *    may be used to endorse or promote products derived from this 
 *    software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "config.h"
#include "cert.h"

void show_usage(void)
{
	printf("usage:\n");
	printf("\tdanish -n <hostname> -c <certfile> [-e] [-m] [-r <certreq>]\n");
	printf("\t       -p <port> -P <tcp | udp> [-u <0-3>] [-s <0,1>] [-m <1,2>]\n");
	printf("\t       [-t] [-q]\n");
	printf("\n");
	printf("\tdanish -h\n");
	printf("\n");
	printf("\tdanish -v\n");
	printf("\n");
	printf("\t-n <hostname> generate TLSA record for <hostname>\n");
	printf("\t-c <certfile> use the X.509 certificate in <certfile>\n");
	printf("\t-e            check certificate expiration\n");
	printf("\t-M            check if the certificate matches <hostname>\n");
	printf("\t-r <reqfile>  check if the certificate matches the certificate\n");
	printf("\t              request in <reqfile>\n");
	printf("\t-p            specify the TLS service port\n");
	printf("\t-P            specify the protocol (udp or tcp)\n");
	printf("\t-u <0-3>      RFC 6698 certificate usage; can be:\n");
	printf("\t                  0 - CA constraint\n");
	printf("\t                  1 - certificate constraint with PKIX validation\n");
	printf("\t                      (default)\n");
	printf("\t                  2 - trust anchor\n");
	printf("\t                  3 - self-signed certificate\n");
	printf("\t-s <0,1>      RFC 6698 selector; can be:\n");
	printf("\t                  0 - full certificate (default)\n");
	printf("\t                  1 - subjectPublicKeyInfo\n");
	printf("\t-m <1,2>      RFC 6698 matching type; can be:\n");
	printf("\t                  0 - unsupported by danish\n");
	printf("\t                  1 - SHA256 hash (default)\n");
	printf("\t                  2 - SHA512 hash\n");
	printf("\t-t            Use TYPE52 as record type instead of TLSA\n");
	printf("\t-q            be quiet (suppress output from the checks that are\n");
	printf("\t              executed and only output the TLSA record)\n");
	printf("\n");
	printf("\t-h            print this help message\n");
	printf("\n");
	printf("\t-v            print version information\n");
}

void show_version(void)
{
	printf("sigvalcheck version %s\n", VERSION);
}

int main(int argc, char* argv[])
{
	char* hostname	= NULL;
	char* certfile	= NULL;
	char* reqfile	= NULL;
	int check_exp	= 0;
	int match_name	= 0;
	int usage		= 1;
	int selector	= 0;
	int match_type	= 1;
	int c			= 0;
	int par_error   = 0;
	char* proto[2]	= { "tcp", "udp" };
	int proto_sel	= -1;
	int port		= 0;
	int rv			= 0;
	int use_type52	= 0;
	int be_quiet	= 0;
	
	cert_ctx 		crt = { 0 };
	req_ctx			req = { 0 };
	
	while ((c = getopt(argc, argv, "n:c:eMr:u:s:m:p:P:tqhv")) != -1)
	{
		switch(c)
		{
		case 'h':
			show_usage();
			return 0;
		case 'v':
			show_version();
			return 0;
		case 'n':
			hostname = strdup(optarg);
			break;
		case 'c':
			certfile = strdup(optarg);
			break;
		case 'r':
			reqfile = strdup(optarg);
			break;
		case 'e':
			check_exp = 1;
			break;
		case 'M':
			match_name = 1;
			break;
		case 'u':
			usage = atoi(optarg);
			
			if ((usage < 0) || (usage > 3))
			{
				fprintf(stderr, "Invalid certificate usage (%d) specified\n", usage);
				
				par_error = 1;
			}
			break;
		case 's':
			selector = atoi(optarg);
			
			if ((selector < 0) || (selector > 1))
			{
				fprintf(stderr, "Invalid selector (%d) specified\n", selector);
				
				par_error = 1;
			}
			break;
		case 'm':
			match_type = atoi(optarg);
			
			if ((match_type < 1) || (match_type > 2))
			{
				fprintf(stderr, "Invalid match type (%d) specified\n", match_type);
				
				par_error = 1;
			}
			break;
		case 'p':
			port = atoi(optarg);
			break;
		case 'P':
			if (!strcasecmp(optarg, "tcp"))
			{
				proto_sel = 0;
			}
			else if (!strcasecmp(optarg, "udp"))
			{
				proto_sel = 1;
			}
			else
			{
				fprintf(stderr, "Invalid protocol %s specified!\n", optarg);
				
				par_error = 1;
			}
			break;
		case 't':
			use_type52 = 1;
			break;
		case 'q':
			be_quiet = 1;
			break;
		default:
			break;
		}
	}
	
	/* Check parameters */
	if (!hostname)
	{
		fprintf(stderr, "Mandatory parameter -n <hostname> missing!\n\n");
		
		par_error = 1;
	}
	
	if (!certfile)
	{
		fprintf(stderr, "Mandatory parameter -c <certfile> missing!\n\n");
		
		par_error = 1;
	}
	
	if ((usage < 0) || (usage > 3))
	{
		fprintf(stderr, "Unknown DANE certificate usage %d!\n\n", usage);
		
		par_error = 1;
	}
	
	if ((selector < 0) || (selector > 1))
	{
		fprintf(stderr, "Unknown DANE certificate selector %d!\n\n", selector);
		
		par_error = 1;
	}
	
	if ((match_type < 1) || (match_type > 2))
	{
		fprintf(stderr, "Unknown or unsupported DANE matching type %d!\n\n", match_type);
		
		par_error = 1;
	}
	
	if ((port < 1) || (port > 65535))
	{
		fprintf(stderr, "Invalid (%d) or no port specified!\n\n", port);
		
		par_error = 1;
	}
	
	if (proto_sel == -1)
	{
		fprintf(stderr, "No protocol specified!\n\n");
		
		par_error = 1;
	}
	
	if (par_error)
	{
		show_usage();
		
		free(hostname);
		free(certfile);
		free(reqfile);
		
		return -1;
	}
	
	/* Process the request */
	
	/* Load the certificate */
	init_cert_ctx(&crt);
	
	if (read_cert(&crt, certfile) != 0)
	{
		fprintf(stderr, "Failed to read X.509 certificate from %s\n", certfile);
		
		return -1;
	}
	
	/* Load the certificate request if necessary */
	init_req_ctx(&req);
	
	if (reqfile)
	{
		if (read_req(&req, reqfile) != 0)
		{
			fprintf(stderr, "Failed to read CSR from %s\n", reqfile);
			
			return -1;
		}
	}
	
	/* Output the TLSA record */
	if (use_type52)
	{
		printf("_%d._%s.%s.\tIN\tTYPE52\t\\# %d %02X%02X%02X%s\n",
			port,
			proto[proto_sel],
			hostname,
			(match_type == 1) ? 35 : 67,
			usage,
			selector,
			match_type,
			(match_type == 1) ? cert_get_sha256_hash(&crt, selector) :
			                    cert_get_sha512_hash(&crt, selector));
	}
	else
	{
		printf("_%d._%s.%s.\tIN\tTLSA\t%d %d %d %s\n",
			port,
			proto[proto_sel],
			hostname,
			usage,
			selector,
			match_type,
			(match_type == 1) ? cert_get_sha256_hash(&crt, selector) :
			                    cert_get_sha512_hash(&crt, selector));
	}
		                    
	/* Perform expiration check if requested */
	if (check_exp)
	{
		rv |= cert_is_valid(&crt, be_quiet);
	}
	
	/* Perform name match check if requested */
	if (match_name)
	{
		rv |= cert_matches_name(&crt, hostname, be_quiet);
	}
	
	if (reqfile != NULL)
	{
		/* Perform CSR match if requested */
		rv |= cert_matches_req(&crt, &req, be_quiet);
	}
	
	free_cert_ctx(&crt);
	free_req_ctx(&req);
	
	free(hostname);
	free(certfile);
	free(reqfile);

	return rv;
}

