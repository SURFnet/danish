/*
 * Copyright (c) 2013-2016 SURFnet bv
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

#include "config.h"
#include "cert.h"
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/asn1.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <ctype.h>

void init_cert_ctx(cert_ctx* ctx)
{
	assert(ctx != NULL);
	
	memset(ctx, 0, sizeof(cert_ctx));
}

void init_req_ctx(req_ctx* ctx)
{
	assert(ctx != NULL);
	
	memset(ctx, 0, sizeof(req_ctx));
}

void free_cert_ctx(cert_ctx* ctx)
{
	assert(ctx != NULL);
	
	if (ctx && ctx->ossl_crt)
	{
		X509_free(ctx->ossl_crt);
		ctx->ossl_crt = NULL;
	}
}

void free_req_ctx(req_ctx* ctx)
{
	assert(ctx != NULL);
	
	if (ctx && ctx->ossl_req)
	{
		X509_REQ_free(ctx->ossl_req);
		ctx->ossl_req = NULL;
	}
}

int read_cert(cert_ctx* ctx, const char* file_name)
{
	assert(ctx != NULL);
	assert(file_name != NULL);
	
	FILE* certfile = fopen(file_name, "r");
	
	if (!certfile)
	{
		return -1;
	}
	
	/* Attempt to read DER encoding of cert */
	ctx->ossl_crt = d2i_X509_fp(certfile, NULL);
	
	if (ctx->ossl_crt == NULL)
	{
		/* That failed, try PEM encoding */
		rewind(certfile);
		
		ctx->ossl_crt = PEM_read_X509(certfile, NULL, NULL, NULL);
	}
	
	fclose(certfile);
	
	if (ctx->ossl_crt == NULL)
	{
		return -1;
	}
	
	return 0;
}

int read_req(req_ctx* ctx, const char* file_name)
{
	assert(ctx != NULL);
	assert(file_name != NULL);
	
	FILE* reqfile = fopen(file_name, "r");
	
	if (!reqfile)
	{
		return -1;
	}
	
	/* Attempt to read DER encoding of request */
	ctx->ossl_req = d2i_X509_REQ_fp(reqfile, NULL);
	
	if (ctx->ossl_req == NULL)
	{
		/* That failed, try PEM encoding */
		rewind(reqfile);
		
		ctx->ossl_req = PEM_read_X509_REQ(reqfile, NULL, NULL, NULL);
	}
	
	fclose(reqfile);
	
	if (ctx->ossl_req == NULL)
	{
		return -1;
	}
	
	return 0;
}

void get_hash_input(const cert_ctx* crt, const int selector, unsigned char** buf, size_t* size)
{
	assert(buf != NULL);
	assert(size != NULL);
	
	if (selector == 0)	/* Full certificate */
	{
		*size = i2d_X509(crt->ossl_crt, NULL);
		
		*buf = OPENSSL_malloc(*size);
		
		unsigned char* write_buf = *buf;
		
		*size = i2d_X509(crt->ossl_crt, &write_buf);
	}
	else /* subjectPublicKeyInfo */
	{
		*size = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(crt->ossl_crt), NULL);
		
		*buf = OPENSSL_malloc(*size);
		
		unsigned char* write_buf = *buf;
		
		*size = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(crt->ossl_crt), &write_buf);
	}
	
}

char* cert_get_der_hexstr(const cert_ctx* ctx, const int selector)
{
	char*		rv		= NULL;
	size_t		cert_data_len	= 0;
	unsigned char*	cert_data	= NULL;
	size_t		i		= 0;

	/* Get the certificate or subjectPublicKeyInfo DER encoding */
	get_hash_input(ctx, selector, &cert_data, &cert_data_len);

	rv = (char*) malloc(((cert_data_len * 2) + 1 ) * sizeof(char));

	for (i = 0; i < cert_data_len; i++)
	{
		sprintf(&rv[i*2], "%02X", cert_data[i]);
	}

	OPENSSL_free(cert_data);

	return rv;
}

char* cert_get_sha256_hash(const cert_ctx* ctx, const int selector)
{
	assert(ctx != NULL);
	
	unsigned char* 	hash_data	= NULL;
	size_t		hash_data_len	= 0;
	char*		hash_str	= (char*) malloc(65 * sizeof(char));	/* SHA256 = 64 hex digits + \0 */
	EVP_MD_CTX	hash_ctx;
	unsigned char	hash[32]	= { 0 };				/* SHA256 = 32 bytes */
	unsigned int	hash_len	= 32;
	int		i		= 0;
	
	get_hash_input(ctx, selector, &hash_data, &hash_data_len);
	
	EVP_DigestInit(&hash_ctx, EVP_sha256());
	EVP_DigestUpdate(&hash_ctx, hash_data, hash_data_len);
	EVP_DigestFinal(&hash_ctx, hash, &hash_len);
	EVP_MD_CTX_cleanup(&hash_ctx);
	
	OPENSSL_free(hash_data);
	
	for (i = 0; i < 32; i++)
	{
		sprintf(&hash_str[i*2], "%02X", hash[i]);
	}
	
	return hash_str;
}

char* cert_get_sha512_hash(const cert_ctx* ctx, const int selector)
{
	assert(ctx != NULL);
	
	unsigned char*	hash_data	= NULL;
	size_t		hash_data_len	= 0;
	char*		hash_str	= (char*) malloc(129 * sizeof(char));	/* SHA512 = 128 hex digits + \0 */
	EVP_MD_CTX	hash_ctx;
	unsigned char	hash[64]	= { 0 };				/* SHA512 = 64 bytes */
	unsigned int	hash_len	= 64;
	int		i		= 0;
	
	get_hash_input(ctx, selector, &hash_data, &hash_data_len);
	
	EVP_DigestInit(&hash_ctx, EVP_sha512());
	EVP_DigestUpdate(&hash_ctx, hash_data, hash_data_len);
	EVP_DigestFinal(&hash_ctx, hash, &hash_len);
	
	OPENSSL_free(hash_data);
	
	for (i = 0; i < 64; i++)
	{
		sprintf(&hash_str[i*2], "%02X", hash[i]);
	}
	
	return hash_str;
}

const char* mail_get_smimea_sha256_hash(const char* mailAddress)
{
	assert(mailAddress != NULL);
	assert(strlen(mailAddress) < 512);

	static char	hash_str[57]	= { 0 };
	EVP_MD_CTX	hash_ctx;
	unsigned char	hash[32]	= { 0 };
	unsigned int	hash_len	= 32;
	size_t		i		= 0;
	char		lowerMail[512]	= { 0 };

	/* Canonicalize to lower case and cut at the '@' sign */
	for (i = 0; i < strlen(mailAddress); i++)
	{
		if (mailAddress[i] == '@') break;

		lowerMail[i] = tolower(mailAddress[i]);
	}

	EVP_DigestInit(&hash_ctx, EVP_sha256());
	EVP_DigestUpdate(&hash_ctx, lowerMail, strlen(lowerMail));
	EVP_DigestFinal(&hash_ctx, hash, &hash_len);

	for (i = 0; i < 28; i++)
	{
		sprintf(&hash_str[i*2], "%02x", hash[i]);
	}
	
	return hash_str;
}

int cert_is_valid(const cert_ctx* ctx, int be_quiet)
{
	assert(ctx != NULL);
	
	ASN1_TIME* notBefore = X509_get_notBefore(ctx->ossl_crt);
	ASN1_TIME* notAfter = X509_get_notAfter(ctx->ossl_crt);
	
	if (!X509_cmp_current_time(notBefore) || !X509_cmp_current_time(notAfter))
	{
		return CERT_FATAL_ERROR;
	}
	
	if ((X509_cmp_current_time(notBefore) > 0) || (X509_cmp_current_time(notAfter) < 0))
	{
		if (!be_quiet)
		{
			printf("The certificate has expired\n");
		}
		
		return CERT_NOT_VALID;
	}
	else
	{
		if (!be_quiet)
		{
			printf("The certificate is valid\n");
		}
		
		return 0;
	}
}

/* 
 * Compare two host names, case insensitive, and taking into account
 * wildcards
 */
int compare_names(const char* left, const char* right)
{
	assert(left != NULL);
	assert(right != NULL);
	
	const char* 	left_copy 	= left;
	const char* 	right_copy	= right;
	char*		left_worker	= NULL;
	char*		right_worker	= NULL;
	char* 		left_token	= NULL;
	char*		right_token	= NULL;
	char*		left_saveptr	= NULL;
	char*		right_saveptr	= NULL;
	size_t		left_dots	= 0;
	size_t		right_dots	= 0;
	int		rv		= 0;
	
	/* Count the number of dots in both strings */
	while((left_copy = strchr(left_copy, '.')) != NULL)
	{
		left_copy++;
	
        /* Don't count trailing . in FQDN */
		if (*left_copy != '\0') left_dots++;
	}
	
	while((right_copy = strchr(right_copy, '.')) != NULL)
	{
		right_copy++;
		
		/* Don't count trailing . in FQDN */
		if (*right_copy != '\0') right_dots++;
	}
	
	if (left_dots != right_dots)
	{
		return -2;
	}
	
	/* Tokenize both strings */
	left_worker = strdup(left);
	right_worker = strdup(right);
	
	left_token = strtok_r(left_worker, ".", &left_saveptr);
	right_token = strtok_r(right_worker, ".", &right_saveptr);
	
	while (left_token && right_token)
	{
		if (!strcmp(left_token, "*"))
		{
			/* 
			 * Wildcard means a match; note: only the left-hand side
			 * can be a wildcard since that will be the data from
			 * the actual certificate when this function is called
			 */
		}
		else if ((rv = strcasecmp(left_token, right_token)) != 0)
		{
			/* No match! */
			break;
		}
		
		left_token = strtok_r(NULL, ".", &left_saveptr);
		right_token = strtok_r(NULL, ".", &right_saveptr);
	}
	
	free(left_worker);
	free(right_worker);
	
	return rv;
}

typedef struct x509_utf8_name_list_entry
{
	char*					utf8_name;
	struct x509_utf8_name_list_entry* 	next;
}
x509_utf8_name_list_entry;

void x509_utf8_name_list_append(x509_utf8_name_list_entry** list, char* utf8_name)
{
	x509_utf8_name_list_entry* iter		= *list;
	x509_utf8_name_list_entry* new_entry 	= NULL;
	
	new_entry = (x509_utf8_name_list_entry*) malloc(sizeof(x509_utf8_name_list_entry));
	new_entry->next = NULL;
	new_entry->utf8_name = utf8_name;
	
	if (*list == NULL)
	{
		*list = new_entry;
	}
	else
	{
		while (iter->next != NULL) iter = iter->next;
		iter->next = new_entry;
	}
}

int in_x509_utf8_name_list(x509_utf8_name_list_entry* list, char* utf8_name)
{
	while (list != NULL)
	{
		if (!strcasecmp(list->utf8_name, utf8_name))
		{
			return 0;
		}
		
		list = list->next;
	}
	
	return -1;
}

void x509_utf8_name_list_free(x509_utf8_name_list_entry* list)
{
	x509_utf8_name_list_entry* iter = list;
	
	if (list == NULL)
	{
		return;
	}
	
	while (iter != NULL)
	{
		iter = list->next;
		
		OPENSSL_free(list->utf8_name);
		free(list);
		
		list = iter;
	}	
}

x509_utf8_name_list_entry* get_subject_cn(const cert_ctx* ctx)
{
	assert(ctx != NULL);
	
	x509_utf8_name_list_entry*	rv			= NULL;
	X509_NAME* 			subject			= NULL;
	X509_NAME_ENTRY*		subject_component	= NULL;
	int				pos			= 0;
	
	subject = X509_get_subject_name(ctx->ossl_crt);
	
	if (subject == NULL)
	{
		return NULL;
	}
	
	while ((pos = X509_NAME_get_index_by_NID(subject, NID_commonName, pos)) != -1)
	{
		subject_component = X509_NAME_get_entry(subject, pos);
		
		if (subject_component != NULL)
		{
			ASN1_STRING* 	subject_cn	= X509_NAME_ENTRY_get_data(subject_component);
			char*		utf8_name	= NULL;
			
			if (ASN1_STRING_to_UTF8((unsigned char**) &utf8_name, subject_cn) > 0)
			{
				x509_utf8_name_list_append(&rv, utf8_name);
			}
		}
	}
	
	return rv;
}

x509_utf8_name_list_entry* get_subject_mailaddrs(const cert_ctx* ctx)
{
	assert(ctx != NULL);
	
	x509_utf8_name_list_entry*	rv			= NULL;
	X509_NAME* 			subject			= NULL;
	X509_NAME_ENTRY*		subject_component	= NULL;
	int				pos			= 0;
	
	subject = X509_get_subject_name(ctx->ossl_crt);
	
	if (subject == NULL)
	{
		return NULL;
	}
	
	while ((pos = X509_NAME_get_index_by_NID(subject, NID_pkcs9_emailAddress, pos)) != -1)
	{
		subject_component = X509_NAME_get_entry(subject, pos);
		
		if (subject_component != NULL)
		{
			ASN1_STRING* 	subject_cn	= X509_NAME_ENTRY_get_data(subject_component);
			char*		utf8_name	= NULL;
			
			if (ASN1_STRING_to_UTF8((unsigned char**) &utf8_name, subject_cn) > 0)
			{
				x509_utf8_name_list_append(&rv, utf8_name);
			}
		}
	}
	
	return rv;
}

x509_utf8_name_list_entry* get_subject_alt_names(const cert_ctx* ctx, const int type)
{
	assert(ctx != NULL);
	
	GENERAL_NAME*			subject_alt_name_component	= NULL;
	STACK_OF(GENERAL_NAME)*		subject_alt_name		= NULL;
	x509_utf8_name_list_entry*	rv				= NULL;
	int 				i				= 0;
	
	subject_alt_name = (STACK_OF(GENERAL_NAME)*) X509_get_ext_d2i(ctx->ossl_crt, NID_subject_alt_name, NULL, NULL);
	
	if (subject_alt_name == NULL)
	{
		return NULL;
	}
	
	for (i = 0; i < sk_GENERAL_NAME_num(subject_alt_name); i++)
	{
		subject_alt_name_component = sk_GENERAL_NAME_value(subject_alt_name, i);
		
		if (subject_alt_name_component->type == type)
		{
			char* name_utf8 = NULL;
			
			if (ASN1_STRING_to_UTF8((unsigned char**) &name_utf8, subject_alt_name_component->d.uniformResourceIdentifier) > 0)
			{
				x509_utf8_name_list_append(&rv, name_utf8);
			}
		}
	}
	
	sk_GENERAL_NAME_pop_free(subject_alt_name, GENERAL_NAME_free);
	
	return rv;
}

int name_matches_subject_cn(const cert_ctx* ctx, const char* name)
{
	assert(ctx != NULL);
	assert(name != NULL);
	
	x509_utf8_name_list_entry* 	common_names	= NULL;
	x509_utf8_name_list_entry* 	iter		= NULL;
	int				rv		= -2;
	
	iter = common_names = get_subject_cn(ctx);
	
	while (iter && (rv != 0))
	{
		rv = compare_names(iter->utf8_name, name);
		
		iter = iter->next;
	}
	
	x509_utf8_name_list_free(common_names);
	
	return rv;
}

int name_matches_subject_alt_name(const cert_ctx* ctx, const char* name)
{
	assert(ctx != NULL);
	assert(name != NULL);
	
	x509_utf8_name_list_entry*	subject_alt_names	= NULL;
	x509_utf8_name_list_entry*	iter			= NULL;
	int				rv			= -2;
	
	iter = subject_alt_names = get_subject_alt_names(ctx, GEN_DNS);
	
	while (iter && (rv != 0))
	{
		rv = compare_names(iter->utf8_name, name);
		
		iter = iter->next;
	}
	
	x509_utf8_name_list_free(subject_alt_names);
	
	return rv;
}

int cert_matches_name(const cert_ctx* ctx, const char* name, int be_quiet)
{
	assert(ctx != NULL);
	assert(name != NULL);
	
	if (name_matches_subject_cn(ctx, name) == 0)
	{
		if (!be_quiet)
		{
			printf("Name matches certificate commonName\n");
		}
		
		return 0;
	}
	
	if (name_matches_subject_alt_name(ctx, name) == 0)
	{
		if (!be_quiet)
		{
			printf("Name matches certificate subjectAltName\n");
		}
		
		return 0;
	}
	
	if (!be_quiet)
	{
		printf("Name does not match certificate commonName or subjectAltName\n");
	}
	
	return CERT_NAME_MISMATCH;
}

int addr_matches_subject_mailaddrs(const cert_ctx* ctx, const char* mailaddr)
{
	assert(ctx != NULL);
	assert(mailaddr != NULL);
	
	x509_utf8_name_list_entry* 	mailaddrs	= NULL;
	x509_utf8_name_list_entry* 	iter		= NULL;
	int				rv		= -2;
	
	iter = mailaddrs = get_subject_mailaddrs(ctx);
	
	while (iter && (rv != 0))
	{
		rv = strcasecmp(iter->utf8_name, mailaddr);
		
		iter = iter->next;
	}
	
	x509_utf8_name_list_free(mailaddrs);
	
	return rv;
}

int addr_matches_subject_alt_name(const cert_ctx* ctx, const char* mailaddr)
{
	assert(ctx != NULL);
	assert(mailaddr != NULL);
	
	x509_utf8_name_list_entry*	subject_alt_names	= NULL;
	x509_utf8_name_list_entry*	iter			= NULL;
	int				rv			= -2;
	
	iter = subject_alt_names = get_subject_alt_names(ctx, GEN_EMAIL);
	
	while (iter && (rv != 0))
	{
		rv = strcasecmp(iter->utf8_name, mailaddr);
		
		iter = iter->next;
	}
	
	x509_utf8_name_list_free(subject_alt_names);
	
	return rv;
}

int cert_matches_mailaddr(const cert_ctx* ctx, const char* mailaddr, int be_quiet)
{
	assert(ctx != NULL);
	assert(mailaddr != NULL);
	
	if (addr_matches_subject_mailaddrs(ctx, mailaddr) == 0)
	{
		if (!be_quiet)
		{
			printf("E-mail address matches certificate subject\n");
		}
		
		return 0;
	}
	
	if (addr_matches_subject_alt_name(ctx, mailaddr) == 0)
	{
		if (!be_quiet)
		{
			printf("E-mail address matches certificate subjectAltName\n");
		}
		
		return 0;
	}
	
	if (!be_quiet)
	{
		printf("E-mail address does not match certificate subject or subjectAltName\n");
	}
	
	return CERT_ADDR_MISMATCH;
}

int cert_matches_req(const cert_ctx* cert, const req_ctx* req, int be_quiet)
{
	assert(cert != NULL);
	assert(req != NULL);
	
	x509_utf8_name_list_entry*	cert_common_names 		= get_subject_cn(cert);
	x509_utf8_name_list_entry*	cert_subject_alt_names		= get_subject_alt_names(cert, GEN_DNS);
	X509_NAME* 			subject				= NULL;
	X509_NAME_ENTRY*		subject_component		= NULL;
	int				pos				= 0;
	STACK_OF(X509_EXTENSION)*	extensions			= NULL;
	GENERAL_NAME*			subject_alt_name_component	= NULL;
	STACK_OF(GENERAL_NAME)*		subject_alt_name		= NULL;
	int 				i				= 0;
	int				rv				= 0;
	EVP_PKEY*			cert_pubkey			= X509_get_pubkey(cert->ossl_crt);
	EVP_PKEY*			req_pubkey			= X509_REQ_get_pubkey(req->ossl_req);
	
	/* Match subject CNs */
	subject = X509_REQ_get_subject_name(req->ossl_req);
	
	if (subject == NULL)
	{
		return CERT_CSR_MISMATCH;
	}
	
	while ((pos = X509_NAME_get_index_by_NID(subject, NID_commonName, pos)) != -1)
	{
		subject_component = X509_NAME_get_entry(subject, pos);
		
		if (subject_component != NULL)
		{
			ASN1_STRING* 	subject_cn	= X509_NAME_ENTRY_get_data(subject_component);
			char*		utf8_name	= NULL;
			
			if (ASN1_STRING_to_UTF8((unsigned char**) &utf8_name, subject_cn) > 0)
			{
				if (in_x509_utf8_name_list(cert_common_names, utf8_name) != 0)
				{
					x509_utf8_name_list_free(cert_common_names);
					x509_utf8_name_list_free(cert_subject_alt_names);
					
					if (!be_quiet)
					{
						printf("Mismatch between request and certificate CN for name %s (in request but not in certificate)\n", utf8_name);
					}
					
					OPENSSL_free(utf8_name);
					
					return CERT_CSR_MISMATCH;
				}
				
				OPENSSL_free(utf8_name);
			}
		}
	}
	
	/* Match subjectAltNames */
	extensions = X509_REQ_get_extensions(req->ossl_req);
	
	if (extensions != NULL)
	{
		pos = X509v3_get_ext_by_NID(extensions, NID_subject_alt_name, -1);
	}
	
	if ((extensions != NULL) && (pos >= 0))
	{
		if (cert_subject_alt_names != NULL)
		{
			x509_utf8_name_list_entry* 	csr_subject_alt_names 	= NULL;
			x509_utf8_name_list_entry* 	iter			= NULL;
			
			subject_alt_name = (STACK_OF(GENERAL_NAME)*) X509V3_EXT_d2i(X509v3_get_ext(extensions, pos));
			
			if (subject_alt_name == NULL)
			{
				return CERT_CSR_MISMATCH;
			}
			
			for (i = 0; (i < sk_GENERAL_NAME_num(subject_alt_name)) && (rv == 0); i++)
			{
				subject_alt_name_component = sk_GENERAL_NAME_value(subject_alt_name, i);
				
				if (subject_alt_name_component->type == GEN_DNS)
				{
					char* dns_name_utf8 = NULL;
					
					if (ASN1_STRING_to_UTF8((unsigned char**) &dns_name_utf8, subject_alt_name_component->d.uniformResourceIdentifier) > 0)
					{
						if (in_x509_utf8_name_list(cert_subject_alt_names, dns_name_utf8) != 0)
						{
							if (!be_quiet)
							{
								printf("Mismatch between request and certificate subjectAltName for name %s (in request but not in certificate)\n", dns_name_utf8);
							}
							
							rv = CERT_CSR_MISMATCH;
						}
						
						x509_utf8_name_list_append(&csr_subject_alt_names, dns_name_utf8);
					}
				}
			}
			
			sk_GENERAL_NAME_pop_free(subject_alt_name, GENERAL_NAME_free);
			
			/* 
			 * We have now checked that all subjectAltName entries that are in the 
			 * CSR are also in the certificate, but we also need to check the
			 * reverse.
			 */
			iter = cert_subject_alt_names;
			
			while (iter)
			{
				if (in_x509_utf8_name_list(csr_subject_alt_names, iter->utf8_name) != 0)
				{
					/* 
					 * Be lenient if this is the same name as the subject; CAs will
					 * correctly issue a certificate for a request that misses the subject
					 * in the subjectAltName extension.
					 */
					if (in_x509_utf8_name_list(cert_common_names, iter->utf8_name) == 0)
					{
						if (!be_quiet)
						{
							printf("WARNING: certificate subject (%s) is in certificate subjectAltName but not in request subjectAltName\n", iter->utf8_name);
						}
					}
					else
					{
						if (!be_quiet)
						{
							printf("Mismatch between request and certificate subjectAltName for name %s (in certificate but not in request)\n", iter->utf8_name);
						}
						
						rv = CERT_CSR_MISMATCH;
					}
				}
				
				iter = iter->next;
			}
			
			x509_utf8_name_list_free(csr_subject_alt_names);
		}
		else
		{
			if (!be_quiet)
			{
				printf("Mismatch between request and certificate subjectAltName; request contains a subjectAltName extension but the certificate does not\n");
			}
			
			rv = CERT_CSR_MISMATCH;
		}
		
		sk_X509_EXTENSION_pop_free(extensions, X509_EXTENSION_free);
	}
	else
	{
		if (cert_subject_alt_names != NULL)
		{
			if (!be_quiet)
			{
				printf("Mismatch between request and certificate subjectAltName; request contains no subjectAltName extension and certificate does\n");
			}
			
			rv = CERT_CSR_MISMATCH;
		}
	}
	
	x509_utf8_name_list_free(cert_common_names);
	x509_utf8_name_list_free(cert_subject_alt_names);
	
	/* 
	 * Finally, and most importantly, we should match the publicKeyInfo
	 * block in the request and the certificate; a simple binary compare
	 * should do since they should be the same
	 */
	if (EVP_PKEY_cmp(cert_pubkey, req_pubkey) != 1)
	{
		if (!be_quiet)
		{
			printf("Public key in certificate does not match public key in request\n");
			
			rv = CERT_CSR_MISMATCH;
		}
	}
	
	if (!be_quiet && !rv)
	{
		printf("Certificate matches request\n");
	}
	
	return rv;
}
