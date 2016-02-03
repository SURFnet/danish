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

#ifndef _DANISH_CERT_H
#define _DANISH_CERT_H

#include <openssl/x509.h>

#define CERT_NOT_VALID		0x00000001
#define CERT_NAME_MISMATCH	0x00000002
#define CERT_CSR_MISMATCH	0x00000004
#define CERT_ADDR_MISMATCH	0x00000008
#define CERT_FATAL_ERROR	0x80000000

typedef struct
{
	X509* 		ossl_crt;
}
cert_ctx;

typedef struct
{
	X509_REQ*	ossl_req;
}
req_ctx;

void init_cert_ctx(cert_ctx* ctx);

void init_req_ctx(req_ctx* ctx);

void free_cert_ctx(cert_ctx* ctx);

void free_req_ctx(req_ctx* ctx);

int read_cert(cert_ctx* ctx, const char* file_name);

int read_req(req_ctx* ctx, const char* file_name);

char* cert_get_der_hexstr(const cert_ctx* ctx, const int selector);

char* cert_get_sha256_hash(const cert_ctx* ctx, const int selector);

char* cert_get_sha512_hash(const cert_ctx* ctx, const int selector);

const char* mail_get_smimea_sha256_hash(const char* mailAddress);

int cert_is_valid(const cert_ctx* ctx, int be_quiet);

int cert_matches_name(const cert_ctx* ctx, const char* name, int be_quiet);

int cert_matches_mailaddr(const cert_ctx* ctx, const char* mailaddr, int be_quiet);

int cert_matches_req(const cert_ctx* cert, const req_ctx* req, int be_quiet);

#endif /* !_DANISH_CERT_H */
