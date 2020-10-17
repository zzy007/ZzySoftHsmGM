/*
 * Copyright (c) 2010 SURFnet bv
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

/*****************************************************************************
 OSSLSM2PublicKey.cpp

 OpenSSL Elliptic Curve public key class
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "OSSLSM2PublicKey.h"
#include "OSSLUtil.h"
#include <openssl/bn.h>
#include <string.h>

// Constructors
OSSLSM2PublicKey::OSSLSM2PublicKey()
{
	eckey = EC_KEY_new_by_curve_name(1121);
}

OSSLSM2PublicKey::OSSLSM2PublicKey(const EC_KEY* inECKEY)
{
	eckey = EC_KEY_new_by_curve_name(1121);

	setFromOSSL(inECKEY);
}

// Destructor
OSSLSM2PublicKey::~OSSLSM2PublicKey()
{
	EC_KEY_free(eckey);
}

// The type
/*static*/ const char* OSSLSM2PublicKey::type = "OpenSSL EC Public Key";

// Get the base point order length
unsigned long OSSLSM2PublicKey::getOrderLength() const
{
	const EC_GROUP* grp = EC_KEY_get0_group(eckey);
	if (grp != NULL)
	{
		BIGNUM* order = BN_new();
		if (order == NULL)
			return 0;
		if (!EC_GROUP_get_order(grp, order, NULL))
		{
			BN_clear_free(order);
			return 0;
		}
		unsigned long len = BN_num_bytes(order);
		BN_clear_free(order);
		return len;
	}
	return 0;
}

// Set from OpenSSL representation
void OSSLSM2PublicKey::setFromOSSL(const EC_KEY* inECKEY)
{
	const EC_GROUP* grp = EC_KEY_get0_group(inECKEY);
	if (grp != NULL)
	{
		ByteString inEC = OSSL::grp2ByteString(grp);
		setEC(inEC);
	}
	const EC_POINT* pub = EC_KEY_get0_public_key(inECKEY);
	if (pub != NULL && grp != NULL)
	{
		ByteString inQ = OSSL::pt2ByteString(pub, grp);
		setQ(inQ);
	}
}

// Check if the key is of the given type
bool OSSLSM2PublicKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

// Setters for the EC public key components
void OSSLSM2PublicKey::setEC(const ByteString& inEC)
{
	SM2PublicKey::setEC(inEC);

	EC_GROUP* grp = OSSL::byteString2grp(inEC);
	EC_KEY_set_group(eckey, grp);
	EC_GROUP_free(grp);
}

void OSSLSM2PublicKey::setQ(const ByteString& inQ)
{
	SM2PublicKey::setQ(inQ);

	EC_POINT* pub = OSSL::byteString2pt(inQ, EC_KEY_get0_group(eckey));
	EC_KEY_set_public_key(eckey, pub);
	EC_POINT_free(pub);
}

// Retrieve the OpenSSL representation of the key
EC_KEY* OSSLSM2PublicKey::getOSSLKey()
{
	if (eckey == NULL) createOSSLKey();

	return eckey;
}


// Create the OpenSSL representation of the key
void OSSLSM2PublicKey::createOSSLKey()
{
	if (eckey != NULL) return;

	eckey = EC_KEY_new_by_curve_name(1121);
	if (eckey == NULL)
	{
		ERROR_MSG("Could not create SM2 object");
		return;
	}
}

