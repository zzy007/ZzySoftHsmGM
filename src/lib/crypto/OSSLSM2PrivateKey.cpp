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
 OSSLSM2PrivateKey.cpp

 OpenSSL SM2 private key class
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "OSSLSM2PrivateKey.h"
#include "OSSLUtil.h"
#include <gmssl/bn.h>
#include <gmssl/x509.h>

// Constructors
OSSLSM2PrivateKey::OSSLSM2PrivateKey()
{
	eckey = EC_KEY_new_by_curve_name(1121);

	// For PKCS#8 encoding
	EC_KEY_set_enc_flags(eckey, EC_PKEY_NO_PUBKEY);
}

OSSLSM2PrivateKey::OSSLSM2PrivateKey(const EC_KEY* inECKEY)
{
	eckey = EC_KEY_new_by_curve_name(1121);

	// For PKCS#8 encoding
	EC_KEY_set_enc_flags(eckey, EC_PKEY_NO_PUBKEY);

	setFromOSSL(inECKEY);
}

// Destructor
OSSLSM2PrivateKey::~OSSLSM2PrivateKey()
{
	EC_KEY_free(eckey);
}

// The type
/*static*/ const char* OSSLSM2PrivateKey::type = "OpenSSL EC Private Key";

// Get the base point order length
unsigned long OSSLSM2PrivateKey::getOrderLength() const
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
void OSSLSM2PrivateKey::setFromOSSL(const EC_KEY* inECKEY)
{
	const EC_GROUP* grp = EC_KEY_get0_group(inECKEY);
	if (grp != NULL)
	{
		ByteString inEC = OSSL::grp2ByteString(grp);
		setEC(inEC);
	}
	const BIGNUM* pk = EC_KEY_get0_private_key(inECKEY);
	if (pk != NULL)
	{
		ByteString inD = OSSL::bn2ByteString(pk);
		setD(inD);
	}
}

// Check if the key is of the given type
bool OSSLSM2PrivateKey::isOfType(const char* inType)
{
	return !strcmp(type, inType);
}

// Setters for the EC private key components
void OSSLSM2PrivateKey::setD(const ByteString& inD)
{
	SM2PrivateKey::setD(inD);

	BIGNUM* pk = OSSL::byteString2bn(inD);
	EC_KEY_set_private_key(eckey, pk);
	BN_clear_free(pk);
}


// Setters for the EC public key components
void OSSLSM2PrivateKey::setEC(const ByteString& inEC)
{
	SM2PrivateKey::setEC(inEC);

	EC_GROUP* grp = OSSL::byteString2grp(inEC);
	EC_KEY_set_group(eckey, grp);
	EC_GROUP_free(grp);
}

// Encode into PKCS#8 DER
ByteString OSSLSM2PrivateKey::PKCS8Encode()
{
	ByteString der;
	if (eckey == NULL) return der;
	EVP_PKEY* pkey = EVP_PKEY_new();
	if (pkey == NULL) return der;
	if (!EVP_PKEY_set1_EC_KEY(pkey, eckey))
	{
		EVP_PKEY_free(pkey);
		return der;
	}
	PKCS8_PRIV_KEY_INFO* p8inf = EVP_PKEY2PKCS8(pkey);
	EVP_PKEY_free(pkey);
	if (p8inf == NULL) return der;
	int len = i2d_PKCS8_PRIV_KEY_INFO(p8inf, NULL);
	if (len < 0)
	{
		PKCS8_PRIV_KEY_INFO_free(p8inf);
		return der;
	}
	der.resize(len);
	unsigned char* priv = &der[0];
	int len2 = i2d_PKCS8_PRIV_KEY_INFO(p8inf, &priv);
	PKCS8_PRIV_KEY_INFO_free(p8inf);
	if (len2 != len) der.wipe();
	return der;
}

// Decode from PKCS#8 BER
bool OSSLSM2PrivateKey::PKCS8Decode(const ByteString& ber)
{
	int len = ber.size();
	if (len <= 0) return false;
	const unsigned char* priv = ber.const_byte_str();
	PKCS8_PRIV_KEY_INFO* p8 = d2i_PKCS8_PRIV_KEY_INFO(NULL, &priv, len);
	if (p8 == NULL) return false;
	EVP_PKEY* pkey = EVP_PKCS82PKEY(p8);
	PKCS8_PRIV_KEY_INFO_free(p8);
	if (pkey == NULL) return false;
	EC_KEY* key = EVP_PKEY_get1_EC_KEY(pkey);
	EVP_PKEY_free(pkey);
	if (key == NULL) return false;
	setFromOSSL(key);
	EC_KEY_free(key);
	return true;
}

// Retrieve the OpenSSL representation of the key
EC_KEY* OSSLSM2PrivateKey::getOSSLKey()
{
	if (eckey == NULL) createOSSLKey();

	return eckey;
}


// Create the OpenSSL representation of the key
void OSSLSM2PrivateKey::createOSSLKey()
{
	if (eckey != NULL) return;

	eckey = EC_KEY_new_by_curve_name(1121);
	if (eckey == NULL)
	{
		ERROR_MSG("Could not create SM2 object");
		return;
	}
}

