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
 OSSLSM2.cpp

 OpenSSL ECDSA asymmetric algorithm implementation
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "OSSLSM2.h"
#include "CryptoFactory.h"
#include "SM2Parameters.h"
#include "OSSLSM2KeyPair.h"
#include "OSSLComp.h"
#include "OSSLUtil.h"
#include <algorithm>
#include <openssl/sm2.h>
#include <openssl/ecdsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <string.h>

// Signing functions
bool OSSLSM2::sign(PrivateKey* privateKey, const ByteString& dataToSign,
		     ByteString& signature, const AsymMech::Type mechanism,
		     const void* /* param = NULL */, const size_t /* paramLen = 0 */)
{
	if (mechanism != AsymMech::SM2)
	{
		
			ERROR_MSG("Invalid mechanism supplied (%i)", mechanism);
			return false;
		
	}


	OSSLSM2PrivateKey* pk = (OSSLSM2PrivateKey*) privateKey;
	EC_KEY* eckey = pk->getOSSLKey();

	if (eckey == NULL)
	{
		ERROR_MSG("Could not get the OpenSSL private key");

		return false;
	}

	// Use the OpenSSL implementation and not any engine
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)

	ECDSA_set_method(eckey, ECDSA_OpenSSL());

#else
	EC_KEY_set_method(eckey, EC_KEY_OpenSSL());
#endif

	// Perform the signature operation
	size_t len = pk->getOrderLength();
	if (len == 0)
	{
		ERROR_MSG("Could not get the order length");
		return false;
	}
	signature.resize(2 * len);
	memset(&signature[0], 0, 2 * len);
	// ECDSA_SIG *sig = ECDSA_do_sign(dataToSign.const_byte_str(), dataToSign.size(), eckey);
	ECDSA_SIG *sig = SM2_do_sign(dataToSign.const_byte_str(), dataToSign.size(), eckey);
	if (sig == NULL)
	{
		ERROR_MSG("SM2 sign failed (0x%08X)", ERR_get_error());
		return false;
	}
	// Store the 2 values with padding
	const BIGNUM* bn_r = NULL;
	const BIGNUM* bn_s = NULL;
	ECDSA_SIG_get0(sig, &bn_r, &bn_s);
	BN_bn2bin(bn_r, &signature[len - BN_num_bytes(bn_r)]);
	BN_bn2bin(bn_s, &signature[2 * len - BN_num_bytes(bn_s)]);
	ECDSA_SIG_free(sig);
	return true;
}

bool OSSLSM2::signInit(PrivateKey* /*privateKey*/, const AsymMech::Type /*mechanism*/,
			 const void* /* param = NULL */, const size_t /* paramLen = 0 */)
{
	ERROR_MSG("ECDSA does not support multi part signing");

	return false;
}

bool OSSLSM2::signUpdate(const ByteString& /*dataToSign*/)
{
	ERROR_MSG("ECDSA does not support multi part signing");

	return false;
}

bool OSSLSM2::signFinal(ByteString& /*signature*/)
{
	ERROR_MSG("ECDSA does not support multi part signing");

	return false;
}

// Verification functions
bool OSSLSM2::verify(PublicKey* publicKey, const ByteString& originalData,
		       const ByteString& signature, const AsymMech::Type mechanism,
		       const void* /* param = NULL */, const size_t /* paramLen = 0 */)
{
	if (mechanism != AsymMech::SM2)
	{
		ERROR_MSG("Invalid mechanism supplied (%i)", mechanism);
		return false;
	}

	// Check if the private key is the right type
	if (!publicKey->isOfType(OSSLSM2PublicKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		return false;
	}

	OSSLSM2PublicKey* pk = (OSSLSM2PublicKey*) publicKey;
	EC_KEY* eckey = pk->getOSSLKey();

	if (eckey == NULL)
	{
		ERROR_MSG("Could not get the OpenSSL public key");

		return false;
	}

	// Use the OpenSSL implementation and not any engine
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)

	ECDSA_set_method(eckey, ECDSA_OpenSSL());

#else
	EC_KEY_set_method(eckey, EC_KEY_OpenSSL());
#endif

	// Perform the verify operation
	size_t len = pk->getOrderLength();
	if (len == 0)
	{
		ERROR_MSG("Could not get the order length");
		return false;
	}
	if (signature.size() != 2 * len)
	{
		ERROR_MSG("Invalid buffer length");
		return false;
	}
	ECDSA_SIG* sig = ECDSA_SIG_new();
	if (sig == NULL)
	{
		ERROR_MSG("Could not create an ECDSA_SIG object");
		return false;
	}
	const unsigned char *s = signature.const_byte_str();
	BIGNUM* bn_r = BN_bin2bn(s, len, NULL);
	BIGNUM* bn_s = BN_bin2bn(s + len, len, NULL);
	if (bn_r == NULL || bn_s == NULL ||
	    !ECDSA_SIG_set0(sig, bn_r, bn_s))
	{
		ERROR_MSG("Could not add data to the ECDSA_SIG object");
		ECDSA_SIG_free(sig);
		return false;
	}
	int ret = SM2_do_verify(originalData.const_byte_str(), originalData.size(), sig, eckey);
	if (ret != 1)
	{
		if (ret < 0)
			ERROR_MSG("ECDSA verify failed (0x%08X)", ERR_get_error());

		ECDSA_SIG_free(sig);
		return false;
	}

	ECDSA_SIG_free(sig);
	return true;
}

bool OSSLSM2::verifyInit(PublicKey* /*publicKey*/, const AsymMech::Type /*mechanism*/,
			   const void* /* param = NULL */, const size_t /* paramLen = 0 */)
{
	ERROR_MSG("ECDSA does not support multi part verifying");

	return false;
}

bool OSSLSM2::verifyUpdate(const ByteString& /*originalData*/)
{
	ERROR_MSG("ECDSA does not support multi part verifying");

	return false;
}

bool OSSLSM2::verifyFinal(const ByteString& /*signature*/)
{
	ERROR_MSG("ECDSA does not support multi part verifying");

	return false;
}

// Encryption functions
bool OSSLSM2::encrypt(PublicKey* /*publicKey*/, const ByteString& /*data*/,
			ByteString& /*encryptedData*/, const AsymMech::Type /*padding*/)
{
	ERROR_MSG("ECDSA does not support encryption");

	return false;
}

// Decryption functions
bool OSSLSM2::decrypt(PrivateKey* /*privateKey*/, const ByteString& /*encryptedData*/,
			ByteString& /*data*/, const AsymMech::Type /*padding*/)
{
	ERROR_MSG("ECDSA does not support decryption");

	return false;
}

// Key factory
// ppKeyPair�Ǵ���Ŀ�ֵ��parameters����Բ���߲������˷���������parameters����ppKeyPair
bool OSSLSM2::generateKeyPair(AsymmetricKeyPair** ppKeyPair, AsymmetricParameters* parameters, RNG* /*rng = NULL */)
{
	// Check parameters
	if ((ppKeyPair == NULL) ||
	    (parameters == NULL))
	{
		return false;
	}

	if (!parameters->areOfType(SM2Parameters::type))
	{
		ERROR_MSG("Invalid parameters supplied for ECDSA key generation");

		return false;
	}

	//SM2Parameters* params = (SM2Parameters*) parameters;

	// Generate the key-pair
	//EC_KEY* eckey = EC_KEY_new();
	//from gmssl sm2.c:275
	EC_KEY* eckey = EC_KEY_new_by_curve_name(1121);
	//if (eckey == NULL)
	//{
	//	ERROR_MSG("Failed to instantiate OpenSSL ECDSA object");

	//	return false;
	//}

	//EC_GROUP* grp = OSSL::byteString2grp(params->getEC());
	//EC_KEY_set_group(eckey, grp);
	//EC_GROUP_free(grp);

	if (!EC_KEY_generate_key(eckey))
	{
		ERROR_MSG("SM2 key generation failed (0x%08X)", ERR_get_error());

		EC_KEY_free(eckey);

		return false;
	}

	// Create an asymmetric key-pair object to return
	OSSLSM2KeyPair* kp = new OSSLSM2KeyPair();

	((OSSLSM2PublicKey*) kp->getPublicKey())->setFromOSSL(eckey);
	((OSSLSM2PrivateKey*) kp->getPrivateKey())->setFromOSSL(eckey);

	*ppKeyPair = kp;

	// Release the key
	EC_KEY_free(eckey);

	return true;
}

unsigned long OSSLSM2::getMinKeySize()
{
	// Smallest EC group is secp112r1
	return 112;
}

unsigned long OSSLSM2::getMaxKeySize()
{
	// Biggest EC group is secp521r1
	return 521;
}

bool OSSLSM2::reconstructKeyPair(AsymmetricKeyPair** ppKeyPair, ByteString& serialisedData)
{
	// Check input
	if ((ppKeyPair == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	ByteString dPub = ByteString::chainDeserialise(serialisedData);
	ByteString dPriv = ByteString::chainDeserialise(serialisedData);

	OSSLSM2KeyPair* kp = new OSSLSM2KeyPair();

	bool rv = true;

	if (!((SM2PublicKey*) kp->getPublicKey())->deserialise(dPub))
	{
		rv = false;
	}

	if (!((SM2PrivateKey*) kp->getPrivateKey())->deserialise(dPriv))
	{
		rv = false;
	}

	if (!rv)
	{
		delete kp;

		return false;
	}

	*ppKeyPair = kp;

	return true;
}

bool OSSLSM2::reconstructPublicKey(PublicKey** ppPublicKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPublicKey == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	OSSLSM2PublicKey* pub = new OSSLSM2PublicKey();

	if (!pub->deserialise(serialisedData))
	{
		delete pub;

		return false;
	}

	*ppPublicKey = pub;

	return true;
}

bool OSSLSM2::reconstructPrivateKey(PrivateKey** ppPrivateKey, ByteString& serialisedData)
{
	// Check input
	if ((ppPrivateKey == NULL) ||
	    (serialisedData.size() == 0))
	{
		return false;
	}

	OSSLSM2PrivateKey* priv = new OSSLSM2PrivateKey();

	if (!priv->deserialise(serialisedData))
	{
		delete priv;

		return false;
	}

	*ppPrivateKey = priv;

	return true;
}

PublicKey* OSSLSM2::newPublicKey()
{
	return (PublicKey*) new OSSLSM2PublicKey();
}

PrivateKey* OSSLSM2::newPrivateKey()
{
	return (PrivateKey*) new OSSLSM2PrivateKey();
}

AsymmetricParameters* OSSLSM2::newParameters()
{
	return (AsymmetricParameters*) new SM2Parameters();
}

bool OSSLSM2::reconstructParameters(AsymmetricParameters** ppParams, ByteString& serialisedData)
{
	// Check input parameters
	if ((ppParams == NULL) || (serialisedData.size() == 0))
	{
		return false;
	}

	SM2Parameters* params = new SM2Parameters();


	if (!params->deserialise(serialisedData))
	{
		delete params;

		return false;
	}

	*ppParams = params;

	return true;
}