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
 OSSLSM2KeyPair.cpp

 OpenSSL Elliptic Curve key-pair class
 *****************************************************************************/

#include "config.h"
#include "log.h"
#include "OSSLSM2KeyPair.h"

// Set the public key
void OSSLSM2KeyPair::setPublicKey(OSSLSM2PublicKey& publicKey)
{
	pubKey = publicKey;
}

// Set the private key
void OSSLSM2KeyPair::setPrivateKey(OSSLSM2PrivateKey& privateKey)
{
	privKey = privateKey;
}

// Return the public key
PublicKey* OSSLSM2KeyPair::getPublicKey()
{
	return &pubKey;
}

const PublicKey* OSSLSM2KeyPair::getConstPublicKey() const
{
	return &pubKey;
}

// Return the private key
PrivateKey* OSSLSM2KeyPair::getPrivateKey()
{
	return &privKey;
}

const PrivateKey* OSSLSM2KeyPair::getConstPrivateKey() const
{
	return &privKey;
}