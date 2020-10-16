MAINTAINERCLEANFILES = 		$(srcdir)/Makefile.in

AM_CPPFLAGS =			-I$(srcdir)/.. \
				-I$(srcdir)/../common \
				-I$(srcdir)/../data_mgr \
				-I$(srcdir)/../pkcs11 \
				@CRYPTO_INCLUDES@

noinst_LTLIBRARIES =		libsofthsm_crypto.la
libsofthsm_crypto_la_SOURCES =	AESKey.cpp \
				AsymmetricAlgorithm.cpp \
				AsymmetricKeyPair.cpp \
				CryptoFactory.cpp \
				DerUtil.cpp \
				DESKey.cpp \
				DHParameters.cpp \
				DHPublicKey.cpp \
				DHPrivateKey.cpp \
				DSAParameters.cpp \
				DSAPublicKey.cpp \
				DSAPrivateKey.cpp \
				ECParameters.cpp \
				ECPublicKey.cpp \
				ECPrivateKey.cpp \
				SM2Parameters.cpp \
				SM2PublicKey.cpp \
				SM2PrivateKey.cpp \
				EDPublicKey.cpp \
				EDPrivateKey.cpp \
				GOSTPublicKey.cpp \
				GOSTPrivateKey.cpp \
				HashAlgorithm.cpp \
				MacAlgorithm.cpp \
				RSAParameters.cpp \
				RSAPrivateKey.cpp \
				RSAPublicKey.cpp \
				SymmetricAlgorithm.cpp \
				SymmetricKey.cpp
libsofthsm_crypto_la_LIBADD =	@CRYPTO_LIBS@

SUBDIRS =			test

EXTRA_DIST =			$(srcdir)/CMakeLists.txt \
				$(srcdir)/*.h \
				$(srcdir)/*.cpp

# Compile with support of OpenSSL
libsofthsm_crypto_la_SOURCES +=	OSSLAES.cpp \
				OSSLComp.cpp \
				OSSLCryptoFactory.cpp \
				OSSLDES.cpp \
				OSSLDH.cpp \
				OSSLDHKeyPair.cpp \
				OSSLDHPrivateKey.cpp \
				OSSLDHPublicKey.cpp \
				OSSLDSA.cpp \
				OSSLDSAKeyPair.cpp \
				OSSLDSAPrivateKey.cpp \
				OSSLDSAPublicKey.cpp \
				OSSLECDH.cpp \
				OSSLECDSA.cpp \
				OSSLECKeyPair.cpp \
				OSSLECPrivateKey.cpp \
				OSSLECPublicKey.cpp \
				OSSLSM2.cpp \
				OSSLSM2KeyPair.cpp \
				OSSLSM2PrivateKey.cpp \
				OSSLSM2PublicKey.cpp \
				OSSLSM3.cpp \
				OSSLEDDSA.cpp \
				OSSLEDKeyPair.cpp \
				OSSLEDPrivateKey.cpp \
				OSSLEDPublicKey.cpp \
				OSSLEVPHashAlgorithm.cpp \
				OSSLEVPMacAlgorithm.cpp \
				OSSLEVPCMacAlgorithm.cpp \
				OSSLEVPSymmetricAlgorithm.cpp \
				OSSLGOST.cpp \
				OSSLGOSTKeyPair.cpp \
				OSSLGOSTPrivateKey.cpp \
				OSSLGOSTPublicKey.cpp \
				OSSLGOSTR3411.cpp \
				OSSLCMAC.cpp \
				OSSLHMAC.cpp \
				OSSLMD5.cpp \
				OSSLRNG.cpp \
				OSSLRSA.cpp \
				OSSLRSAKeyPair.cpp \
				OSSLRSAPrivateKey.cpp \
				OSSLRSAPublicKey.cpp \
				OSSLSHA1.cpp \
				OSSLSHA224.cpp \
				OSSLSHA256.cpp \
				OSSLSHA384.cpp \
				OSSLSHA512.cpp \
				OSSLUtil.cpp
