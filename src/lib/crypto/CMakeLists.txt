project(softhsm_crypto)

set(INCLUDE_DIRS ${PROJECT_SOURCE_DIR}
                 ${PROJECT_SOURCE_DIR}/../common
                 ${PROJECT_SOURCE_DIR}/../data_mgr
                 ${PROJECT_SOURCE_DIR}/../pkcs11
                 ${CRYPTO_INCLUDES}
                 )

set(SOURCES AESKey.cpp
            AsymmetricAlgorithm.cpp
            AsymmetricKeyPair.cpp
            CryptoFactory.cpp
            DerUtil.cpp
            DESKey.cpp
            DHParameters.cpp
            DHPrivateKey.cpp
            DHPublicKey.cpp
            DSAParameters.cpp
            DSAPrivateKey.cpp
            DSAPublicKey.cpp
            SM2PrivateKey.cpp
            SM2Parameters.cpp
            SM2PublicKey.cpp
            ECParameters.cpp
            ECPrivateKey.cpp
            ECPublicKey.cpp
            EDPrivateKey.cpp
            EDPublicKey.cpp
            GOSTPrivateKey.cpp
            GOSTPublicKey.cpp
            HashAlgorithm.cpp
            MacAlgorithm.cpp
            RSAParameters.cpp
            RSAPrivateKey.cpp
            RSAPublicKey.cpp
            SymmetricAlgorithm.cpp
            SymmetricKey.cpp
            )

    list(APPEND SOURCES OSSLAES.cpp
                        OSSLCMAC.cpp
                        OSSLComp.cpp
                        OSSLCryptoFactory.cpp
                        OSSLDES.cpp
                        OSSLDH.cpp
                        OSSLDHKeyPair.cpp
                        OSSLDHPrivateKey.cpp
                        OSSLDHPublicKey.cpp
                        OSSLDSA.cpp
                        OSSLDSAKeyPair.cpp
                        OSSLDSAPrivateKey.cpp
                        OSSLDSAPublicKey.cpp
                        OSSLECDH.cpp
                        OSSLECDSA.cpp
                        OSSLECKeyPair.cpp
                        OSSLECPrivateKey.cpp
                        OSSLECPublicKey.cpp
                        OSSLSM2.cpp
                        OSSLSM2KeyPair.cpp
                        OSSLSM2PrivateKey.cpp
                        OSSLSM2PublicKey.cpp
                        OSSLSM3.cpp
                        OSSLEDDSA.cpp
                        OSSLEDKeyPair.cpp
                        OSSLEDPrivateKey.cpp
                        OSSLEDPublicKey.cpp
                        OSSLEVPCMacAlgorithm.cpp
                        OSSLEVPHashAlgorithm.cpp
                        OSSLEVPMacAlgorithm.cpp
                        OSSLEVPSymmetricAlgorithm.cpp
                        OSSLGOST.cpp
                        OSSLGOSTKeyPair.cpp
                        OSSLGOSTPrivateKey.cpp
                        OSSLGOSTPublicKey.cpp
                        OSSLGOSTR3411.cpp
                        OSSLHMAC.cpp
                        OSSLMD5.cpp
                        OSSLRNG.cpp
                        OSSLRSA.cpp
                        OSSLRSAKeyPair.cpp
                        OSSLRSAPrivateKey.cpp
                        OSSLRSAPublicKey.cpp
                        OSSLSHA1.cpp
                        OSSLSHA224.cpp
                        OSSLSHA256.cpp
                        OSSLSHA384.cpp
                        OSSLSHA512.cpp
                        OSSLUtil.cpp
                        )


include_directories(${INCLUDE_DIRS})

add_library(${PROJECT_NAME} OBJECT ${SOURCES})
# Versions before CMake 3.12 cannot use target_link_libraries on object
# libraries, a workaround exists in src/lib/CMakeLists.txt.
if(NOT CMAKE_VERSION VERSION_LESS "3.12")
        target_link_libraries(${PROJECT_NAME} ${CRYPTO_LIBS})
endif()

if(BUILD_TESTS)
    add_subdirectory(test)
endif(BUILD_TESTS)
