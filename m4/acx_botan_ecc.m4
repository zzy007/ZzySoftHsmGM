AC_DEFUN([ACX_BOTAN_ECC],[
	AC_MSG_CHECKING(for Botan ECC support)

	tmp_CPPFLAGS=$CPPFLAGS
	tmp_LIBS=$LIBS

	CPPFLAGS="$CPPFLAGS $CRYPTO_INCLUDES"
	LIBS="$CRYPTO_LIBS $LIBS"

	AC_LANG_PUSH([C++])
	AC_CACHE_VAL([acx_cv_lib_botan_ecc_support],[
		acx_cv_lib_botan_ecc_support=no
		AC_RUN_IFELSE([
			AC_LANG_SOURCE([[
				#include <botan/ec_group.h>
				#include <botan/oids.h>
				#include <botan/version.h>
				int main()
				{
					const std::string name("secp256r1");
					const Botan::OID oid(Botan::OIDS::lookup(name));
					const Botan::EC_Group ecg(oid);
					try {
						const std::vector<Botan::byte> der =
						ecg.DER_encode(Botan::EC_DOMPAR_ENC_OID);
					} catch(...) {
						return 1;
					}
					return 0;
				}
			]])
		],[
			AC_MSG_RESULT([Found P256])
			acx_cv_lib_botan_ecc_support=yes
		],[
			AC_MSG_RESULT([Cannot find P256])
			acx_cv_lib_botan_ecc_support=no
		],[
			AC_MSG_WARN([Cannot test, assuming P256])
			acx_cv_lib_botan_ecc_support=yes
		])
	])
	AC_LANG_POP([C++])

	CPPFLAGS=$tmp_CPPFLAGS
	LIBS=$tmp_LIBS
	have_lib_botan_ecc_support="${acx_cv_lib_botan_ecc_support}"
])
