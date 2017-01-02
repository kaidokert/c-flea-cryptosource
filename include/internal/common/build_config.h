/*
__________________
***** cryptosource
******************
  Cryptography. Security.

    flea cryptographic library for embedded systems
    Copyright (C) 2015 cryptosource GmbH

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/



#ifndef _flea_build_config__H_
#define _flea_build_config__H_

/**
 * Uncomment to print error messages with printf (for debugging purposes)
 */
//#define FLEA_DO_PRINTF_ERRS

/**
 * Activate this flag to let flea make heap allocation for buffers. Deactivate
 * this flag to let flea only use stack buffers. In the latter case, be sure to
 * correctly define the RSA and EC key sizes.
 */
#define FLEA_USE_HEAP_BUF  // FBFLAGS_CORE_ON_OFF

/**
 * Activate this flag to make use of the buffer overwrite detection. Should not
 * be used in productive code due to performance and code size effects.
 */
//#define FLEA_USE_BUF_DBG_CANARIES // FBFLAGS_CORE_ON_OFF

#define FLEA_HAVE_HMAC              // FBFLAGS_MACALGS_ON_OFF
#define FLEA_HAVE_CMAC              // FBFLAGS_MACALGS_ON_OFF
#define FLEA_HAVE_EAX               // FBLAGS_AEALGS_ON_OFF

#define FLEA_HAVE_MD5               // FBFLAGS_MD5_ON_OFF
#define FLEA_HAVE_SHA1              // FBFLAGS_SHA1_ON_OFF
#define FLEA_HAVE_SHA224_256        // NOT CONFIGURABLE
#define FLEA_HAVE_SHA384_512        // FBFLAGS_HAVE_SHA512_ON_OFF
#define FLEA_HAVE_DAVIES_MEYER_HASH // FBFLAGS_DAVIES_MEYER_HASH_ON_OFF

/**
 * Configuration
 */
#define FLEA_USE_MD5_ROUND_MACRO    // FBFLAGS_MD5_ON_OFF
#define FLEA_USE_SHA1_ROUND_MACRO   // FBFLAGS_SHA1_ON_OFF
#define FLEA_USE_SHA256_ROUND_MACRO // FBFLAGS_SHA256_ON_OFF
#define FLEA_USE_SHA512_ROUND_MACRO // FBFLAGS_SHA512_ON_OFF

#define FLEA_HAVE_DES               // FBFLAGS_HAVE_DES_ON_OFF
#define FLEA_HAVE_TDES_2KEY         // FBFLAGS_HAVE_TDES_ON_OFF
#define FLEA_HAVE_TDES_3KEY         // FBFLAGS_HAVE_TDES_ON_OFF
#define FLEA_HAVE_DESX              // FBFLAGS_HAVE_DESX_ON_OFF
#define FLEA_HAVE_AES               // NOT CONFIGURABLE

/**
 * If set, then AES block decryption and ECB and CBC mode are enabled. Otherwise
 * only the AES block encryption is available, which is sufficient for both
 * directions in CTR mode.
 */
#define FLEA_HAVE_AES_BLOCK_DECR  // FBFLAGS_AES_ON_OFF
#define FLEA_USE_SMALL_AES        // FBFLAGS_AES_ON_OFF

#define FLEA_HAVE_RSA             // FBFLAGS_PKALGS_ON_OFF
#define FLEA_HAVE_ECDSA           // FBFLAGS_PKALGS_ON_OFF
#define FLEA_HAVE_ECKA            // FBFLAGS_PKALGS_ON_OFF

/**
 * Choose 5 for greatest speed and 1 for smallest RAM footprint.
 */
#define FLEA_CRT_RSA_WINDOW_SIZE 5            // FBFLAGS__INT_LIST 1 2 3 4 5
/**
 * A window size of up to 5 is beneficial for single point multiplications even
 * for 112 bit curves.
 */
#define FLEA_ECC_SINGLE_MUL_MAX_WINDOW_SIZE 5 // FBFLAGS__INT_LIST 1 2 3 4 5

#define FLEA_RSA_MAX_KEY_BIT_SIZE 2048        // FBFLAGS__INT_LIST 1024 1536 2048
#define FLEA_ECC_MAX_MOD_BIT_SIZE 521         // FBFLAGS__INT_LIST 112 128 160 192 224 256 320 384 521

/**
 * Don't change this.
 */
#define FLEA_HAVE_32BIT_WORD // NOT CONFIGURABLE

/**
 * Don't change this.
 */
#define FLEA_HAVE_DTL_32BIT // FBFLAGS_DTL_32_BIT_ON_OFF

// include must remain at the very end:
#include "internal/common/build_config_util.h"



#endif /* h-guard */
