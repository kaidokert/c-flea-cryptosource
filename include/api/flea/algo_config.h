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


#ifndef _flea_algo_config__H_
#define _flea_algo_config__H_

#include "internal/common/algo_len_int.h"


/**
 * Maximal size of the
 */
#define FLEA_RSA_CRT_KEY_INTERNAL_FORMAT_MAX_SIZE ((((FLEA_RSA_MAX_KEY_BIT_SIZE)+7) / 8) * 5)

/**
 * Maximal length of the ECDSA signature in simple concatenation format
 */
#define FLEA_ECDSA_MAX_SIG_LEN ((FLEA_ECC_MAX_MOD_BYTE_SIZE * 2))

/**
 * the maximal output length in bytes of the supported hash algorithms.
 */
#define FLEA_MAX_HASH_OUT_LEN __FLEA_COMPUTED_MAX_HASH_OUT_LEN

/**
 * Maximal size of an encoded public key.
 */
#define FLEA_PK_MAX_PUBKEY_LEN __FLEA_COMPUTED_MAX_PUBKEY_LEN

/**
 * Maximal length of a private key of a public key scheme
 */
#define FLEA_PK_MAX_PRIVKEY_LEN __FLEA_COMPUTED_PK_MAX_ASYM_PRIVKEY_LEN
/**
 * Maximal length of a signature of a public key scheme
 */
#define FLEA_PK_MAX_SIGNATURE_LEN __FLEA_COMPUTED_MAX_ASYM_SIG_LEN
/**
 * Maximal output length of a raw public key scheme function
 */
#define FLEA_PK_MAX_PRIMITIVE_INPUT_LEN __FLEA_COMPUTED_ASYM_PRIMITIVE_INPUT_LEN
/**
 * Maximal input length of a raw public key scheme function
 */
#define FLEA_PK_MAX_PRIMITIVE_OUTPUT_LEN __FLEA_COMPUTED_ASYM_MAX_PRIMITIVE_OUTPUT_LEN

#endif /* h-guard */
