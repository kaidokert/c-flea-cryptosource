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


#ifndef _flea_ecdsa__H_
#define _flea_ecdsa__H_

#include "flea/types.h"

#ifdef __cplusplus
extern "C" {
#endif


/**
 * Verify an ECDSA signature on a hash value.
 *
 * @param enc_r big endian encoded value of the signature part r
 * @param enc_r_len length of encr_r
 * @param enc_s big endian encoded value of the signature part s
 * @param enc_s_len length of encr_r
 * @param message the hash value that was signed
 * @param message_len the length of message
 * @param dp pointer to the domain parameters in the flea internal format
 * associated with the key
 * @param pub_point_enc the encoded public point
 * @param pub_point_enc_len the length of pub_point_enc
 *
 * @return flea error code: FLEA_ERR_FINE on success verification, FLEA_ERR_INV_SIGNATURE if the signature is
 * invalid
 *
 */
flea_err_t THR_flea_ecdsa__raw_verify(const flea_u8_t* enc_r, flea_al_u8_t enc_r_len, const flea_u8_t* enc_s, flea_al_u8_t enc_s_len, const flea_u8_t* message, flea_al_u8_t message_len, const flea_u8_t * dp, const flea_u8_t* pub_point_enc,  flea_al_u8_t pub_point_enc_len);

/**
 * Generate an ECDSA signature on a hash value.
 *
 * @param result_r pointer to the memory area where to store the signature part r
 * @param result_r_len the length of result_r
 * @param result_r pointer to the memory area where to store the signature part s
 * @param result_s_len the length of result_s
 * @param message the hash value that to be signed signed
 * @param message_len the length of message
 * @param dp pointer to the domain parameters in the flea internal format
 * @param priv_key_enc the big endian encoded private key value
 * @param priv_key_enc_len the length of priv_key_enc
 *
 * @return flea error code
 */
flea_err_t THR_flea_ecdsa__raw_sign(flea_u8_t* result_r, flea_al_u8_t* result_r_len, flea_u8_t* result_s, flea_al_u8_t* result_s_len, const flea_u8_t* message, flea_al_u8_t message_len, const flea_u8_t* dp, const flea_u8_t* priv_key_enc, flea_al_u8_t priv_key_enc_len);

#ifdef __cplusplus
}
#endif

#endif /* h-guard */
