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


#ifndef _flea_ecka__H_
#define _flea_ecka__H_

#include "flea/types.h"
#include "flea/hash.h"

#ifdef __cplusplus
extern "C" {
#endif


/**
 * Carry out the EC key agreement operation as specified in ANSI X9.63 and BSI TR-03111 v2.0 (Sec. 4.3)
 *
 * @param public_point_enc the encoded public point of the other party
 * @param public_point_enc_len the length of public_point_enc
 * @param secret_key the secret key, big endian encoded
 * @param secret_key_len the length of secret_key
 * @param enc_dp pointer to the domain parameters in flea's internal format
 * @param result pointer to the memory area where to store the computation
 * result
 * @param result_len the caller must provide a pointer to a value which contains
 * the available length of result. when the function returns, *result_len will
 * contain the length of the data set in result
 *
 * @return flea error code
 *
 */
flea_err_t THR_flea_ecka__compute_raw(const flea_u8_t* public_point_enc, flea_al_u8_t public_point_enc_len, const flea_u8_t* secret_key, flea_al_u8_t secret_key_len, const flea_u8_t* enc_dp, flea_u8_t* result, flea_al_u8_t* result_len);

/**
 * Carry out the EC key agreement operation using ANSI X9.63 key derivation
 * function.
 *
 * @param hash_id id of the hash algorithm to use in the key derivation function
 * @param public_point_enc the encoded public point of the other party
 * @param public_point_enc_len the length of public_point_enc
 * @param secret_key the secret key, big endian encoded
 * @param secret_key_len the length of secret_key
 * @param enc_dp pointer to the domain parameters in flea's internal format
 * @param shared_info shared info value to be used in the key derivation
 * function, may be NULL, then also its length must be 0
 * @param shared_info_len the length of shared_info
 * @param result pointer to the memory area where to store the computation
 * result
 * @param result_len the caller must provide a pointer to a value which contains
 * the available length of result. when the function returns, *result_len will
 * contain the length of the data set in result
 *
 * @return flea error code
 *
 */
flea_err_t THR_flea_ecka__compute_kdf_ansi_x9_63(flea_hash_id_t hash_id, const flea_u8_t* public_point_enc, flea_al_u8_t public_point_enc_len, const flea_u8_t* secret_key, flea_al_u8_t secret_key_len, const flea_u8_t* enc_dp, const flea_u8_t* shared_info, flea_al_u16_t shared_info_len, flea_u8_t* result, flea_al_u16_t result_len);

#ifdef __cplusplus
}
#endif

#endif /* h-guard */
