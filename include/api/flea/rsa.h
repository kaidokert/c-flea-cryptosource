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


#ifndef _flea_rsa__H_
#define _flea_rsa__H_

#ifdef __cplusplus
extern "C" {
#endif


#include "internal/common/build_config.h"
#include  "flea/types.h"


/**
 *  RSA 2048-bit private raw operation.
 *  @param result_arr array to receive the big endian encoded exponentiation
 *  result. Must have length of the modulus.
 *  @param exponent_enc big endian encoded exponent used in the exponentiation.
 *  @param exponent_length length of the exponent_enc array
 *  @param base_enc big endian encoded base used in the exponentiation
 *  @param base_length length of the base_enc array
 *  @param modulus_enc big endian encoded modulus
 *  @param modulus_length length of the modulus_enc array
 *
 */
flea_err_t THR_flea_rsa_raw_operation(flea_u8_t* result_arr, const flea_u8_t * exponent_enc, flea_al_u16_t exponent_length, const flea_u8_t* base_enc, flea_al_u16_t base_length, const flea_u8_t * modulus_enc, flea_al_u16_t modulus_length  );

/**
 *  RSA 2048-bit private raw operation using chinese remainder theorem.
 *  @param result_enc array to receive the big endian encoded exponentiation
 *  result. Must have length of the modulus (modulus_length), may be equal to
 *  base (then base_length must be equal to modulus_length).
 *  @param base_enc big endian encoded base used in the exponentiation
 *  @param base_length length of the base_enc array
 *  @param modulus_length byte length of the modulus
 *  @param p_enc big endian encoded prime p of length modulus_length/2
 *  @param p_enc_len length of p_enc
 *  @param q_enc big endian encoded prime q of length modulus_length/2
 *  @param q_enc_len length of q_enc
 *  @param d1_enc big endian encoded exponent d mod (p-1) of length modulus_length/2
 *  @param d1_enc_len length of d1_enc
 *  @param d2_enc big endian encoded exponent d mod (q-1) of length modulus_length/2
 *  @param d2_enc_len length of d2_enc
 *  @param c_enc big endian encoded q^(-1) mod p of length modulus_length/2
 *  @param c_enc_len length of c_enc
 *
 *  @return flea error code
 *
 */
flea_err_t THR_flea_rsa_raw_operation_crt(
  flea_u8_t* result_enc,
  const flea_u8_t* base_enc,
  flea_al_u16_t base_length,
  flea_al_u16_t modulus_length,
  const flea_u8_t* p_enc,
  flea_mpi_ulen_t p_enc_len,
  const flea_u8_t * q_enc,
  flea_mpi_ulen_t q_enc_len,
  const flea_u8_t* d1_enc,
  flea_mpi_ulen_t d1_enc_len,
  const flea_u8_t* d2_enc,
  flea_mpi_ulen_t d2_enc_len,
  const flea_u8_t * c_enc,
  flea_mpi_ulen_t c_enc_len);

/**
 *  RSA 2048-bit private raw operation using chinese remainder theorem with the
 *  key given in flea's internal format. This format is given by the
 *  concatenation of the values of p,q,d1,d2,c, each having the half modulus
 *  length, e.g. 128 bytes in case of 2048-bit RSA.
 *
 *  @param result_enc array to receive the big endian encoded exponentiation
 *  result. Must have length of the modulus (modulus_length)
 *  @param base_enc big endian encoded base used in the exponentiation
 *  @param base_length length of the base_enc array
 *  @param modulus_length byte length of the modulus
 *  @param key pointer to the key in flea's internal format
 *  @param key_len the length of key, must be equal to  5*(modulus_length+1)/2
 */
flea_err_t THR_flea_rsa_raw_operation_crt_internal_key_format(
  flea_u8_t* result_enc,
  const flea_u8_t* base_enc,
  flea_al_u16_t base_length,
  flea_al_u16_t modulus_length,
  const flea_u8_t* key,
  flea_al_u16_t key_len
  );

#ifdef __cplusplus
}
#endif

#endif /* h-guard */
