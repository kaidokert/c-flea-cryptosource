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



#ifndef __flea_bin_utils_H_
#define __flea_bin_utils_H_

#include "flea/types.h"
/**
 * number of bits in a flea_uword_t
 */
#define FLEA_BITS_PER_WORD (sizeof(flea_uword_t) * 8)

/**
 * decode a 4-byte big endian array to an u32
 */
#define FLEA_DECODE_U32_BE(arr) (((flea_u32_t)(arr)[0] << 24) ^ ((flea_u32_t)(arr)[1] << 16) ^ ((flea_u32_t)(arr)[2] <<  8) ^ ((flea_u32_t)(arr)[3]))

/**
 * encode an u32 value into a 4-byte big endian array
 */
#define FLEA_ENCODE_U32_BE(u32_val, result_arr) do { (result_arr)[0] = (flea_u8_t)((u32_val) >> 24); (result_arr)[1] = (flea_u8_t)((u32_val) >> 16); (result_arr)[2] = (flea_u8_t)((u32_val) >>  8); (result_arr)[3] = (flea_u8_t)(u32_val); } while(0)


#ifdef __cplusplus
extern "C" {
#endif

/**
 * XOR bytes.
 *
 * @param bytes to be XORed with in2
 * @param in2 bytes to be XORed to in_out
 * @param len length of in_out and in2
 *
 */
void flea__xor_bytes_in_place(flea_u8_t* in_out, const flea_u8_t* in2, flea_dtl_t len);

/**
 * XOR bytes.
 * @param out result, contents will be overwritten
 * @param in1 first operand of the XOR operation
 * @param in2 second operand of the XOR operation
 * @param len the length of the out, in1 and in2
 *
 */
void flea__xor_bytes(flea_u8_t* out, const flea_u8_t* in1, const flea_u8_t* in2, flea_dtl_t len);

/**
 * Decode a 4-byte big endian encoded array.
 *
 * @param enc the 4-byte data to decode.
 *
 * @return the big endian decoded value of the input data.
 */
flea_u32_t flea__decode_U32_BE(const flea_u8_t enc[4]);

/**
 * Encode a 4-byte value big endian.
 *
 * @param to_enc the value to encode
 * @param res 4-byte memory location to store the encoded result.
 */
void flea__encode_U32_BE(flea_u32_t to_enc, flea_u8_t res[4]);

/**
 * Encode a 4-byte value little endian.
 *
 * @param to_enc the value to encode
 * @param res 4-byte memory location to store the encoded result.
 */
void flea__encode_U32_LE(flea_u32_t to_enc, flea_u8_t res[4]);

/**
 * Increment a big endian encoded integer value. Performs wrapparound to zero if
 * the integer already has the maximal possible value.
 *
 * @param ctr_block pointer to the encoded integer value
 * @param ctr_block_len the length of the counter
 */
void flea__increment_encoded_BE_int(flea_u8_t* ctr_block, flea_al_u8_t ctr_block_len);

/**
 * Compute the number of leading zero bits in a word.
 *
 * @param x the word
 *
 * @return the number of leading zero bits x
 */
flea_al_u8_t flea__nlz_uword(flea_uword_t x);

/**
 * Determine the bit length of a big endian encoded integer.
 *
 * @param enc pointer to the encoded integer
 * @param enc_len length of enc
 *
 * @return the bit length of the integer
 */
flea_mpi_ulen_t flea__get_BE_int_bit_len(const flea_u8_t* enc, flea_mpi_ulen_t enc_len);

#ifdef __cplusplus
}
#endif

#endif /* h-guard */
