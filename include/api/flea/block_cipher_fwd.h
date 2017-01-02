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



#ifndef _flea_block_cipher_fwd__H_
#define _flea_block_cipher_fwd__H_


#ifdef __cplusplus
extern "C" {
#endif

/**
 * Forward declaration for ecb_mode_ctx_t
 */
struct struct_flea_ecb_mode_ctx_t;

/**
 *  ECB mode context type.
 */
typedef struct struct_flea_ecb_mode_ctx_t flea_ecb_mode_ctx_t;

/**
 * supported block ciphers.
 */
typedef enum { flea_des_single, flea_tdes_2key, flea_tdes_3key, flea_desx, flea_aes128, flea_aes192, flea_aes256 } flea_block_cipher_id_t;

#ifdef __cplusplus
}
#endif


#endif /* h-guard */
