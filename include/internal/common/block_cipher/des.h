

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


#include "flea/types.h"
#include "flea/block_cipher.h"

/**
 * The lowest bit of each byte is unused.
 */
flea_err_t THR_flea_single_des_setup_key(flea_ecb_mode_ctx_t* ctx__p_t, const flea_u8_t *key);

flea_err_t THR_flea_single_des_setup_key_with_key_offset(flea_ecb_mode_ctx_t* ctx__p_t, flea_al_u16_t expanded_key_offset__alu16,  const flea_u8_t *key);


void flea_single_des_encrypt_block(const flea_ecb_mode_ctx_t* ctx__p_t, const flea_u8_t* input__pc_u8, flea_u8_t* output__p_u8);

void flea_single_des_encrypt_block_with_key_offset(const flea_ecb_mode_ctx_t* ctx__p_t, flea_al_u16_t expanded_key_offset__alu16, const flea_u8_t* input__pc_u8, flea_u8_t* output__p_u8);


void flea_single_des_decrypt_block(const flea_ecb_mode_ctx_t* ctx__p_t, const flea_u8_t* input__pc_u8, flea_u8_t* output__p_u8);

void flea_single_des_decrypt_block_with_key_offset(const flea_ecb_mode_ctx_t* ctx__p_t, flea_al_u16_t expanded_key_offset__alu16, const flea_u8_t* input__pc_u8, flea_u8_t* output__p_u8);





