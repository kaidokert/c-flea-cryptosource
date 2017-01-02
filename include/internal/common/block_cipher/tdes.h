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



#ifndef _flea_tdes__H_
#define _flea_tdes__H_

#include "flea/types.h"
#include "flea/block_cipher.h"
#include "internal/common/block_cipher/tdes.h"

flea_err_t THR_flea_triple_des_ede_2key_setup_key(flea_ecb_mode_ctx_t* ctx__pt,  const flea_u8_t *key);

void flea_triple_des_ede_2key_encrypt_block(const flea_ecb_mode_ctx_t* ctx__pt, const flea_u8_t* input__pcu8, flea_u8_t* output__pu8);

void flea_triple_des_ede_2key_decrypt_block(const flea_ecb_mode_ctx_t* ctx__pt, const flea_u8_t* input__pcu8, flea_u8_t* output__pu8);

flea_err_t THR_flea_triple_des_ede_3key_setup_key(flea_ecb_mode_ctx_t* ctx__pt,  const flea_u8_t *key);

void flea_triple_des_ede_3key_encrypt_block(const flea_ecb_mode_ctx_t* ctx__pt, const flea_u8_t* input__pcu8, flea_u8_t* output__pu8);

void flea_triple_des_ede_3key_decrypt_block(const flea_ecb_mode_ctx_t* ctx__pt, const flea_u8_t* input__pcu8, flea_u8_t* output__pu8);

#endif /* h-guard */
