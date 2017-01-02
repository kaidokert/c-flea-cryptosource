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


#ifndef __flea_aes_H_
#define __flea_aes_H_

#include "flea/types.h"
#include "flea/block_cipher.h"

#define FLEA_AES256_KEY_BYTE_LENGTH 32
#define FLEA_AES192_KEY_BYTE_LENGTH 24
#define FLEA_AES128_KEY_BYTE_LENGTH 16
#define FLEA_AES_BLOCK_LENGTH       16

void flea_aes_decrypt_block(const flea_ecb_mode_ctx_t* ctx, const flea_u8_t* ct, flea_u8_t* pt);

void flea_aes_encrypt_block(const flea_ecb_mode_ctx_t* ctx,  const flea_u8_t* pt, flea_u8_t* ct);

void flea_aes_setup_encr_key(flea_ecb_mode_ctx_t* ctx, const flea_u8_t* key);

flea_err_t THR_flea_aes_setup_encr_key(flea_ecb_mode_ctx_t* ctx, const flea_u8_t* key);

flea_err_t THR_flea_aes_setup_decr_key(flea_ecb_mode_ctx_t* ctx, const flea_u8_t* key);

#endif /* h-guard */
