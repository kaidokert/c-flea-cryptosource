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


#include "internal/common/default.h"
#include "internal/common/block_cipher/des.h"
#include "internal/common/block_cipher/desx.h"
#include "flea/alloc.h"
#include "flea/bin_utils.h"
#include "flea/error_handling.h"
#include "flea/block_cipher.h"

#define  FLEA_DES_BLOCK_SIZE 8

#if defined FLEA_HAVE_DES && defined FLEA_HAVE_DESX

flea_err_t THR_flea_desx_setup_key (flea_ecb_mode_ctx_t* ctx__pt,   const flea_u8_t *key)
{
  FLEA_THR_BEG_FUNC();

  FLEA_CCALL(THR_flea_single_des_setup_key(ctx__pt, key));
  memcpy(ctx__pt->expanded_key__bu8 + 32, key + 8, 2 * FLEA_DES_BLOCK_SIZE);
  FLEA_THR_FIN_SEC_empty();
}

void flea_desx_encrypt_block (const flea_ecb_mode_ctx_t* ctx__pt, const flea_u8_t* input__pcu8, flea_u8_t* output__pu8)
{
  flea__xor_bytes(output__pu8, ((const flea_u8_t*)(ctx__pt->expanded_key__bu8 + 32)), input__pcu8, FLEA_DES_BLOCK_SIZE);
  flea_single_des_encrypt_block(ctx__pt, output__pu8, output__pu8);
  flea__xor_bytes_in_place(output__pu8, ((const flea_u8_t*)(ctx__pt->expanded_key__bu8 + 32)) + FLEA_DES_BLOCK_SIZE, FLEA_DES_BLOCK_SIZE);
}

void flea_desx_decrypt_block (const flea_ecb_mode_ctx_t* ctx__pt, const flea_u8_t* input__pcu8, flea_u8_t* output__pu8)
{
  flea__xor_bytes(output__pu8, ((const flea_u8_t*)(ctx__pt->expanded_key__bu8 + 32)) + FLEA_DES_BLOCK_SIZE, input__pcu8, FLEA_DES_BLOCK_SIZE);
  flea_single_des_decrypt_block(ctx__pt, output__pu8, output__pu8);
  flea__xor_bytes_in_place(output__pu8, ((const flea_u8_t*)(ctx__pt->expanded_key__bu8 + 32)), FLEA_DES_BLOCK_SIZE);
}

#endif // #if defined FLEA_HAVE_DES && defined FLEA_HAVE_DESX
