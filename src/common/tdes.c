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


#include "internal/common/block_cipher/tdes.h"
#include "internal/common/default.h"
#include "internal/common/block_cipher/des.h"
#include "flea/alloc.h"
#include "flea/error_handling.h"
#include "flea/block_cipher.h"

#ifdef FLEA_HAVE_DES
#ifdef FLEA_HAVE_TDES_2KEY
/**
 * expects the key as k1||k2 where TDES_ENC(m) =
 * DES_ENC_k1(DES_DEC_k2(DES_ENC_k1(m)))
 */
flea_err_t THR_flea_triple_des_ede_2key_setup_key (flea_ecb_mode_ctx_t* ctx__pt,  const flea_u8_t *key)
{
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_single_des_setup_key(ctx__pt, key));
  FLEA_CCALL(THR_flea_single_des_setup_key_with_key_offset(ctx__pt, 32, key + 8));
  FLEA_THR_FIN_SEC_empty();
}

void flea_triple_des_ede_2key_encrypt_block (const flea_ecb_mode_ctx_t* ctx__pt, const flea_u8_t* input__pcu8, flea_u8_t* output__pu8)
{
  flea_single_des_encrypt_block(ctx__pt, input__pcu8, output__pu8);
  flea_single_des_decrypt_block_with_key_offset(ctx__pt, 32, output__pu8, output__pu8);
  flea_single_des_encrypt_block(ctx__pt, output__pu8, output__pu8);
}

void flea_triple_des_ede_2key_decrypt_block (const flea_ecb_mode_ctx_t* ctx__pt, const flea_u8_t* input__pcu8, flea_u8_t* output__pu8)
{
  flea_single_des_decrypt_block(ctx__pt, input__pcu8, output__pu8);
  flea_single_des_encrypt_block_with_key_offset(ctx__pt, 32, output__pu8, output__pu8);
  flea_single_des_decrypt_block(ctx__pt, output__pu8, output__pu8);
}
#endif // #ifdef FLEA_HAVE_TDES_2KEY
#ifdef FLEA_HAVE_TDES_3KEY
/**
 * expects the key as k1||k2||k3 where TDES_ENC(m) =
 * DES_ENC_k1(DES_DEC_k2(DES_ENC_k3(m)))
 */
flea_err_t THR_flea_triple_des_ede_3key_setup_key (flea_ecb_mode_ctx_t* ctx__pt,  const flea_u8_t *key)
{
  FLEA_THR_BEG_FUNC();

  FLEA_CCALL(THR_flea_single_des_setup_key(ctx__pt, key));
  FLEA_CCALL(THR_flea_single_des_setup_key_with_key_offset(ctx__pt, 32, key + 8));
  FLEA_CCALL(THR_flea_single_des_setup_key_with_key_offset(ctx__pt, 64, key + 16));
  FLEA_THR_FIN_SEC_empty();
}

void flea_triple_des_ede_3key_encrypt_block (const flea_ecb_mode_ctx_t* ctx__pt, const flea_u8_t* input__pcu8, flea_u8_t* output__pu8)
{
  flea_single_des_encrypt_block(ctx__pt, input__pcu8, output__pu8);
  flea_single_des_decrypt_block_with_key_offset(ctx__pt, 32, output__pu8, output__pu8);
  flea_single_des_encrypt_block_with_key_offset(ctx__pt, 64, output__pu8, output__pu8);
}

void flea_triple_des_ede_3key_decrypt_block (const flea_ecb_mode_ctx_t* ctx__pt, const flea_u8_t* input__pcu8, flea_u8_t* output__pu8)
{
  flea_single_des_decrypt_block_with_key_offset(ctx__pt, 64, input__pcu8, output__pu8);
  flea_single_des_encrypt_block_with_key_offset(ctx__pt, 32, output__pu8, output__pu8);
  flea_single_des_decrypt_block(ctx__pt, output__pu8, output__pu8);
}
#endif  // #ifdef FLEA_HAVE_TDES_3KEY
#endif  // #ifdef FLEA_HAVE_DES
