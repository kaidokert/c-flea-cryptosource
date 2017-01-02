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
#include "flea/error_handling.h"
#include "flea/error.h"
#include "flea/alloc.h"
#include  "flea/rsa.h"
#include  "flea/block_cipher.h"
#include <string.h>

flea_err_t THR_flea_test_cbc_mode ()
{
  // from https://tools.ietf.org/html/rfc3602
  const flea_u8_t aes128_cbc_key[] = { 0x56, 0xe4, 0x7a, 0x38, 0xc5, 0x59, 0x89, 0x74, 0xbc, 0x46, 0x90, 0x3d, 0xba, 0x29, 0x03, 0x49 };
  const flea_u8_t aes128_cbc_iv[] = { 0x8c, 0xe8, 0x2e, 0xef, 0xbe, 0xa0, 0xda, 0x3c, 0x44, 0x69, 0x9e, 0xd7, 0xdb, 0x51, 0xb7, 0xd9 };


  const flea_u8_t aes128_cbc_pt[]  = {
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
    0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
    0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf
  };

  const flea_u8_t aes128_cbc_exp_ct[] = {
    0xc3, 0x0e, 0x32, 0xff, 0xed, 0xc0, 0x77, 0x4e, 0x6a, 0xff, 0x6a, 0xf0, 0x86, 0x9f, 0x71, 0xaa,
    0x0f, 0x3a, 0xf0, 0x7a, 0x9a, 0x31, 0xa9, 0xc6, 0x84, 0xdb, 0x20, 0x7e, 0xb0, 0xef, 0x8e, 0x4e,
    0x35, 0x90, 0x7a, 0xa6, 0x32, 0xc3, 0xff, 0xdf, 0x86, 0x8b, 0xb7, 0xb2, 0x9d, 0x3d, 0x46, 0xad,
    0x83, 0xce, 0x9f, 0x9a, 0x10, 0x2e, 0xe9, 0x9d, 0x49, 0xa5, 0x3e, 0x87, 0xf4, 0xc3, 0xda, 0x55
  };

  flea_dtl_t max_ct_size = sizeof(aes128_cbc_pt);
  const flea_u8_t* in_ptr__pcu8;
  flea_u8_t* out_ptr__pu8;

  FLEA_DECL_OBJ(encr_ctx__t, flea_cbc_mode_ctx_t);
#ifdef FLEA_HAVE_AES_BLOCK_DECR
  FLEA_DECL_OBJ(decr_ctx__t, flea_cbc_mode_ctx_t);
#endif
  FLEA_DECL_BUF(encr__bu8, flea_u8_t, max_ct_size);
  FLEA_DECL_BUF(decr__bu8, flea_u8_t, max_ct_size);

  flea_u8_t block_len__u8 = 16; // AES
  FLEA_THR_BEG_FUNC();

  FLEA_ALLOC_BUF(encr__bu8, max_ct_size);
  FLEA_ALLOC_BUF(decr__bu8, max_ct_size);

  FLEA_CCALL(THR_flea_cbc_mode__encrypt_data(flea_aes128, aes128_cbc_key, sizeof(aes128_cbc_key), aes128_cbc_iv, sizeof(aes128_cbc_iv), encr__bu8, aes128_cbc_pt, sizeof(aes128_cbc_pt)));
  if(memcmp(encr__bu8, aes128_cbc_exp_ct, sizeof(aes128_cbc_exp_ct)))
  {
    FLEA_THROW("error with CBC encrypted result (1)", FLEA_ERR_FAILED_TEST);
  }
#ifdef FLEA_HAVE_AES_BLOCK_DECR
  FLEA_CCALL(THR_flea_cbc_mode__decrypt_data(flea_aes128, aes128_cbc_key, sizeof(aes128_cbc_key), aes128_cbc_iv, sizeof(aes128_cbc_iv), decr__bu8, encr__bu8, sizeof(aes128_cbc_pt)));

  if(memcmp(decr__bu8, aes128_cbc_pt, sizeof(aes128_cbc_pt)))
  {
    FLEA_THROW("error with CBC decrypted result (1)", FLEA_ERR_FAILED_TEST);
  }
#else // #ifdef FLEA_HAVE_AES_BLOCK_DECR
  if(FLEA_ERR_INV_ALGORITHM != THR_flea_cbc_mode__decrypt_data(flea_aes128, aes128_cbc_key, sizeof(aes128_cbc_key), aes128_cbc_iv, sizeof(aes128_cbc_iv), decr__bu8, encr__bu8, sizeof(aes128_cbc_pt)))
  {
    FLEA_THROW("error with unsupported decryption", FLEA_ERR_FAILED_TEST);
  }
#endif // #else of #ifdef FLEA_HAVE_AES_BLOCK_DECR

  // now try update functionality

  memset(encr__bu8, 0, max_ct_size);
  memset(decr__bu8, 0, max_ct_size);
  FLEA_CCALL(THR_flea_cbc_mode_ctx_t__ctor(&encr_ctx__t, flea_aes128, aes128_cbc_key, sizeof(aes128_cbc_key), aes128_cbc_iv, sizeof(aes128_cbc_iv), flea_encrypt));
#ifdef FLEA_HAVE_AES_BLOCK_DECR
  FLEA_CCALL(THR_flea_cbc_mode_ctx_t__ctor(&decr_ctx__t, flea_aes128, aes128_cbc_key, sizeof(aes128_cbc_key), aes128_cbc_iv, sizeof(aes128_cbc_iv), flea_decrypt));
#endif // #ifdef FLEA_HAVE_AES_BLOCK_DECR

  in_ptr__pcu8 = aes128_cbc_pt;
  out_ptr__pu8 = encr__bu8;;
  FLEA_CCALL(THR_flea_cbc_mode_ctx_t__crypt(&encr_ctx__t, in_ptr__pcu8, out_ptr__pu8, block_len__u8));
  in_ptr__pcu8 += block_len__u8;
  out_ptr__pu8 += block_len__u8;
  FLEA_CCALL(THR_flea_cbc_mode_ctx_t__crypt(&encr_ctx__t, in_ptr__pcu8, out_ptr__pu8, 2 * block_len__u8));
  in_ptr__pcu8 += 2 * block_len__u8;
  out_ptr__pu8 += 2 * block_len__u8;
  FLEA_CCALL(THR_flea_cbc_mode_ctx_t__crypt(&encr_ctx__t, in_ptr__pcu8, out_ptr__pu8, block_len__u8));
  if(memcmp(encr__bu8, aes128_cbc_exp_ct, sizeof(aes128_cbc_exp_ct)))
  {
    FLEA_THROW("error with CBC encrypted result (2)", FLEA_ERR_FAILED_TEST);
  }

#ifdef FLEA_HAVE_AES_BLOCK_DECR
  in_ptr__pcu8 = encr__bu8;
  out_ptr__pu8 = encr__bu8;
  FLEA_CCALL(THR_flea_cbc_mode_ctx_t__crypt(&decr_ctx__t, in_ptr__pcu8, out_ptr__pu8, block_len__u8));
  in_ptr__pcu8 += block_len__u8;
  out_ptr__pu8 += block_len__u8;
  FLEA_CCALL(THR_flea_cbc_mode_ctx_t__crypt(&decr_ctx__t, in_ptr__pcu8, out_ptr__pu8, 2 * block_len__u8));
  in_ptr__pcu8 += 2 * block_len__u8;
  out_ptr__pu8 += 2 * block_len__u8;
  FLEA_CCALL(THR_flea_cbc_mode_ctx_t__crypt(&decr_ctx__t, in_ptr__pcu8, out_ptr__pu8, block_len__u8));

  if(memcmp(encr__bu8, aes128_cbc_pt, sizeof(aes128_cbc_pt)))
  {
    FLEA_THROW("error with CBC decrypted result (3)", FLEA_ERR_FAILED_TEST);
  }
#endif // #ifdef FLEA_HAVE_AES_BLOCK_DECR

  // set up encryptor again
  flea_cbc_mode_ctx_t__dtor(&encr_ctx__t);
  FLEA_CCALL(THR_flea_cbc_mode_ctx_t__ctor(&encr_ctx__t, flea_aes128, aes128_cbc_key, sizeof(aes128_cbc_key), aes128_cbc_iv, sizeof(aes128_cbc_iv), flea_encrypt));
// encrypt in place
  in_ptr__pcu8 = aes128_cbc_pt;
  out_ptr__pu8 = encr__bu8;
  FLEA_CCALL(THR_flea_cbc_mode_ctx_t__crypt(&encr_ctx__t, in_ptr__pcu8, out_ptr__pu8, block_len__u8));
  in_ptr__pcu8 += block_len__u8;
  out_ptr__pu8 += block_len__u8;
  FLEA_CCALL(THR_flea_cbc_mode_ctx_t__crypt(&encr_ctx__t, in_ptr__pcu8, out_ptr__pu8, 2 * block_len__u8));
  in_ptr__pcu8 += 2 * block_len__u8;
  out_ptr__pu8 += 2 * block_len__u8;
  FLEA_CCALL(THR_flea_cbc_mode_ctx_t__crypt(&encr_ctx__t, in_ptr__pcu8, out_ptr__pu8, block_len__u8));
  if(memcmp(encr__bu8, aes128_cbc_exp_ct, sizeof(aes128_cbc_exp_ct)))
  {
    FLEA_THROW("error with CBC encrypted result (4)", FLEA_ERR_FAILED_TEST);
  }

  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(encr__bu8);
    FLEA_FREE_BUF_FINAL(decr__bu8);
    flea_cbc_mode_ctx_t__dtor(&encr_ctx__t);
    FLEA_DO_IF_HAVE_AES_BLOCK_DECR(flea_cbc_mode_ctx_t__dtor(&decr_ctx__t); );
    );

}
