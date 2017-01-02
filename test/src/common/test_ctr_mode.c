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



#include "flea/block_cipher.h"
#include "flea/error_handling.h"
#include "flea/error.h"
#include "flea/alloc.h"
#include <string.h>
#include <stdio.h>

flea_err_t THR_flea_test_ctr_mode_1 ()
{
  flea_u8_t key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
  flea_u8_t nonce[] = { 0xAB, 0xCD, 0xEF };
  flea_u32_t nonce_int = 0xABCDEF00;
  flea_u8_t message[] = { 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02,
                          0x00, 0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00,
                          0x03, 0xFF };
  flea_u8_t exp_ct[] = {
    0x26, 0x1d, 0x1d, 0xf5, 0x61, 0xc2, 0xed, 0xf2, 0xf8, 0x39, 0x15, 0xab, 0x4e, 0xe5, 0x1c, 0x2a,
    0xc4, 0x69, 0x74, 0x45, 0xd7, 0x21, 0x37, 0x09, 0x6a, 0xfb, 0x95, 0xc7, 0xcc, 0x39, 0xda, 0xef,
    0xa7, 0x77
  };
  flea_u8_t decr[sizeof(message)];
  flea_u8_t encr[sizeof(message)];
  flea_u8_t message_length = sizeof(message);
  flea_al_u8_t key_length = sizeof(key);
  flea_al_u8_t nonce_length = sizeof(nonce);

  FLEA_DECL_OBJ(ctx, flea_ctr_mode_ctx_t);
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_ctr_mode_ctx_t__ctor(&ctx, flea_aes128, key, key_length, nonce, nonce_length));
  flea_ctr_mode_ctx_t__crypt(&ctx, message, encr, message_length);
  if(memcmp(encr, exp_ct, message_length))
  {
    FLEA_THROW("error with encryption result for counter mode with aes", FLEA_ERR_FAILED_TEST);
  }
  flea_ctr_mode_ctx_t__dtor(&ctx);
  FLEA_CCALL(THR_flea_ctr_mode_ctx_t__ctor(&ctx, flea_aes128, key, key_length, nonce, nonce_length));
  flea_ctr_mode_ctx_t__crypt(&ctx, encr, decr, message_length);
  if(memcmp(decr, message, message_length))
  {
    FLEA_THROW("error with decryption result for counter mode with aes", FLEA_ERR_FAILED_TEST);
  }

  memset(encr, 0, sizeof(message));
  FLEA_CCALL(THR_flea_ctr_mode_crypt_data(flea_aes128, key, key_length, nonce, nonce_length, message, encr, message_length));
  if(memcmp(encr, exp_ct, message_length))
  {
    FLEA_THROW("error with encryption result for counter mode with aes (convenience function)", FLEA_ERR_FAILED_TEST);
  }

  memset(encr, 0, sizeof(message));
  FLEA_CCALL(THR_flea_ctr_mode_crypt_data_short_nonce(flea_aes128, key, key_length, nonce_int, message, encr, message_length));
  if(memcmp(encr, exp_ct, message_length))
  {
    FLEA_THROW("error with encryption result for counter mode with aes (convenience function)", FLEA_ERR_FAILED_TEST);
  }
  FLEA_THR_FIN_SEC(
    flea_ctr_mode_ctx_t__dtor(&ctx);
    );

}


flea_err_t THR_flea_test_ctr_mode_parts ()
{
  flea_u8_t key[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
  flea_u8_t nonce[] = { 0xAB, 0xCD, 0xEF };

  flea_u8_t message_arr[] = { 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02,
                              0x00, 0x01, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00,
                              0x03, 0xFF };
  flea_u8_t exp_ct[] = {
    0x26, 0x1d, 0x1d, 0xf5, 0x61, 0xc2, 0xed, 0xf2, 0xf8, 0x39, 0x15, 0xab, 0x4e, 0xe5, 0x1c, 0x2a,
    0xc4, 0x69, 0x74, 0x45, 0xd7, 0x21, 0x37, 0x09, 0x6a, 0xfb, 0x95, 0xc7, 0xcc, 0x39, 0xda, 0xef,
    0xa7, 0x77
  };
  flea_u8_t decr_arr[sizeof(message_arr)];
  flea_u8_t encr_arr[sizeof(message_arr)];
  flea_u8_t message_length = sizeof(message_arr);
  flea_al_u8_t key_length = sizeof(key);
  flea_al_u8_t nonce_length = sizeof(nonce);
  flea_u8_t* message = message_arr;
  flea_u8_t* decr = decr_arr;
  flea_u8_t* encr = encr_arr;
  flea_al_u16_t part_size;

  FLEA_DECL_OBJ(ctx, flea_ctr_mode_ctx_t);
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_ctr_mode_ctx_t__ctor(&ctx, flea_aes128, key, key_length, nonce, nonce_length));
  part_size = 1;
  flea_ctr_mode_ctx_t__crypt(&ctx, message, encr, part_size);
  message_length -= part_size;
  encr += part_size;
  message += part_size;

  part_size = 16;
  flea_ctr_mode_ctx_t__crypt(&ctx, message, encr, part_size);
  message_length -= part_size;
  encr += part_size;
  message += part_size;

  part_size = 1;
  flea_ctr_mode_ctx_t__crypt(&ctx, message, encr, part_size);
  message_length -= part_size;
  encr += part_size;
  message += part_size;

  part_size = 3;
  flea_ctr_mode_ctx_t__crypt(&ctx, message, encr, part_size);
  message_length -= part_size;
  encr += part_size;
  message += part_size;

  part_size = 0;
  flea_ctr_mode_ctx_t__crypt(&ctx, message, encr, part_size);
  message_length -= part_size;
  encr += part_size;
  message += part_size;

  part_size = 3;
  flea_ctr_mode_ctx_t__crypt(&ctx, message, encr, part_size);
  message_length -= part_size;
  encr += part_size;
  message += part_size;

  part_size = message_length;
  flea_ctr_mode_ctx_t__crypt(&ctx, message, encr, part_size);
  message_length -= part_size;
  encr += part_size;
  message += part_size;

  if(memcmp(encr_arr, exp_ct, sizeof(message_arr)))
  {
    FLEA_THROW("error with encryption result for counter mode with aes", FLEA_ERR_FAILED_TEST);
  }
  flea_ctr_mode_ctx_t__dtor(&ctx);
  FLEA_CCALL(THR_flea_ctr_mode_ctx_t__ctor(&ctx, flea_aes128, key, key_length, nonce, nonce_length));
  message_length = sizeof(message_arr);
  encr = encr_arr;
  part_size = 33;
  flea_ctr_mode_ctx_t__crypt(&ctx, encr, decr, part_size);
  encr += part_size;
  decr += part_size;
  message_length -= part_size;
  flea_ctr_mode_ctx_t__crypt(&ctx, encr, decr, message_length);

  if(memcmp(decr_arr, message_arr, sizeof(message_arr)))
  {
    FLEA_THROW("error with decryption result for counter mode with aes", FLEA_ERR_FAILED_TEST);
  }

  FLEA_THR_FIN_SEC(
    flea_ctr_mode_ctx_t__dtor(&ctx);
    );

}
