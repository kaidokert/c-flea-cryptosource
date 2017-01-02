
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
#include <stdlib.h>
#include <string.h>
#include "flea/error.h"
#include "flea/alloc.h"
#include "flea/array_util.h"
#include "flea/util.h"
#include "flea/pk_api.h"
#include "internal/common/pk_enc/oaep.h"
#include "test_data_rsa_key_internal_format.h"


/*
 * Reference test data created with Botan.
 */
#ifdef FLEA_HAVE_PK_CS
static flea_err_t THR_flea_test_oaep_sha1_and_pkcs1_v1_5_reference_ct ()
{
#if FLEA_RSA_MAX_KEY_BIT_SIZE >= 2048 && defined FLEA_HAVE_SHA1 && defined FLEA_HAVE_RSA
  const flea_u8_t ct_oaep[2048 / 8] =
  {
    0x1B, 0x12, 0x65, 0xC7, 0xCE, 0x34, 0x45, 0x5E, 0x58, 0x1C, 0xD8, 0xDD, 0x3E, 0x7D, 0xE2, 0x26, 0x2E, 0xB2, 0x4F, 0xD9, 0x56, 0x5C, 0xAB, 0xD6, 0xE6, 0x73, 0xEF, 0xFA, 0xD4, 0x1F, 0xD8, 0xF5, 0x4D, 0x6B, 0xD3, 0x70, 0xE7, 0x4C, 0x0B, 0x89, 0xC5, 0x73, 0xA9, 0x48, 0x16, 0x52, 0xD0, 0x5E, 0xC8, 0x00, 0xA3, 0x95, 0xFA, 0xCE, 0x2F, 0x87, 0x4E, 0xDE, 0x93, 0xEE, 0x9B, 0x3B, 0x5C, 0x96, 0x66, 0x43, 0x4A, 0x62, 0x34, 0x40, 0xAF, 0x60, 0xB9, 0x42, 0x6F, 0x29, 0xBF, 0xCB, 0xF0, 0x62, 0x29, 0xB1, 0x23, 0x9A, 0xA7, 0xE0, 0xAA, 0x49, 0x68, 0x3C, 0x7B, 0x0F, 0x8B, 0xCF, 0x4B, 0xC0, 0x0F, 0x77, 0xE4, 0xFE, 0x7E, 0x6D, 0xAD, 0xFC, 0x77, 0x1B, 0x3F, 0x3F, 0x0E, 0xDF, 0x43, 0x96, 0x49, 0x46, 0xEC, 0xC5, 0x35, 0xAE, 0xD9, 0x09, 0x89, 0xD1, 0x88, 0x64, 0x01, 0xA7, 0x0D, 0x91, 0xFC, 0x87, 0x43, 0xD5, 0xE9, 0x6D, 0x9A, 0x11, 0x97, 0xDA, 0x25, 0x4E, 0xA4, 0xBF, 0xAA, 0xDD, 0x19, 0x43, 0x53, 0xC9, 0xAD, 0xD3, 0xEF, 0xAA, 0x10, 0xBB, 0xBC, 0xC8, 0xFD, 0x76, 0x59, 0xB5, 0x14, 0xDF, 0x87, 0x89, 0x25, 0xF2, 0x40, 0xF3, 0x41, 0x6E, 0x8F, 0x4D, 0x8C, 0x75, 0x3F, 0x98, 0x97, 0x33, 0x22, 0xDF, 0x34, 0xA9, 0x6A, 0xA3, 0xCB, 0x6C, 0x95, 0xDE, 0xF1, 0x3D, 0x49, 0xA7, 0x74, 0x7B, 0x56, 0x12, 0xB5, 0x31, 0xA1, 0xDC, 0xFD, 0x3D, 0xD4, 0xB5, 0xE7, 0x91, 0x71, 0xA3, 0x63, 0xC2, 0xFE, 0xD0, 0x34, 0x0F, 0xE8, 0x39, 0x9F, 0xCA, 0x2F, 0x38, 0x72, 0xA1, 0x68, 0x6E, 0x2B, 0x42, 0xF2, 0x80, 0x97, 0x7D, 0xD4, 0xF5, 0xF6, 0x8A, 0xD9, 0x2D, 0xCD, 0x9B, 0x7B, 0xB8, 0xAE, 0x32, 0xF6, 0x1D, 0xA6, 0x43, 0x85, 0xD3, 0x99, 0xBB, 0xE6, 0x62, 0xA6, 0x51, 0x5A, 0x4D
  };

  const flea_u8_t ct_pkcs1_v1_5[] = {
    0x0C, 0x6F, 0x56, 0x8A, 0xF7, 0xE6, 0x1D, 0xDC, 0x85, 0x6B, 0x8A, 0x30, 0x88, 0x5C, 0xFA, 0x69, 0x95, 0x34, 0x2F, 0x6F, 0x96, 0xDD, 0xC0, 0xC2, 0x80, 0x84, 0x26, 0xA4, 0x63, 0xBB, 0x6D, 0xB3, 0xF1, 0x28, 0x68, 0xD8, 0x83, 0x1E, 0xB2, 0xAE, 0xF6, 0x4E, 0x19, 0x79, 0x3C, 0x3F, 0xE2, 0x26, 0x85, 0xFF, 0x48, 0xE9, 0x1C, 0xD2, 0xF7, 0x21, 0x30, 0xE1, 0x44, 0x6E, 0x67, 0xC7, 0x63, 0xAF, 0x1C, 0xE1, 0xA4, 0xEC, 0xB3, 0xCE, 0x94, 0x57, 0x62, 0x33, 0x7B, 0x1E, 0x90, 0xD1, 0xF3, 0xC4, 0xA5, 0x9D, 0xA5, 0xCA, 0xED, 0x7C, 0xF3, 0xEA, 0xEB, 0x06, 0x0F, 0x8F, 0xD7, 0x4B, 0x9A, 0xD7, 0x35, 0xD8, 0xB4, 0xA7, 0x12, 0x32, 0x6E, 0xAD, 0x3B, 0xD7, 0x52, 0x9E, 0x23, 0xD0, 0x98, 0x8A, 0x59, 0x4D, 0xDA, 0xDF, 0xFF, 0x20, 0x00, 0x38, 0x64, 0x4A, 0xC0, 0x08, 0xC3, 0x9E, 0x43, 0x17, 0x8F, 0x40, 0x59, 0xB6, 0x00, 0x91, 0xA7, 0x0A, 0xC6, 0x0B, 0x0B, 0xD3, 0x41, 0xC1, 0xBA, 0xEA, 0xD9, 0x85, 0xDD, 0x63, 0xB6, 0x9F, 0x0D, 0xD3, 0xE7, 0x88, 0xD4, 0xD3, 0xF7, 0x42, 0xC1, 0x51, 0xEF, 0x2C, 0xD4, 0xB9, 0x0E, 0xC6, 0x00, 0x5F, 0xD8, 0x46, 0x68, 0xC3, 0x4A, 0xF2, 0xF8, 0x7F, 0x58, 0xE4, 0x38, 0x23, 0xFA, 0x69, 0x75, 0xAA, 0x78, 0x98, 0x68, 0x83, 0x4E, 0x5E, 0xEF, 0x25, 0x63, 0x43, 0x95, 0xEF, 0x26, 0x0F, 0xB0, 0xA3, 0x36, 0x89, 0x23, 0xB5, 0x32, 0x7F, 0xA5, 0xE8, 0x1D, 0x93, 0x8E, 0x9F, 0x43, 0xCF, 0xE8, 0x9C, 0x4B, 0x46, 0x28, 0xF1, 0x84, 0xD4, 0x63, 0xF8, 0xC3, 0xCB, 0x76, 0x57, 0x7F, 0x46, 0xB5, 0xBA, 0xA0, 0xB7, 0x64, 0x07, 0x01, 0x8F, 0xC2, 0x2A, 0xD9, 0xC4, 0x5A, 0xAA, 0x94, 0xF7, 0xCE, 0xF1, 0x4B, 0x3A, 0x51, 0x6C, 0x79, 0x14, 0x94, 0xDA
  };
  FLEA_DECL_BUF(decr__bu8, flea_u8_t, 2048 / 8);
  flea_al_u16_t decr_len__alu16 = 2048 / 8;
  const flea_u8_t exp_res__acu8[] = "abc";
  FLEA_THR_BEG_FUNC();

  FLEA_ALLOC_BUF(decr__bu8, 2048 / 8);
  // test OAEP decryption
  FLEA_CCALL(THR_flea_pk_api__decrypt_message(flea_rsa_oaep_encr, flea_sha1, ct_oaep, sizeof(ct_oaep), decr__bu8, &decr_len__alu16, rsa_2048_crt_key_internal_format__acu8, sizeof(rsa_2048_crt_key_internal_format__acu8), NULL, 0));
  if(decr_len__alu16 != sizeof(exp_res__acu8))
  {
    FLEA_THROW("error with RSA-OAEP decrypted reference ct length", FLEA_ERR_FAILED_TEST);
  }
  if(memcmp(exp_res__acu8, decr__bu8, sizeof(exp_res__acu8)))
  {
    FLEA_THROW("error with RSA-OAEP decrypted reference ct value", FLEA_ERR_FAILED_TEST);
  }
  // test PKCS#1 v1.5 decryption
  decr_len__alu16 = 2048 / 8;
  FLEA_CCALL(THR_flea_pk_api__decrypt_message(flea_rsa_pkcs1_v1_5_encr, flea_sha1, ct_pkcs1_v1_5, sizeof(ct_pkcs1_v1_5), decr__bu8, &decr_len__alu16, rsa_2048_crt_key_internal_format__acu8, sizeof(rsa_2048_crt_key_internal_format__acu8), NULL, 0));
  if(decr_len__alu16 != sizeof(exp_res__acu8))
  {
    FLEA_THROW("error with RSA-PKCS#1 v1.5 decrypted reference ct length", FLEA_ERR_FAILED_TEST);
  }
  if(memcmp(exp_res__acu8, decr__bu8, sizeof(exp_res__acu8)))
  {
    FLEA_THROW("error with RSA-PKCS#1 v1.5 decrypted reference ct value", FLEA_ERR_FAILED_TEST);
  }
  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(decr__bu8);
    );
#else // #if FLEA_RSA_MAX_KEY_BIT_SIZE >= 2048 && defined FLEA_HAVE_SHA1 && defined FLEA_HAVE_RSA

  return FLEA_ERR_FINE;
#endif // #else or #if FLEA_RSA_MAX_KEY_BIT_SIZE >= 2048 && defined FLEA_HAVE_SHA1 && defined FLEA_HAVE_RSA

}
static flea_err_t THR_flea_test_pkcs1_v1_5_encoding_encr ()
{
  const flea_u8_t message[41] = { 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB,
                                  0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB,
                                  0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB,
                                  0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB,
                                  0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB,0x11  };

  FLEA_DECL_BUF(extr_message, flea_u8_t, sizeof(message));
  flea_al_u16_t extr_message_len = sizeof(message);
  FLEA_DECL_BUF(res, flea_u8_t, 1536 / 8);
  flea_al_u16_t output_size__alu16 = 1536 / 8, i;
  FLEA_THR_BEG_FUNC();
  FLEA_ALLOC_BUF(res, output_size__alu16);
  FLEA_ALLOC_BUF(extr_message, sizeof(message));
  memcpy(res, message, sizeof(message));

  FLEA_CCALL(THR_flea_pk_api__encode_message__pkcs1_v1_5_encr(res, sizeof(message), &output_size__alu16, 1536, 0));
  if(output_size__alu16 != 1536 / 8)
  {
    FLEA_THROW("output size of pkcs#1 v1.5 encoding incorrect", FLEA_ERR_FAILED_TEST);
  }
  if(memcmp(message, res + (1536 / 8 - sizeof(message)), sizeof(message)))
  {
    FLEA_THROW("output of message part of pkcs#1 v1.5 encoding incorrect", FLEA_ERR_FAILED_TEST);
  }
  if(res[(1536 / 8 - sizeof(message) - 1)] != 0)
  {
    FLEA_THROW("output of message zero seperator of pkcs#1 v1.5 encoding incorrect", FLEA_ERR_FAILED_TEST);
  }
  if((res[0] != 0x00) || res[1] != 0x02)
  {
    FLEA_THROW("output of message leading two bytes of pkcs#1 v1.5 encoding incorrect", FLEA_ERR_FAILED_TEST);
  }
  for( i = 2; i < (1536 / 8 - sizeof(message) - 1); i++)
  {
    if(res[i] == 0x00)
    {
      FLEA_THROW("output of non-zero bytes of pkcs#1 v1.5 encoding incorrect", FLEA_ERR_FAILED_TEST);
    }
  }

  FLEA_CCALL(THR_flea_pk_api__decode_message__pkcs1_v1_5(res, 1536 / 8, extr_message, &extr_message_len, 1536));
  if(extr_message_len != sizeof(message))
  {
    FLEA_THROW("extracted message length of pkcs#1 v1.5 encoding incorrect", FLEA_ERR_FAILED_TEST);
  }
  if(memcmp(extr_message, message, sizeof(message)))
  {
    FLEA_THROW("extracted message content of pkcs#1 v1.5 encoding incorrect", FLEA_ERR_FAILED_TEST);
  }

  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(res);
    FLEA_FREE_BUF_FINAL(extr_message);
    );
}

#ifdef FLEA_HAVE_ASYM_SIG
static flea_err_t THR_flea_test_pkcs1_v1_5_encoding_sign ()
{
  const flea_u8_t hash_256[32] = { 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB,
                                   0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB,
                                   0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB,
                                   0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB  };
  const flea_u8_t exp_res[] =
  {
    0x00, 0x01,
    0xff, 0xff,0xff,	0xff,	 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff,0xff,	0xff,	 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff,0xff,	0xff,	 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff,0xff,	0xff,	 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff,0xff,	0xff,	 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff,0xff,	0xff,	 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff,0xff,	0xff,	 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff,0xff,	0xff,	 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff,0xff,	0xff,	 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff,
    0x00,
    0x30, 0x31,0x30,	0x0d,	 0x06, 0x09, 0x60, 0x86,
    0x48, 0x01,0x65,	0x03,	 0x04, 0x02, 0x01, 0x05,0x00,	 0x04,	0x20,
    0xAB, 0xAB,0xAB,	0xAB,	 0xAB, 0xAB, 0xAB, 0xAB,
    0xAB, 0xAB,0xAB,	0xAB,	 0xAB, 0xAB, 0xAB, 0xAB,
    0xAB, 0xAB,0xAB,	0xAB,	 0xAB, 0xAB, 0xAB, 0xAB,
    0xAB, 0xAB,0xAB,	0xAB,	 0xAB, 0xAB, 0xAB, 0xAB
  };
  const flea_al_u16_t output_size__c_u16 = sizeof(exp_res) + 10;
  flea_al_u16_t output_size__alu16 = output_size__c_u16;

  FLEA_DECL_BUF(res, flea_u8_t, output_size__c_u16); // check that function decreases it correctly
  FLEA_THR_BEG_FUNC();
  if(sizeof(exp_res) != 1024 / 8)
  {
    FLEA_THROW("error in test specification", FLEA_ERR_FAILED_TEST);
  }
  FLEA_ALLOC_BUF(res, output_size__c_u16);
  memcpy(res, hash_256, sizeof(hash_256));


  FLEA_CCALL(THR_flea_pk_api__encode_message__pkcs1_v1_5_sign(res, sizeof(hash_256), &output_size__alu16, 1024, flea_sha256));
  if(output_size__alu16 != sizeof(exp_res))
  {
    FLEA_THROW("output size of pkcs#1 v1.5 encoding incorrect", FLEA_ERR_FAILED_TEST);
  }
  if(memcmp(exp_res, res, sizeof(exp_res)))
  {
    FLEA_THROW("output content of pkcs#1 v1.5 encoding incorrect", FLEA_ERR_FAILED_TEST);
  }
  output_size__alu16 = 1023 / 8;
  if(FLEA_ERR_BUFF_TOO_SMALL != THR_flea_pk_api__encode_message__pkcs1_v1_5_sign(res, sizeof(hash_256), &output_size__alu16, 1024 /*wrong size*/, flea_sha256))
  {
    FLEA_THROW("error with buffer size not detected", FLEA_ERR_FAILED_TEST);
  }
  // pathologically short rsa key size, this must be caught:
  output_size__alu16 = 1024 / 8;
  if(FLEA_ERR_BUFF_TOO_SMALL != THR_flea_pk_api__encode_message__pkcs1_v1_5_sign(res, sizeof(hash_256), &output_size__alu16, 1024 / 8, flea_sha256))
  {
    FLEA_THROW("error with buffer size not detected", FLEA_ERR_FAILED_TEST);
  }
  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(res);
    );
}
#endif

flea_err_t THR_flea_test_emsa1 ()
{
  const flea_u8_t input_const [] = { 0x96, 0x78, 0xBE, 0x0F, 0x17, 0xC5, 0x0A, 0x6C, 0x92, 0x90, 0x53, 0x3A, 0x19, 0x28, 0xD6, 0x9A, 0x81, 0x43, 0xE6, 0x53, 0x96, 0xC1, 0xCD, 0x9A };
  const flea_u8_t exp_output [] = { 0x25, 0x9E, 0x2F, 0x83, 0xC5, 0xF1, 0x42, 0x9B, 0x24, 0xA4, 0x14, 0xCE, 0x86, 0x4A, 0x35 };
  const flea_al_u8_t output_bits = 118;
  flea_al_u16_t output_len = 0;

  FLEA_DECL_BUF(input, flea_u8_t, sizeof(input_const));
  FLEA_THR_BEG_FUNC();
  FLEA_ALLOC_BUF(input, sizeof(input_const));
  memcpy(input, input_const, sizeof(input_const));
  FLEA_CCALL(THR_flea_pk_api__encode_message__emsa1(input, sizeof(input_const), &output_len, output_bits));
  if(output_len != sizeof(exp_output))
  {
    FLEA_THROW("emsa1 output lenght is wrong", FLEA_ERR_FAILED_TEST);
  }
  if(memcmp(exp_output, input, sizeof(exp_output)))
  {
    FLEA_THROW("emsa1 content is wrong", FLEA_ERR_FAILED_TEST);
  }
  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(input);
    );
}

flea_err_t THR_flea_test_oaep ()
{
  const flea_u8_t input[] = { 0xB2, 0x20, 0x75, 0x19, 0xBA, 0xFE, 0xA1, 0xFF, 0xA5, 0x56, 0x1C, 0xE4, 0x7F, 0x90, 0x3C, 0xE5, 0x9D, 0xA9, 0xFE, 0x82, 0xDA, 0x7D, 0x4C, 0x86, 0x7A, 0x92, 0xF2, 0x8F, 0x18, 0x0D };
  const flea_al_u16_t key_len = 1023;

  const flea_al_u16_t mod_len = 1024 / 8;

  flea_al_u16_t out_len__al_u16 = mod_len;

  FLEA_DECL_BUF(enc__b_u8, flea_u8_t, mod_len);
  FLEA_DECL_BUF(decr__b_u8, flea_u8_t, sizeof(input));


  FLEA_THR_BEG_FUNC();

  FLEA_ALLOC_BUF(enc__b_u8, mod_len);
  FLEA_ALLOC_BUF(decr__b_u8, sizeof(input));

  memcpy(enc__b_u8, input, sizeof(input));

#ifdef FLEA_HAVE_SHA1
  FLEA_CCALL(THR_flea_pk_api__encode_message__oaep(enc__b_u8, sizeof(input), &out_len__al_u16, key_len,  flea_sha1));
#else
  if( FLEA_ERR_INV_ALGORITHM != THR_flea_pk_api__encode_message__oaep(enc__b_u8, sizeof(input), &out_len__al_u16, key_len,  flea_sha1))
  {
    FLEA_THROW("wrong error code for unsupported hash id", FLEA_ERR_FAILED_TEST);
  }
  FLEA_THR_RETURN();
#endif

  if(out_len__al_u16 != mod_len)
  {
    FLEA_THROW("error with encoded length", FLEA_ERR_FAILED_TEST);
  }
  out_len__al_u16 = sizeof(input);
  FLEA_CCALL(THR_flea_pk_api__decode_message__oaep(decr__b_u8, &out_len__al_u16, enc__b_u8, mod_len, key_len, flea_sha1));
  if(out_len__al_u16 != sizeof(input))
  {
    FLEA_THROW("error with oaep decoded length", FLEA_ERR_FAILED_TEST);
  }
  if(memcmp(decr__b_u8, input, sizeof(input)))
  {
    FLEA_THROW("error with encoded content", FLEA_ERR_FAILED_TEST);
  }

  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(enc__b_u8);
    FLEA_FREE_BUF_FINAL(decr__b_u8);
    );
}

flea_err_t THR_flea_test_pkcs1_v1_5_encoding ()
{
  FLEA_THR_BEG_FUNC();
#ifdef FLEA_HAVE_ASYM_SIG
  FLEA_CCALL(THR_flea_test_pkcs1_v1_5_encoding_sign());
#endif
  FLEA_CCALL(THR_flea_test_pkcs1_v1_5_encoding_encr());
  FLEA_THR_FIN_SEC_empty();
}
static flea_err_t THR_flea_inner_test_pk_encryption (flea_pk_scheme_id_t id__t, flea_hash_id_t hash_id__t)
{

  const flea_u8_t rsa_pub_exp__acu8[] = { 0x01, 0x00, 0x01 };

  FLEA_DECL_BUF(ciphertext__bu8, flea_u8_t, 2048 / 8); //FLEA_PK_MAX_PRIMITIVE_OUTPUT_LEN);
  const flea_u8_t message__acu8 [] = { 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB,
                                       0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB,
                                       0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB,
                                       0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB,
                                       0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB,0x11  };
  FLEA_DECL_BUF(decrypted__bu8, flea_u8_t, sizeof(message__acu8));
  flea_al_u16_t ciphertext_len__alu16 = 2048 / 8;
  flea_al_u16_t decrypted_len__alu16 = sizeof(message__acu8);
  FLEA_THR_BEG_FUNC();
  FLEA_ALLOC_BUF(ciphertext__bu8, ciphertext_len__alu16);
  FLEA_ALLOC_BUF(decrypted__bu8, decrypted_len__alu16);

  FLEA_CCALL(THR_flea_pk_api__encrypt_message(id__t, hash_id__t, message__acu8, sizeof(message__acu8), ciphertext__bu8, &ciphertext_len__alu16, rsa_2048_pub_key_internal_format__acu8, sizeof(rsa_2048_pub_key_internal_format__acu8), rsa_pub_exp__acu8, sizeof(rsa_pub_exp__acu8)));

  FLEA_CCALL(THR_flea_pk_api__decrypt_message(id__t, hash_id__t, ciphertext__bu8, ciphertext_len__alu16, decrypted__bu8, &decrypted_len__alu16, rsa_2048_crt_key_internal_format__acu8, sizeof(rsa_2048_crt_key_internal_format__acu8), NULL, 0));
  if(decrypted_len__alu16 != sizeof(message__acu8))
  {
    FLEA_THROW("decrypted pk message has incorrect length", FLEA_ERR_FAILED_TEST);
  }
  if(memcmp(decrypted__bu8, message__acu8, sizeof(message__acu8)))
  {
    FLEA_THROW("decrypted pk message has incorrect content", FLEA_ERR_FAILED_TEST);
  }
  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(ciphertext__bu8);
    FLEA_FREE_BUF_FINAL(decrypted__bu8);
    );
}


static flea_err_t THR_flea_test_pk_encryption_algos ()
{

  FLEA_THR_BEG_FUNC();
#ifdef FLEA_HAVE_SHA1
  FLEA_CCALL(THR_flea_inner_test_pk_encryption(flea_rsa_oaep_encr, flea_sha1));
  FLEA_CCALL(THR_flea_inner_test_pk_encryption(flea_rsa_pkcs1_v1_5_encr, flea_sha1));
#endif
#ifdef FLEA_HAVE_SHA224_256
  FLEA_CCALL(THR_flea_inner_test_pk_encryption(flea_rsa_pkcs1_v1_5_encr, flea_sha256));
  FLEA_CCALL(THR_flea_inner_test_pk_encryption(flea_rsa_oaep_encr, flea_sha256));
#endif
  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_test_pk_encryption ()
{
  FLEA_THR_BEG_FUNC();
  flea_err_t err = THR_flea_test_pk_encryption_algos();
  if(err !=
#if FLEA_RSA_MAX_KEY_BIT_SIZE < 2048 && !defined FLEA_USE_HEAP_BUF
     FLEA_ERR_INV_KEY_SIZE && err != FLEA_ERR_BUFF_TOO_SMALL
#else
     FLEA_ERR_FINE
#endif
     )
  {
    FLEA_THROW("error with return value in RSA Encryption test", FLEA_ERR_FAILED_TEST);
  }
  FLEA_CCALL(THR_flea_test_oaep_sha1_and_pkcs1_v1_5_reference_ct());
  FLEA_THR_FIN_SEC_empty();
}
#endif // #ifdef FLEA_HAVE_PK_CS
