
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
#include "flea/hash.h"
#include "self_test.h"
#include "flea/error_handling.h"
#include "flea/alloc.h"
#include "flea/algo_config.h"
#include <string.h>
static flea_err_t THR_flea_test_hash_init_dtor ()
{
  FLEA_DECL_OBJ(ctx, flea_hash_ctx_t);
  flea_hash_ctx_t ctx2;
  FLEA_THR_BEG_FUNC();
  flea_hash_ctx_t__INIT(&ctx2);

  FLEA_THR_FIN_SEC(
    flea_hash_ctx_t__dtor(&ctx);
    flea_hash_ctx_t__dtor(&ctx2);
    );
}
static flea_err_t THR_flea_test_hash_abc (flea_hash_id_t id__t, const flea_u8_t* exp_res__pcu8, flea_al_u16_t exp_res_len__alu16)
{
  flea_u8_t m__a_u8[] = { 0x61, 0x62, 0x63 };
  flea_al_u16_t m_len__al_u16 = sizeof(m__a_u8);

  FLEA_DECL_BUF(digest__b_u8, flea_u8_t, FLEA_MAX_HASH_OUT_LEN);

  FLEA_DECL_OBJ(ctx, flea_hash_ctx_t);
  FLEA_THR_BEG_FUNC();

  FLEA_ALLOC_BUF(digest__b_u8, flea_hash__get_output_length_by_id(id__t));


  FLEA_CCALL(THR_flea_hash_ctx_t__ctor(&ctx, id__t));

  FLEA_CCALL(THR_flea_hash_ctx_t__update(&ctx, m__a_u8, m_len__al_u16));

  FLEA_CCALL(THR_flea_hash_ctx_t__final(&ctx, digest__b_u8));
  if(exp_res_len__alu16 != flea_hash_ctx_t__get_output_length(&ctx))
  {
    FLEA_THROW("error with length of hash output in test", FLEA_ERR_FAILED_TEST);
  }

  if(memcmp(digest__b_u8, exp_res__pcu8, flea_hash_ctx_t__get_output_length(&ctx)))
  {
    FLEA_THROW("error with hash result value", FLEA_ERR_FAILED_TEST);
  }
  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(digest__b_u8);
    flea_hash_ctx_t__dtor(&ctx);
    );
}

flea_err_t THR_flea_test_hash ()
{

  FLEA_THR_BEG_FUNC();
#ifdef FLEA_HAVE_SHA1
  flea_u8_t exp_res_abc_sha1__a_u8 [] = {
    0xa9, 0x99, 0x3e, 0x36,
    0x47, 0x06, 0x81, 0x6a,
    0xba, 0x3e, 0x25, 0x71,
    0x78, 0x50, 0xc2, 0x6c,
    0x9c, 0xd0, 0xd8, 0x9d
  };
#endif
#ifdef FLEA_HAVE_SHA224_256
  flea_u8_t exp_res_abc_sha224__a_u8[] = { 0x23, 0x09, 0x7d, 0x22,  0x34, 0x05, 0xd8, 0x22,  0x86, 0x42, 0xa4, 0x77,  0xbd, 0xa2, 0x55, 0xb3,  0x2a, 0xad, 0xbc, 0xe4,  0xbd, 0xa0, 0xb3, 0xf7,  0xe3, 0x6c, 0x9d, 0xa7 };
#endif

#ifdef FLEA_HAVE_MD5
  flea_u8_t exp_res_abc_md5__a_u8[] = { 0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0, 0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72 };
#endif
#ifdef FLEA_HAVE_SHA1
  FLEA_CCALL(THR_flea_test_hash_abc(flea_sha1, exp_res_abc_sha1__a_u8, sizeof(exp_res_abc_sha1__a_u8)));
#endif
#ifdef FLEA_HAVE_SHA224_256
  FLEA_CCALL(THR_flea_test_hash_abc(flea_sha224, exp_res_abc_sha224__a_u8, sizeof(exp_res_abc_sha224__a_u8)));
#endif
#ifdef FLEA_HAVE_MD5
  FLEA_CCALL(THR_flea_test_hash_abc(flea_md5, exp_res_abc_md5__a_u8, sizeof(exp_res_abc_md5__a_u8)));
#endif
  FLEA_CCALL(THR_flea_test_hash_init_dtor());
  FLEA_THR_FIN_SEC_empty();
}

