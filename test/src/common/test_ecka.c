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
#include "flea/ec_gfp_dom_par.h"
#include "flea/ecka.h"
#include "flea/algo_config.h"
#include "flea/ec_key_gen.h"
#include "flea/ecc.h"

#ifdef FLEA_HAVE_ECKA
static flea_err_t THR_flea_test_ecka_raw_basic_inner (const flea_u8_t* dp__pcu8)
{
  FLEA_DECL_BUF(res_a_arr__bu8, flea_u8_t, FLEA_ECC_MAX_MOD_BYTE_SIZE);
  FLEA_DECL_BUF(res_b_arr__bu8, flea_u8_t, FLEA_ECC_MAX_MOD_BYTE_SIZE);

  flea_al_u8_t res_a_len__alu8 = sizeof(res_a_arr__bu8);
  flea_al_u8_t res_b_len__alu8 = sizeof(res_b_arr__bu8);
  flea_al_u8_t pub_point_enc_len__alu8 = FLEA_ECC_MAX_UNCOMPR_POINT_SIZE;
  flea_al_u8_t sk_enc_len__alu8 = FLEA_ECC_MAX_PRIVATE_KEY_BYTE_SIZE;

  flea_al_u8_t pub_point_a_enc_len__alu8 = pub_point_enc_len__alu8;
  flea_al_u8_t pub_point_b_enc_len__alu8 = pub_point_enc_len__alu8;
  flea_al_u8_t sk_a_enc_len__alu8 = sk_enc_len__alu8;
  flea_al_u8_t sk_b_enc_len__alu8 = sk_enc_len__alu8;
  FLEA_DECL_BUF(pub_point_a_enc__bu8, flea_u8_t, pub_point_enc_len__alu8);
  FLEA_DECL_BUF(pub_point_b_enc__bu8, flea_u8_t, pub_point_enc_len__alu8);
  FLEA_DECL_BUF(sk_a_enc__bu8, flea_u8_t, sk_enc_len__alu8);
  FLEA_DECL_BUF(sk_b_enc__bu8, flea_u8_t, sk_enc_len__alu8);


  FLEA_THR_BEG_FUNC();
  res_a_len__alu8 = res_b_len__alu8 = flea_ec_dom_par__get_elem_len(dp__pcu8, flea_dp__p);
  FLEA_ALLOC_BUF(res_a_arr__bu8, res_a_len__alu8);
  FLEA_ALLOC_BUF(res_b_arr__bu8, res_b_len__alu8);
  FLEA_ALLOC_BUF(pub_point_a_enc__bu8, pub_point_enc_len__alu8);
  FLEA_ALLOC_BUF(pub_point_b_enc__bu8, pub_point_enc_len__alu8);
  FLEA_ALLOC_BUF(sk_a_enc__bu8, sk_enc_len__alu8);
  FLEA_ALLOC_BUF(sk_b_enc__bu8, sk_enc_len__alu8);
  FLEA_CCALL(THR_flea_generate_ecc_key(pub_point_a_enc__bu8, &pub_point_a_enc_len__alu8, sk_a_enc__bu8, &sk_a_enc_len__alu8, dp__pcu8));
  FLEA_CCALL(THR_flea_generate_ecc_key(pub_point_b_enc__bu8, &pub_point_b_enc_len__alu8, sk_b_enc__bu8, &sk_b_enc_len__alu8, dp__pcu8));

  FLEA_CCALL(THR_flea_ecka__compute_raw(pub_point_a_enc__bu8, pub_point_a_enc_len__alu8, sk_b_enc__bu8, sk_b_enc_len__alu8, dp__pcu8, res_b_arr__bu8, &res_b_len__alu8));
  FLEA_CCALL(THR_flea_ecka__compute_raw(pub_point_b_enc__bu8, pub_point_b_enc_len__alu8, sk_a_enc__bu8, sk_a_enc_len__alu8, dp__pcu8, res_a_arr__bu8, &res_a_len__alu8));
  if(res_a_len__alu8 != res_b_len__alu8)
  {
    FLEA_THROW("ECKA results differ in length", FLEA_ERR_FAILED_TEST);
  }
  if(memcmp(res_a_arr__bu8, res_b_arr__bu8, res_a_len__alu8))
  {
    FLEA_THROW("ECKA results differ in value", FLEA_ERR_FAILED_TEST);
  }
#if FLEA_ECC_MAX_MOD_BYTE_SIZE >= (224 / 8)
  res_a_len__alu8 = res_b_len__alu8 = flea_ec_dom_par__get_elem_len(dp__pcu8, flea_dp__p);
  FLEA_CCALL(THR_flea_ecka__compute_kdf_ansi_x9_63(flea_sha224, pub_point_a_enc__bu8, pub_point_a_enc_len__alu8, sk_b_enc__bu8, sk_b_enc_len__alu8, dp__pcu8, NULL, 0, res_b_arr__bu8, res_b_len__alu8));
  FLEA_CCALL(THR_flea_ecka__compute_kdf_ansi_x9_63(flea_sha224, pub_point_b_enc__bu8, pub_point_b_enc_len__alu8, sk_a_enc__bu8, sk_a_enc_len__alu8, dp__pcu8, NULL, 0, res_a_arr__bu8, res_a_len__alu8));

  if(memcmp(res_a_arr__bu8, res_b_arr__bu8, res_a_len__alu8))
  {
    FLEA_THROW("ECKA ANSI X9.63 KDF results differ in value", FLEA_ERR_FAILED_TEST);
  }
#endif

  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(pub_point_a_enc__bu8);
    FLEA_FREE_BUF_FINAL(pub_point_b_enc__bu8);
    FLEA_FREE_BUF_FINAL(sk_a_enc__bu8);
    FLEA_FREE_BUF_FINAL(sk_b_enc__bu8);
    FLEA_FREE_BUF_FINAL(res_a_arr__bu8);
    FLEA_FREE_BUF_FINAL(res_b_arr__bu8);
    );
}


flea_err_t THR_flea_test_ecka_raw_basic (const flea_u8_t* p_dp)
{
  FLEA_THR_BEG_FUNC();
  flea_al_u8_t i;
  for(i = 0; i <= flea_gl_ec_dom_par_max_id; i++)
  {
    const flea_u8_t* ec_dp = flea_ec_dom_par__get_predefined_dp_ptr(i);
    if(NULL == ec_dp)
    {
      continue;
    }
    FLEA_CCALL(THR_flea_test_ecka_raw_basic_inner(ec_dp));
  }
  FLEA_THR_FIN_SEC_empty();
}

#endif // #ifdef FLEA_HAVE_ECKA
