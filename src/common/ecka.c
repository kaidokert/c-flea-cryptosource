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
#include "internal/common/math/mpi.h"
#include "flea/error.h"
#include "flea/alloc.h"
#include "flea/array_util.h"
#include "flea/util.h"
#include "flea/rng.h"
#include "flea/ec_gfp_dom_par.h"
#include "internal/common/math/curve_gfp.h"
#include "internal/common/math/point_gfp.h"
#include "flea/ecka.h"
#include "flea/kdf.h"
#include "flea/hash.h"
#include "flea/algo_config.h"
#include "internal/common/ecc_int.h"

#ifdef FLEA_HAVE_ECKA

flea_err_t THR_flea_ecka__compute_kdf_ansi_x9_63 (flea_hash_id_t hash_id__t, const flea_u8_t* public_point_enc__pcu8, flea_al_u8_t public_point_enc_len__alu8, const flea_u8_t* secret_key__pcu8, flea_al_u8_t secret_key_len__alu8, const flea_u8_t* enc_dp__pcu8, const flea_u8_t* shared_info__pcu8, flea_al_u16_t shared_info_len__alu16, flea_u8_t* result__pu8, flea_al_u16_t result_len__alu16)
{
  FLEA_DECL_BUF(shared_x__bu8, flea_u8_t, FLEA_ECC_MAX_MOD_BYTE_SIZE);
  flea_al_u8_t shared_x_len__alu8 = 0;
  FLEA_THR_BEG_FUNC();
  if(public_point_enc_len__alu8 == 0)
  {
    FLEA_THROW("invalid public point length for ecka kdf-ansi-X9.63", FLEA_ERR_INV_ARG);
  }
  shared_x_len__alu8 = (public_point_enc_len__alu8 - 1) / 2;
#ifdef FLEA_USE_STACK_BUF
  if(shared_x_len__alu8 > FLEA_ECC_MAX_MOD_BYTE_SIZE)
  {
    FLEA_THROW("field size not supported", FLEA_ERR_INV_ARG);
  }
#endif
  FLEA_ALLOC_BUF(shared_x__bu8, shared_x_len__alu8);
  FLEA_CCALL(THR_flea_ecka__compute_raw(public_point_enc__pcu8, public_point_enc_len__alu8, secret_key__pcu8, secret_key_len__alu8, enc_dp__pcu8, shared_x__bu8, &shared_x_len__alu8));
  FLEA_CCALL(THR_flea_kdf_X9_63(hash_id__t, shared_x__bu8, shared_x_len__alu8, shared_info__pcu8, shared_info_len__alu16, result__pu8, result_len__alu16));
  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_SECRET_ARR(shared_x__bu8, FLEA_HEAP_OR_STACK_CODE(shared_x_len__alu8, FLEA_NB_ARRAY_ENTRIES(shared_x__bu8)));
    );
}

flea_err_t THR_flea_ecka__compute_raw (const flea_u8_t* public_point_enc__pcu8, flea_al_u8_t public_point_enc_len__alu8, const flea_u8_t* secret_key__pcu8, flea_al_u8_t secret_key_len__alu8, const flea_u8_t* enc_dp__pcu8, flea_u8_t* result__pu8, flea_al_u8_t* result_len__palu8)
{
  flea_mpi_t d, l, n;
  const flea_al_u8_t sign_mpi_ws_count = 4;
  flea_mpi_t mpi_worksp_arr[sign_mpi_ws_count];
  flea_curve_gfp_t curve;
  flea_point_gfp_t Q;
  flea_al_u8_t enc_order_len;

#ifdef FLEA_USE_HEAP_BUF
  flea_al_u8_t enc_field_len;
  flea_mpi_ulen_t prime_word_len;
#endif
#ifdef FLEA_USE_STACK_BUF
  flea_uword_t ecc_ws_mpi_arrs [sign_mpi_ws_count][FLEA_ECC_MAX_ORDER_WORD_SIZE];
#else
  flea_uword_t* ecc_ws_mpi_arrs [sign_mpi_ws_count];
#endif
  FLEA_DECL_BUF(vn, flea_hlf_uword_t, FLEA_MPI_DIV_VN_HLFW_LEN_FROM_DIVISOR_W_LEN(FLEA_ECC_MAX_ORDER_WORD_SIZE));
  FLEA_DECL_BUF(un, flea_hlf_uword_t, FLEA_MPI_DIV_UN_HLFW_LEN_FROM_DIVIDENT_W_LEN(2 * (FLEA_ECC_MAX_MOD_WORD_SIZE + 1)));

  FLEA_DECL_BUF(n_arr, flea_uword_t, FLEA_ECC_MAX_ORDER_WORD_SIZE);
  FLEA_DECL_BUF(d_arr, flea_uword_t, FLEA_ECC_MAX_ORDER_WORD_SIZE);
  FLEA_DECL_BUF(l_arr, flea_uword_t, 2 * FLEA_ECC_MAX_ORDER_WORD_SIZE); // must be able to hold intermediate result multiplication result
  FLEA_DECL_BUF(Q_arr, flea_uword_t, 2 * FLEA_ECC_MAX_MOD_WORD_SIZE);
  FLEA_DECL_BUF(curve_word_arr, flea_uword_t, 3 * FLEA_ECC_MAX_MOD_WORD_SIZE);
  flea_mpi_ulen_t curve_word_arr_word_len = FLEA_NB_STACK_BUF_ENTRIES(curve_word_arr);
  flea_mpi_ulen_t Q_arr_word_len = FLEA_NB_STACK_BUF_ENTRIES(Q_arr);
  flea_mpi_ulen_t vn_len = FLEA_NB_STACK_BUF_ENTRIES(vn); // overridden for heap-version
  flea_mpi_ulen_t un_len = FLEA_NB_STACK_BUF_ENTRIES(un); // overridden for heap-version
  flea_mpi_ulen_t order_word_len = FLEA_ECC_MAX_ORDER_WORD_SIZE;

  flea_mpi_div_ctx_t div_ctx;
  flea_al_u8_t i;
  FLEA_THR_BEG_FUNC();

  enc_order_len = flea_ec_dom_par__get_elem_len(enc_dp__pcu8, flea_dp__n);


#ifdef FLEA_USE_HEAP_BUF
  enc_field_len = flea_ec_dom_par__get_elem_len(enc_dp__pcu8, flea_dp__p);

  prime_word_len = FLEA_CEIL_WORD_LEN_FROM_BYTE_LEN( enc_field_len );
  order_word_len = FLEA_CEIL_WORD_LEN_FROM_BYTE_LEN( enc_order_len );

  Q_arr_word_len = 2 * prime_word_len;
  curve_word_arr_word_len = 3 * prime_word_len;
  vn_len = FLEA_MPI_DIV_VN_HLFW_LEN_FROM_DIVISOR_W_LEN(order_word_len);
  un_len = FLEA_MPI_DIV_UN_HLFW_LEN_FROM_DIVIDENT_W_LEN(2 * (prime_word_len + 1)); // + 1 due to reducing R^2 !
  memset(ecc_ws_mpi_arrs, 0, sizeof(ecc_ws_mpi_arrs));

#endif

  FLEA_ALLOC_BUF(n_arr, order_word_len);
  FLEA_ALLOC_BUF(d_arr, order_word_len);
  FLEA_ALLOC_BUF(Q_arr, Q_arr_word_len);
  FLEA_ALLOC_BUF(curve_word_arr, curve_word_arr_word_len);

  FLEA_CCALL(THR_flea_curve_gfp_t__init_dp_array(
               &curve,
               enc_dp__pcu8,
               curve_word_arr,
               curve_word_arr_word_len));
  FLEA_CCALL(THR_flea_point_gfp_t__init_decode(&Q, public_point_enc__pcu8, public_point_enc_len__alu8, Q_arr, Q_arr_word_len));
  flea_mpi_t__init(&n, n_arr, order_word_len);
  flea_mpi_t__init(&d, d_arr, order_word_len);

  FLEA_ALLOC_BUF(vn, vn_len);
  FLEA_ALLOC_BUF(un, un_len);
  div_ctx.vn = vn;
  div_ctx.un = un;
  div_ctx.vn_len = vn_len;
  div_ctx.un_len = un_len;
  /* no need to check Ph != 0 as this is done implicitly by protocol */
  FLEA_CCALL(THR_flea_point_gfp_t__validate_point(&Q, &curve, NULL, &div_ctx));

  FLEA_CCALL(THR_flea_mpi_t__decode(&d, flea_ec_dom_par__get_ptr_to_elem(enc_dp__pcu8, flea_dp__h), flea_ec_dom_par__get_elem_len(enc_dp__pcu8, flea_dp__h)));
  FLEA_CCALL(THR_flea_point_gfp_t__mul(&Q, &d, &curve));

  // l_arr doesn't live in parallel to point multiplication
  FLEA_ALLOC_BUF(l_arr, 2 * order_word_len);
  flea_mpi_t__init(&l, l_arr, 2 * order_word_len);

  FLEA_CCALL(THR_flea_mpi_t__decode(&n, flea_ec_dom_par__get_ptr_to_elem(enc_dp__pcu8, flea_dp__n), enc_order_len));

  for(i = 0; i < FLEA_NB_ARRAY_ENTRIES(ecc_ws_mpi_arrs); i++)
  {
#ifdef FLEA_USE_HEAP_BUF
    FLEA_ALLOC_MEM_ARR(ecc_ws_mpi_arrs[i], order_word_len);
#endif
    flea_mpi_t__init(&mpi_worksp_arr[i], ecc_ws_mpi_arrs[i], order_word_len);
  }
  // invert h
  FLEA_CCALL(THR_flea_mpi_t__invert_odd_mod(&l, &d, &n, mpi_worksp_arr));

  FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(&mpi_worksp_arr[0], &l));
  FLEA_CCALL(THR_flea_mpi_t__decode(&d, secret_key__pcu8, secret_key_len__alu8 ));
  // d *= l mod n
  FLEA_CCALL(THR_flea_mpi_t__mul(&l, &d, &mpi_worksp_arr[0]));

#ifdef FLEA_USE_HEAP_BUF
  for(i = 0; i < FLEA_NB_ARRAY_ENTRIES(ecc_ws_mpi_arrs); i++)
  {
    FLEA_FREE_MEM_SET_NULL(ecc_ws_mpi_arrs[i]);
  }
#endif
  // l contains d*l unreduced
  // ...mod n:

  FLEA_CCALL(THR_flea_mpi_t__divide(NULL, &d, &l, &n, &div_ctx));
  FLEA_FREE_BUF_SECRET_ARR(l_arr, 2 * order_word_len);
  // zero point conversion detected inside this function:
  FLEA_CCALL(THR_flea_point_gfp_t__mul(&Q, &d, &curve));

  // now take x-coord of d
  *result_len__palu8 = flea_mpi_t__get_byte_size(&Q.m_x);
  FLEA_CCALL(THR_flea_mpi_t__encode(result__pu8, *result_len__palu8, &Q.m_x));
  FLEA_THR_FIN_SEC(
    FLEA_DO_IF_USE_HEAP_BUF(
      for(i = 0; i < FLEA_NB_ARRAY_ENTRIES(ecc_ws_mpi_arrs); i++)
      {
        FLEA_FREE_MEM_CHK_NULL(ecc_ws_mpi_arrs[i]);
      }
      );
    FLEA_FREE_BUF_FINAL(n_arr);
    FLEA_FREE_BUF_FINAL(curve_word_arr);
    FLEA_FREE_BUF_SECRET_ARR(Q_arr, Q_arr_word_len);
    FLEA_FREE_BUF_SECRET_ARR(l_arr, 2 * order_word_len);
    FLEA_FREE_BUF_SECRET_ARR(d_arr, order_word_len);
    FLEA_FREE_BUF_SECRET_ARR(vn, vn_len);
    FLEA_FREE_BUF_SECRET_ARR(un, un_len);
    );
}

#endif // #ifdef FLEA_HAVE_ECKA
