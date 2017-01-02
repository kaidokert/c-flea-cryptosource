
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
#include "internal/common/math/mpi.h"
#include "flea/error_handling.h"
#include "internal/common/math/point_gfp.h"
#include  "flea/alloc.h"
#include  "flea/array_util.h"
#include "flea/util.h"
#include "flea/algo_config.h"
#include <string.h>
#include "internal/common/ecc_int.h"

#ifdef FLEA_HAVE_ECC


/**
 * For values larger than 2, the precomputation cost and size explodes
 */
#define FLEA_ECC_MULTI_MUL_MAX_WINDOW_SIZE 2

/**
 * check whether the given point is the point at infinity
 */
static flea_bool_t flea_point_jac_proj_t__is_zero (const flea_point_jac_proj_t* p_point)
{
  return flea_mpi_t__is_zero(&p_point->m_z);
}

static flea_err_t THR_flea_point_gfp_t__verify_cofactor (const flea_point_gfp_t* point__pt, const flea_curve_gfp_t* curve__pct, const flea_mpi_t* cofactor__pt)
{

  flea_point_gfp_t point__t;

  FLEA_DECL_BUF(G_arr, flea_uword_t, 2 * FLEA_ECC_MAX_MOD_WORD_SIZE);
  flea_al_u16_t G_arr_word_len;
  FLEA_THR_BEG_FUNC();
  G_arr_word_len = 2 * curve__pct->m_p.m_nb_used_words;

  FLEA_ALLOC_BUF(G_arr, G_arr_word_len);

  FLEA_CCALL(THR_flea_point_gfp_t__init_copy(&point__t, point__pt, G_arr, G_arr_word_len));
  /* check that hP != 0, function throws if result = O*/
  FLEA_CCALL(THR_flea_point_gfp_t__mul(&point__t, cofactor__pt, curve__pct));
  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(G_arr);
    );
}

flea_err_t THR_flea_point_gfp_t__validate_point (const flea_point_gfp_t*point__pt, const flea_curve_gfp_t* curve__pct, const flea_mpi_t* cofactor__pt, flea_mpi_div_ctx_t * div_ctx__pt)
{
  /*
   * verify the conditions given in
   * "Validation of Elliptic Curve Public Keys" by Antipa et al.
   *
   * P != O (impossible in affine coords)
   * hP != O
   * P fulfills curve equation
   * P.x and P.y are in fact field elements

   */
  flea_mpi_t lhs, rhs, ws;

  FLEA_DECL_BUF(lhs_word_arr, flea_uword_t, FLEA_ECC_MAX_MOD_WORD_SIZE);
  FLEA_DECL_BUF(rhs_word_arr, flea_uword_t, FLEA_ECC_MAX_MOD_WORD_SIZE);
  FLEA_DECL_BUF(ws_word_arr, flea_uword_t, 2 * FLEA_ECC_MAX_MOD_WORD_SIZE + 1);
  flea_mpi_ulen_t dbl_mod_word_len, mod_word_len;
  FLEA_THR_BEG_FUNC();
  dbl_mod_word_len = 2 * curve__pct->m_p.m_nb_used_words + 1;
  mod_word_len = curve__pct->m_p.m_nb_used_words;
  if((cofactor__pt != NULL) && (0 != flea_mpi_t__compare_with_uword(cofactor__pt, 1)))
  {
    FLEA_CCALL(THR_flea_point_gfp_t__verify_cofactor(point__pt, curve__pct, cofactor__pt));
  }

  FLEA_ALLOC_BUF(lhs_word_arr, mod_word_len);
  FLEA_ALLOC_BUF(rhs_word_arr, mod_word_len);
  FLEA_ALLOC_BUF(ws_word_arr, dbl_mod_word_len);



  /* check that the coords of P are field elements */
  if((0 <= flea_mpi_t__compare(&point__pt->m_x, &curve__pct->m_p)) || (0 <= flea_mpi_t__compare(&point__pt->m_y, &curve__pct->m_p)) )
  {
    FLEA_THROW("ec point not curve", FLEA_ERR_POINT_NOT_ON_CURVE);
  }

  /* check the curve equation:
     check y^2 = x^3 + ax + b [ = (x^2 + a) x + b ] */
  flea_mpi_t__init(&lhs, lhs_word_arr, mod_word_len);
  flea_mpi_t__init(&rhs, rhs_word_arr, mod_word_len);
  flea_mpi_t__init(&ws, ws_word_arr, dbl_mod_word_len);
  FLEA_CCALL(THR_flea_mpi_t__mul(&ws, &point__pt->m_x, &point__pt->m_x));
  FLEA_CCALL(THR_flea_mpi_t__add_in_place_ignore_sign(&ws, &curve__pct->m_a));
  FLEA_CCALL(THR_flea_mpi_t__divide(NULL, &rhs, &ws, &curve__pct->m_p, div_ctx__pt));
  FLEA_CCALL(THR_flea_mpi_t__mul(&ws, &rhs, &point__pt->m_x));
  FLEA_CCALL(THR_flea_mpi_t__add_in_place_ignore_sign(&ws, &curve__pct->m_b));
  FLEA_CCALL(THR_flea_mpi_t__divide(NULL, &rhs, &ws, &curve__pct->m_p, div_ctx__pt));

  FLEA_CCALL(THR_flea_mpi_t__mul(&ws, &point__pt->m_y, &point__pt->m_y));
  FLEA_CCALL(THR_flea_mpi_t__divide(NULL, &lhs, &ws, &curve__pct->m_p, div_ctx__pt));

  if(!flea_mpi_t__equal(&lhs, &rhs))
  {
    FLEA_THROW("ec point not curve", FLEA_ERR_POINT_NOT_ON_CURVE);
  }
  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(lhs_word_arr);
    FLEA_FREE_BUF_FINAL(rhs_word_arr);
    FLEA_FREE_BUF_FINAL(ws_word_arr);
    );
}

flea_err_t THR_flea_point_gfp_t__encode (flea_u8_t* p_u8__result, flea_al_u8_t* p_al_u8__result_len, flea_point_gfp_t* p_t_point, const flea_curve_gfp_t* p_t_curve )
{
  flea_al_u16_t al_u16__prime_byte_len;

  FLEA_THR_BEG_FUNC();

  al_u16__prime_byte_len = flea_mpi_t__get_byte_size(&p_t_curve->m_p);

  if(*p_al_u8__result_len < 2 * al_u16__prime_byte_len + 1)
  {
    FLEA_THROW("result buffer too small for point encoding", FLEA_ERR_BUFF_TOO_SMALL);
  }
  p_u8__result[0] = 0x04;
// assuming that the correct curve has been used
  FLEA_CCALL(THR_flea_mpi_t__encode(&p_u8__result[1], al_u16__prime_byte_len, &p_t_point->m_x));
  FLEA_CCALL(THR_flea_mpi_t__encode(&p_u8__result[1 + al_u16__prime_byte_len], al_u16__prime_byte_len, &p_t_point->m_y));
  *p_al_u8__result_len =  2 * al_u16__prime_byte_len + 1;
  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_point_gfp_t__init_decode (flea_point_gfp_t* p_result, const flea_u8_t* enc_point__pc_u8, flea_al_u16_t enc_point_len__al_u8, flea_uword_t* memory, flea_al_u16_t memory_word_len)
{

  const flea_u8_t* x_enc__p_u8;
  const flea_u8_t* y_enc__p_u8;
  flea_al_u8_t enc_coord_len__al_u8;

  FLEA_THR_BEG_FUNC();
  enc_coord_len__al_u8 = (enc_point_len__al_u8 - 1) / 2;
  if((enc_point_len__al_u8 < 3) || !(enc_point_len__al_u8 & 1) || enc_point__pc_u8[0] != 0x04 )
  {
    FLEA_THROW("invalid encoded point", FLEA_ERR_DECODING_FAILURE);
  }
  x_enc__p_u8 = &enc_point__pc_u8[1];
  y_enc__p_u8 = &enc_point__pc_u8[1 + enc_coord_len__al_u8];
  FLEA_CCALL(THR_flea_point_gfp_t__init(p_result, x_enc__p_u8, enc_coord_len__al_u8, y_enc__p_u8, enc_coord_len__al_u8, memory, memory_word_len));

  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_point_gfp_t__init_copy (flea_point_gfp_t* result__pt, const flea_point_gfp_t* other__pct, flea_uword_t* memory, flea_al_u16_t memory_word_len)
{

  flea_mpi_ulen_t p_word_len = memory_word_len / 2;

  FLEA_THR_BEG_FUNC();
  flea_mpi_t__init(&result__pt->m_x, memory, p_word_len);
  flea_mpi_t__init(&result__pt->m_y, memory + p_word_len, p_word_len);

  FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(&result__pt->m_x, &other__pct->m_x));
  FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(&result__pt->m_y, &other__pct->m_y));

  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_point_gfp_t__init (flea_point_gfp_t* p_result, const flea_u8_t* x_enc, flea_al_u16_t x_enc_len, const flea_u8_t* y_enc, flea_al_u16_t y_enc_len, flea_uword_t* memory, flea_al_u16_t memory_word_len)
{

  flea_mpi_ulen_t p_word_len = memory_word_len / 2;

  FLEA_THR_BEG_FUNC();
  flea_mpi_t__init(&p_result->m_x, memory, p_word_len);
  flea_mpi_t__init(&p_result->m_y, memory + p_word_len, p_word_len);

  FLEA_CCALL(THR_flea_mpi_t__decode(&p_result->m_x, x_enc, x_enc_len));
  FLEA_CCALL(THR_flea_mpi_t__decode(&p_result->m_y, y_enc, y_enc_len));

  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_point_jac_proj_t__set_to_zero (flea_point_jac_proj_t * p_result,   const flea_mpi_t* p_montg_const_sq_mod_p,  flea_montgm_mul_ctx_t* p_mm_ctx, flea_mpi_t* p_double_sized_ws)
{
  FLEA_THR_BEG_FUNC();

  flea_mpi_t__set_to_word_value(&p_result->m_x, 0);
  flea_mpi_t__set_to_word_value(&p_result->m_z, 1);
  FLEA_CCALL(THR_flea_mpi_t__montgm_mul(p_double_sized_ws, &p_result->m_z, p_montg_const_sq_mod_p, p_mm_ctx));
  FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(&p_result->m_y, p_double_sized_ws));
  flea_mpi_t__set_to_word_value(&p_result->m_z, 0);
  FLEA_THR_FIN_SEC_empty();
}


flea_err_t THR_flea_point_jac_proj_t__init (flea_point_jac_proj_t * p_result, const flea_point_gfp_t* p_affine_point, const flea_mpi_t* p_montg_const_sq_mod_p, flea_mpi_t* p_mod_sized_ws, flea_montgm_mul_ctx_t* p_mm_ctx, flea_uword_t* memory, flea_al_u16_t memory_word_len, flea_mpi_t* p_mm_mul_result_ws )
{
  FLEA_THR_BEG_FUNC();
  flea_mpi_ulen_t p_word_len  = p_mm_ctx->p_mod->m_nb_used_words;
  if(memory_word_len < p_word_len * 3)
  {
    FLEA_THROW("point jac proj (gfp) ctor called with too small memory for mpi storage", FLEA_ERR_BUFF_TOO_SMALL);
  }
  flea_mpi_t__init(&p_result->m_x, memory, p_word_len);
  flea_mpi_t__init(&p_result->m_y, memory + p_word_len, p_word_len);
  flea_mpi_t__init(&p_result->m_z, memory + 2 * p_word_len, p_word_len);

  FLEA_CCALL(THR_flea_mpi_t__montgm_mul(p_mm_mul_result_ws, &p_affine_point->m_x, p_montg_const_sq_mod_p, p_mm_ctx));
  FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(&p_result->m_x, p_mm_mul_result_ws));

  FLEA_CCALL(THR_flea_mpi_t__montgm_mul(p_mm_mul_result_ws, &p_affine_point->m_y, p_montg_const_sq_mod_p, p_mm_ctx));
  FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(&p_result->m_y, p_mm_mul_result_ws));

  flea_mpi_t__set_to_word_value(p_mod_sized_ws, 1);
  FLEA_CCALL(THR_flea_mpi_t__montgm_mul(p_mm_mul_result_ws, p_mod_sized_ws, p_montg_const_sq_mod_p, p_mm_ctx));
  FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(&p_result->m_z, p_mm_mul_result_ws));

  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_point_jac_proj_t__init_copy (flea_point_jac_proj_t * p_result, const flea_point_jac_proj_t* p_other_point,  flea_uword_t* memory, flea_al_u16_t memory_word_len )
{
  FLEA_THR_BEG_FUNC();
  flea_mpi_ulen_t p_word_len  = memory_word_len / 3;
  flea_mpi_t__init(&p_result->m_x, memory, p_word_len);
  flea_mpi_t__init(&p_result->m_y, memory + p_word_len, p_word_len);
  flea_mpi_t__init(&p_result->m_z, memory + 2 * p_word_len, p_word_len);

  FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(&p_result->m_x, &p_other_point->m_x));

  FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(&p_result->m_y, &p_other_point->m_y));

  FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(&p_result->m_z, &p_other_point->m_z));

  FLEA_THR_FIN_SEC_empty();
}


flea_err_t THR_flea_point_jac_proj_t__add (flea_point_jac_proj_t* p_point_1, const flea_point_jac_proj_t* p_point_2, const flea_mpi_t* p_aR, const flea_mpi_t* p_bR, flea_montgm_mul_ctx_t* p_mm_ctx, flea_mpi_t p_workspace_arr[9],  const flea_mpi_t* p_montg_const_sq_mod_p)
{

  FLEA_THR_BEG_FUNC();

  if(flea_point_jac_proj_t__is_zero(p_point_1))
  {
    FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(&p_point_1->m_x, &p_point_2->m_x));
    FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(&p_point_1->m_y, &p_point_2->m_y));
    FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(&p_point_1->m_z, &p_point_2->m_z));
    FLEA_THR_RETURN();
  }
  else if(flea_point_jac_proj_t__is_zero(p_point_2))
  {
    FLEA_THR_RETURN();
  }

  FLEA_CCALL(THR_flea_mpi_t__montgm_mul(&p_workspace_arr[0], &p_point_2->m_z, &p_point_2->m_z, p_mm_ctx));
  // ws[1] = U1
  FLEA_CCALL(THR_flea_mpi_t__montgm_mul(&p_workspace_arr[1], &p_point_1->m_x, &p_workspace_arr[0], p_mm_ctx));
  // ws[2] = intermed rhs.z * rhs_z2
  FLEA_CCALL(THR_flea_mpi_t__montgm_mul(&p_workspace_arr[2], &p_point_2->m_z, &p_workspace_arr[0], p_mm_ctx));

  // ws[3] = S1
  FLEA_CCALL(THR_flea_mpi_t__montgm_mul(&p_workspace_arr[3], &p_point_1->m_y, &p_workspace_arr[2], p_mm_ctx));

  // ws[2] = lhs_z2
  FLEA_CCALL(THR_flea_mpi_t__montgm_mul(&p_workspace_arr[2], &p_point_1->m_z, &p_point_1->m_z, p_mm_ctx));
  // ws[4] = U2
  FLEA_CCALL(THR_flea_mpi_t__montgm_mul(&p_workspace_arr[4], &p_point_2->m_x, &p_workspace_arr[2], p_mm_ctx));

  // ws[5] = intermed lhs_z2 * lhs.z
  FLEA_CCALL(THR_flea_mpi_t__montgm_mul(&p_workspace_arr[5], &p_point_1->m_z, &p_workspace_arr[2], p_mm_ctx));

  // ws[6] = S2
  FLEA_CCALL(THR_flea_mpi_t__montgm_mul(&p_workspace_arr[6], &p_point_2->m_y, &p_workspace_arr[5], p_mm_ctx));

  // both z2 not needed anymore from here on: ws[0] and ws[2]
  //
  // H = ws[0]
  FLEA_CCALL(THR_flea_mpi_t__subtract_mod(&p_workspace_arr[0], &p_workspace_arr[4], &p_workspace_arr[1], p_mm_ctx->p_mod, &p_workspace_arr[7] ));
  // r = ws[7]
  FLEA_CCALL(THR_flea_mpi_t__subtract_mod(&p_workspace_arr[7], &p_workspace_arr[6], &p_workspace_arr[3], p_mm_ctx->p_mod, &p_workspace_arr[8]));

  if(flea_mpi_t__is_zero(&p_workspace_arr[0]))
  {
    if(flea_mpi_t__is_zero(&p_workspace_arr[7]))
    {
      FLEA_CCALL(THR_flea_point_jac_proj_t__double(p_point_1, p_aR, p_bR, p_mm_ctx, p_workspace_arr, p_montg_const_sq_mod_p));
      FLEA_THR_RETURN();
    }
    // set point to zero
    FLEA_CCALL(THR_flea_point_jac_proj_t__set_to_zero(p_point_1, p_montg_const_sq_mod_p,  p_mm_ctx, &p_workspace_arr[0]));
    FLEA_THR_RETURN();
  }

  FLEA_CCALL(THR_flea_mpi_t__montgm_mul(&p_workspace_arr[4], &p_workspace_arr[0], &p_workspace_arr[0], p_mm_ctx));


  FLEA_CCALL(THR_flea_mpi_t__montgm_mul(&p_workspace_arr[6], &p_workspace_arr[4], &p_workspace_arr[0], p_mm_ctx));

  FLEA_CCALL(THR_flea_mpi_t__montgm_mul(&p_workspace_arr[8], &p_workspace_arr[4], &p_workspace_arr[1], p_mm_ctx));

  FLEA_CCALL(THR_flea_mpi_t__montgm_mul(&p_workspace_arr[5], &p_workspace_arr[7], &p_workspace_arr[7], p_mm_ctx));
  FLEA_CCALL(THR_flea_mpi_t__subtract(&p_point_1->m_x, &p_workspace_arr[5], &p_workspace_arr[6]));

  FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(&p_workspace_arr[4], &p_workspace_arr[8]));


  FLEA_CCALL(THR_flea_mpi_t__shift_left_small(&p_workspace_arr[8], 1));
  FLEA_CCALL(THR_flea_mpi_t__subtract(&p_workspace_arr[5], &p_point_1->m_x, &p_workspace_arr[8]));
  FLEA_CCALL(THR_flea_mpi_t__quick_reduce_smaller_zero(&p_workspace_arr[5], p_mm_ctx->p_mod, &p_workspace_arr[8]));
  FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(&p_point_1->m_x, &p_workspace_arr[5]));

  FLEA_CCALL(THR_flea_mpi_t__subtract_mod(&p_workspace_arr[4], &p_workspace_arr[4], &p_point_1->m_x, p_mm_ctx->p_mod, &p_workspace_arr[8]));

  FLEA_CCALL(THR_flea_mpi_t__montgm_mul(&p_workspace_arr[8],  &p_workspace_arr[7], &p_workspace_arr[4], p_mm_ctx));
  FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(&p_point_1->m_y, &p_workspace_arr[8]));

  FLEA_CCALL(THR_flea_mpi_t__montgm_mul(&p_workspace_arr[8], &p_workspace_arr[6], &p_workspace_arr[3], p_mm_ctx));

  FLEA_CCALL(THR_flea_mpi_t__subtract_mod(&p_point_1->m_y, &p_point_1->m_y, &p_workspace_arr[8], p_mm_ctx->p_mod, &p_workspace_arr[1]));

  FLEA_CCALL(THR_flea_mpi_t__montgm_mul(&p_workspace_arr[8], &p_point_1->m_z, &p_point_2->m_z, p_mm_ctx));

  FLEA_CCALL(THR_flea_mpi_t__montgm_mul(&p_workspace_arr[1], &p_workspace_arr[8], &p_workspace_arr[0], p_mm_ctx));

  FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(&p_point_1->m_z, &p_workspace_arr[1]));


  FLEA_THR_FIN_SEC_empty();
}
flea_err_t THR_flea_point_jac_proj_t__double (flea_point_jac_proj_t* p_point, const flea_mpi_t* p_aR, const flea_mpi_t* p_bR, flea_montgm_mul_ctx_t* p_mm_ctx, flea_mpi_t p_workspace_arr[9], const flea_mpi_t* p_montg_const_sq_mod_p)
{

  flea_mpi_t* p_z_quad = &p_workspace_arr[0];
  flea_mpi_t* p_y_sq = &p_workspace_arr[1];
  flea_mpi_t* p_a_z_quad = &p_workspace_arr[2];

  flea_mpi_t* p_S = &p_workspace_arr[3];
  flea_mpi_t* p_M = &p_workspace_arr[4];
  flea_mpi_t* p_U = &p_workspace_arr[5];
  flea_mpi_t* p_x = &p_workspace_arr[6];
  flea_mpi_t* p_y = &p_workspace_arr[7];
  flea_mpi_t* p_z = &p_workspace_arr[8];


  FLEA_THR_BEG_FUNC();



  if(flea_point_jac_proj_t__is_zero(p_point))
  {
    FLEA_THR_RETURN();
  }
  else if(flea_mpi_t__is_zero(&p_point->m_y))
  {
    FLEA_CCALL(THR_flea_point_jac_proj_t__set_to_zero(p_point, p_montg_const_sq_mod_p,  p_mm_ctx, &p_workspace_arr[0]));
    FLEA_THR_RETURN();
  }

  FLEA_CCALL(THR_flea_mpi_t__montgm_mul(p_y_sq, &p_point->m_y, &p_point->m_y, p_mm_ctx));
  FLEA_CCALL(THR_flea_mpi_t__montgm_mul(p_S, &p_point->m_x, p_y_sq, p_mm_ctx));

  // S*=4
  FLEA_CCALL(THR_flea_mpi_t__shift_left_small(p_S, 2));

  FLEA_CCALL(THR_flea_mpi_t__quick_reduce_greater_zero(p_S, p_mm_ctx->p_mod, p_M));

  FLEA_CCALL(THR_flea_mpi_t__montgm_mul(p_M, &p_point->m_z, &p_point->m_z, p_mm_ctx));  // M = z^2
  FLEA_CCALL(THR_flea_mpi_t__montgm_mul(p_z_quad, p_M, p_M, p_mm_ctx));                 //  z^4

  flea_mpi_t__set_to_word_value(p_U, 3);

  FLEA_CCALL(THR_flea_mpi_t__montgm_mul(p_x, &p_point->m_x, &p_point->m_x, p_mm_ctx));

  FLEA_CCALL(THR_flea_mpi_t__montgm_mul(p_a_z_quad, p_z_quad, p_aR, p_mm_ctx));
  FLEA_CCALL(THR_flea_mpi_t__mul(p_M, p_U, p_x)); // M = 3 * x^2

  FLEA_CCALL(THR_flea_mpi_t__add_in_place_ignore_sign(p_M, p_a_z_quad));

  while(0 < flea_mpi_t__compare_absolute(p_M, p_mm_ctx->p_mod))
  {
    FLEA_CCALL(THR_flea_mpi_t__subtract(p_x, p_M, p_mm_ctx->p_mod));
    FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(p_M, p_x));
  }
  FLEA_CCALL(THR_flea_mpi_t__montgm_mul(p_x, p_M, p_M, p_mm_ctx));

  FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(p_y, p_S));
  FLEA_CCALL(THR_flea_mpi_t__shift_left_small(p_y, 1));

  FLEA_CCALL(THR_flea_mpi_t__subtract(p_z, p_x, p_y ));

  FLEA_CCALL(THR_flea_mpi_t__quick_reduce_smaller_zero(p_z, p_mm_ctx->p_mod, p_y));
  // z contains x
  FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(p_x, p_z));

  FLEA_CCALL(THR_flea_mpi_t__montgm_mul(p_U, p_y_sq, p_y_sq, p_mm_ctx));
  FLEA_CCALL(THR_flea_mpi_t__shift_left_small(p_U, 3));
  FLEA_CCALL(THR_flea_mpi_t__quick_reduce_greater_zero(p_U, p_mm_ctx->p_mod, p_y_sq));

  FLEA_CCALL(THR_flea_mpi_t__subtract_mod(p_y_sq, p_S, p_x, p_mm_ctx->p_mod, p_z_quad));

  FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(p_S, p_y_sq));

  FLEA_CCALL(THR_flea_mpi_t__montgm_mul(p_z_quad, p_M, p_S, p_mm_ctx));                           // calc y = M* S
  FLEA_CCALL(THR_flea_mpi_t__subtract_mod(p_y, p_z_quad, p_U, p_mm_ctx->p_mod, p_mm_ctx->p_ws));  // y -= U

  FLEA_CCALL(THR_flea_mpi_t__montgm_mul(p_z_quad, &p_point->m_y, &p_point->m_z, p_mm_ctx));       // z = y*z
  FLEA_CCALL(THR_flea_mpi_t__shift_left_small(p_z_quad, 1));

  if(0 < flea_mpi_t__compare(p_z_quad, p_mm_ctx->p_mod))
  {
    FLEA_CCALL(THR_flea_mpi_t__subtract(p_z, p_z_quad, p_mm_ctx->p_mod));
    FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(p_z_quad, p_z));
  }

  FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(&p_point->m_x, p_x));
  FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(&p_point->m_y, p_y));
  FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(&p_point->m_z, p_z_quad));

  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_point_gfp_t__mul (flea_point_gfp_t* p_point_in_out, const flea_mpi_t* p_scalar, const flea_curve_gfp_t* p_curve)
{
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_point_gfp_t__mul_multi(p_point_in_out, p_scalar, NULL, NULL, p_curve));
  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_point_gfp_t__mul_multi (flea_point_gfp_t* p_point_in_out, const flea_mpi_t* p_scalar, const flea_point_gfp_t* p_point_2, const flea_mpi_t* p_scalar_2, const flea_curve_gfp_t* p_curve)
{

  flea_point_jac_proj_t p2;
  flea_mpi_ulen_t i;
  const flea_al_u16_t prime_word_len = FLEA_ECC_MAX_MOD_WORD_SIZE;

  const flea_al_u16_t proj_point_word_arr_word_len = 3 * FLEA_ECC_MAX_MOD_WORD_SIZE;

  const flea_al_u16_t vn_len = FLEA_MPI_DIV_VN_HLFW_LEN_FROM_DIVISOR_W_LEN((prime_word_len + 1));       // + 1 due to reducing R^2 !
  const flea_al_u16_t un_len = FLEA_MPI_DIV_UN_HLFW_LEN_FROM_DIVIDENT_W_LEN(2 * (prime_word_len + 1));  // + 1 due to reducing R^2 !

  FLEA_DECL_BUF(vn, flea_hlf_uword_t, FLEA_MPI_DIV_VN_HLFW_LEN_FROM_DIVISOR_W_LEN((FLEA_ECC_MAX_MOD_WORD_SIZE + 1)));
  FLEA_DECL_BUF(un, flea_hlf_uword_t, FLEA_MPI_DIV_UN_HLFW_LEN_FROM_DIVIDENT_W_LEN(2 * (FLEA_ECC_MAX_MOD_WORD_SIZE + 1)));
  flea_mpi_div_ctx_t div_ctx;


  flea_mpi_t montg_const, montg_const_sq_mod_p, mod_sized_ws, montgm_mul_ws, aR_mod_p, bR_mod_p;

  flea_mpi_t mpi_worksp_arr_double_mod_size[9];
  const flea_al_u8_t precomp_points_count_const = FLEA_MAX(1 << FLEA_ECC_SINGLE_MUL_MAX_WINDOW_SIZE, (1 << (2 * FLEA_ECC_MULTI_MUL_MAX_WINDOW_SIZE)));
  flea_al_u8_t precomp_points_count;
  flea_al_u8_t window_size;
  flea_point_jac_proj_t precomp_points[precomp_points_count_const];

  const flea_mpi_ulen_t montg_const_word_arr_word_len = prime_word_len + 1;
  const flea_mpi_ulen_t montg_const_sq_mod_p_word_len = prime_word_len;
  const flea_mpi_ulen_t montgm_mul_ws_word_len = (prime_word_len) * 2 + 1;


  FLEA_DECL_BUF(montg_const_word_arr, flea_uword_t, montg_const_word_arr_word_len );
  FLEA_DECL_BUF(montg_const_sq_mod_p_arr, flea_uword_t, montg_const_sq_mod_p_word_len);
  FLEA_DECL_BUF(mod_sized_ws_word_arr, flea_uword_t, prime_word_len );
  FLEA_DECL_BUF(montgm_mul_ws_word_arr, flea_uword_t, montgm_mul_ws_word_len);
  FLEA_DECL_BUF(aR_mod_p_word_arr, flea_uword_t, prime_word_len);
  FLEA_DECL_BUF(bR_mod_p_word_arr, flea_uword_t, prime_word_len);

  FLEA_DECL_BUF(proj_point_word_arr_2, flea_uword_t, proj_point_word_arr_word_len);

  FLEA_DECL_BUF(precomp_points_word_arr, flea_uword_t, proj_point_word_arr_word_len * precomp_points_count_const);

  flea_montgm_mul_ctx_t mm_ctx;
  const flea_al_u8_t ecc_ws_mpi_arrs_word_len = (prime_word_len + 1) * 2 + 1; // + 1 in brackets because we need it to square R
#ifdef FLEA_USE_STACK_BUF
  flea_uword_t ecc_ws_mpi_arrs [9][ecc_ws_mpi_arrs_word_len];
#else
  flea_uword_t* ecc_ws_mpi_arrs [9];
#endif
  flea_al_u8_t line_col_size = 0;
  FLEA_THR_BEG_FUNC();

  precomp_points_count = p_point_2 ? (1 << (2 * FLEA_ECC_MULTI_MUL_MAX_WINDOW_SIZE)) : (1 << FLEA_ECC_SINGLE_MUL_MAX_WINDOW_SIZE);
#ifdef FLEA_USE_HEAP_BUF
  memset(ecc_ws_mpi_arrs, 0, sizeof(ecc_ws_mpi_arrs));
  for(i = 0; i < FLEA_NB_ARRAY_ENTRIES(ecc_ws_mpi_arrs); i++)
  {
    FLEA_ALLOC_MEM_ARR(ecc_ws_mpi_arrs[i], ecc_ws_mpi_arrs_word_len);
  }
#endif
  if(p_scalar_2 == NULL)
  {
    // this captures the cofactor multiplication
    if(flea_mpi_t__get_bit_size(p_scalar) <= 32)
    {
      window_size = 1;
    }
    else
    {
      window_size = FLEA_ECC_SINGLE_MUL_MAX_WINDOW_SIZE;
    }
  }
  else
  {
    window_size = FLEA_ECC_MULTI_MUL_MAX_WINDOW_SIZE;
  }
  FLEA_ALLOC_BUF(proj_point_word_arr_2, proj_point_word_arr_word_len);

  FLEA_ALLOC_BUF(montg_const_word_arr, montg_const_word_arr_word_len );
  FLEA_ALLOC_BUF(montg_const_sq_mod_p_arr, montg_const_sq_mod_p_word_len);
  FLEA_ALLOC_BUF(mod_sized_ws_word_arr, prime_word_len );
  FLEA_ALLOC_BUF(montgm_mul_ws_word_arr, montgm_mul_ws_word_len);
  FLEA_ALLOC_BUF(aR_mod_p_word_arr, prime_word_len);
  FLEA_ALLOC_BUF(bR_mod_p_word_arr, prime_word_len);

  FLEA_ALLOC_BUF(precomp_points_word_arr, proj_point_word_arr_word_len * precomp_points_count);


  flea_mpi_t__init(&montg_const, montg_const_word_arr, montg_const_word_arr_word_len);
  flea_mpi_t__init(&montg_const_sq_mod_p, montg_const_sq_mod_p_arr, montg_const_sq_mod_p_word_len);
  flea_mpi_t__init(&mod_sized_ws, mod_sized_ws_word_arr, prime_word_len);
  flea_mpi_t__init(&montgm_mul_ws, montgm_mul_ws_word_arr, montgm_mul_ws_word_len);
  flea_mpi_t__init(&aR_mod_p, aR_mod_p_word_arr, prime_word_len );
  flea_mpi_t__init(&bR_mod_p, bR_mod_p_word_arr, prime_word_len );

  for(i = 0; i < FLEA_NB_ARRAY_ENTRIES(ecc_ws_mpi_arrs); i++)
  {
    flea_mpi_t__init(&mpi_worksp_arr_double_mod_size[i], ecc_ws_mpi_arrs[i], ecc_ws_mpi_arrs_word_len);
  }
  FLEA_ALLOC_BUF(vn, vn_len);
  FLEA_ALLOC_BUF(un, un_len);

  div_ctx.vn = vn;
  div_ctx.un = un;
  div_ctx.vn_len = vn_len;
  div_ctx.un_len = un_len;

  mm_ctx.p_ws = &montgm_mul_ws;
  mm_ctx.mod_prime = flea_montgomery_compute_n_prime(p_curve->m_p.m_words[0]);
  mm_ctx.p_mod = &p_curve->m_p;

  FLEA_CCALL(THR_flea_mpi_t__set_pow_2(&montg_const, p_curve->m_p.m_nb_used_words * FLEA_WORD_BIT_SIZE));

  FLEA_CCALL(THR_flea_mpi_t__mul(&mpi_worksp_arr_double_mod_size[0], &montg_const, &montg_const));
  FLEA_CCALL(THR_flea_mpi_t__divide(NULL, &montg_const_sq_mod_p, &mpi_worksp_arr_double_mod_size[0], &p_curve->m_p, &div_ctx ));


  FLEA_CCALL(THR_flea_mpi_t__mul(&mpi_worksp_arr_double_mod_size[0], &montg_const, &p_curve->m_a));
  FLEA_CCALL(THR_flea_mpi_t__divide(NULL, &aR_mod_p, &mpi_worksp_arr_double_mod_size[0], &p_curve->m_p, &div_ctx ));

  FLEA_CCALL(THR_flea_mpi_t__mul(&mpi_worksp_arr_double_mod_size[0], &montg_const, &p_curve->m_b));
  FLEA_CCALL(THR_flea_mpi_t__divide(NULL, &bR_mod_p, &mpi_worksp_arr_double_mod_size[0], &p_curve->m_p, &div_ctx ));

  // init as zero directly, use dummy values
  FLEA_CCALL(THR_flea_point_jac_proj_t__init(&p2, p_point_in_out, &montg_const_sq_mod_p, &mod_sized_ws, &mm_ctx, proj_point_word_arr_2, proj_point_word_arr_word_len, &mpi_worksp_arr_double_mod_size[0]));


  if(p_point_2)
  {
    flea_al_u8_t i, j;
    window_size = FLEA_ECC_MULTI_MUL_MAX_WINDOW_SIZE;
    line_col_size = 1 << window_size;

    FLEA_CCALL(THR_flea_point_jac_proj_t__init(&precomp_points[1], p_point_2, &montg_const_sq_mod_p, &mod_sized_ws, &mm_ctx, precomp_points_word_arr + 1 * proj_point_word_arr_word_len, proj_point_word_arr_word_len, &mpi_worksp_arr_double_mod_size[0]));
    // p1 already set
    // process first line
    for(i = 1; i < line_col_size; i++)
    {
      if(1 != i)
      {
        FLEA_CCALL(THR_flea_point_jac_proj_t__init_copy(&precomp_points[i], &precomp_points[i - 1], precomp_points_word_arr + i * proj_point_word_arr_word_len, proj_point_word_arr_word_len));
        FLEA_CCALL(THR_flea_point_jac_proj_t__add(&precomp_points[i], &precomp_points[1], &aR_mod_p, &bR_mod_p, &mm_ctx, mpi_worksp_arr_double_mod_size, &montg_const_sq_mod_p));
      }
      // now spread it to the whole column
      for(j = 1; j < line_col_size; j++)
      {
        FLEA_CCALL(THR_flea_point_jac_proj_t__init_copy(&precomp_points[i + j * line_col_size], &precomp_points[i], precomp_points_word_arr + (i + j * line_col_size) * proj_point_word_arr_word_len, proj_point_word_arr_word_len));
      }
    }
    // process first column
    // first entry (in 2nd row):
    FLEA_CCALL(THR_flea_point_jac_proj_t__init(&precomp_points[1 * line_col_size], p_point_in_out, &montg_const_sq_mod_p, &mod_sized_ws, &mm_ctx, precomp_points_word_arr + (line_col_size * proj_point_word_arr_word_len), proj_point_word_arr_word_len, &mpi_worksp_arr_double_mod_size[0]));
    //  remaining entries:
    for(j = 2; j < line_col_size; j++)
    {
      FLEA_CCALL(THR_flea_point_jac_proj_t__init_copy(&precomp_points[j * line_col_size], &precomp_points[(j - 1) * line_col_size], precomp_points_word_arr + j * line_col_size * proj_point_word_arr_word_len, proj_point_word_arr_word_len));
      FLEA_CCALL(THR_flea_point_jac_proj_t__add(&precomp_points[j * line_col_size], &precomp_points[1 * line_col_size], &aR_mod_p, &bR_mod_p, &mm_ctx, mpi_worksp_arr_double_mod_size, &montg_const_sq_mod_p));

    }
    // now the first row and first column are finished, and the remaining points
    // have already there p1 contribution.
    // add the p2 contribution:
    for(i = 1; i < line_col_size; i++)
    {
      for(j = 1; j < line_col_size; j++)
      {
        FLEA_CCALL(THR_flea_point_jac_proj_t__add(&precomp_points[j * line_col_size + i], &precomp_points[j * line_col_size], &aR_mod_p, &bR_mod_p, &mm_ctx, mpi_worksp_arr_double_mod_size, &montg_const_sq_mod_p));
      }
    }

  }
  else
  {
    // precomp for single mul window

    FLEA_CCALL(THR_flea_point_jac_proj_t__init(&precomp_points[1], p_point_in_out, &montg_const_sq_mod_p, &mod_sized_ws, &mm_ctx, precomp_points_word_arr + 1 * proj_point_word_arr_word_len, proj_point_word_arr_word_len, &mpi_worksp_arr_double_mod_size[0]));
    for(i = 2; i < precomp_points_count; i++)
    {
      FLEA_CCALL(THR_flea_point_jac_proj_t__init_copy(&precomp_points[i], &precomp_points[i - 1], precomp_points_word_arr + i * proj_point_word_arr_word_len, proj_point_word_arr_word_len));
      FLEA_CCALL(THR_flea_point_jac_proj_t__add(&precomp_points[i], &precomp_points[1], &aR_mod_p, &bR_mod_p, &mm_ctx, mpi_worksp_arr_double_mod_size, &montg_const_sq_mod_p));
    }
  }
  // create the point O
  FLEA_CCALL(THR_flea_point_jac_proj_t__set_to_zero(&p2,  &montg_const_sq_mod_p, &mm_ctx, &mpi_worksp_arr_double_mod_size[0]));

  i = flea_mpi_t__get_bit_size(p_scalar);
  if(p_scalar_2)
  {
    flea_mpi_ulen_t i2 = flea_mpi_t__get_bit_size(p_scalar_2);
    i = FLEA_MAX(i, i2);
  }

  if(i < window_size)
  {
    window_size = 1;
  }
  while(i)
  {
    flea_u8_t exp_bit1;
    flea_al_u8_t j;
    for(j = 0; j < window_size; j++)
    {
      FLEA_CCALL(THR_flea_point_jac_proj_t__double(&p2, &aR_mod_p, &bR_mod_p, &mm_ctx, mpi_worksp_arr_double_mod_size, &montg_const_sq_mod_p));
    }
    exp_bit1 = flea_mpi_t__get_bit(p_scalar, i - 1);
    for(j = 1; j < window_size; j++)
    {
      exp_bit1 <<= 1;
      exp_bit1 |= flea_mpi_t__get_bit(p_scalar, i - j - 1);
    }
    if(p_scalar_2)
    {
      // multi-mul

      flea_al_u8_t j;
      flea_u8_t exp_bit2;
      exp_bit2 = flea_mpi_t__get_bit(p_scalar_2, i - 1);
      for(j = 1; j < window_size; j++)
      {
        exp_bit2 <<= 1;
        exp_bit2 |= flea_mpi_t__get_bit(p_scalar_2, i - j - 1);
      }
      if(exp_bit1 | exp_bit2)
      {
        FLEA_CCALL(THR_flea_point_jac_proj_t__add(&p2, &precomp_points[exp_bit2 + exp_bit1 * line_col_size], &aR_mod_p, &bR_mod_p, &mm_ctx, mpi_worksp_arr_double_mod_size, &montg_const_sq_mod_p));
      }
    }
    else
    {
      // single-mul

      if(exp_bit1)
      {
        FLEA_CCALL(THR_flea_point_jac_proj_t__add(&p2, &precomp_points[exp_bit1], &aR_mod_p, &bR_mod_p, &mm_ctx, mpi_worksp_arr_double_mod_size, &montg_const_sq_mod_p));

      }
    }
    i -= window_size;
    if(i < window_size)
    {
      window_size = 1;
    }

  }

  FLEA_CCALL(THR_flea_point_jac_proj_t__get_affine_x(&p_point_in_out->m_x, &p2, &mm_ctx, mpi_worksp_arr_double_mod_size, &montg_const_sq_mod_p ));
  FLEA_CCALL(THR_flea_point_jac_proj_t__get_affine_y(&p_point_in_out->m_y, &p2, &mm_ctx, mpi_worksp_arr_double_mod_size, &montg_const_sq_mod_p ));
  FLEA_THR_FIN_SEC(
    FLEA_DO_IF_USE_HEAP_BUF(
      for(i = 0; i < FLEA_NB_ARRAY_ENTRIES(ecc_ws_mpi_arrs); i++)
      {
        FLEA_FREE_MEM_CHK_NULL(ecc_ws_mpi_arrs[i]);
      }
      );
    FLEA_FREE_BUF_FINAL(proj_point_word_arr_2);
    FLEA_FREE_BUF_FINAL(montg_const_word_arr);
    FLEA_FREE_BUF_FINAL(montg_const_sq_mod_p_arr);
    FLEA_FREE_BUF_FINAL(mod_sized_ws_word_arr);
    FLEA_FREE_BUF_FINAL(montgm_mul_ws_word_arr);
    FLEA_FREE_BUF_FINAL(aR_mod_p_word_arr);
    FLEA_FREE_BUF_FINAL(bR_mod_p_word_arr);
    FLEA_FREE_BUF_FINAL(precomp_points_word_arr);

    FLEA_FREE_BUF_FINAL(vn);
    FLEA_FREE_BUF_FINAL(un);
    );
}

// each inv_ws entry must have double  mod size + 1 allocated (as mm-mul result)
flea_err_t THR_flea_point_jac_proj_t__get_affine_x (flea_mpi_t* p_result, const flea_point_jac_proj_t* p_point,  flea_montgm_mul_ctx_t* p_mm_ctx, flea_mpi_t inv_ws[4], flea_mpi_t* p_montg_const_sq_mod_p)
{
  FLEA_THR_BEG_FUNC();
  if(flea_point_jac_proj_t__is_zero(p_point))
  {
    FLEA_THROW("zero point cannot be converted to affine", FLEA_ERR_ZERO_POINT_AFF_TRF);
  }
  FLEA_CCALL(THR_flea_mpi_t__montgm_mul(&inv_ws[0], &p_point->m_z, &p_point->m_z, p_mm_ctx));
  FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc( p_result, &inv_ws[0]));
  FLEA_CCALL(THR_flea_mpi_t__invert_odd_mod(p_mm_ctx->p_ws, p_result, p_mm_ctx->p_mod, inv_ws));
  FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(&inv_ws[0], p_mm_ctx->p_ws));
  FLEA_CCALL(THR_flea_mpi_t__montgm_mul(&inv_ws[1], &inv_ws[0], p_montg_const_sq_mod_p, p_mm_ctx));
  FLEA_CCALL(THR_flea_mpi_t__montgm_mul(&inv_ws[0], &inv_ws[1], &p_point->m_x, p_mm_ctx));
  FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc( p_result, &inv_ws[0]));
  FLEA_THR_FIN_SEC_empty();
}
flea_err_t THR_flea_point_jac_proj_t__get_affine_y (flea_mpi_t* p_result, const flea_point_jac_proj_t* p_point,  flea_montgm_mul_ctx_t* p_mm_ctx, flea_mpi_t inv_ws[4], flea_mpi_t* p_montg_const_sq_mod_p)
{
  FLEA_THR_BEG_FUNC();
  if(flea_point_jac_proj_t__is_zero(p_point))
  {
    FLEA_THROW("zero point cannot be converted to affine", FLEA_ERR_ZERO_POINT_AFF_TRF);
  }
  FLEA_CCALL(THR_flea_mpi_t__montgm_mul(&inv_ws[0], &p_point->m_z, &p_point->m_z, p_mm_ctx));
  FLEA_CCALL(THR_flea_mpi_t__montgm_mul(&inv_ws[1], &p_point->m_z, &inv_ws[0], p_mm_ctx));
  FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc( p_result, &inv_ws[1]));

  FLEA_CCALL(THR_flea_mpi_t__invert_odd_mod(p_mm_ctx->p_ws, p_result, p_mm_ctx->p_mod, inv_ws));
  FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(&inv_ws[0], p_mm_ctx->p_ws));
  FLEA_CCALL(THR_flea_mpi_t__montgm_mul(&inv_ws[1], &inv_ws[0], p_montg_const_sq_mod_p, p_mm_ctx));
  FLEA_CCALL(THR_flea_mpi_t__montgm_mul(&inv_ws[0], &inv_ws[1], &p_point->m_y, p_mm_ctx));
  FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc( p_result, &inv_ws[0]));
  FLEA_THR_FIN_SEC_empty();
}
#endif // #ifdef FLEA_HAVE_ECC
