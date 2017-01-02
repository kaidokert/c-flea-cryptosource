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
#include "internal/common/math/mpi.h"
#include "flea/alloc.h"
#include "flea/array_util.h"
#include "flea/util.h"
#include "internal/common/math/curve_gfp.h"
#include "internal/common/math/point_gfp.h"

#if defined FLEA_HAVE_ECC && FLEA_ECC_MAX_MOD_BIT_SIZE >= 160
flea_err_t THR_flea_test_ecc_point_gfp_mul ()
{

  flea_u8_t prime_enc[] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x7f, 0xff, 0xff, 0xff
  };
  flea_u8_t a_enc[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xfc };
  flea_u8_t b_enc[] = { 0x1c, 0x97, 0xbe, 0xfc, 0x54, 0xbd, 0x7a, 0x8b, 0x65, 0xac, 0xf8, 0x9f, 0x81, 0xd4, 0xd4, 0xad, 0xc5, 0x65, 0xfa, 0x45 };
  flea_u8_t p_x_enc[] = { 0x4A, 0x96, 0xB5, 0x68, 0x8E, 0xF5, 0x73, 0x28, 0x46, 0x64, 0x69, 0x89, 0x68, 0xC3, 0x8B, 0xB9, 0x13, 0xCB, 0xFC, 0x82 };
  flea_u8_t p_y_enc[] = { 0x23, 0xA6, 0x28, 0x55, 0x31, 0x68, 0x94, 0x7D, 0x59, 0xDC, 0xC9, 0x12, 0x04, 0x23, 0x51, 0x37, 0x7A, 0xC5, 0xFB, 0x32 };

  flea_u8_t exp_x_enc[] = { 0x51, 0xB4, 0x49, 0x6F, 0xEC, 0xC4, 0x06, 0xED, 0x0E, 0x75, 0xA2, 0x4A, 0x3C, 0x03, 0x20, 0x62, 0x51, 0x41, 0x9D, 0xC0 };
  flea_u8_t exp_y_enc[] = { 0xC2, 0x8D, 0xCB, 0x4B, 0x73, 0xA5, 0x14, 0xB4, 0x68, 0xD7, 0x93, 0x89, 0x4F, 0x38, 0x1C, 0xCC, 0x17, 0x56, 0xAA, 0x6C };

  flea_u8_t scalar_enc[] = {
    0xaa, 0x37, 0x4f, 0xfc, 0x3c, 0xe1, 0x44, 0xe6, 0xb0, 0x73, 0x30, 0x79, 0x72, 0xcb, 0x6d, 0x57, 0xb2, 0xa4, 0xe9, 0x82
  };

  flea_curve_gfp_t curve;
  flea_mpi_t scalar, exp_x, exp_y;
  flea_point_gfp_t point;
  const flea_al_u16_t scalar_word_len = FLEA_CEIL_WORD_LEN_FROM_BYTE_LEN(sizeof(scalar_enc));
  const flea_al_u16_t curve_word_arr_word_len = 3 * ((sizeof(prime_enc) + sizeof(flea_uword_t) - 1) / sizeof(flea_uword_t));
  const flea_al_u16_t exp_affine_word_len = FLEA_CEIL_WORD_LEN_FROM_BYTE_LEN(sizeof(prime_enc));
  const flea_al_u16_t aff_point_word_arr_word_len = 2 * ((sizeof(prime_enc) + sizeof(flea_uword_t) - 1) / sizeof(flea_uword_t));

  FLEA_DECL_BUF(aff_point_word_arr, flea_uword_t, aff_point_word_arr_word_len);
  FLEA_DECL_BUF(exp_x_arr, flea_uword_t, exp_affine_word_len);
  FLEA_DECL_BUF(exp_y_arr, flea_uword_t, exp_affine_word_len);

  FLEA_DECL_BUF(curve_word_arr, flea_uword_t, curve_word_arr_word_len);
  FLEA_DECL_BUF(scalar_arr, flea_uword_t, scalar_word_len);
  FLEA_THR_BEG_FUNC();


  FLEA_ALLOC_BUF(exp_x_arr, exp_affine_word_len);
  FLEA_ALLOC_BUF(exp_y_arr, exp_affine_word_len);
  FLEA_ALLOC_BUF(scalar_arr, scalar_word_len);
  FLEA_ALLOC_BUF(curve_word_arr, curve_word_arr_word_len);
  FLEA_ALLOC_BUF(aff_point_word_arr, aff_point_word_arr_word_len);

  flea_mpi_t__init(&scalar, scalar_arr, scalar_word_len );
  flea_mpi_t__init(&exp_x, exp_x_arr, exp_affine_word_len);
  flea_mpi_t__init(&exp_y, exp_y_arr, exp_affine_word_len);
  FLEA_CCALL(THR_flea_mpi_t__decode(&scalar, scalar_enc, sizeof(scalar_enc)));
  FLEA_CCALL(THR_flea_mpi_t__decode(&exp_x, exp_x_enc, sizeof(exp_x_enc)));
  FLEA_CCALL(THR_flea_mpi_t__decode(&exp_y, exp_y_enc, sizeof(exp_y_enc)));

  FLEA_CCALL(THR_flea_curve_gfp_t__init(&curve, a_enc, sizeof(a_enc), b_enc, sizeof(b_enc), prime_enc, sizeof(prime_enc), curve_word_arr, curve_word_arr_word_len));
  FLEA_CCALL(THR_flea_point_gfp_t__init(&point, p_x_enc, sizeof(p_x_enc), p_y_enc, sizeof(p_y_enc), aff_point_word_arr, aff_point_word_arr_word_len));

  FLEA_CCALL(THR_flea_point_gfp_t__mul(&point, &scalar, &curve));

  if(flea_mpi_t__compare_absolute(&point.m_x, &exp_x) || flea_mpi_t__compare_absolute(&point.m_y, &exp_y))
  {
    FLEA_THROW("error with point mul", FLEA_ERR_FAILED_TEST);
  }
  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(curve_word_arr);
    FLEA_FREE_BUF_FINAL(aff_point_word_arr);
    FLEA_FREE_BUF_FINAL(scalar_arr);
    FLEA_FREE_BUF_FINAL(exp_x_arr);
    FLEA_FREE_BUF_FINAL(exp_y_arr);
    );
}

flea_err_t THR_flea_test_ecc_point_gfp_add ()
{

  flea_al_u16_t i;
  // curve: secP160r1
  flea_u8_t prime_enc[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xff };
  flea_u8_t a_enc[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xfc };
  flea_u8_t b_enc[] = { 0x1c, 0x97, 0xbe, 0xfc, 0x54, 0xbd, 0x7a, 0x8b, 0x65, 0xac, 0xf8, 0x9f, 0x81, 0xd4, 0xd4, 0xad, 0xc5, 0x65, 0xfa, 0x45 };
  flea_u8_t p_x1_enc[] = {
    0x5B, 0x2C, 0x5E, 0x03, 0xD8, 0x03, 0xB4, 0x06, 0xBA, 0x23, 0xCD, 0x3C, 0x09, 0x5E, 0x86, 0x99, 0xAD, 0x82, 0x8B, 0x90
  };
  flea_u8_t p_y1_enc[] = {
    0xA8, 0xE8, 0xF6, 0x90, 0xA2, 0x33, 0x17, 0xDE, 0x30, 0x6F, 0x0F, 0xD5, 0x3E, 0x69, 0x84, 0x6D, 0x1F, 0x27, 0x51, 0x1A
  };
  flea_u8_t p_x2_enc[] = { 
    0x2D, 0x39, 0xDC, 0x26, 0x40, 0x70, 0xC8, 0xB5, 0x5E, 0x8C, 0x9E, 0x31, 0xBC, 0xC3, 0xAE, 0xFB, 0xF2, 0x7F, 0xC0, 0xB3
  };
  flea_u8_t p_y2_enc[] = { 
    0x42, 0x18, 0x3B, 0x21, 0x4A, 0xF4, 0x46, 0xA1, 0x90, 0x47, 0x35, 0x70, 0x0E, 0x8B, 0x9C, 0xB1, 0xD2, 0xB3, 0xBF, 0xC9
  };


  flea_u8_t exp_x_enc[] = { 
    0x31, 0x80, 0x8E, 0xD9, 0x1F, 0x46, 0x05, 0x1B, 0x46, 0x1C, 0x7F, 0xD6, 0x69, 0xB6, 0x27, 0x4E, 0x4D, 0x62, 0x7F, 0xF2
  };

  flea_u8_t exp_y_enc[] = { 
    0x25, 0x99, 0x2F, 0x73, 0x3A, 0xEA, 0x30, 0x7B, 0xC7, 0xF3, 0x1C, 0xEA, 0x95, 0xF6, 0x46, 0x25, 0xCF, 0x0F, 0x76, 0x01
  };
  const flea_al_u16_t curve_word_arr_word_len = 3 * ((sizeof(prime_enc) + sizeof(flea_uword_t) - 1) / sizeof(flea_uword_t));

  FLEA_DECL_BUF(curve_word_arr, flea_uword_t, curve_word_arr_word_len);

  const flea_al_u16_t aff_point_word_arr_word_len = 2 * ((sizeof(prime_enc) + sizeof(flea_uword_t) - 1) / sizeof(flea_uword_t));
  FLEA_DECL_BUF(aff_point_word_arr, flea_uword_t, aff_point_word_arr_word_len);
  FLEA_DECL_BUF(aff_point_word_arr_2, flea_uword_t, aff_point_word_arr_word_len);

  const flea_al_u16_t proj_point_word_arr_word_len = 3 * ((sizeof(prime_enc) + sizeof(flea_uword_t) - 1) / sizeof(flea_uword_t));
  FLEA_DECL_BUF(proj_point_word_arr, flea_uword_t, proj_point_word_arr_word_len);
  FLEA_DECL_BUF(proj_point_word_arr_2, flea_uword_t, proj_point_word_arr_word_len);

  const flea_al_u16_t prime_word_len = (sizeof(prime_enc) + sizeof(flea_uword_t) - 1) / sizeof(flea_uword_t);
  const flea_al_u16_t vn_len = FLEA_MPI_DIV_VN_HLFW_LEN_FROM_DIVISOR_W_LEN((prime_word_len + 1));       // + 1 due to reducing R^2 !
  const flea_al_u16_t un_len = FLEA_MPI_DIV_UN_HLFW_LEN_FROM_DIVIDENT_W_LEN(2 * (prime_word_len + 1));  // + 1 due to reducing R^2 !

  FLEA_DECL_BUF(vn, flea_hlf_uword_t, vn_len);
  FLEA_DECL_BUF(un, flea_hlf_uword_t, un_len);

  flea_mpi_div_ctx_t div_ctx;


  flea_curve_gfp_t curve;
  flea_point_gfp_t aff_point;
  flea_point_gfp_t aff_point_2;
  flea_point_jac_proj_t work_point;
  flea_point_jac_proj_t work_point_2;

  flea_mpi_t montg_const, montg_const_sq_mod_p, mod_sized_ws, montgm_mul_ws, aR_mod_p, bR_mod_p;
  flea_mpi_t exp_x, exp_y, x, y, x2, y2;
  flea_mpi_t mpi_worksp_arr_double_mod_size[9];

  const flea_mpi_ulen_t montg_const_word_arr_word_len = prime_word_len + 1;
  const flea_mpi_ulen_t montg_const_sq_mod_p_word_len = prime_word_len;
  const flea_mpi_ulen_t montgm_mul_ws_word_len = (prime_word_len) * 2 + 1;

  flea_montgm_mul_ctx_t mm_ctx;

  FLEA_DECL_BUF(montg_const_word_arr, flea_uword_t, montg_const_word_arr_word_len );
  FLEA_DECL_BUF(montg_const_sq_mod_p_arr, flea_uword_t, montg_const_sq_mod_p_word_len);
  FLEA_DECL_BUF(mod_sized_ws_word_arr, flea_uword_t, prime_word_len );
  FLEA_DECL_BUF(montgm_mul_ws_word_arr, flea_uword_t, montgm_mul_ws_word_len);
  FLEA_DECL_BUF(aR_mod_p_word_arr, flea_uword_t, prime_word_len);
  FLEA_DECL_BUF(bR_mod_p_word_arr, flea_uword_t, prime_word_len);
  FLEA_DECL_BUF(exp_x_arr, flea_uword_t, prime_word_len);
  FLEA_DECL_BUF(x_arr, flea_uword_t, prime_word_len * 2 + 1);                 // currently needs to be a mm-mul result (for get_affine...)
  FLEA_DECL_BUF(x2_arr, flea_uword_t, prime_word_len * 2 + 1);                // currently needs to be a mm-mul result (for get_affine...)
  FLEA_DECL_BUF(exp_y_arr, flea_uword_t, prime_word_len);
  FLEA_DECL_BUF(y_arr, flea_uword_t, prime_word_len * 2 + 1);                 // currently needs to be a mm-mul result (for get_affine...)
  FLEA_DECL_BUF(y2_arr, flea_uword_t, prime_word_len * 2 + 1);                // currently needs to be a mm-mul result (for get_affine...)

  const flea_al_u8_t ecc_ws_mpi_arrs_word_len = (prime_word_len + 1) * 2 + 1; // + 1 in brackets because I need it to square R!
#ifdef FLEA_USE_STACK_BUF
  flea_uword_t ecc_ws_mpi_arrs [9][ecc_ws_mpi_arrs_word_len];
#else
  flea_uword_t* ecc_ws_mpi_arrs [9];
#endif

  FLEA_THR_BEG_FUNC();

#ifdef FLEA_USE_HEAP_BUF
  memset(ecc_ws_mpi_arrs, 0, sizeof(ecc_ws_mpi_arrs));
  for(i = 0; i < FLEA_NB_ARRAY_ENTRIES(ecc_ws_mpi_arrs); i++)
  {
    FLEA_ALLOC_MEM_ARR(ecc_ws_mpi_arrs[i], ecc_ws_mpi_arrs_word_len);
  }
#endif

  FLEA_ALLOC_BUF(curve_word_arr, curve_word_arr_word_len);
  FLEA_ALLOC_BUF(aff_point_word_arr, aff_point_word_arr_word_len);
  FLEA_ALLOC_BUF(aff_point_word_arr_2, aff_point_word_arr_word_len);
  FLEA_ALLOC_BUF(proj_point_word_arr, proj_point_word_arr_word_len);
  FLEA_ALLOC_BUF(proj_point_word_arr_2, proj_point_word_arr_word_len);

  FLEA_ALLOC_BUF(montg_const_word_arr, montg_const_word_arr_word_len );
  FLEA_ALLOC_BUF(montg_const_sq_mod_p_arr, montg_const_sq_mod_p_word_len);
  FLEA_ALLOC_BUF(mod_sized_ws_word_arr, prime_word_len );
  FLEA_ALLOC_BUF(montgm_mul_ws_word_arr, montgm_mul_ws_word_len);
  FLEA_ALLOC_BUF(aR_mod_p_word_arr, prime_word_len);
  FLEA_ALLOC_BUF(bR_mod_p_word_arr, prime_word_len);
  FLEA_ALLOC_BUF(exp_x_arr, prime_word_len);
  FLEA_ALLOC_BUF(x_arr, prime_word_len * 2 + 1);  // currently needs to be a mm-mul result (for get_affine...)
  FLEA_ALLOC_BUF(x2_arr, prime_word_len * 2 + 1); // currently needs to be a mm-mul result (for get_affine...)

  FLEA_ALLOC_BUF(exp_y_arr, prime_word_len);
  FLEA_ALLOC_BUF(y_arr, prime_word_len * 2 + 1);  // currently needs to be a mm-mul result (for get_affine...)
  FLEA_ALLOC_BUF(y2_arr, prime_word_len * 2 + 1); // currently needs to be a mm-mul result (for get_affine...)


  flea_mpi_t__init(&montg_const, montg_const_word_arr, montg_const_word_arr_word_len);
  flea_mpi_t__init(&montg_const_sq_mod_p, montg_const_sq_mod_p_arr, montg_const_sq_mod_p_word_len);
  flea_mpi_t__init(&mod_sized_ws, mod_sized_ws_word_arr, prime_word_len);
  flea_mpi_t__init(&montgm_mul_ws, montgm_mul_ws_word_arr, montgm_mul_ws_word_len);
  flea_mpi_t__init(&aR_mod_p, aR_mod_p_word_arr, prime_word_len );
  flea_mpi_t__init(&bR_mod_p, bR_mod_p_word_arr, prime_word_len );
  flea_mpi_t__init(&exp_x, exp_x_arr, prime_word_len );
  flea_mpi_t__init(&x, x_arr, prime_word_len * 2 + 1 );   // currently needs to be a mm-mul result (for get_affine...)
  flea_mpi_t__init(&x2, x2_arr, prime_word_len * 2 + 1 ); // currently needs to be a mm-mul result (for get_affine...)
  flea_mpi_t__init(&exp_y, exp_y_arr, prime_word_len );
  flea_mpi_t__init(&y, y_arr, prime_word_len * 2 + 1 );   // currently needs to be a mm-mul result (for get_affine...)
  flea_mpi_t__init(&y2, y2_arr, prime_word_len * 2 + 1 ); // currently needs to be a mm-mul result (for get_affine...)


  FLEA_CCALL(THR_flea_mpi_t__decode(&exp_x, exp_x_enc, sizeof(exp_x_enc)));
  FLEA_CCALL(THR_flea_mpi_t__decode(&exp_y, exp_y_enc, sizeof(exp_y_enc)));
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

  FLEA_CCALL(THR_flea_curve_gfp_t__init(&curve, a_enc, sizeof(a_enc), b_enc, sizeof(b_enc), prime_enc, sizeof(prime_enc), curve_word_arr, curve_word_arr_word_len));

  mm_ctx.p_ws = &montgm_mul_ws;
  mm_ctx.p_mod = &curve.m_p;
  mm_ctx.mod_prime = flea_montgomery_compute_n_prime(curve.m_p.m_words[0]);

// set/compute the mpi values
  FLEA_CCALL(THR_flea_mpi_t__set_pow_2(&montg_const, curve.m_p.m_nb_used_words * FLEA_WORD_BIT_SIZE));
  FLEA_CCALL(THR_flea_mpi_t__mul(&mpi_worksp_arr_double_mod_size[0], &montg_const, &montg_const));
  FLEA_CCALL(THR_flea_mpi_t__divide(NULL, &montg_const_sq_mod_p, &mpi_worksp_arr_double_mod_size[0], &curve.m_p, &div_ctx ));


  FLEA_CCALL(THR_flea_mpi_t__mul(&mpi_worksp_arr_double_mod_size[0], &montg_const, &curve.m_a));
  FLEA_CCALL(THR_flea_mpi_t__divide(NULL, &aR_mod_p, &mpi_worksp_arr_double_mod_size[0], &curve.m_p, &div_ctx ));

  FLEA_CCALL(THR_flea_mpi_t__mul(&mpi_worksp_arr_double_mod_size[0], &montg_const, &curve.m_b));
  FLEA_CCALL(THR_flea_mpi_t__divide(NULL, &bR_mod_p, &mpi_worksp_arr_double_mod_size[0], &curve.m_p, &div_ctx ));

  FLEA_CCALL(THR_flea_point_gfp_t__init(&aff_point, p_x1_enc, sizeof(p_x1_enc), p_y1_enc, sizeof(p_y1_enc), aff_point_word_arr, aff_point_word_arr_word_len));
  FLEA_CCALL(THR_flea_point_gfp_t__init(&aff_point_2, p_x2_enc, sizeof(p_x2_enc), p_y2_enc, sizeof(p_y2_enc), aff_point_word_arr_2, aff_point_word_arr_word_len));
  FLEA_CCALL(THR_flea_point_jac_proj_t__init(&work_point, &aff_point, &montg_const_sq_mod_p, &mod_sized_ws, &mm_ctx, proj_point_word_arr, proj_point_word_arr_word_len, &mpi_worksp_arr_double_mod_size[0]));
  FLEA_CCALL(THR_flea_point_jac_proj_t__init(&work_point_2, &aff_point_2, &montg_const_sq_mod_p, &mod_sized_ws, &mm_ctx, proj_point_word_arr_2, proj_point_word_arr_word_len, &mpi_worksp_arr_double_mod_size[0]));

  FLEA_CCALL(THR_flea_point_jac_proj_t__add(&work_point, &work_point_2, &aR_mod_p, &bR_mod_p, &mm_ctx, mpi_worksp_arr_double_mod_size, &montg_const_sq_mod_p));

  FLEA_CCALL(THR_flea_point_jac_proj_t__get_affine_x(&x, &work_point,  &mm_ctx, mpi_worksp_arr_double_mod_size, &montg_const_sq_mod_p ));
  FLEA_CCALL(THR_flea_point_jac_proj_t__get_affine_y(&y, &work_point,  &mm_ctx, mpi_worksp_arr_double_mod_size, &montg_const_sq_mod_p ));
  // get affine x,y from work_point
  //compare them to the expected values
  if(flea_mpi_t__compare_absolute(&x, &exp_x) || flea_mpi_t__compare_absolute(&y, &exp_y))
  {
    FLEA_THROW("error with point add", FLEA_ERR_FAILED_TEST);
  }
  FLEA_THR_FIN_SEC(
    FLEA_DO_IF_USE_HEAP_BUF(
      for(i = 0; i < FLEA_NB_ARRAY_ENTRIES(ecc_ws_mpi_arrs); i++)
      {
        FLEA_FREE_MEM_CHK_NULL(ecc_ws_mpi_arrs[i]);
      }
      );
    FLEA_FREE_BUF_FINAL(curve_word_arr);
    FLEA_FREE_BUF_FINAL(aff_point_word_arr);
    FLEA_FREE_BUF_FINAL(aff_point_word_arr_2);
    FLEA_FREE_BUF_FINAL(proj_point_word_arr);
    FLEA_FREE_BUF_FINAL(proj_point_word_arr_2);
    FLEA_FREE_BUF_FINAL(aR_mod_p_word_arr);
    FLEA_FREE_BUF_FINAL(bR_mod_p_word_arr);
    FLEA_FREE_BUF_FINAL(exp_x_arr);
    FLEA_FREE_BUF_FINAL(exp_y_arr);
    FLEA_FREE_BUF_FINAL(x_arr);
    FLEA_FREE_BUF_FINAL(y_arr);
    FLEA_FREE_BUF_FINAL(x2_arr);
    FLEA_FREE_BUF_FINAL(y2_arr);
    FLEA_FREE_BUF_FINAL(montgm_mul_ws_word_arr);
    FLEA_FREE_BUF_FINAL(mod_sized_ws_word_arr);
    FLEA_FREE_BUF_FINAL(montg_const_word_arr);
    FLEA_FREE_BUF_FINAL(montg_const_sq_mod_p_arr);
    FLEA_FREE_BUF_FINAL(vn);
    FLEA_FREE_BUF_FINAL(un);

    );

}

flea_err_t THR_flea_test_ecc_point_gfp_double ()
{

  flea_al_u16_t i;
  // curve: secP160r1
  flea_u8_t prime_enc[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xff };
  flea_u8_t a_enc[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xfc };
  flea_u8_t b_enc[] = { 0x1c, 0x97, 0xbe, 0xfc, 0x54, 0xbd, 0x7a, 0x8b, 0x65, 0xac, 0xf8, 0x9f, 0x81, 0xd4, 0xd4, 0xad, 0xc5, 0x65, 0xfa, 0x45 };
  flea_u8_t p_x_enc[] = { 0x4A, 0x96, 0xB5, 0x68, 0x8E, 0xF5, 0x73, 0x28, 0x46, 0x64, 0x69, 0x89, 0x68, 0xC3, 0x8B, 0xB9, 0x13, 0xCB, 0xFC, 0x82 };
  flea_u8_t p_y_enc[] = { 0x23, 0xA6, 0x28, 0x55, 0x31, 0x68, 0x94, 0x7D, 0x59, 0xDC, 0xC9, 0x12, 0x04, 0x23, 0x51, 0x37, 0x7A, 0xC5, 0xFB, 0x32 };
  const flea_al_u16_t curve_word_arr_word_len = 3 * ((sizeof(prime_enc) + sizeof(flea_uword_t) - 1) / sizeof(flea_uword_t));

  FLEA_DECL_BUF(curve_word_arr, flea_uword_t, curve_word_arr_word_len);

  const flea_al_u16_t aff_point_word_arr_word_len = 2 * ((sizeof(prime_enc) + sizeof(flea_uword_t) - 1) / sizeof(flea_uword_t));
  FLEA_DECL_BUF(aff_point_word_arr, flea_uword_t, aff_point_word_arr_word_len);

  const flea_al_u16_t proj_point_word_arr_word_len = 3 * ((sizeof(prime_enc) + sizeof(flea_uword_t) - 1) / sizeof(flea_uword_t));
  FLEA_DECL_BUF(proj_point_word_arr, flea_uword_t, proj_point_word_arr_word_len);

  const flea_al_u16_t prime_word_len = (sizeof(prime_enc) + sizeof(flea_uword_t) - 1) / sizeof(flea_uword_t);
  const flea_al_u16_t vn_len = FLEA_MPI_DIV_VN_HLFW_LEN_FROM_DIVISOR_W_LEN((prime_word_len + 1));       // + 1 due to reducing R^2 !
  const flea_al_u16_t un_len = FLEA_MPI_DIV_UN_HLFW_LEN_FROM_DIVIDENT_W_LEN(2 * (prime_word_len + 1));  // + 1 due to reducing R^2 !

  FLEA_DECL_BUF(vn, flea_hlf_uword_t, vn_len);
  FLEA_DECL_BUF(un, flea_hlf_uword_t, un_len);

  flea_mpi_div_ctx_t div_ctx;

  flea_u8_t exp_x_enc[] = { 0x02, 0xF9, 0x97, 0xF3, 0x3C, 0x5E, 0xD0, 0x4C, 0x55, 0xD3, 0xED, 0xF8, 0x67, 0x5D, 0x3E, 0x92, 0xE8, 0xF4, 0x66, 0x86 };

  flea_u8_t exp_y_enc[] = { 0xF0, 0x83, 0xA3, 0x23, 0x48, 0x29, 0x93, 0xE9, 0x44, 0x0E, 0x81, 0x7E, 0x21, 0xCF, 0xB7, 0x73, 0x7D, 0xF8, 0x79, 0x7B };

  flea_curve_gfp_t curve;
  flea_point_gfp_t aff_point;
  flea_point_jac_proj_t work_point;

  flea_mpi_t montg_const, montg_const_sq_mod_p, mod_sized_ws, montgm_mul_ws, aR_mod_p, bR_mod_p;
  flea_mpi_t exp_x, exp_y, x, y;
  flea_mpi_t mpi_worksp_arr_double_mod_size[9];

  const flea_mpi_ulen_t montg_const_word_arr_word_len = prime_word_len + 1;
  const flea_mpi_ulen_t montg_const_sq_mod_p_word_len = prime_word_len;
  const flea_mpi_ulen_t montgm_mul_ws_word_len = (prime_word_len) * 2 + 1;

  flea_montgm_mul_ctx_t mm_ctx;

  FLEA_DECL_BUF(montg_const_word_arr, flea_uword_t, montg_const_word_arr_word_len );
  FLEA_DECL_BUF(montg_const_sq_mod_p_arr, flea_uword_t, montg_const_sq_mod_p_word_len);
  FLEA_DECL_BUF(mod_sized_ws_word_arr, flea_uword_t, prime_word_len );
  FLEA_DECL_BUF(montgm_mul_ws_word_arr, flea_uword_t, montgm_mul_ws_word_len);
  FLEA_DECL_BUF(aR_mod_p_word_arr, flea_uword_t, prime_word_len);
  FLEA_DECL_BUF(bR_mod_p_word_arr, flea_uword_t, prime_word_len);
  FLEA_DECL_BUF(exp_x_arr, flea_uword_t, prime_word_len);
  FLEA_DECL_BUF(x_arr, flea_uword_t, prime_word_len * 2 + 1);                 // currently needs to be a mm-mul result (for get_affine...)
  FLEA_DECL_BUF(exp_y_arr, flea_uword_t, prime_word_len);
  FLEA_DECL_BUF(y_arr, flea_uword_t, prime_word_len * 2 + 1);                 // currently needs to be a mm-mul result (for get_affine...)

  const flea_al_u8_t ecc_ws_mpi_arrs_word_len = (prime_word_len + 1) * 2 + 1; // + 1 in brackets because I need it to square R!
#ifdef FLEA_USE_STACK_BUF
  flea_uword_t ecc_ws_mpi_arrs [9][ecc_ws_mpi_arrs_word_len];
#else
  flea_uword_t* ecc_ws_mpi_arrs [9];
#endif

  FLEA_THR_BEG_FUNC();

#ifdef FLEA_USE_HEAP_BUF
  memset(ecc_ws_mpi_arrs, 0, sizeof(ecc_ws_mpi_arrs));
  for(i = 0; i < FLEA_NB_ARRAY_ENTRIES(ecc_ws_mpi_arrs); i++)
  {
    FLEA_ALLOC_MEM_ARR(ecc_ws_mpi_arrs[i], ecc_ws_mpi_arrs_word_len);
  }
#endif

  FLEA_ALLOC_BUF(curve_word_arr, curve_word_arr_word_len);
  FLEA_ALLOC_BUF(aff_point_word_arr, aff_point_word_arr_word_len);
  FLEA_ALLOC_BUF(proj_point_word_arr, proj_point_word_arr_word_len);

  FLEA_ALLOC_BUF(montg_const_word_arr, montg_const_word_arr_word_len );
  FLEA_ALLOC_BUF(montg_const_sq_mod_p_arr, montg_const_sq_mod_p_word_len);
  FLEA_ALLOC_BUF(mod_sized_ws_word_arr, prime_word_len );
  FLEA_ALLOC_BUF(montgm_mul_ws_word_arr, montgm_mul_ws_word_len);
  FLEA_ALLOC_BUF(aR_mod_p_word_arr, prime_word_len);
  FLEA_ALLOC_BUF(bR_mod_p_word_arr, prime_word_len);
  FLEA_ALLOC_BUF(exp_x_arr, prime_word_len);
  FLEA_ALLOC_BUF(x_arr, prime_word_len * 2 + 1); // currently needs to be a mm-mul result (for get_affine...)

  FLEA_ALLOC_BUF(exp_y_arr, prime_word_len);
  FLEA_ALLOC_BUF(y_arr, prime_word_len * 2 + 1); // currently needs to be a mm-mul result (for get_affine...)


  flea_mpi_t__init(&montg_const, montg_const_word_arr, montg_const_word_arr_word_len);
  flea_mpi_t__init(&montg_const_sq_mod_p, montg_const_sq_mod_p_arr, montg_const_sq_mod_p_word_len);
  flea_mpi_t__init(&mod_sized_ws, mod_sized_ws_word_arr, prime_word_len);
  flea_mpi_t__init(&montgm_mul_ws, montgm_mul_ws_word_arr, montgm_mul_ws_word_len);
  flea_mpi_t__init(&aR_mod_p, aR_mod_p_word_arr, prime_word_len );
  flea_mpi_t__init(&bR_mod_p, bR_mod_p_word_arr, prime_word_len );
  flea_mpi_t__init(&exp_x, exp_x_arr, prime_word_len );
  flea_mpi_t__init(&x, x_arr, prime_word_len * 2 + 1 ); // currently needs to be a mm-mul result (for get_affine...)
  flea_mpi_t__init(&exp_y, exp_y_arr, prime_word_len );
  flea_mpi_t__init(&y, y_arr, prime_word_len * 2 + 1 ); // currently needs to be a mm-mul result (for get_affine...)


  FLEA_CCALL(THR_flea_mpi_t__decode(&exp_x, exp_x_enc, sizeof(exp_x_enc)));
  FLEA_CCALL(THR_flea_mpi_t__decode(&exp_y, exp_y_enc, sizeof(exp_y_enc)));
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

  FLEA_CCALL(THR_flea_curve_gfp_t__init(&curve, a_enc, sizeof(a_enc), b_enc, sizeof(b_enc), prime_enc, sizeof(prime_enc), curve_word_arr, curve_word_arr_word_len));

  mm_ctx.p_ws = &montgm_mul_ws;
  mm_ctx.p_mod = &curve.m_p;
  mm_ctx.mod_prime = flea_montgomery_compute_n_prime(curve.m_p.m_words[0]);

// set/compute the mpi values
  FLEA_CCALL(THR_flea_mpi_t__set_pow_2(&montg_const, curve.m_p.m_nb_used_words * FLEA_WORD_BIT_SIZE));
  FLEA_CCALL(THR_flea_mpi_t__mul(&mpi_worksp_arr_double_mod_size[0], &montg_const, &montg_const));
  FLEA_CCALL(THR_flea_mpi_t__divide(NULL, &montg_const_sq_mod_p, &mpi_worksp_arr_double_mod_size[0], &curve.m_p, &div_ctx ));


  FLEA_CCALL(THR_flea_mpi_t__mul(&mpi_worksp_arr_double_mod_size[0], &montg_const, &curve.m_a));
  FLEA_CCALL(THR_flea_mpi_t__divide(NULL, &aR_mod_p, &mpi_worksp_arr_double_mod_size[0], &curve.m_p, &div_ctx ));

  FLEA_CCALL(THR_flea_mpi_t__mul(&mpi_worksp_arr_double_mod_size[0], &montg_const, &curve.m_b));
  FLEA_CCALL(THR_flea_mpi_t__divide(NULL, &bR_mod_p, &mpi_worksp_arr_double_mod_size[0], &curve.m_p, &div_ctx ));

  FLEA_CCALL(THR_flea_point_gfp_t__init(&aff_point, p_x_enc, sizeof(p_x_enc), p_y_enc, sizeof(p_y_enc), aff_point_word_arr, aff_point_word_arr_word_len));
  FLEA_CCALL(THR_flea_point_jac_proj_t__init(&work_point, &aff_point, &montg_const_sq_mod_p, &mod_sized_ws, &mm_ctx, proj_point_word_arr, proj_point_word_arr_word_len, &mpi_worksp_arr_double_mod_size[0]));

  FLEA_CCALL(THR_flea_point_jac_proj_t__double(&work_point, &aR_mod_p, &bR_mod_p, &mm_ctx, mpi_worksp_arr_double_mod_size, &montg_const_sq_mod_p));

  FLEA_CCALL(THR_flea_point_jac_proj_t__get_affine_x(&x, &work_point,  &mm_ctx, mpi_worksp_arr_double_mod_size, &montg_const_sq_mod_p ));
  FLEA_CCALL(THR_flea_point_jac_proj_t__get_affine_y(&y, &work_point,  &mm_ctx, mpi_worksp_arr_double_mod_size, &montg_const_sq_mod_p ));
  if(flea_mpi_t__compare_absolute(&x, &exp_x) || flea_mpi_t__compare_absolute(&y, &exp_y))
  {

    FLEA_THROW("error with point doubling", FLEA_ERR_FAILED_TEST);
  }
  FLEA_THR_FIN_SEC(
    FLEA_DO_IF_USE_HEAP_BUF(
      for(i = 0; i < FLEA_NB_ARRAY_ENTRIES(ecc_ws_mpi_arrs); i++)
      {
        FLEA_FREE_MEM_CHK_NULL(ecc_ws_mpi_arrs[i]);
      }
      );
    FLEA_FREE_BUF_FINAL(curve_word_arr);
    FLEA_FREE_BUF_FINAL(aff_point_word_arr);
    FLEA_FREE_BUF_FINAL(proj_point_word_arr);
    FLEA_FREE_BUF_FINAL(aR_mod_p_word_arr);
    FLEA_FREE_BUF_FINAL(bR_mod_p_word_arr);
    FLEA_FREE_BUF_FINAL(exp_x_arr);
    FLEA_FREE_BUF_FINAL(exp_y_arr);
    FLEA_FREE_BUF_FINAL(x_arr);
    FLEA_FREE_BUF_FINAL(y_arr);
    FLEA_FREE_BUF_FINAL(montgm_mul_ws_word_arr);
    FLEA_FREE_BUF_FINAL(mod_sized_ws_word_arr);
    FLEA_FREE_BUF_FINAL(montg_const_word_arr);
    FLEA_FREE_BUF_FINAL(montg_const_sq_mod_p_arr);
    FLEA_FREE_BUF_FINAL(vn);
    FLEA_FREE_BUF_FINAL(un);

    );

}

#endif // #ifdef FLEA_HAVE_ECC && FLEA_ECC_MAX_MOD_BIT_SIZE >= 160
