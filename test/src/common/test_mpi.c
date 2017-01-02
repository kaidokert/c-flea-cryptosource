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
#include <stdio.h>
#include "internal/common/math/mpi.h"
#include "flea/error.h"
#include "flea/alloc.h"
#include "flea/util.h"
#include "flea/array_util.h"

flea_err_t THR_flea_test_mpi_mul ()
{
  FLEA_THR_BEG_FUNC();
  flea_u8_t a_enc [] = { 0x80, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC, 0x03, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x07, 0xFC, 0xF2, 0xFD, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC, 0x0F, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xF8, 0x00, 0x00, 0x0F, 0xFF, 0x01, 0xFF, 0xE0, 0x00, 0x00, 0x1F, 0xFF, 0x80, 0xF8, 0x7F, 0xF8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xFF, 0x00, 0x00, 0x0F, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3F, 0xFF, 0xFF, 0xFF, 0xFC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFC, 0x00, 0x1F, 0xFF, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3F, 0xFF, 0xFF, 0x80, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0x00, 0x00, 0xB0, 0x00, 0x01, 0x00, 0x00, 0x00 };
  flea_u8_t b_enc [] = { 0x80, 0x80, 0xFC, 0xFF, 0xFF, 0xFF, 0xFC, 0x03, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x07, 0xFC, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC, 0x0F, 0xFF, 0xFF, 0xFF, 0x0D, 0xAB, 0x00, 0x01, 0xFC, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xF8, 0x00, 0x00, 0x0F, 0xFF, 0x01, 0xFF, 0xE0, 0x00, 0x00, 0x1F, 0xFF, 0x80, 0xF8, 0x7F, 0xF8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xFF, 0x00, 0x00, 0x0F, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3F, 0xFF, 0xFF, 0xFF, 0xFC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFC, 0x00, 0x1F, 0xFF, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3F, 0xFF, 0xFF, 0x80, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xD8, 0x00, 0x00, 0x00, 0x1E, 0x00, 0x00, 0x02, 0x04 };
  flea_u8_t exp_res_enc[sizeof(a_enc) + sizeof(b_enc)] = {
    0x40, 0x80, 0xBE, 0xFE, 0x7F, 0xFF, 0xFC, 0x00, 0x00, 0x0F, 0xF3, 0xFE, 0xFF, 0x0E, 0xEB, 0x14, 0xFE, 0x5D, 0x82, 0x9C, 0x84, 0xC3, 0x58, 0x1C, 0xD0, 0x07, 0xF8, 0x21, 0xDC, 0x47, 0xAC, 0x18, 0xF9, 0x7E, 0x83, 0x81, 0xC9, 0x6A, 0xAB, 0xB0, 0x34, 0xB8, 0x8F, 0xD4, 0x5F, 0x3E, 0x57, 0x4F, 0x79, 0x54, 0xA0, 0xFD, 0xFA, 0xFF, 0xBA, 0x4B, 0xCD, 0xC4, 0x63, 0xBC, 0xDF, 0xFC, 0xD5, 0xE8, 0x24, 0xDB, 0x46, 0xBF, 0xE0, 0x1E, 0x20, 0x99, 0x96, 0xFB, 0x7F, 0x9E, 0x8B, 0x66, 0x2D, 0xCC, 0x95, 0x53, 0x27, 0x4B, 0xFD, 0x05, 0x6C, 0xD6, 0x81, 0x02, 0x46, 0x81, 0xD3, 0x17, 0x28, 0x40, 0x12, 0xC8, 0x07, 0x3E, 0x67, 0x10, 0x25, 0x79, 0xDF, 0xCA, 0x65, 0xDF, 0x31, 0xBA, 0x28, 0x33, 0xBC, 0x6F, 0xF4, 0xFF, 0xD5, 0x3A, 0x5D, 0x28, 0x67, 0x15, 0xF4, 0xB7, 0xEE, 0x2B, 0x49, 0x41, 0x6F, 0x58, 0x53, 0xCC, 0xEC, 0x32, 0xC8, 0xEE, 0x23, 0x02, 0x82, 0xA3, 0xB6, 0xD6, 0x91, 0x19, 0x8D, 0xB2, 0x14, 0x69, 0xD6, 0xB4, 0x06, 0x1E, 0x6C, 0x19, 0x06, 0x52, 0x94, 0x87, 0x91, 0x8C, 0x62, 0x07, 0x06, 0x15, 0x7A, 0xCC, 0x98, 0x95, 0xAA, 0x19, 0x1C, 0x58, 0x7E, 0xAF, 0xFA, 0xD6, 0xD3, 0x28, 0x11, 0x6B, 0x64, 0xDD, 0x6B, 0xFD, 0x3F, 0x99, 0x88, 0x34, 0x43, 0x76, 0x90, 0x51, 0x11, 0x40, 0x4D, 0xCA, 0x50, 0x7E, 0xB3, 0x43, 0x76, 0x48, 0x36, 0xA0, 0x6D, 0xCE, 0xD9, 0xD8, 0xFC, 0x7A, 0xB8, 0xE9, 0x7E, 0x94, 0xC8, 0xAC, 0xCC, 0x35, 0x35, 0x33, 0x7F, 0xBF, 0x30, 0xBF, 0xC6, 0x25, 0x84, 0x3B, 0xD9, 0xB2, 0xBE, 0xF4, 0xD6, 0x10, 0x82, 0x3F, 0xBF, 0x67, 0xA3, 0x3F, 0x54, 0xB2, 0x9C, 0x2A, 0x6A, 0xE2, 0x2A, 0xD7, 0x23, 0xC8, 0x7C, 0x5D, 0x1E, 0x07, 0x91, 0xC0, 0x70, 0x9D, 0x6D, 0x02, 0x5B, 0xC8, 0x18, 0x3C, 0x0E, 0x0C, 0x87, 0x6C, 0x81, 0x38, 0x1E, 0x56, 0x80, 0xA8, 0xAB, 0xD7, 0x46, 0x42, 0x01, 0x2E, 0xD4, 0xB0, 0x20, 0x55, 0x44, 0x41, 0xB1, 0x05, 0xFB, 0x43, 0xF1, 0xFB, 0x3F, 0x7C, 0x40, 0xDD, 0x7F, 0x68, 0xA2, 0xC8, 0x80, 0xFE, 0x4F, 0xE6, 0xF4, 0x7B, 0xFE, 0x2C, 0x07, 0x80, 0x40, 0x2A, 0x80, 0xAB, 0x4F, 0xE3, 0x5F, 0x3C, 0x00, 0x4C, 0x03, 0xEC, 0x7F, 0xC3, 0xD8, 0x14, 0x9B, 0xF8, 0x1F, 0x62, 0xC0, 0x02, 0x04, 0x00, 0x00, 0x00
  };
  const flea_u16_t a_words = (sizeof(a_enc) + sizeof(flea_uword_t) - 1) / sizeof(flea_uword_t);
  const flea_u16_t b_words = (sizeof(b_enc) + sizeof(flea_uword_t) - 1) / sizeof(flea_uword_t);
  flea_uword_t a_arr[a_words];
  flea_uword_t b_arr[b_words];
  flea_uword_t result_arr[a_words + b_words];
  flea_uword_t exp_res_arr[a_words + b_words];

  flea_mpi_t exp_res, result, a, b;
  flea_mpi_t__init(&a, a_arr, sizeof(a_arr) / sizeof(a_arr[0]));
  flea_mpi_t__init(&b, b_arr, sizeof(b_arr) / sizeof(b_arr[0]));
  flea_mpi_t__init(&result, result_arr, sizeof(result_arr) / sizeof(result_arr[0]));
  flea_mpi_t__init(&exp_res, exp_res_arr, sizeof(exp_res_arr) / sizeof(exp_res_arr[0]));

  FLEA_CCALL(THR_flea_mpi_t__decode(&a, a_enc, sizeof(a_enc)));
  FLEA_CCALL(THR_flea_mpi_t__decode(&b, b_enc, sizeof(b_enc)));
  FLEA_CCALL(THR_flea_mpi_t__decode(&exp_res, exp_res_enc, sizeof(exp_res_enc)));

  FLEA_CCALL(THR_flea_mpi_t__mul(&result, &a, &b));

  if(!flea_mpi_t__equal(&exp_res, &result))
  {
    FLEA_THROW("multiplication: expected and actual results differ", FLEA_ERR_FAILED_TEST);
  }


  FLEA_THR_FIN_SEC();
}
flea_err_t THR_flea_test_mpi_square ()
{
  FLEA_THR_BEG_FUNC();
  flea_u8_t a_enc [] = { 0x80, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC, 0x03, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x07, 0xFC, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC, 0x0F, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xF8, 0x00, 0x00, 0x0F, 0xFF, 0x01, 0xFF, 0xE0, 0x00, 0x00, 0x1F, 0xFF, 0x80, 0xF8, 0x7F, 0xF8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xFF, 0x00, 0x00, 0x0F, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3F, 0xFF, 0xFF, 0xFF, 0xFC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFC, 0x00, 0x1F, 0xFF, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3F, 0xFF, 0xFF, 0x80, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
  const flea_u16_t a_words = (sizeof(a_enc) + sizeof(flea_uword_t) - 1) / sizeof(flea_uword_t);
  flea_uword_t a_arr[a_words];
  flea_uword_t result_arr[2 * a_words];
  flea_uword_t mul_res_arr[2 * a_words];

  flea_mpi_t mul_res, result, a;
  flea_mpi_t__init(&a, a_arr, sizeof(a_arr) / sizeof(a_arr[0]));
  flea_mpi_t__init(&result, result_arr, sizeof(result_arr) / sizeof(result_arr[0]));
  flea_mpi_t__init(&mul_res, mul_res_arr, sizeof(mul_res_arr) / sizeof(mul_res_arr[0]));

  FLEA_CCALL(THR_flea_mpi_t__decode(&a, a_enc, sizeof(a_enc)));

  FLEA_CCALL(THR_flea_mpi_t__mul(&mul_res, &a, &a));
  FLEA_CCALL(THR_flea_mpi_square(&result, &a));

  if(!flea_mpi_t__equal(&mul_res, &result))
  {
    FLEA_THROW("squaring and multiplication result differ", FLEA_ERR_FAILED_TEST);
  }


  FLEA_THR_FIN_SEC();
}

flea_err_t THR_flea_test_mpi_div ()
{
  FLEA_THR_BEG_FUNC();

  const flea_u8_t exp_q_enc [] = { 0xFC, 0xD1, 0xB9, 0x7B };
  const flea_u8_t exp_r_enc [] = { 0x01, 0x8B, 0x05, 0x1D, 0x4A, 0x65, 0x29, 0x60, 0xAA, 0x87, 0xC9, 0x63, 0x0D, 0x70, 0xF7, 0xE2, 0x96, 0x2F, 0xC9, 0x62, 0xFD, 0xB5, 0xD6, 0xBA };

  const flea_u8_t divident_enc [] = { 0xFC, 0xCF, 0xFD, 0xFE, 0x3E, 0xEE, 0xDD, 0x33, 0x3D, 0xF8, 0x9C, 0xC2, 0x32, 0x3A, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDF };
  const flea_u8_t mod_enc [] = { 0xFF, 0xFE, 0x3E, 0xEE, 0xDD, 0x33, 0x33, 0x78, 0x88, 0x82, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDF };

  flea_mpi_ulen_t mod_arr_word_len_static = (sizeof(mod_enc) + sizeof(flea_uword_t) - 1) / sizeof(flea_uword_t);
  flea_mpi_ulen_t divident_arr_word_len_static = (sizeof(divident_enc) + sizeof(flea_uword_t) - 1) / sizeof(flea_uword_t);
  flea_mpi_ulen_t q_arr_word_len_static = (sizeof(exp_q_enc) + sizeof(flea_uword_t) - 1) / sizeof(flea_uword_t) + 1;
  flea_mpi_ulen_t r_arr_word_len_static = (sizeof(exp_r_enc) + sizeof(flea_uword_t) - 1) / sizeof(flea_uword_t);
  FLEA_DECL_BUF(divident_arr, flea_uword_t,  divident_arr_word_len_static);
  FLEA_DECL_BUF(mod_arr, flea_uword_t,  mod_arr_word_len_static );
  FLEA_DECL_BUF(exp_q_arr, flea_uword_t, q_arr_word_len_static);
  FLEA_DECL_BUF(q_arr, flea_uword_t, q_arr_word_len_static);
  FLEA_DECL_BUF(r_arr, flea_uword_t, r_arr_word_len_static);
  FLEA_DECL_BUF(exp_r_arr, flea_uword_t, r_arr_word_len_static);

  const flea_al_u16_t vn_len = mod_arr_word_len_static * sizeof(flea_uword_t);
  const flea_al_u16_t un_len = divident_arr_word_len_static * sizeof(flea_uword_t) + 2;
  FLEA_DECL_BUF(vn, flea_hlf_uword_t, vn_len);
  FLEA_DECL_BUF(un, flea_hlf_uword_t, un_len);

  FLEA_ALLOC_BUF(divident_arr, divident_arr_word_len_static);
  FLEA_ALLOC_BUF(mod_arr, mod_arr_word_len_static);
  FLEA_ALLOC_BUF(exp_q_arr, q_arr_word_len_static);
  FLEA_ALLOC_BUF(q_arr, q_arr_word_len_static);
  FLEA_ALLOC_BUF(r_arr, r_arr_word_len_static);
  FLEA_ALLOC_BUF(exp_r_arr, r_arr_word_len_static);
  FLEA_ALLOC_BUF(vn, mod_arr_word_len_static * sizeof(flea_uword_t));
  FLEA_ALLOC_BUF(un, divident_arr_word_len_static * sizeof(flea_uword_t) + 2);

  flea_mpi_t divident, divisor, res_q, res_r, exp_r, exp_q;

  flea_mpi_div_ctx_t div_ctx;
  div_ctx.vn = vn;
  div_ctx.un = un;
  div_ctx.un_len = un_len;
  div_ctx.vn_len = vn_len;

  flea_mpi_t__init(&divident, divident_arr, divident_arr_word_len_static);
  flea_mpi_t__init(&divisor, mod_arr, mod_arr_word_len_static);
  flea_mpi_t__init(&res_q, q_arr, q_arr_word_len_static);
  flea_mpi_t__init(&exp_q, exp_q_arr, q_arr_word_len_static);
  flea_mpi_t__init(&res_r, r_arr, r_arr_word_len_static);
  flea_mpi_t__init(&exp_r, exp_r_arr, r_arr_word_len_static);

  FLEA_CCALL(THR_flea_mpi_t__decode(&divident, divident_enc, sizeof(divident_enc)));
  FLEA_CCALL(THR_flea_mpi_t__decode(&divisor, mod_enc, sizeof(mod_enc)));
  FLEA_CCALL(THR_flea_mpi_t__decode(&exp_q, exp_q_enc, sizeof(exp_q_enc)));
  FLEA_CCALL(THR_flea_mpi_t__decode(&exp_r, exp_r_enc, sizeof(exp_r_enc)));

  FLEA_CCALL(THR_flea_mpi_t__divide(&res_q, &res_r, &divident, &divisor, &div_ctx));

  if(FLEA_FALSE == flea_mpi_t__equal(&res_q, &exp_q))
  {
    FLEA_THROW("failure with quotient", FLEA_ERR_FAILED_TEST);
  }
  if(FLEA_FALSE == flea_mpi_t__equal(&res_r, &exp_r))
  {
    FLEA_THROW("failure with quotient", FLEA_ERR_FAILED_TEST);
  }
  FLEA_THR_FIN_SEC(

    FLEA_FREE_BUF_FINAL(divident_arr );
    FLEA_FREE_BUF_FINAL(mod_arr );
    FLEA_FREE_BUF_FINAL(exp_q_arr );
    FLEA_FREE_BUF_FINAL(q_arr );
    FLEA_FREE_BUF_FINAL(r_arr );
    FLEA_FREE_BUF_FINAL(exp_r_arr );
    FLEA_FREE_BUF_FINAL(vn );
    FLEA_FREE_BUF_FINAL(un );
    );
}

flea_err_t THR_flea_test_mpi_subtract ()
{

  flea_u8_t a_enc[] = {
    0x25, 0x1F, 0xC1, 0xEC,
    0x86, 0x93, 0xA8, 0x5A,
    0x6C, 0x09, 0xE1, 0x2E
  };
  flea_u8_t b_enc[] = {
    0x7B,
    0xA8,0x1D,	0x8D,	 0xDF,
    0x17,0x7F,	0xD7,	 0xDB,
    0xAB,0x1D,	0xBC,	 0x4E
  };

  flea_u8_t exp_res_neg_enc[] = {
    0x7B, 0x82, 0xFD, 0xCB, 0xF2, 0x90, 0xEC, 0x2F, 0x81, 0x3F, 0x13, 0xDB, 0x20
  };

  flea_uword_t a_arr [(sizeof(a_enc) + sizeof(flea_uword_t) - 1 ) / sizeof(flea_uword_t)];
  flea_uword_t b_arr [(sizeof(b_enc) + sizeof(flea_uword_t) - 1 ) / sizeof(flea_uword_t)];
  flea_uword_t exp_res_neg_arr [(sizeof(exp_res_neg_enc) + sizeof(flea_uword_t) - 1 ) / sizeof(flea_uword_t)];
  flea_uword_t res_arr [(sizeof(exp_res_neg_enc) + sizeof(flea_uword_t) - 1 ) / sizeof(flea_uword_t)];

  flea_mpi_t a, b, res, exp_res_neg;

  FLEA_THR_BEG_FUNC();
  flea_mpi_t__init(&a, a_arr, sizeof(a_arr) / sizeof(flea_uword_t));
  flea_mpi_t__init(&b, b_arr, sizeof(b_arr) / sizeof(flea_uword_t));
  flea_mpi_t__init(&exp_res_neg, exp_res_neg_arr, sizeof(exp_res_neg_arr) / sizeof(flea_uword_t));
  flea_mpi_t__init(&res, res_arr, sizeof(res_arr) / sizeof(flea_uword_t));
  FLEA_CCALL(THR_flea_mpi_t__decode(&a, a_enc, sizeof(a_enc)));
  FLEA_CCALL(THR_flea_mpi_t__decode(&b, b_enc, sizeof(b_enc)));
  FLEA_CCALL(THR_flea_mpi_t__decode(&exp_res_neg, exp_res_neg_enc, sizeof(exp_res_neg_enc)));
  FLEA_CCALL(THR_flea_mpi_t__subtract(&res, &a, &b));
  if(res.m_sign > 0)
  {
    FLEA_THROW("subtraction result not negative as required", FLEA_ERR_FAILED_TEST);
  }
  if(0 != flea_mpi_t__compare_absolute(&res, &exp_res_neg))
  {
    FLEA_THROW("subtraction result wrong", FLEA_ERR_FAILED_TEST);
  }

  FLEA_THR_FIN_SEC();
}

flea_err_t THR_flea_test_mpi_subtract_2 ()
{

  flea_u8_t a_enc[] = {
    0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
  };
  flea_u8_t b_enc[] = { 5 };

  flea_u8_t exp_res_neg_enc[] = { 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC };

  flea_uword_t a_arr [(sizeof(a_enc) + sizeof(flea_uword_t) - 1 ) / sizeof(flea_uword_t)];
  flea_uword_t b_arr [(sizeof(b_enc) + sizeof(flea_uword_t) - 1 ) / sizeof(flea_uword_t)];
  flea_uword_t exp_res_neg_arr [(sizeof(exp_res_neg_enc) + sizeof(flea_uword_t) - 1 ) / sizeof(flea_uword_t)];
  flea_uword_t res_arr [(sizeof(exp_res_neg_enc) + sizeof(flea_uword_t) - 1 ) / sizeof(flea_uword_t)];

  flea_mpi_t a, b, res, exp_res_neg;

  FLEA_THR_BEG_FUNC();
  flea_mpi_t__init(&a, a_arr, sizeof(a_arr) / sizeof(flea_uword_t));
  flea_mpi_t__init(&b, b_arr, sizeof(b_arr) / sizeof(flea_uword_t));
  flea_mpi_t__init(&exp_res_neg, exp_res_neg_arr, sizeof(exp_res_neg_arr) / sizeof(flea_uword_t));
  flea_mpi_t__init(&res, res_arr, sizeof(res_arr) / sizeof(flea_uword_t));
  FLEA_CCALL(THR_flea_mpi_t__decode(&a, a_enc, sizeof(a_enc)));
  FLEA_CCALL(THR_flea_mpi_t__decode(&b, b_enc, sizeof(b_enc)));
  FLEA_CCALL(THR_flea_mpi_t__decode(&exp_res_neg, exp_res_neg_enc, sizeof(exp_res_neg_enc)));
  FLEA_CCALL(THR_flea_mpi_t__subtract(&res, &a, &b));
  if(res.m_sign != 1)
  {
    FLEA_THROW("subtraction result not positive as required", FLEA_ERR_FAILED_TEST);
  }
  if(0 != flea_mpi_t__compare_absolute(&res, &exp_res_neg))
  {
    FLEA_THROW("subtraction result wrong", FLEA_ERR_FAILED_TEST);
  }

  FLEA_THR_FIN_SEC();
}


flea_err_t THR_flea_test_mpi_subtract_3 ()
{

  flea_u8_t a_enc[] = {
    0x01,
    0x00,0x00,	0x00,	 0xFF,
    0x00,0x00,	0x00,	 0x00
  };
  flea_u8_t b_enc[] = {

    0xFF,
    0x00,0x00,	0x00,	 0x01
  };

  flea_u8_t exp_res_neg_enc[] = {
    0x00,
    0xFF,0xFF,	0xFF,	 0xFF,
    0xFF,0xFF,	0xFF,	 0xFF
  };

  flea_uword_t a_arr [(sizeof(a_enc) + sizeof(flea_uword_t) - 1 ) / sizeof(flea_uword_t)];
  flea_uword_t b_arr [(sizeof(b_enc) + sizeof(flea_uword_t) - 1 ) / sizeof(flea_uword_t)];
  flea_uword_t exp_res_neg_arr [(sizeof(exp_res_neg_enc) + sizeof(flea_uword_t) - 1 ) / sizeof(flea_uword_t)];
  flea_uword_t res_arr [(sizeof(exp_res_neg_enc) + sizeof(flea_uword_t) - 1 ) / sizeof(flea_uword_t)];

  flea_mpi_t a, b, res, exp_res_neg;

  FLEA_THR_BEG_FUNC();
  flea_mpi_t__init(&a, a_arr, sizeof(a_arr) / sizeof(flea_uword_t));
  flea_mpi_t__init(&b, b_arr, sizeof(b_arr) / sizeof(flea_uword_t));
  flea_mpi_t__init(&exp_res_neg, exp_res_neg_arr, sizeof(exp_res_neg_arr) / sizeof(flea_uword_t));
  flea_mpi_t__init(&res, res_arr, sizeof(res_arr) / sizeof(flea_uword_t));
  FLEA_CCALL(THR_flea_mpi_t__decode(&a, a_enc, sizeof(a_enc)));
  FLEA_CCALL(THR_flea_mpi_t__decode(&b, b_enc, sizeof(b_enc)));
  FLEA_CCALL(THR_flea_mpi_t__decode(&exp_res_neg, exp_res_neg_enc, sizeof(exp_res_neg_enc)));
  FLEA_CCALL(THR_flea_mpi_t__subtract(&res, &a, &b));
  if(res.m_sign != 1)
  {
    FLEA_THROW("subtraction result not positive as required", FLEA_ERR_FAILED_TEST);
  }
  if(0 != flea_mpi_t__compare_absolute(&res, &exp_res_neg))
  {
    FLEA_THROW("subtraction result wrong", FLEA_ERR_FAILED_TEST);
  }

  FLEA_THR_FIN_SEC();
}
flea_err_t THR_flea_test_mpi_add ()
{

  flea_u8_t a_enc[] = {
    0x25, 0x1F, 0xC1, 0xEC,
    0x86, 0x93, 0xA8, 0x5A,
    0x6C, 0x09, 0xE1, 0x2E
  };
  flea_u8_t b_enc[] = {
    0x7B,
    0xA8,0x1D,	0x8D,	 0xDF,
    0x17,0x7F,	0xD7,	 0xDB,
    0xAB,0x1D,	0xBC,	 0x4E
  };

  flea_u8_t exp_res_enc[] = {
    0x7B, 0xCD, 0x3D, 0x4F, 0xCB, 0x9E, 0x13, 0x80, 0x36, 0x17, 0x27, 0x9D, 0x7C
  };

  
  flea_uword_t a_arr [(sizeof(a_enc) + sizeof(flea_uword_t) - 1 ) / sizeof(flea_uword_t) + 1];
  flea_uword_t b_arr [(sizeof(b_enc) + sizeof(flea_uword_t) - 1 ) / sizeof(flea_uword_t)];
  flea_uword_t exp_res_arr [(sizeof(exp_res_enc) + sizeof(flea_uword_t) - 1 ) / sizeof(flea_uword_t)];

  flea_mpi_t a, b, exp_res;

  FLEA_THR_BEG_FUNC();
  flea_mpi_t__init(&a, a_arr, sizeof(a_arr) / sizeof(flea_uword_t));
  flea_mpi_t__init(&b, b_arr, sizeof(b_arr) / sizeof(flea_uword_t));
  flea_mpi_t__init(&exp_res, exp_res_arr, sizeof(exp_res_arr) / sizeof(flea_uword_t));
  FLEA_CCALL(THR_flea_mpi_t__decode(&a, a_enc, sizeof(a_enc)));
  FLEA_CCALL(THR_flea_mpi_t__decode(&b, b_enc, sizeof(b_enc)));
  FLEA_CCALL(THR_flea_mpi_t__decode(&exp_res, exp_res_enc, sizeof(exp_res_enc)));
  FLEA_CCALL(THR_flea_mpi_t__add_in_place_ignore_sign(&a, &b)); // b gets the result
  if(!flea_mpi_t__equal(&a, &exp_res))
  {
    FLEA_THROW("addition result wrong", FLEA_ERR_FAILED_TEST);
  }

  FLEA_THR_FIN_SEC();
}

flea_err_t THR_flea_test_mpi_add_2 ()
{

  flea_u8_t a_enc[] = {
    0x00,
    0xFF,0xFF,	0xFF,	 0xFF,
    0xFF,0xFF,	0xFF,	 0xFF
  };
  flea_u8_t b_enc[] = {
    0x01
  };

  flea_u8_t exp_res_enc[] = {
    0x01,
    0x00,0x00,	0x00,	 0x00,
    0x00,0x00,	0x00,	 0x00
  };

  
  flea_uword_t a_arr [(sizeof(a_enc) + sizeof(flea_uword_t) - 1 ) / sizeof(flea_uword_t) + 1];
  flea_uword_t b_arr [(sizeof(b_enc) + sizeof(flea_uword_t) - 1 ) / sizeof(flea_uword_t)];
  flea_uword_t exp_res_arr [(sizeof(exp_res_enc) + sizeof(flea_uword_t) - 1 ) / sizeof(flea_uword_t)];

  flea_mpi_t a, b, exp_res;

  FLEA_THR_BEG_FUNC();
  flea_mpi_t__init(&a, a_arr, sizeof(a_arr) / sizeof(flea_uword_t));
  flea_mpi_t__init(&b, b_arr, sizeof(b_arr) / sizeof(flea_uword_t));
  flea_mpi_t__init(&exp_res, exp_res_arr, sizeof(exp_res_arr) / sizeof(flea_uword_t));
  FLEA_CCALL(THR_flea_mpi_t__decode(&a, a_enc, sizeof(a_enc)));
  FLEA_CCALL(THR_flea_mpi_t__decode(&b, b_enc, sizeof(b_enc)));
  FLEA_CCALL(THR_flea_mpi_t__decode(&exp_res, exp_res_enc, sizeof(exp_res_enc)));
  FLEA_CCALL(THR_flea_mpi_t__add_in_place_ignore_sign(&a, &b)); // b gets the result
  if(!flea_mpi_t__equal(&a, &exp_res))
  {
    FLEA_THROW("addition result wrong", FLEA_ERR_FAILED_TEST);
  }

  FLEA_THR_FIN_SEC();
}
flea_err_t THR_flea_test_mpi_add_sign ()
{

  flea_u8_t a_enc[] = {
    0x25, 0x1F, 0xC1, 0xEC,
    0x86, 0x93, 0xA8, 0x5A,
    0x6C, 0x09, 0xE1, 0x2E
  };
  flea_u8_t b_enc[] = {
    0x7B,
    0xA8,0x1D,	0x8D,	 0xDF,
    0x17,0x7F,	0xD7,	 0xDB,
    0xAB,0x1D,	0xBC,	 0x4E
  };

  flea_u8_t exp_res_abs_add_enc[] = {
    0x7B, 0xCD, 0x3D, 0x4F, 0xCB, 0x9E, 0x13, 0x80, 0x36, 0x17, 0x27, 0x9D, 0x7C
  };

  flea_u8_t exp_res_abs_diff_enc[] = {
    0x7B, 0x82, 0xFD, 0xCB, 0xF2, 0x90, 0xEC, 0x2F, 0x81, 0x3F, 0x13, 0xDB, 0x20
  };
  const flea_al_u16_t a_word_len = (sizeof(a_enc) + sizeof(flea_uword_t) - 1 ) / sizeof(flea_uword_t) + 2;
  const flea_al_u16_t b_word_len = (sizeof(b_enc) + sizeof(flea_uword_t) - 1 ) / sizeof(flea_uword_t) + 1;

  FLEA_DECL_BUF(a_words, flea_uword_t, a_word_len);
  FLEA_DECL_BUF(b_words, flea_uword_t, b_word_len);
  FLEA_DECL_BUF(ws_words, flea_uword_t, a_word_len);

  flea_mpi_t a, b, ws;
  FLEA_THR_BEG_FUNC();

  FLEA_ALLOC_BUF(a_words, a_word_len);
  FLEA_ALLOC_BUF(b_words, b_word_len);
  FLEA_ALLOC_BUF(ws_words, a_word_len);

  flea_mpi_t__init(&a, a_words, a_word_len);
  flea_mpi_t__init(&b, b_words, b_word_len);
  flea_mpi_t__init(&ws, ws_words, a_word_len);
  FLEA_CCALL(THR_flea_mpi_t__decode(&a, a_enc, sizeof(a_enc)));
  FLEA_CCALL(THR_flea_mpi_t__decode(&b, b_enc, sizeof(b_enc)));

  FLEA_CCALL(THR_flea_mpi_t__add_in_place(&a, &b, &ws));

  FLEA_CCALL(THR_flea_mpi_t__decode(&ws, exp_res_abs_add_enc, sizeof(exp_res_abs_add_enc)));

  if(!flea_mpi_t__equal(&ws, &a))
  {
    FLEA_THROW("error with add in place", FLEA_ERR_FAILED_TEST);
  }

// next combination:
  FLEA_CCALL(THR_flea_mpi_t__decode(&a, a_enc, sizeof(a_enc)));
  FLEA_CCALL(THR_flea_mpi_t__decode(&b, b_enc, sizeof(b_enc)));
  a.m_sign = -1;

  FLEA_CCALL(THR_flea_mpi_t__add_in_place(&a, &b, &ws));
  FLEA_CCALL(THR_flea_mpi_t__decode(&ws, exp_res_abs_diff_enc, sizeof(exp_res_abs_diff_enc)));
  ws.m_sign = 1; // since a is smaller than b

  if(!flea_mpi_t__equal(&ws, &a))
  {
    FLEA_THROW("error with add in place", FLEA_ERR_FAILED_TEST);
  }

// next combination:
  FLEA_CCALL(THR_flea_mpi_t__decode(&a, a_enc, sizeof(a_enc)));
  FLEA_CCALL(THR_flea_mpi_t__decode(&b, b_enc, sizeof(b_enc)));
  a.m_sign = 1;
  b.m_sign = -1;

  FLEA_CCALL(THR_flea_mpi_t__add_in_place(&a, &b, &ws));
  FLEA_CCALL(THR_flea_mpi_t__decode(&ws, exp_res_abs_diff_enc, sizeof(exp_res_abs_diff_enc)));
  ws.m_sign = -1; // since a is smaller than b

  if(!flea_mpi_t__equal(&ws, &a))
  {
    FLEA_THROW("error with add in place", FLEA_ERR_FAILED_TEST);
  }

// next combination:
  FLEA_CCALL(THR_flea_mpi_t__decode(&a, a_enc, sizeof(a_enc)));
  FLEA_CCALL(THR_flea_mpi_t__decode(&b, b_enc, sizeof(b_enc)));
  a.m_sign = -1;
  b.m_sign = -1;

  FLEA_CCALL(THR_flea_mpi_t__add_in_place(&a, &b, &ws));
  FLEA_CCALL(THR_flea_mpi_t__decode(&ws, exp_res_abs_add_enc, sizeof(exp_res_abs_add_enc)));
  ws.m_sign = -1; // since a is smaller than b

  if(!flea_mpi_t__equal(&ws, &a))
  {
    FLEA_THROW("error with add in place", FLEA_ERR_FAILED_TEST);
  }

  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(a_words);
    FLEA_FREE_BUF_FINAL(b_words);
    FLEA_FREE_BUF_FINAL(ws_words);
    );
}



flea_err_t THR_flea_test_arithm ()
{

  typedef enum { add, subtract, square, multiply, divide } operation_t;
  typedef struct
  {
    operation_t op_type;
    flea_u8_t op1[4 * 4];
    flea_u8_t op2[4 * 4];
    flea_u8_t exp_res[8 * 4];
    flea_u8_t exp_res2[4 * 4];
    flea_s8_t op1_sign;
    flea_s8_t op2_sign;
    flea_s8_t exp_res_sign;
    flea_s8_t exp_res2_sign;
  } arithm_test_entry_t;

  flea_al_u16_t i;
  const arithm_test_entry_t test_data[] =
  {
    {
      .op_type = subtract,
      .op1 ={
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 1
      },
      .op1_sign = +1,
      .op2 ={
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 1
      },
      .op2_sign = +1,
      .exp_res ={
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0
      },
      .exp_res_sign = 1,
      .exp_res2 ={ 0														 }, // not used
      .exp_res2_sign = 0,               // not used
    },
    {
      .op_type = subtract,
      .op1 ={
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0
      },
      .op1_sign = +1,
      .op2 ={
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 1
      },
      .op2_sign = +1,
      .exp_res ={
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 1
      },
      .exp_res_sign = -1,
      .exp_res2 ={ 0														 }, // not used
      .exp_res2_sign = 0,               // not used
    },
    {
      .op_type = add,
      .op1 ={
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0
      },
      .op1_sign = +1,
      .op2 ={
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 1
      },
      .op2_sign = -1,
      .exp_res ={
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 1
      },
      .exp_res_sign = -1,
      .exp_res2 ={ 0														 }, // not used
      .exp_res2_sign = 0,               // not used
    },
    {
      .op_type = add,
      .op1 ={
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 1
      },
      .op1_sign = -1,
      .op2 ={
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 1
      },
      .op2_sign = +1,
      .exp_res ={
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0
      },
      .exp_res_sign = +1,
      .exp_res2 ={ 0														 }, // not used
      .exp_res2_sign = 0,               // not used
    },
    {
      .op_type = add,
      .op1 ={
        1, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 1
      },
      .op1_sign = +1,
      .op2 ={
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 2
      },
      .op2_sign = -1,
      .exp_res ={
        0,		0,			 0,		 0,
        0,		0,			 0,		 0,
        0,		0,			 0,		 0,
        0,		0,			 0,		 0,
        0,		0xff,		 0xff, 0xff,
        0xff, 0xff,		 0xff, 0xff,
        0xff, 0xff,		 0xff, 0xff,
        0xff, 0xff,		 0xff, 0xff
      },
      .exp_res_sign = +1,
      .exp_res2 ={ 0														 }, // not used
      .exp_res2_sign = 0,               // not used
    },
    {
      .op_type = add,
      .op1 ={
        0,		0xff,		 0xff, 0xff,
        0xff, 0xff,		 0xff, 0xff,
        0xff, 0xff,		 0xff, 0xff,
        0xff, 0xff,		 0xff, 0xff
      },
      .op1_sign = +1,
      .op2 ={
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 2
      },
      .op2_sign = 1,
      .exp_res ={
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        1, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 1
      },
      .exp_res_sign = +1,
      .exp_res2 ={ 0														 }, // not used
      .exp_res2_sign = 0,               // not used
    },
    {
      .op_type = multiply,
      .op1 ={
        0x12, 0xab, 0xcd, 0xef,
        0x12, 0xab, 0xcd, 0xef,
        0x12, 0xab, 0xcd, 0xef,
        0x12, 0xab, 0xcd, 0xef
      },
      .op1_sign = +1,
      .op2 ={
        0x12, 0x34, 0x56, 0x87,
        0x12, 0x34, 0x56, 0x78,
        0x12, 0x34, 0x56, 0x78,
        0x12, 0x34, 0x56, 0x78
      },
      .op2_sign = -1,
      .exp_res ={
        0x01, 0x53, 0xE5, 0xB0,
        0x34, 0xFB, 0xAE, 0x68,
        0x50, 0x92, 0x66, 0x1F,
        0x6C, 0x29, 0x1D, 0xD6,

        0x85, 0x18, 0x0A, 0x2E,
        0x51, 0x70, 0x41, 0x76,
        0x35, 0xD9, 0x89, 0xBF,
        0x1A, 0x42, 0xD2, 0x08,
      },
      .exp_res_sign = -1,
      .exp_res2 ={ 0														 }, // not used
      .exp_res2_sign = 0,               // not used
    },
    {
      .op_type = add,
      .op1 ={
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 1
      },
      .op1_sign = -1,
      .op2 ={
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0
      },
      .op2_sign = +1,
      .exp_res ={
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 1
      },
      .exp_res_sign = -1,
      .exp_res2 ={ 0														 }, // not used
      .exp_res2_sign = 0,               // not used
    },
    {
      .op_type = multiply,
      .op1 ={
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 1
      },
      .op1_sign = -1,
      .op2 ={
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0
      },
      .op2_sign = +1,
      .exp_res ={
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0
      },
      .exp_res_sign = +1,
      .exp_res2 ={ 0														 }, // not used
      .exp_res2_sign = 0,               // not used
    },
    {
      .op_type = multiply,
      .op1 ={
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 1
      },
      .op1_sign = -1,
      .op2 ={
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 1
      },
      .op2_sign = +1,
      .exp_res ={
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 1
      },
      .exp_res_sign = -1,
      .exp_res2 ={ 0														 }, // not used
      .exp_res2_sign = 0,               // not used
    },
    {
      .op_type = subtract,
      .op1 ={
        0, 0, 0, 0,
        0, 0, 1, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
      },
      .op1_sign = +1,
      .op2 ={
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 1, 0
      },
      .op2_sign = 1,
      .exp_res ={
        0,		0,		0,		0,
        0,		0,		0,		0,
        0,		0,		0,		0,
        0,		0,		0,		0,
        0,		0,		0,		0,
        0,		0,		0,		0xff,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0x00
      },
      .exp_res_sign = +1,
      .exp_res2 ={ 0														 }, // not used
      .exp_res2_sign = 0,               // not used
    }
  };
  const flea_al_u8_t op_array_word_len = sizeof(test_data[0].op1) / sizeof(flea_uword_t);
  const flea_al_u8_t res_array_word_len = 2 * op_array_word_len;
  const flea_al_u8_t res2_array_word_len = op_array_word_len;

  flea_mpi_t op1_fresh, op2_fresh, res_fresh, res2_fresh;
  flea_mpi_t op1_reuse, op2_reuse, res_reuse, res2_reuse;
  flea_mpi_t exp_res_reuse;
  flea_mpi_t exp_res2_reuse;
  flea_mpi_t wksp;

  FLEA_DECL_BUF(res_enc_fresh, flea_u8_t, sizeof(test_data[0].exp_res));
  FLEA_DECL_BUF(res2_enc_fresh, flea_u8_t, sizeof(test_data[0].exp_res2));

  FLEA_DECL_BUF(op1_words_arr_reuse, flea_uword_t, op_array_word_len);
  FLEA_DECL_BUF(op2_words_arr_reuse, flea_uword_t, op_array_word_len);
  FLEA_DECL_BUF(res_words_arr_reuse, flea_uword_t, res_array_word_len);
  FLEA_DECL_BUF(res2_words_arr_reuse, flea_uword_t, res2_array_word_len);

  // wksp for addition and subtraction
  FLEA_DECL_BUF(wksp_words_arr_reuse, flea_uword_t, op_array_word_len + 1);

  FLEA_DECL_BUF(exp_res_words_arr_reuse, flea_uword_t, res_array_word_len);
  FLEA_DECL_BUF(exp_res2_words_arr_reuse, flea_uword_t, res2_array_word_len);

  FLEA_DECL_BUF(op1_words_arr_fresh, flea_uword_t, op_array_word_len);
  FLEA_DECL_BUF(op2_words_arr_fresh, flea_uword_t, op_array_word_len);
  FLEA_DECL_BUF(res_words_arr_fresh, flea_uword_t, res_array_word_len);
  FLEA_DECL_BUF(res2_words_arr_fresh, flea_uword_t, res2_array_word_len);

  FLEA_THR_BEG_FUNC();

  FLEA_ALLOC_BUF(op1_words_arr_reuse, op_array_word_len);
  FLEA_ALLOC_BUF(op2_words_arr_reuse, op_array_word_len);
  FLEA_ALLOC_BUF(res_words_arr_reuse, res_array_word_len);
  FLEA_ALLOC_BUF(res2_words_arr_reuse, res2_array_word_len);

  FLEA_ALLOC_BUF(wksp_words_arr_reuse, op_array_word_len + 1);

  FLEA_ALLOC_BUF(exp_res_words_arr_reuse, res_array_word_len);
  FLEA_ALLOC_BUF(exp_res2_words_arr_reuse, res2_array_word_len);

  flea_mpi_t__init(&op1_reuse, op1_words_arr_reuse, op_array_word_len);
  flea_mpi_t__init(&op2_reuse, op2_words_arr_reuse, op_array_word_len);
  flea_mpi_t__init(&res_reuse, res_words_arr_reuse, res_array_word_len);
  flea_mpi_t__init(&res2_reuse, res2_words_arr_reuse, res2_array_word_len);

  flea_mpi_t__init(&exp_res_reuse, exp_res_words_arr_reuse, res_array_word_len);
  flea_mpi_t__init(&exp_res2_reuse, exp_res2_words_arr_reuse, res2_array_word_len);

  flea_mpi_t__init(&wksp, wksp_words_arr_reuse, op_array_word_len + 1);

  for(i = 0; i < FLEA_NB_ARRAY_ENTRIES(test_data); i++)
  {
    flea_al_u16_t j;
    flea_al_u8_t res_enc_len = sizeof(test_data[i].exp_res);
    flea_al_u8_t res2_enc_len = sizeof(test_data[i].exp_res2);

    flea_mpi_t *op1_p, *op2_p, *res_p, *res2_p;
    operation_t op_type = test_data[i].op_type;

    flea_s8_t op1_sign = test_data[i].op1_sign;
    flea_s8_t op2_sign = test_data[i].op2_sign;
    flea_s8_t exp_res_sign = test_data[i].exp_res_sign;
    flea_s8_t exp_res2_sign = test_data[i].exp_res2_sign;
    FLEA_ALLOC_BUF(res_enc_fresh, res_enc_len);   // must use the full length to have simple comparison with exp_res
    FLEA_ALLOC_BUF(res2_enc_fresh, res2_enc_len); // must use the full length to have simple comparison with exp_res

    FLEA_ALLOC_BUF(op1_words_arr_fresh, op_array_word_len);
    FLEA_ALLOC_BUF(op2_words_arr_fresh, op_array_word_len);
    FLEA_ALLOC_BUF(res_words_arr_fresh, res_array_word_len);
    FLEA_ALLOC_BUF(res2_words_arr_fresh, res2_array_word_len);

    flea_mpi_t__init(&op1_fresh, op1_words_arr_fresh, op_array_word_len);
    flea_mpi_t__init(&op2_fresh, op2_words_arr_fresh, op_array_word_len);
    flea_mpi_t__init(&res_fresh, res_words_arr_fresh, res_array_word_len);
    flea_mpi_t__init(&res2_fresh, res2_words_arr_fresh, res2_array_word_len);

    // j = 0: use fresh mpis
    // j = 1: reuse, decode into existing mpi
    // j = 2 reuse, decode into tmp mpi and then copy into existing mpi
    for(j = 0; j < 3; j++)
    {
      if(j == 0)
      {
        op1_p = &op1_fresh;
        op2_p = &op2_fresh;
        res_p = &res_fresh;
        res2_p = &res2_fresh;
      }
      else
      {
        op1_p = &op1_reuse;
        op2_p = &op2_reuse;
        res_p = &res_reuse;
        res2_p = &res2_reuse;
      }
      if(j == 2)
      {
        // use op1 fresh as tmp var
        FLEA_CCALL(THR_flea_mpi_t__decode(&op1_fresh, test_data[i].op1, sizeof(test_data[i].op1)));
        FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(op1_p, &op1_fresh));
        FLEA_CCALL(THR_flea_mpi_t__decode(&op1_fresh, test_data[i].op2, sizeof(test_data[i].op2)));
        FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(op2_p, &op1_fresh));

        FLEA_CCALL(THR_flea_mpi_t__decode(&res_fresh, test_data[i].exp_res, sizeof(test_data[i].exp_res)));
        FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(&exp_res_reuse, &res_fresh));
        FLEA_CCALL(THR_flea_mpi_t__decode(&op1_fresh, test_data[i].exp_res2, sizeof(test_data[i].exp_res2)));
        FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(&exp_res2_reuse, &op1_fresh));
      }
      else
      {
        FLEA_CCALL(THR_flea_mpi_t__decode(op1_p, test_data[i].op1, sizeof(test_data[i].op1)));
        FLEA_CCALL(THR_flea_mpi_t__decode(op2_p, test_data[i].op2, sizeof(test_data[i].op1)));
        FLEA_CCALL(THR_flea_mpi_t__decode(&exp_res_reuse, test_data[i].exp_res, sizeof(test_data[i].exp_res)));
        FLEA_CCALL(THR_flea_mpi_t__decode(&exp_res2_reuse, test_data[i].exp_res2, sizeof(test_data[i].exp_res2)));
      }
    }

    op1_p->m_sign = op1_sign;
    op2_p->m_sign = op2_sign;
    exp_res_reuse.m_sign = exp_res_sign;
    exp_res2_reuse.m_sign = exp_res2_sign;

    if(op_type == subtract)
    {
      FLEA_CCALL(THR_flea_mpi_t__subtract(res_p, op1_p, op2_p));
    }
    else if(op_type == add)
    {
      FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(res_p, op1_p));
      FLEA_CCALL(THR_flea_mpi_t__add_in_place(res_p, op2_p, &wksp));
    }
    else if(op_type == multiply)
    {
      FLEA_CCALL(THR_flea_mpi_t__mul(res_p, op1_p, op2_p));
    }
    else if(op_type == square)
    {
      FLEA_CCALL(THR_flea_mpi_t__mul(res_p, op1_p, op1_p));
    }
    else
    {
      FLEA_THROW("error: uncovered op type", FLEA_ERR_INT_ERR);
    }

    // compare the result.
    // first, using encoding...
    FLEA_CCALL(THR_flea_mpi_t__encode(res_enc_fresh, res_enc_len, res_p));
    if(memcmp(res_enc_fresh, test_data[i].exp_res, res_enc_len))
    {
      FLEA_THROW("error with comparison of encoded res", FLEA_ERR_FAILED_TEST);
    }
    if(exp_res_sign != res_p->m_sign)
    {
      FLEA_THROW("error with sign in res", FLEA_ERR_FAILED_TEST);
    }
    if(op_type == divide)
    {
      FLEA_CCALL(THR_flea_mpi_t__encode(res2_enc_fresh, res2_enc_len, res2_p));
      if(memcmp(res2_enc_fresh, test_data[i].exp_res2, res2_enc_len))
      {
        FLEA_THROW("error with comparison of encoded res2", FLEA_ERR_FAILED_TEST);
      }

      if(exp_res2_sign != res2_p->m_sign)
      {
        FLEA_THROW("error with sign in res", FLEA_ERR_FAILED_TEST);
      }
    }
    // now use the already decoded expected results
    if(flea_mpi_t__compare(res_p, &exp_res_reuse))
    {
      FLEA_THROW("error with comparison of decoded res", FLEA_ERR_FAILED_TEST);
    }
    if(op_type == divide)
    {
      if(flea_mpi_t__compare(res2_p, &exp_res2_reuse))
      {
        FLEA_THROW("error with comparison of decoded res", FLEA_ERR_FAILED_TEST);
      }
    }


    FLEA_FREE_BUF(res_enc_fresh );  // must use the full length to have simple comparison with exp_res
    FLEA_FREE_BUF(res2_enc_fresh);  // must use the full length to have simple comparison with exp_res

    FLEA_FREE_BUF(op1_words_arr_fresh );
    FLEA_FREE_BUF(op2_words_arr_fresh );
    FLEA_FREE_BUF(res_words_arr_fresh );
    FLEA_FREE_BUF(res2_words_arr_fresh );

  }

  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(res_enc_fresh );    // must use the full length to have simple comparison with exp_res
    FLEA_FREE_BUF_FINAL(res2_enc_fresh);    // must use the full length to have simple comparison with exp_res

    FLEA_FREE_BUF_FINAL(op1_words_arr_fresh );
    FLEA_FREE_BUF_FINAL(op2_words_arr_fresh );
    FLEA_FREE_BUF_FINAL(res_words_arr_fresh );
    FLEA_FREE_BUF_FINAL(res2_words_arr_fresh );

    FLEA_FREE_BUF_FINAL(exp_res_words_arr_reuse );
    FLEA_FREE_BUF_FINAL(exp_res2_words_arr_reuse );

    FLEA_FREE_BUF_FINAL(wksp_words_arr_reuse);

    FLEA_FREE_BUF_FINAL(op1_words_arr_reuse );
    FLEA_FREE_BUF_FINAL(op2_words_arr_reuse);
    FLEA_FREE_BUF_FINAL(res_words_arr_reuse);
    FLEA_FREE_BUF_FINAL(res2_words_arr_reuse);

    );
}

static flea_err_t THR_flea_test_mpi_encode_decode (const flea_u8_t* a_enc, flea_mpi_ulen_t a_len)
{
  FLEA_THR_BEG_FUNC();


  flea_u8_t a_re_enc[16];
  // one word larger than needed:
  flea_uword_t a_arr [(sizeof(a_re_enc) + sizeof(flea_uword_t) - 1 ) / sizeof(flea_uword_t) + 1];
  flea_mpi_t a;
  flea_mpi_t__init(&a, a_arr, sizeof(a_arr) / sizeof(flea_uword_t));
  FLEA_CCALL(THR_flea_mpi_t__decode(&a, a_enc, a_len));
  FLEA_CCALL(THR_flea_mpi_t__encode(a_re_enc, a_len, &a));
  if(memcmp(a_enc, a_re_enc, a_len))
  {
    FLEA_THROW("error with re-encoded mpi", FLEA_ERR_FAILED_TEST);
  }
  FLEA_THR_FIN_SEC();

}
flea_err_t THR_flea_test_mpi_encode ()
{

  flea_u8_t lead_zero_byte_enc[] = {
    0x00, 0x1F, 0xC1, 0xEC,
    0x86, 0x93, 0xA8, 0x5A,
    0x6C, 0x09, 0xE1, 0x2E
  };
  flea_u8_t lead_zero_word_enc[] = {
    0x00, 0x00, 0x00, 0x00,
    0x86, 0x93, 0xA8, 0x5A,
    0x6C, 0x09, 0xE1, 0x2E
  };
  flea_u8_t full_length_lead_zero_byte[] = {
    0x00, 0x1F, 0xC1, 0xEC,
    0x00, 0x00, 0x00, 0x00,
    0x86, 0x93, 0xA8, 0x5A,
    0x6C, 0x09, 0xE1, 0x2E
  };
  flea_u8_t full_length_lead_zero_word[] = {
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x1F, 0xC1, 0xEC,
    0x86, 0x93, 0xA8, 0x5A,
    0x00, 0x00, 0x00, 0x00
  };

  FLEA_THR_BEG_FUNC();

  FLEA_CCALL(THR_flea_test_mpi_encode_decode(lead_zero_byte_enc, sizeof(lead_zero_byte_enc)));
  FLEA_CCALL(THR_flea_test_mpi_encode_decode(lead_zero_word_enc, sizeof(lead_zero_word_enc)));
  FLEA_CCALL(THR_flea_test_mpi_encode_decode(full_length_lead_zero_byte, sizeof(full_length_lead_zero_byte)));
  FLEA_CCALL(THR_flea_test_mpi_encode_decode(full_length_lead_zero_word, sizeof(full_length_lead_zero_word)));
  FLEA_THR_FIN_SEC();

}

flea_err_t THR_flea_test_mpi_shift_left_small ()
{
  flea_u8_t a_enc[] = { 0xAB, 0xCC, 0x3F, 0xDB };

  //flea_uword_t a_arr[1];
  FLEA_DECL_BUF(a_arr, flea_uword_t, 2);
  FLEA_DECL_BUF(four_arr, flea_uword_t, 1);
  FLEA_DECL_BUF(a_mul_arr, flea_uword_t, 2);
  flea_mpi_t four;
  flea_mpi_t a;
  flea_mpi_t a_mul;
  FLEA_THR_BEG_FUNC();
  FLEA_ALLOC_BUF(a_arr, 2);
  FLEA_ALLOC_BUF(four_arr, 1);
  FLEA_ALLOC_BUF(a_mul_arr, 2);

  flea_mpi_t__init(&a, a_arr, 2);
  flea_mpi_t__init(&four, four_arr, 1);
  flea_mpi_t__init(&a_mul, a_mul_arr, 2);

  FLEA_CCALL(THR_flea_mpi_t__decode(&a, a_enc, sizeof(a_enc)));
  flea_mpi_t__set_to_word_value(&four, 4);

  FLEA_CCALL(THR_flea_mpi_t__mul(&a_mul, &a, &four));
  FLEA_CCALL(THR_flea_mpi_t__shift_left_small(&a, 2));

  if(!flea_mpi_t__equal(&a_mul, &a))
  {
    FLEA_THROW("error with left shift (compared to mul result)", FLEA_ERR_FAILED_TEST);
  }
  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(a_arr);
    FLEA_FREE_BUF_FINAL(four_arr);
    FLEA_FREE_BUF_FINAL(a_mul_arr);
    );
}

flea_err_t THR_flea_test_mpi_shift_right ()
{

  flea_u8_t a_enc[] = { 0x82, 0x03, 0x04, 0x01, 0x12, 0x00, 0x00, 0x82 };
  flea_u8_t exp_enc[] = { 0x41, 0x01, 0x82, 0x00 };

  //flea_uword_t a_arr[1];
  FLEA_DECL_BUF(a_arr, flea_uword_t, 2);
  //FLEA_DECL_BUF(four_arr, flea_uword_t, 1);
  FLEA_DECL_BUF(exp_arr, flea_uword_t, 2);
  flea_mpi_t a;
  flea_mpi_t exp;
  FLEA_THR_BEG_FUNC();
  FLEA_ALLOC_BUF(a_arr, 2);
  FLEA_ALLOC_BUF(exp_arr, 2);

  flea_mpi_t__init(&a, a_arr, 2);
  flea_mpi_t__init(&exp, exp_arr, 2);

  FLEA_CCALL(THR_flea_mpi_t__decode(&a, a_enc, sizeof(a_enc)));
  FLEA_CCALL(THR_flea_mpi_t__decode(&exp, exp_enc, sizeof(exp_enc)));

  flea_mpi_t__shift_right(&a, 33);

  if(!flea_mpi_t__equal(&exp, &a))
  {
    FLEA_THROW("error with right shift", FLEA_ERR_FAILED_TEST);
  }
  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(a_arr);
    FLEA_FREE_BUF_FINAL(exp_arr);
    );

}

flea_err_t THR_flea_test_mpi_invert_odd_mod ()
{

  flea_u8_t prime_enc[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xff };
  flea_u8_t a_enc[] =     { 0xAf, 0xec, 0xaf, 0xff, 0xff, 0xff, 0xfd, 0x03, 0xff, 0xff, 0xff, 0xdd, 0xee, 0xaf, 0xff, 0x4f, 0x7f, 0xff, 0xff, 0xf0 };
  flea_u8_t a_exp_inv_enc[] = { 0xDD, 0x01, 0x1B, 0xCC, 0x7A, 0x1B, 0xFD, 0xF7, 0xCC, 0x18, 0x5F, 0xDD, 0xBA, 0x0A, 0x5D, 0xBD, 0xC1, 0xAF, 0xCB, 0x70 };
  const flea_al_u16_t prime_word_len = FLEA_CEIL_WORD_LEN_FROM_BYTE_LEN(sizeof(prime_enc));
  const flea_al_u16_t a_word_len = FLEA_CEIL_WORD_LEN_FROM_BYTE_LEN(sizeof(a_enc));
  const flea_al_u16_t a_inv_word_len = prime_word_len + 1;
  const flea_al_u16_t a_exp_inv_word_len = prime_word_len;
  const flea_al_u16_t a_inv_inv_word_len = prime_word_len + 1;

  const flea_al_u16_t ws_word_len = prime_word_len + 1;
  flea_uword_t ws_words[4][ws_word_len];

  FLEA_DECL_BUF(prime_words, flea_uword_t, prime_word_len);
  FLEA_DECL_BUF(a_words, flea_uword_t, a_word_len);
  FLEA_DECL_BUF(a_inv_words, flea_uword_t, a_inv_word_len);
  FLEA_DECL_BUF(a_exp_inv_words, flea_uword_t, a_exp_inv_word_len);
  FLEA_DECL_BUF(a_inv_inv_words, flea_uword_t, a_inv_inv_word_len);

  flea_mpi_t prime, a, a_exp_inv, a_inv, a_inv_inv;
  flea_mpi_t ws[4];
  FLEA_THR_BEG_FUNC();
  FLEA_ALLOC_BUF(prime_words, prime_word_len);
  FLEA_ALLOC_BUF(a_words, a_word_len);
  FLEA_ALLOC_BUF(a_inv_words, a_inv_word_len);
  FLEA_ALLOC_BUF(a_exp_inv_words, a_exp_inv_word_len);
  FLEA_ALLOC_BUF(a_inv_inv_words, a_inv_inv_word_len);

  flea_mpi_t__init(&prime, prime_words, prime_word_len);
  flea_mpi_t__init(&a, a_words, a_word_len);
  flea_mpi_t__init(&a_inv, a_inv_words, a_inv_word_len);
  flea_mpi_t__init(&a_exp_inv, a_exp_inv_words, a_exp_inv_word_len);
  flea_mpi_t__init(&a_inv_inv, a_inv_inv_words, a_inv_inv_word_len);
  flea_mpi_t__init(&ws[0], ws_words[0], ws_word_len);
  flea_mpi_t__init(&ws[1], ws_words[1], ws_word_len);
  flea_mpi_t__init(&ws[2], ws_words[2], ws_word_len);
  flea_mpi_t__init(&ws[3], ws_words[3], ws_word_len);

  FLEA_CCALL(THR_flea_mpi_t__decode(&prime, prime_enc, sizeof(prime_enc)));
  FLEA_CCALL(THR_flea_mpi_t__decode(&a, a_enc, sizeof(a_enc)));
  FLEA_CCALL(THR_flea_mpi_t__decode(&a_exp_inv, a_exp_inv_enc, sizeof(a_exp_inv_enc)));

  FLEA_CCALL(THR_flea_mpi_t__invert_odd_mod(&a_inv, &a, &prime, ws));
  if(flea_mpi_t__compare(&a_inv, &a_exp_inv))
  {
    FLEA_THROW("error with inverse (odd mod)", FLEA_ERR_FAILED_TEST);
  }
  FLEA_CCALL(THR_flea_mpi_t__invert_odd_mod(&a_inv_inv, &a_inv, &prime, ws));

  if(flea_mpi_t__compare_absolute(&a, &a_inv_inv) || a.m_sign != 1 || a_inv_inv.m_sign != 1)
  {
    FLEA_THROW("error with 2nd inverse (odd mod)", FLEA_ERR_FAILED_TEST);
  }
  FLEA_THR_FIN_SEC(

    FLEA_FREE_BUF_FINAL(prime_words);
    FLEA_FREE_BUF_FINAL(a_words);
    FLEA_FREE_BUF_FINAL(a_inv_words);
    FLEA_FREE_BUF_FINAL(a_exp_inv_words);
    FLEA_FREE_BUF_FINAL(a_inv_inv_words);
    );
}


flea_err_t THR_flea_test_mpi_invert_odd_mod_2 ()
{

  flea_u8_t prime_enc[] = { 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xF4, 0xC8, 0xF9, 0x27, 0xAE, 0xD3, 0xCA, 0x75, 0x22, 0x57 };
  flea_u8_t a_enc[] =     { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xF4, 0xC8, 0xF9, 0x27, 0xAE, 0xD3, 0xCA, 0x75, 0x22, 0x4D };
  flea_u8_t a_exp_inv_enc[] = { 0xE6, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x68, 0x29, 0x1B, 0x46, 0xA3, 0xB6, 0xF1, 0xCF, 0xCF, 0xD2, 0x1B };

  const flea_al_u16_t prime_word_len = FLEA_CEIL_WORD_LEN_FROM_BYTE_LEN(sizeof(prime_enc));
  const flea_al_u16_t a_word_len = FLEA_CEIL_WORD_LEN_FROM_BYTE_LEN(sizeof(a_enc));
  const flea_al_u16_t a_inv_word_len = prime_word_len + 1;
  const flea_al_u16_t a_exp_inv_word_len = prime_word_len;
  const flea_al_u16_t a_inv_inv_word_len = prime_word_len + 1;

  const flea_al_u16_t ws_word_len = prime_word_len + 1;
  flea_uword_t ws_words[4][ws_word_len];

  FLEA_DECL_BUF(prime_words, flea_uword_t, prime_word_len);
  FLEA_DECL_BUF(a_words, flea_uword_t, a_word_len);
  FLEA_DECL_BUF(a_inv_words, flea_uword_t, a_inv_word_len);
  FLEA_DECL_BUF(a_exp_inv_words, flea_uword_t, a_exp_inv_word_len);
  FLEA_DECL_BUF(a_inv_inv_words, flea_uword_t, a_inv_inv_word_len);

  flea_mpi_t prime, a, a_exp_inv, a_inv, a_inv_inv;
  flea_mpi_t ws[4];
  FLEA_THR_BEG_FUNC();
  FLEA_ALLOC_BUF(prime_words, prime_word_len);
  FLEA_ALLOC_BUF(a_words, a_word_len);
  FLEA_ALLOC_BUF(a_inv_words, a_inv_word_len);
  FLEA_ALLOC_BUF(a_exp_inv_words, a_exp_inv_word_len);
  FLEA_ALLOC_BUF(a_inv_inv_words, a_inv_inv_word_len);

  flea_mpi_t__init(&prime, prime_words, prime_word_len);
  flea_mpi_t__init(&a, a_words, a_word_len);
  flea_mpi_t__init(&a_inv, a_inv_words, a_inv_word_len);
  flea_mpi_t__init(&a_exp_inv, a_exp_inv_words, a_exp_inv_word_len);
  flea_mpi_t__init(&a_inv_inv, a_inv_inv_words, a_inv_inv_word_len);
  flea_mpi_t__init(&ws[0], ws_words[0], ws_word_len);
  flea_mpi_t__init(&ws[1], ws_words[1], ws_word_len);
  flea_mpi_t__init(&ws[2], ws_words[2], ws_word_len);
  flea_mpi_t__init(&ws[3], ws_words[3], ws_word_len);

  FLEA_CCALL(THR_flea_mpi_t__decode(&prime, prime_enc, sizeof(prime_enc)));
  FLEA_CCALL(THR_flea_mpi_t__decode(&a, a_enc, sizeof(a_enc)));
  FLEA_CCALL(THR_flea_mpi_t__decode(&a_exp_inv, a_exp_inv_enc, sizeof(a_exp_inv_enc)));

  FLEA_CCALL(THR_flea_mpi_t__invert_odd_mod(&a_inv, &a, &prime, ws));
  if(flea_mpi_t__compare(&a_inv, &a_exp_inv))
  {
    FLEA_THROW("error with inverse (odd mod)", FLEA_ERR_FAILED_TEST);
  }
  FLEA_CCALL(THR_flea_mpi_t__invert_odd_mod(&a_inv_inv, &a_inv, &prime, ws));

  if(flea_mpi_t__compare_absolute(&a, &a_inv_inv) || a.m_sign != 1 || a_inv_inv.m_sign != 1)
  {
    FLEA_THROW("error with 2nd inverse (odd mod)", FLEA_ERR_FAILED_TEST);
  }
  FLEA_THR_FIN_SEC(

    FLEA_FREE_BUF_FINAL(prime_words);
    FLEA_FREE_BUF_FINAL(a_words);
    FLEA_FREE_BUF_FINAL(a_inv_words);
    FLEA_FREE_BUF_FINAL(a_exp_inv_words);
    FLEA_FREE_BUF_FINAL(a_inv_inv_words);
    );
}


