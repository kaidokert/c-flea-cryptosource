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
#include "flea/error.h"
#include "internal/common/math/mpi.h"



flea_err_t THR_flea_test_montgm_mul_comp_n_prime ()
{
  flea_uword_t test_vec[] = { 1, 3, 5, 7, 101, 257, 259, 65535, 65537, 3021, 343525, (flea_uword_t)-1, ((flea_uword_t)-1) - 2, ((flea_uword_t)-1) - 4 };
  unsigned i;
  const unsigned nb_test_vecs = sizeof(test_vec) / sizeof(test_vec[0]);

  FLEA_THR_BEG_FUNC();
  for(i = 0; i < nb_test_vecs; i++)
  {
    flea_dbl_uword_t prod, q, rem;
    const flea_dbl_uword_t mod = ((flea_dbl_uword_t)FLEA_UWORD_MAX) + 1;
    flea_uword_t inv = flea_montgomery_compute_n_prime(test_vec[i]);
    prod = -(flea_dbl_uword_t)inv * test_vec[i];
    q = prod / mod;       // reduce modulo mod ...
    rem = prod - q * mod; // ... completed
    if(rem != 1)          // n*n^{-1} modulo "mod" = 1
    {
      FLEA_THROW("error in computing n'", FLEA_ERR_FAILED_TEST);
    }

  }
  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_test_montgm_mul_small2 ()
{
  FLEA_THR_BEG_FUNC();
  flea_u8_t exp_res_enc [] = { 6 };

  flea_u8_t a_enc [] = {
    4
  };

  flea_u8_t b_enc [] = {
    5
  };

  flea_u8_t mod_enc [] = {
    7
  };

  flea_u8_t R_enc [] = {
    0x01,
    0x00,0x00,	0x00,	 0x00
  };

  flea_u8_t one_enc[] = { 1 };
  const flea_mpi_ulen_t mod_byte_len = sizeof(mod_enc);
  const flea_mpi_ulen_t mod_word_len = (mod_byte_len + sizeof(flea_uword_t) - 1) / sizeof(flea_uword_t);
  flea_uword_t result_arr [(mod_word_len + 1) * 2];
  flea_uword_t a_arr [mod_word_len];
  flea_uword_t a_trf_arr [mod_word_len];
  flea_uword_t b_arr [mod_word_len];
  flea_uword_t b_trf_arr [mod_word_len];
  flea_uword_t mod_arr [mod_word_len];
  flea_uword_t exp_res_arr [mod_word_len];
  flea_uword_t R_arr [mod_word_len + 1];
  flea_uword_t large_tmp_arr[(mod_word_len) * 2 + 1];
  flea_uword_t q_arr[2 * mod_word_len];
  flea_uword_t mm_ws_arr[mod_word_len + 1];
  flea_uword_t one_arr[1];


  const flea_al_u16_t vn_len = sizeof(mod_arr);
  const flea_al_u16_t un_len = sizeof(large_tmp_arr) + 2;

  flea_hlf_uword_t vn [vn_len];
  flea_hlf_uword_t un [un_len];

  flea_montgm_mul_ctx_t mm_ctx;
  flea_mpi_div_ctx_t div_ctx;
  div_ctx.un = un;
  div_ctx.vn = vn;
  div_ctx.un_len = un_len;
  div_ctx.vn_len = vn_len;

  flea_mpi_t a, b, q, mod, res, exp_res, R, a_trf, b_trf, large_tmp, mm_ws, one;

  flea_mpi_t__init(&a, a_arr, sizeof(a_arr) / sizeof(flea_uword_t));
  flea_mpi_t__init(&b, b_arr, sizeof(b_arr) / sizeof(flea_uword_t));
  flea_mpi_t__init(&mod, mod_arr, sizeof(b_arr) / sizeof(flea_uword_t));
  flea_mpi_t__init(&res, result_arr, sizeof(result_arr) / sizeof(flea_uword_t));
  flea_mpi_t__init(&exp_res, exp_res_arr, sizeof(exp_res_arr) / sizeof(flea_uword_t));
  flea_mpi_t__init(&R, R_arr, sizeof(R_arr) / sizeof(flea_uword_t));
  flea_mpi_t__init(&large_tmp, large_tmp_arr, sizeof(large_tmp_arr) / sizeof(flea_uword_t));
  flea_mpi_t__init(&a_trf, a_trf_arr, sizeof(a_trf_arr) / sizeof(flea_uword_t));
  flea_mpi_t__init(&b_trf, b_trf_arr, sizeof(b_trf_arr) / sizeof(flea_uword_t));
  flea_mpi_t__init(&q, q_arr, sizeof(q_arr) / sizeof(flea_uword_t));
  flea_mpi_t__init(&mm_ws, mm_ws_arr, sizeof(mm_ws_arr) / sizeof(flea_uword_t));
  flea_mpi_t__init(&one, one_arr, sizeof(one_arr) / sizeof(flea_uword_t));


  FLEA_CCALL(THR_flea_mpi_t__decode(&a, a_enc, sizeof(a_enc)));
  FLEA_CCALL(THR_flea_mpi_t__decode(&b, b_enc, sizeof(b_enc)));
  FLEA_CCALL(THR_flea_mpi_t__decode(&mod, mod_enc, sizeof(mod_enc)));
  FLEA_CCALL(THR_flea_mpi_t__decode(&exp_res, exp_res_enc, sizeof(exp_res_enc)));
  FLEA_CCALL(THR_flea_mpi_t__decode(&R, R_enc, sizeof(R_enc)));
  FLEA_CCALL(THR_flea_mpi_t__decode(&one, one_enc, sizeof(one_enc)));

  mm_ctx.p_ws = &mm_ws;
  mm_ctx.p_mod = &mod;
  mm_ctx.mod_prime = flea_montgomery_compute_n_prime(mod.m_words[0]);

  FLEA_CCALL(THR_flea_mpi_t__mul(&large_tmp, &R, &a));
  FLEA_CCALL(THR_flea_mpi_t__divide(&q, &a_trf, &large_tmp, &mod, &div_ctx));

  flea_mpi_t__init(&large_tmp, large_tmp_arr, sizeof(large_tmp_arr) / sizeof(flea_uword_t));

  FLEA_CCALL(THR_flea_mpi_t__mul(&large_tmp, &R, &b));
  FLEA_CCALL(THR_flea_mpi_t__divide(&q, &b_trf, &large_tmp, &mod, &div_ctx));

  flea_mpi_t__init(&large_tmp, large_tmp_arr, sizeof(large_tmp_arr) / sizeof(flea_uword_t));

  FLEA_CCALL(THR_flea_mpi_t__montgm_mul(&large_tmp, &a_trf, &b_trf, &mm_ctx));

  FLEA_CCALL(THR_flea_mpi_t__montgm_mul(&res, &large_tmp, &one, &mm_ctx ));

  if(!flea_mpi_t__equal(&res, &exp_res))
  {
    FLEA_THROW("montgomery multiplication result not correct", FLEA_ERR_FAILED_TEST);
  }
  FLEA_THR_FIN_SEC_empty();
}
flea_err_t THR_flea_test_montgm_mul_small ()
{
  FLEA_THR_BEG_FUNC();
  flea_u8_t exp_res_enc [] = { 0x11, 0xAE, 0x54 };

  flea_u8_t a_enc [] = {
    0x04, 0x00, 0x00
  };

  flea_u8_t b_enc [] = {
    0x05, 0x00, 0x00
  };

  flea_u8_t mod_enc [] = {
    0x7F, 0xBF, 0xAF
  };

  flea_u8_t R_enc [] = {
    0x01,
    0x00,0x00,	0x00,	 0x00
  };

  flea_u8_t one_enc[] = { 1 };
  const flea_mpi_ulen_t mod_byte_len = sizeof(mod_enc);
  const flea_mpi_ulen_t mod_word_len = (mod_byte_len + sizeof(flea_uword_t) - 1) / sizeof(flea_uword_t);
  flea_uword_t result_arr [(mod_word_len + 1) * 2];
  flea_uword_t ws_arr [mod_word_len + 1];
  flea_uword_t a_arr [mod_word_len];
  flea_uword_t a_trf_arr [mod_word_len];
  flea_uword_t b_arr [mod_word_len];
  flea_uword_t b_trf_arr [mod_word_len];
  flea_uword_t mod_arr [mod_word_len];
  flea_uword_t exp_res_arr [mod_word_len];
  flea_uword_t R_arr [mod_word_len + 1];
  flea_uword_t large_tmp_arr[(mod_word_len + 1) * 2 ];
  flea_uword_t q_arr[3];
  flea_uword_t mm_ws_arr[mod_word_len + 1];
  flea_uword_t one_arr[1];



  const flea_al_u16_t vn_len = sizeof(mod_arr);
  const flea_al_u16_t un_len = sizeof(large_tmp_arr) + 2;

  flea_montgm_mul_ctx_t mm_ctx;
  flea_hlf_uword_t vn [vn_len];
  flea_hlf_uword_t un [un_len];

  flea_mpi_div_ctx_t div_ctx;
  div_ctx.un = un;
  div_ctx.vn = vn;
  div_ctx.un_len = un_len;
  div_ctx.vn_len = vn_len;

  flea_mpi_t a, b, q, mod, res, ws, exp_res, R, a_trf, b_trf, large_tmp, mm_ws, one;

  flea_mpi_t__init(&a, a_arr, sizeof(a_arr) / sizeof(flea_uword_t));
  flea_mpi_t__init(&b, b_arr, sizeof(b_arr) / sizeof(flea_uword_t));
  flea_mpi_t__init(&mod, mod_arr, sizeof(b_arr) / sizeof(flea_uword_t));
  flea_mpi_t__init(&res, result_arr, sizeof(result_arr) / sizeof(flea_uword_t));
  flea_mpi_t__init(&ws, ws_arr, sizeof(ws_arr) / sizeof(flea_uword_t));
  flea_mpi_t__init(&exp_res, exp_res_arr, sizeof(exp_res_arr) / sizeof(flea_uword_t));
  flea_mpi_t__init(&R, R_arr, sizeof(R_arr) / sizeof(flea_uword_t));
  flea_mpi_t__init(&large_tmp, large_tmp_arr, sizeof(large_tmp_arr) / sizeof(flea_uword_t));
  flea_mpi_t__init(&a_trf, a_trf_arr, sizeof(a_trf_arr) / sizeof(flea_uword_t));
  flea_mpi_t__init(&b_trf, b_trf_arr, sizeof(b_trf_arr) / sizeof(flea_uword_t));
  flea_mpi_t__init(&q, q_arr, sizeof(q_arr) / sizeof(flea_uword_t));
  flea_mpi_t__init(&mm_ws, mm_ws_arr, sizeof(mm_ws_arr) / sizeof(flea_uword_t));
  flea_mpi_t__init(&one, one_arr, sizeof(one_arr) / sizeof(flea_uword_t));


  FLEA_CCALL(THR_flea_mpi_t__decode(&a, a_enc, sizeof(a_enc)));
  FLEA_CCALL(THR_flea_mpi_t__decode(&b, b_enc, sizeof(b_enc)));
  FLEA_CCALL(THR_flea_mpi_t__decode(&mod, mod_enc, sizeof(mod_enc)));
  FLEA_CCALL(THR_flea_mpi_t__decode(&exp_res, exp_res_enc, sizeof(exp_res_enc)));
  FLEA_CCALL(THR_flea_mpi_t__decode(&R, R_enc, sizeof(R_enc)));
  FLEA_CCALL(THR_flea_mpi_t__decode(&one, one_enc, sizeof(one_enc)));

  mm_ctx.p_ws = &mm_ws;
  mm_ctx.p_mod = &mod;
  mm_ctx.mod_prime = flea_montgomery_compute_n_prime(mod.m_words[0]);

  FLEA_CCALL(THR_flea_mpi_t__mul(&large_tmp, &R, &a));
  FLEA_CCALL(THR_flea_mpi_t__divide(&q, &a_trf, &large_tmp, &mod, &div_ctx));

  flea_mpi_t__init(&large_tmp, large_tmp_arr, sizeof(large_tmp_arr) / sizeof(flea_uword_t));

  FLEA_CCALL(THR_flea_mpi_t__mul(&large_tmp, &R, &b));
  FLEA_CCALL(THR_flea_mpi_t__divide(&q, &b_trf, &large_tmp, &mod, &div_ctx));

  flea_mpi_t__init(&large_tmp, large_tmp_arr, sizeof(large_tmp_arr) / sizeof(flea_uword_t));

  FLEA_CCALL(THR_flea_mpi_t__montgm_mul(&large_tmp, &a_trf, &b_trf, &mm_ctx));

  FLEA_CCALL(THR_flea_mpi_t__montgm_mul(&res, &large_tmp, &one, &mm_ctx ));

  if(!flea_mpi_t__equal(&res, &exp_res))
  {
    FLEA_THROW("montgomery multiplication result not correct", FLEA_ERR_FAILED_TEST);
  }

  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_test_montgm_mul ()
{
  FLEA_THR_BEG_FUNC();
  flea_u8_t exp_res_enc [] = { 0x82, 0x13, 0xAE, 0x9A, 0x94, 0xAE, 0x0F, 0x00, 0xDB, 0x38, 0x3B, 0x89, 0xB9, 0x37, 0x58, 0x6E, 0x80, 0x11, 0x41, 0x36, 0x5A, 0x2B, 0xED, 0x9C };

  flea_u8_t a_enc [] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF
  };

  flea_u8_t b_enc [] = {
    0xFF, 0xCE, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE,
    0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE,
    0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE
  };

  flea_u8_t mod_enc [] = {
    0xFF, 0xFE, 0x3E, 0xEE, 0xDD, 0x33, 0x33, 0x78,
    0x88, 0x82, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE,
    0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDF
  };

  flea_u8_t R_enc [] = {
    0x01,
    0x00,0x00,	0x00,	 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00,0x00,	0x00,	 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00,0x00,	0x00,	 0x00, 0x00, 0x00, 0x00, 0x00
  };

  flea_u8_t one_enc[] = { 1 };
  const flea_mpi_ulen_t mod_byte_len = sizeof(mod_enc);
  const flea_mpi_ulen_t mod_word_len = (mod_byte_len + sizeof(flea_uword_t) - 1) / sizeof(flea_uword_t);
  flea_uword_t result_arr [(mod_word_len + 1) * 2];
  flea_uword_t ws_arr [mod_word_len + 1];
  flea_uword_t a_arr [mod_word_len];
  flea_uword_t a_trf_arr [mod_word_len];
  flea_uword_t b_arr [mod_word_len];
  flea_uword_t b_trf_arr [mod_word_len];
  flea_uword_t mod_arr [mod_word_len];
  flea_uword_t exp_res_arr [mod_word_len];
  flea_uword_t R_arr [mod_word_len + 1];
  flea_uword_t large_tmp_arr[(mod_word_len + 1) * 2 ];
  flea_uword_t q_arr[2 * mod_word_len];
  flea_uword_t mm_ws_arr[mod_word_len + 1];
  flea_uword_t one_arr[1];


  flea_montgm_mul_ctx_t mm_ctx;


  const flea_al_u16_t vn_len = sizeof(mod_arr);
  const flea_al_u16_t un_len = sizeof(large_tmp_arr) + 2;

  flea_hlf_uword_t vn [vn_len];
  flea_hlf_uword_t un [un_len];

  flea_mpi_div_ctx_t div_ctx;
  div_ctx.un = un;
  div_ctx.vn = vn;
  div_ctx.un_len = un_len;
  div_ctx.vn_len = vn_len;

  flea_mpi_t a, b, q, mod, res, ws, exp_res, R, a_trf, b_trf, large_tmp, mm_ws, one;

  flea_mpi_t__init(&a, a_arr, sizeof(a_arr) / sizeof(flea_uword_t));
  flea_mpi_t__init(&b, b_arr, sizeof(b_arr) / sizeof(flea_uword_t));
  flea_mpi_t__init(&mod, mod_arr, sizeof(b_arr) / sizeof(flea_uword_t));
  flea_mpi_t__init(&res, result_arr, sizeof(result_arr) / sizeof(flea_uword_t));
  flea_mpi_t__init(&ws, ws_arr, sizeof(ws_arr) / sizeof(flea_uword_t));
  flea_mpi_t__init(&exp_res, exp_res_arr, sizeof(exp_res_arr) / sizeof(flea_uword_t));
  flea_mpi_t__init(&R, R_arr, sizeof(R_arr) / sizeof(flea_uword_t));
  flea_mpi_t__init(&large_tmp, large_tmp_arr, sizeof(large_tmp_arr) / sizeof(flea_uword_t));
  flea_mpi_t__init(&a_trf, a_trf_arr, sizeof(a_trf_arr) / sizeof(flea_uword_t));
  flea_mpi_t__init(&b_trf, b_trf_arr, sizeof(b_trf_arr) / sizeof(flea_uword_t));
  flea_mpi_t__init(&q, q_arr, sizeof(q_arr) / sizeof(flea_uword_t));
  flea_mpi_t__init(&mm_ws, mm_ws_arr, sizeof(mm_ws_arr) / sizeof(flea_uword_t));
  flea_mpi_t__init(&one, one_arr, sizeof(one_arr) / sizeof(flea_uword_t));


  FLEA_CCALL(THR_flea_mpi_t__decode(&a, a_enc, sizeof(a_enc)));
  FLEA_CCALL(THR_flea_mpi_t__decode(&b, b_enc, sizeof(b_enc)));
  FLEA_CCALL(THR_flea_mpi_t__decode(&mod, mod_enc, sizeof(mod_enc)));
  FLEA_CCALL(THR_flea_mpi_t__decode(&exp_res, exp_res_enc, sizeof(exp_res_enc)));
  FLEA_CCALL(THR_flea_mpi_t__decode(&R, R_enc, sizeof(R_enc)));
  FLEA_CCALL(THR_flea_mpi_t__decode(&one, one_enc, sizeof(one_enc)));

  mm_ctx.p_ws = &mm_ws;
  mm_ctx.p_mod = &mod;
  mm_ctx.mod_prime = flea_montgomery_compute_n_prime(mod.m_words[0]);

  FLEA_CCALL(THR_flea_mpi_t__mul(&large_tmp, &R, &a));
  FLEA_CCALL(THR_flea_mpi_t__divide(&q, &a_trf, &large_tmp, &mod, &div_ctx));

  flea_mpi_t__init(&large_tmp, large_tmp_arr, sizeof(large_tmp_arr) / sizeof(flea_uword_t));

  FLEA_CCALL(THR_flea_mpi_t__mul(&large_tmp, &R, &b));
  FLEA_CCALL(THR_flea_mpi_t__divide(&q, &b_trf, &large_tmp, &mod, &div_ctx));

  flea_mpi_t__init(&large_tmp, large_tmp_arr, sizeof(large_tmp_arr) / sizeof(flea_uword_t));

  FLEA_CCALL(THR_flea_mpi_t__montgm_mul(&large_tmp, &a_trf, &b_trf, &mm_ctx));

  FLEA_CCALL(THR_flea_mpi_t__montgm_mul(&res, &large_tmp, &one, &mm_ctx));

  if(!flea_mpi_t__equal(&res, &exp_res))
  {
    FLEA_THROW("montgomery multiplication result not correct", FLEA_ERR_FAILED_TEST);
  }
  FLEA_THR_FIN_SEC_empty();
}



