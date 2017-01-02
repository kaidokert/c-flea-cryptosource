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
#include "flea/util.h"
#include "flea/error_handling.h"
#include "flea/rsa.h"
#include "flea/alloc.h"
#include "flea/array_util.h"

/**
 * number of words by which the larger prime in CRT-RSA may become larger than
 * the number of words in the half modulus length. (with a PQ-diff of x, one
 * prime is longer by x/2 bits, the other shorter by x/2 bits than the half
 * bit length of the modulus.
 */
#define FLEA_RSA_CRT_PQ_MAX_WORDS_HALF_DIFF FLEA_CEIL_WORD_LEN_FROM_BIT_LEN(FLEA_RSA_CRT_PQ_BIT_DIFF / 2)

#define FLEA_MPI_DIV_VN_HLFW_LEN_FOR_RSA_CRT_REDUCTIONS FLEA_MPI_DIV_VN_HLFW_LEN_FROM_DIVISOR_W_LEN(FLEA_RSA_CRT_MAX_PRIME_WORD_LEN)
#define FLEA_MPI_DIV_UN_HLFW_LEN_FOR_RSA_CRT_REDUCTIONS FLEA_MPI_DIV_UN_HLFW_LEN_FROM_DIVIDENT_W_LEN(2 * FLEA_RSA_CRT_MAX_PRIME_WORD_LEN)

#define FLEA_MPI_DIV_VN_HLFW_LEN_FOR_RSA_SF_REDUCTIONS FLEA_MPI_DIV_VN_HLFW_LEN_FROM_DIVISOR_W_LEN(FLEA_RSA_SF_MAX_MOD_WORD_LEN)
#define FLEA_MPI_DIV_UN_HLFW_LEN_FOR_RSA_SF_REDUCTIONS FLEA_MPI_DIV_UN_HLFW_LEN_FROM_DIVIDENT_W_LEN(2 * FLEA_RSA_SF_MAX_MOD_WORD_LEN)

#define FLEA_RSA_CRT_MAX_PRIME_WORD_LEN (((FLEA_RSA_MAX_KEY_BIT_SIZE / 2) + (FLEA_RSA_CRT_PQ_BIT_DIFF) / 2 + FLEA_WORD_BIT_SIZE - 1) / FLEA_WORD_BIT_SIZE)

#define FLEA_RSA_SF_MAX_MOD_WORD_LEN ((FLEA_RSA_MAX_KEY_BIT_SIZE + FLEA_WORD_BIT_SIZE - 1) / FLEA_WORD_BIT_SIZE)

#ifdef FLEA_HAVE_RSA
flea_err_t THR_flea_rsa_raw_operation_crt_internal_key_format (
  flea_u8_t* result_enc,
  const flea_u8_t* base_enc,
  flea_al_u16_t base_length,
  flea_al_u16_t modulus_length,
  const flea_u8_t* key__pc_u8,
  flea_al_u16_t key_len__al_u16
  )
{
  flea_al_u16_t half_mod_len__al_u16;

  FLEA_THR_BEG_FUNC();
  half_mod_len__al_u16 = key_len__al_u16 / 5;
  if(((modulus_length + 1) / 2 != half_mod_len__al_u16) || key_len__al_u16 % 5)
  {
    FLEA_THROW("invalid length of RSA key in internal format", FLEA_ERR_INV_ARG);
  }
  FLEA_CCALL(THR_flea_rsa_raw_operation_crt(
               result_enc,
               base_enc,
               base_length,
               modulus_length,
               key__pc_u8,
               half_mod_len__al_u16,
               key__pc_u8 + half_mod_len__al_u16,
               half_mod_len__al_u16,
               key__pc_u8 + 2 * half_mod_len__al_u16,
               half_mod_len__al_u16,
               key__pc_u8 + 3 * half_mod_len__al_u16,
               half_mod_len__al_u16,
               key__pc_u8 + 4 * half_mod_len__al_u16,
               half_mod_len__al_u16
               ));
  FLEA_THR_FIN_SEC_empty();

}
// result is of same length as modulus
flea_err_t THR_flea_rsa_raw_operation_crt (
  flea_u8_t* result_enc,
  const flea_u8_t* base_enc,
  flea_al_u16_t base_length,
  flea_al_u16_t modulus_length,
  const flea_u8_t* p_enc,
  flea_mpi_ulen_t p_enc_len,
  const flea_u8_t * q_enc,
  flea_mpi_ulen_t q_enc_len,
  const flea_u8_t* d1_enc,
  flea_mpi_ulen_t d1_enc_len,
  const flea_u8_t* d2_enc,
  flea_mpi_ulen_t d2_enc_len,
  const flea_u8_t * c_enc,
  flea_mpi_ulen_t c_enc_len
  )
{

  FLEA_DECL_BUF(result_arr, flea_uword_t, FLEA_RSA_SF_MAX_MOD_WORD_LEN + 1);
  FLEA_DECL_BUF(base_arr, flea_uword_t, FLEA_RSA_SF_MAX_MOD_WORD_LEN + (2 * FLEA_RSA_CRT_PQ_MAX_WORDS_HALF_DIFF) ); // "+2" due to p-q-diff ( must store product of two "+1" mpis)
  FLEA_DECL_BUF(base_mod_prime_arr, flea_uword_t, (FLEA_RSA_SF_MAX_MOD_WORD_LEN + 1) / 2 + 1);
  FLEA_DECL_BUF(large_tmp_arr, flea_uword_t, (FLEA_RSA_SF_MAX_MOD_WORD_LEN ) * 2 + 1);
  FLEA_DECL_BUF(ws_trf_base_arr, flea_uword_t, FLEA_RSA_SF_MAX_MOD_WORD_LEN );

  FLEA_DECL_BUF(p_arr, flea_uword_t, (FLEA_RSA_SF_MAX_MOD_WORD_LEN + 1) / 2 + FLEA_RSA_CRT_PQ_MAX_WORDS_HALF_DIFF);   //  due to p-q-diff
  FLEA_DECL_BUF(q_arr, flea_uword_t, (FLEA_RSA_SF_MAX_MOD_WORD_LEN + 1) / 2 + FLEA_RSA_CRT_PQ_MAX_WORDS_HALF_DIFF);   //  due to p-q-diff
  FLEA_DECL_BUF(d1_arr, flea_uword_t, (FLEA_RSA_SF_MAX_MOD_WORD_LEN + 1) / 2 + FLEA_RSA_CRT_PQ_MAX_WORDS_HALF_DIFF);  //  due to p-q-diff
  FLEA_DECL_BUF(d2_arr,  flea_uword_t, (FLEA_RSA_SF_MAX_MOD_WORD_LEN + 1) / 2 + FLEA_RSA_CRT_PQ_MAX_WORDS_HALF_DIFF); //  due to p-q-diff
  FLEA_DECL_BUF(j1_arr,  flea_uword_t, (FLEA_RSA_SF_MAX_MOD_WORD_LEN + 1) / 2 + FLEA_RSA_CRT_PQ_MAX_WORDS_HALF_DIFF); //  due to p-q-diff

  FLEA_DECL_BUF(vn, flea_hlf_uword_t, FLEA_MPI_DIV_VN_HLFW_LEN_FROM_DIVISOR_W_LEN(FLEA_RSA_CRT_MAX_PRIME_WORD_LEN));
  FLEA_DECL_BUF(un, flea_hlf_uword_t, FLEA_MPI_DIV_UN_HLFW_LEN_FROM_DIVIDENT_W_LEN(2 * FLEA_RSA_CRT_MAX_PRIME_WORD_LEN));

  flea_mpi_t result,  base,  large_tmp, ws_trf_base, d1, d2, j1, p, q, base_mod_prime;
  flea_mpi_div_ctx_t div_ctx;

#ifdef FLEA_USE_HEAP_BUF
  flea_mpi_ulen_t mod_byte_len, mod_word_len,  base_mod_prime_len, large_tmp_len, ws_trf_base_len, half_mod_word_len, prime_word_len;
  flea_mpi_ulen_t result_len, base_word_len, vn_len, un_len;
#endif // #ifdef FLEA_USE_HEAP_BUF

  FLEA_THR_BEG_FUNC();
#ifdef FLEA_USE_HEAP_BUF
  mod_byte_len = p_enc_len + q_enc_len;
  mod_word_len = FLEA_CEIL_WORD_LEN_FROM_BYTE_LEN(mod_byte_len);
  base_mod_prime_len = (mod_word_len + 1) / 2 + FLEA_RSA_CRT_PQ_MAX_WORDS_HALF_DIFF; // +1 due to p-q-diff
  large_tmp_len = (mod_word_len) * 2 + 1;
  ws_trf_base_len = mod_word_len;
  half_mod_word_len = (mod_word_len + 1) / 2;
  prime_word_len = half_mod_word_len +  FLEA_RSA_CRT_PQ_MAX_WORDS_HALF_DIFF;
  base_word_len = mod_word_len + (2 * FLEA_RSA_CRT_PQ_MAX_WORDS_HALF_DIFF); // "+2" due to p-q-diff ( must store product of two "+1" mpis)
  result_len = mod_word_len + 1;
  vn_len = FLEA_MPI_DIV_VN_HLFW_LEN_FROM_DIVISOR_W_LEN(prime_word_len);
  un_len = FLEA_MPI_DIV_UN_HLFW_LEN_FROM_DIVIDENT_W_LEN(2 * prime_word_len);
#endif // #ifdef FLEA_USE_HEAP_BUF

  FLEA_ALLOC_BUF(result_arr, result_len);

  FLEA_ALLOC_BUF(base_arr, base_word_len);
  FLEA_ALLOC_BUF(base_mod_prime_arr, base_mod_prime_len);
  FLEA_ALLOC_BUF(large_tmp_arr, large_tmp_len);
  FLEA_ALLOC_BUF(ws_trf_base_arr, ws_trf_base_len);
  FLEA_ALLOC_BUF(p_arr, prime_word_len);
  FLEA_ALLOC_BUF(q_arr, prime_word_len);
  FLEA_ALLOC_BUF(d1_arr, prime_word_len);
  FLEA_ALLOC_BUF(d2_arr, prime_word_len);
  FLEA_ALLOC_BUF(j1_arr, prime_word_len);


  FLEA_ALLOC_BUF(vn, vn_len);
  FLEA_ALLOC_BUF(un, un_len);

  div_ctx.vn = vn;
  div_ctx.un = un;
  div_ctx.vn_len = FLEA_HEAP_OR_STACK_CODE(vn_len, FLEA_STACK_BUF_NB_ENTRIES(vn));
  div_ctx.un_len = FLEA_HEAP_OR_STACK_CODE(un_len, FLEA_STACK_BUF_NB_ENTRIES(un));


  flea_mpi_t__init(&result, result_arr, FLEA_HEAP_OR_STACK_CODE(result_len, FLEA_STACK_BUF_NB_ENTRIES(result_arr)));
  flea_mpi_t__init(&base, base_arr, FLEA_HEAP_OR_STACK_CODE(base_word_len, FLEA_STACK_BUF_NB_ENTRIES(base_arr)));
  flea_mpi_t__init(&base_mod_prime, base_mod_prime_arr, FLEA_HEAP_OR_STACK_CODE(base_mod_prime_len, FLEA_STACK_BUF_NB_ENTRIES(base_mod_prime_arr)));
  flea_mpi_t__init(&large_tmp, large_tmp_arr, FLEA_HEAP_OR_STACK_CODE(large_tmp_len, FLEA_STACK_BUF_NB_ENTRIES(large_tmp_arr)));
  flea_mpi_t__init(&ws_trf_base, ws_trf_base_arr, FLEA_HEAP_OR_STACK_CODE(ws_trf_base_len, FLEA_STACK_BUF_NB_ENTRIES(ws_trf_base_arr)));
  flea_mpi_t__init(&p, p_arr, FLEA_HEAP_OR_STACK_CODE(prime_word_len, FLEA_STACK_BUF_NB_ENTRIES(p_arr)));
  flea_mpi_t__init(&q, q_arr, FLEA_HEAP_OR_STACK_CODE(prime_word_len, FLEA_STACK_BUF_NB_ENTRIES(q_arr)));
  flea_mpi_t__init(&d1, d1_arr, FLEA_HEAP_OR_STACK_CODE(prime_word_len, FLEA_STACK_BUF_NB_ENTRIES(d1_arr)));
  flea_mpi_t__init(&d2, d2_arr, FLEA_HEAP_OR_STACK_CODE(prime_word_len, FLEA_STACK_BUF_NB_ENTRIES(d2_arr)));
  flea_mpi_t__init(&j1, j1_arr, FLEA_HEAP_OR_STACK_CODE(prime_word_len, FLEA_STACK_BUF_NB_ENTRIES(j1_arr)));

  FLEA_CCALL(THR_flea_mpi_t__decode(&base, base_enc, base_length));
  FLEA_CCALL(THR_flea_mpi_t__decode(&p, p_enc, p_enc_len));
  FLEA_CCALL(THR_flea_mpi_t__decode(&q, q_enc, q_enc_len));
  FLEA_CCALL(THR_flea_mpi_t__decode(&d1, d1_enc, d1_enc_len));
  FLEA_CCALL(THR_flea_mpi_t__decode(&d2, d2_enc, d2_enc_len));


  // reduce the base for the first prime
  FLEA_CCALL(THR_flea_mpi_t__divide(NULL, &base_mod_prime, &base, &p, &div_ctx));
  // result used as workspace here
  FLEA_CCALL(THR_flea_mpi_t__mod_exp_window(&j1, &d1, &base_mod_prime, &p, &large_tmp, &div_ctx, &ws_trf_base, &result, FLEA_CRT_RSA_WINDOW_SIZE));

  // d1 unused from here, used for j2
  FLEA_CCALL(THR_flea_mpi_t__divide(NULL, &base_mod_prime, &base, &q, &div_ctx));
  // result used as workspace here
  FLEA_CCALL(THR_flea_mpi_t__mod_exp_window(&d1, &d2, &base_mod_prime, &q, &large_tmp, &div_ctx, &ws_trf_base, &result, FLEA_CRT_RSA_WINDOW_SIZE));


  // subtract mod cannot be used because d1=j2 may be larger than p
  FLEA_CCALL(THR_flea_mpi_t__subtract(&result, &j1, &d1)); //result = j1-j2
  // check if the intermediate absolute value is larger than p
  if(-1 == flea_mpi_t__compare_absolute(&p, &result))
  {
    // result must be reduced by p (sign is ignored in division)
    FLEA_CCALL(THR_flea_mpi_t__divide(NULL, &base, &result, &p, &div_ctx));
    FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(&result, &base));

  }

// trf-base unused from here, used as j1_prime
  if(result.m_sign < 0)
  {
    result.m_sign = +1;
    // result contains absolute value of what is negative to be reduced by p

    FLEA_CCALL(THR_flea_mpi_t__subtract(&base, &p, &result));
    FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(&result, &base));

  }
  // use j1 as q_inv
  FLEA_CCALL(THR_flea_mpi_t__decode(&j1, c_enc, c_enc_len));
  FLEA_CCALL(THR_flea_mpi_t__mul(&base, &result, &j1)); // base = j1' = (j1-d1)*c

  FLEA_CCALL(THR_flea_mpi_t__divide(NULL, &ws_trf_base, &base, &p, &div_ctx));

  FLEA_CCALL(THR_flea_mpi_t__mul(&result, &ws_trf_base, &q));

  FLEA_CCALL(THR_flea_mpi_t__add_in_place_ignore_sign(&result, &d1));

  FLEA_CCALL(THR_flea_mpi_t__encode(result_enc, modulus_length, &result)); // r
  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(result_arr);
    FLEA_FREE_BUF_SECRET_ARR(base_arr, FLEA_HEAP_OR_STACK_CODE(base_word_len, FLEA_STACK_BUF_NB_ENTRIES(base_arr)));
    FLEA_FREE_BUF_SECRET_ARR(base_mod_prime_arr, FLEA_HEAP_OR_STACK_CODE(base_mod_prime_len, FLEA_STACK_BUF_NB_ENTRIES(base_mod_prime_arr)));
    FLEA_FREE_BUF_SECRET_ARR(large_tmp_arr, FLEA_HEAP_OR_STACK_CODE(large_tmp_len, FLEA_STACK_BUF_NB_ENTRIES(large_tmp_arr)));
    FLEA_FREE_BUF_SECRET_ARR(ws_trf_base_arr, FLEA_HEAP_OR_STACK_CODE(ws_trf_base_len, FLEA_STACK_BUF_NB_ENTRIES(ws_trf_base_arr)));
    FLEA_FREE_BUF_SECRET_ARR(p_arr, FLEA_HEAP_OR_STACK_CODE(prime_word_len, FLEA_STACK_BUF_NB_ENTRIES(p_arr)));
    FLEA_FREE_BUF_SECRET_ARR(q_arr, FLEA_HEAP_OR_STACK_CODE(prime_word_len, FLEA_STACK_BUF_NB_ENTRIES(q_arr)));
    FLEA_FREE_BUF_SECRET_ARR(d1_arr, FLEA_HEAP_OR_STACK_CODE(prime_word_len, FLEA_STACK_BUF_NB_ENTRIES(d1_arr)));
    FLEA_FREE_BUF_SECRET_ARR(d2_arr, FLEA_HEAP_OR_STACK_CODE(prime_word_len, FLEA_STACK_BUF_NB_ENTRIES(d2_arr)));
    FLEA_FREE_BUF_SECRET_ARR(j1_arr, FLEA_HEAP_OR_STACK_CODE(prime_word_len, FLEA_STACK_BUF_NB_ENTRIES(j1_arr)));
    FLEA_FREE_BUF_SECRET_ARR(vn, FLEA_HEAP_OR_STACK_CODE(vn_len, FLEA_STACK_BUF_NB_ENTRIES(vn)));
    FLEA_FREE_BUF_SECRET_ARR(un, FLEA_HEAP_OR_STACK_CODE(un_len, FLEA_STACK_BUF_NB_ENTRIES(un)));
    );
}
flea_err_t THR_flea_rsa_raw_operation (flea_u8_t* result_enc, const flea_u8_t * exponent_enc, flea_al_u16_t exponent_length, const flea_u8_t* base_enc, flea_al_u16_t base_length, const flea_u8_t * modulus_enc, flea_al_u16_t modulus_length  )
{

  FLEA_DECL_BUF(result_arr, flea_uword_t, FLEA_RSA_SF_MAX_MOD_WORD_LEN + 1);
  FLEA_DECL_BUF(base_arr, flea_uword_t, FLEA_RSA_SF_MAX_MOD_WORD_LEN );
  FLEA_DECL_BUF(exponent_arr, flea_uword_t, FLEA_RSA_SF_MAX_MOD_WORD_LEN );
  FLEA_DECL_BUF(mod_arr, flea_uword_t, FLEA_RSA_SF_MAX_MOD_WORD_LEN );
  FLEA_DECL_BUF(large_tmp_arr, flea_uword_t, FLEA_RSA_SF_MAX_MOD_WORD_LEN * 2 + 1);
  FLEA_DECL_BUF(ws_trf_base_arr, flea_uword_t, FLEA_RSA_SF_MAX_MOD_WORD_LEN );
  FLEA_DECL_BUF(ws_q_arr, flea_uword_t, FLEA_RSA_SF_MAX_MOD_WORD_LEN + 1);


  flea_mpi_ulen_t mod_word_len, result_word_len, large_tmp_word_len, ws_q_word_len;
#ifdef FLEA_USE_HEAP_BUF
  flea_mpi_ulen_t vn_len, un_len;
#endif

  FLEA_DECL_BUF(vn, flea_hlf_uword_t, FLEA_MPI_DIV_VN_HLFW_LEN_FOR_RSA_SF_REDUCTIONS);
  FLEA_DECL_BUF(un, flea_hlf_uword_t,  FLEA_MPI_DIV_UN_HLFW_LEN_FOR_RSA_SF_REDUCTIONS);
  flea_mpi_t result, exponent, base, mod, large_tmp, ws_q, ws_trf_base;
  flea_mpi_div_ctx_t div_ctx;
  FLEA_THR_BEG_FUNC();
#ifdef FLEA_USE_STACK_BUF
  if(modulus_length > FLEA_RSA_MAX_KEY_BIT_SIZE / 8)
  {
    FLEA_THROW("modulus length too large", FLEA_ERR_INV_KEY_SIZE);
  }
#endif
  mod_word_len = FLEA_CEIL_WORD_LEN_FROM_BYTE_LEN(modulus_length);

  result_word_len = mod_word_len + 1;
  large_tmp_word_len = (mod_word_len) * 2 + 1;
  ws_q_word_len = mod_word_len + 1;
#ifdef FLEA_USE_HEAP_BUF
  vn_len = FLEA_MPI_DIV_VN_HLFW_LEN_FROM_DIVISOR_W_LEN(mod_word_len);
  un_len = FLEA_MPI_DIV_UN_HLFW_LEN_FROM_DIVIDENT_W_LEN(2 * mod_word_len);
#endif

  FLEA_ALLOC_BUF(result_arr, result_word_len);
  FLEA_ALLOC_BUF(base_arr, mod_word_len);
  FLEA_ALLOC_BUF(exponent_arr, mod_word_len);
  FLEA_ALLOC_BUF(mod_arr, mod_word_len);
  FLEA_ALLOC_BUF(large_tmp_arr, large_tmp_word_len);
  FLEA_ALLOC_BUF(ws_trf_base_arr, mod_word_len);
  FLEA_ALLOC_BUF(ws_q_arr, ws_q_word_len);

  FLEA_ALLOC_BUF(vn, vn_len);
  FLEA_ALLOC_BUF(un, un_len );

  div_ctx.vn = vn;
  div_ctx.un = un;
  div_ctx.vn_len = FLEA_HEAP_OR_STACK_CODE(vn_len, FLEA_STACK_BUF_NB_ENTRIES(vn));
  div_ctx.un_len = FLEA_HEAP_OR_STACK_CODE(un_len, FLEA_STACK_BUF_NB_ENTRIES(un));


  flea_mpi_t__init(&result, result_arr, result_word_len);
  flea_mpi_t__init(&base, base_arr, mod_word_len);
  flea_mpi_t__init(&exponent, exponent_arr, mod_word_len);
  flea_mpi_t__init(&mod, mod_arr, mod_word_len);
  flea_mpi_t__init(&large_tmp, large_tmp_arr, large_tmp_word_len);
  flea_mpi_t__init(&ws_trf_base, ws_trf_base_arr, mod_word_len);
  flea_mpi_t__init(&ws_q, ws_q_arr, ws_q_word_len);


  FLEA_CCALL(THR_flea_mpi_t__decode(&mod, modulus_enc, modulus_length));
  FLEA_CCALL(THR_flea_mpi_t__decode(&exponent, exponent_enc, exponent_length ));
  FLEA_CCALL(THR_flea_mpi_t__decode(&base, base_enc, base_length));
  // need to use window size 1 because window heap/stack allocations only
  // account for CRT-RSA
  FLEA_CCALL(THR_flea_mpi_t__mod_exp_window(&result, &exponent, &base, &mod, &large_tmp, &div_ctx, &ws_trf_base, &ws_q, 1));
  FLEA_CCALL(THR_flea_mpi_t__encode(result_enc, modulus_length, &result));

  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(result_arr);
    FLEA_FREE_BUF_FINAL(base_arr);
    FLEA_FREE_BUF_FINAL(exponent_arr);
    FLEA_FREE_BUF_FINAL(mod_arr);
    FLEA_FREE_BUF_FINAL(large_tmp_arr);
    FLEA_FREE_BUF_FINAL(ws_trf_base_arr);
    FLEA_FREE_BUF_FINAL(ws_q_arr);
    FLEA_FREE_BUF_FINAL(vn);
    FLEA_FREE_BUF_FINAL(un);
    );
}

#endif // #ifdef FLEA_HAVE_RSA
