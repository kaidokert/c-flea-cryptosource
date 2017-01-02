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
#include "flea/types.h"
#include "flea/bin_utils.h"
#include "flea/error.h"
#include "flea/alloc.h"
#include "flea/array_util.h"
#include "flea/bin_utils.h"
#include "flea/array_util.h"
#include "flea/util.h"
#include "flea/rng.h"
#include "internal/common/rng_int.h"
#include <string.h>
#include <stdio.h>

#define FLEA_SET_HLF_UWORD(__dest, __idx, __val) \
  do { \
    __dest[(__idx) / 2] &= ~(FLEA_HLF_UWORD_MAX << (((__idx) % 2) * 8 * sizeof(flea_hlf_uword_t))); \
    __dest[(__idx) / 2] |= (__val) << (((__idx) % 2) * 8 * sizeof(flea_hlf_uword_t)); \
  } while(0)

#define FLEA_GET_HLF_UWORD(__src, __idx) \
  ((__src[(__idx) / 2] >> (((__idx) % 2) * sizeof(flea_hlf_uword_t) * 8)) & FLEA_HLF_UWORD_MAX)


#define FLEA_WORD_MAX_SHIFT_RANGE   (FLEA_WORD_BIT_SIZE - 1)

static flea_u8_t flea_mpi_t__get_byte (const flea_mpi_t* p_mpi, flea_mpi_ulen_t byte_pos)
{
  flea_mpi_ulen_t word_pos = byte_pos / sizeof(p_mpi->m_words[0]);

  if(byte_pos > flea_mpi_t__get_byte_size(p_mpi))
  {
    return 0x00;
  }
  byte_pos %= sizeof(p_mpi->m_words[0]);
  return (p_mpi->m_words[word_pos] >> (byte_pos * 8)) & 0xFF;
}
static void flea_mpi_t__inner_multiply (const flea_uword_t * restrict a_ptr, flea_mpi_ulen_t a_len, const flea_uword_t * restrict b_ptr, flea_mpi_ulen_t b_len, flea_uword_t * restrict result_ptr)
{
  flea_mpi_ulen_t i, j;

  for(i = 0; i < b_len; i++)
  {
    flea_uword_t carry = 0;
    flea_uword_t i_word = ((flea_dbl_uword_t)b_ptr[i]);
    for(j = 0; j < a_len; j++)
    {
      flea_dbl_uword_t carry__res = result_ptr[i + j] + ((flea_dbl_uword_t)a_ptr[j]) * i_word + ((flea_dbl_uword_t)carry);
      result_ptr[i + j] = (flea_uword_t)carry__res; // lower part
      carry = carry__res >> (sizeof(flea_uword_t) * 8);
    }
    result_ptr[i + a_len] = carry;
  }
}
static void flea_mpi_t__set_used_words (flea_mpi_t* p_mpi)
{
  flea_mpi_slen_t i = p_mpi->m_nb_alloc_words - 1;

  while(i > 0 && p_mpi->m_words[i] == 0 )
  {
    i--;
  }
  // i points to the first significant word
  p_mpi->m_nb_used_words = i + 1;

}
void flea_mpi_swap (flea_mpi_t* p_a, flea_mpi_t* p_b)
{
  flea_uword_t* p_tmp;
  flea_al_u16_t tmp_count;

  p_tmp = p_a->m_words;
  p_a->m_words = p_b->m_words;
  p_b->m_words = p_tmp;

  tmp_count = p_a->m_nb_alloc_words;
  p_a->m_nb_alloc_words = p_b->m_nb_alloc_words;
  p_b->m_nb_alloc_words = tmp_count;

  tmp_count = p_a->m_nb_used_words;
  p_a->m_nb_used_words = p_b->m_nb_used_words;
  p_b->m_nb_used_words = tmp_count;

}
flea_err_t THR_flea_mpi_t__mul (flea_mpi_t* p_result, const flea_mpi_t* p_a, const flea_mpi_t* p_b)
{
  FLEA_THR_BEG_FUNC();
  if(p_result->m_nb_alloc_words < p_a->m_nb_used_words + p_b->m_nb_used_words)
  {
    FLEA_THROW("result size insufficient", FLEA_ERR_INV_ARG);
  }
  p_result->m_nb_used_words = p_a->m_nb_used_words + p_b->m_nb_used_words;

  memset(p_result->m_words, 0, p_result->m_nb_alloc_words * sizeof(p_result->m_words[0]));
  flea_mpi_t__inner_multiply(p_a->m_words, p_a->m_nb_used_words,  p_b->m_words, p_b->m_nb_used_words, p_result->m_words);
  flea_mpi_t__set_used_words(p_result);
  p_result->m_sign = p_a->m_sign * p_b->m_sign;
  if(flea_mpi_t__is_zero(p_result))
  {
    p_result->m_sign = +1;
  }
  FLEA_THR_FIN_SEC();
}

flea_err_t THR_flea_mpi_square (flea_mpi_t* p_result, const flea_mpi_t* p_a)
{
  FLEA_THR_BEG_FUNC();
  flea_mpi_ulen_t i, j;
  flea_uword_t * restrict result_ptr = p_result->m_words;
  flea_uword_t * restrict a_ptr = p_a->m_words;
  flea_uword_t carry = 0;
  if(p_result->m_nb_alloc_words < 2 * p_a->m_nb_used_words )
  {
    FLEA_THROW("result size insufficient", FLEA_ERR_INV_ARG);
  }
  p_result->m_nb_used_words = 2 * p_a->m_nb_used_words;

  memset(result_ptr, 0, p_result->m_nb_alloc_words * sizeof(p_result->m_words[0]));

  // compute all elements "below" the diagonal
  for(i = 0; i < p_a->m_nb_used_words; i++)
  {
    carry = 0;
    flea_dbl_uword_t a_ptr_i = ((flea_dbl_uword_t)a_ptr[i]);
#define combined_iters  4
    // determine number of leading iters
    flea_mpi_ulen_t nb_lead = p_a->m_nb_used_words - (i + 1);
    nb_lead %= combined_iters;
    flea_mpi_ulen_t lead_limit = nb_lead + i + 1;
    for(j = i + 1; j < lead_limit; j++)
    {
      flea_dbl_uword_t carry__res = result_ptr[i + j] + ((flea_dbl_uword_t)a_ptr[j]) * a_ptr_i + ((flea_dbl_uword_t)carry);
      result_ptr[i + j] = (flea_uword_t)carry__res; // lower part
      carry = carry__res >> (sizeof(flea_uword_t) * 8);
    }
    for(; j < p_a->m_nb_used_words - 1; j += combined_iters)
    {
      flea_dbl_uword_t carry__res = result_ptr[i + j] + ((flea_dbl_uword_t)a_ptr[j]) * a_ptr_i + ((flea_dbl_uword_t)carry);
      result_ptr[i + j] = (flea_uword_t)carry__res; // lower part
      carry = carry__res >> (sizeof(flea_uword_t) * 8);


      carry__res = result_ptr[i + j + 1] + ((flea_dbl_uword_t)a_ptr[j + 1]) * a_ptr_i + ((flea_dbl_uword_t)carry);
      result_ptr[i + j + 1] = (flea_uword_t)carry__res; // lower part
      carry = carry__res >> (sizeof(flea_uword_t) * 8);
#if combined_iters == 4

      carry__res = result_ptr[i + j + 2] + ((flea_dbl_uword_t)a_ptr[j + 2]) * a_ptr_i + ((flea_dbl_uword_t)carry);
      result_ptr[i + j + 2] = (flea_uword_t)carry__res; // lower part
      carry = carry__res >> (sizeof(flea_uword_t) * 8);

      carry__res = result_ptr[i + j + 3] + ((flea_dbl_uword_t)a_ptr[j + 3]) * a_ptr_i + ((flea_dbl_uword_t)carry);
      result_ptr[i + j + 3] = (flea_uword_t)carry__res; // lower part
      carry = carry__res >> (sizeof(flea_uword_t) * 8);
#endif
    }
    result_ptr[i + p_a->m_nb_used_words] = carry;
  }

  // multiply result by two
  carry = 0;
  for(i = 1; i < p_result->m_nb_used_words; i++) // lowest word is still zero
  {
    flea_dbl_uword_t carry__res = ((flea_dbl_uword_t)result_ptr[i]) * 2 + ((flea_dbl_uword_t)carry);
    result_ptr[i] = (flea_uword_t)carry__res;   // lower part
    carry = carry__res >> (sizeof(flea_uword_t) * 8);

  }
  // now take care of the diagonal elements
  carry = 0;
  for(i = 0; i < p_a->m_nb_used_words; i++)
  {
    flea_dbl_uword_t a_ptr_i = a_ptr[i];
    flea_dbl_uword_t a_ptr_i_next_odd = result_ptr[2 * i + 1];
    flea_dbl_uword_t carry__res = ((flea_dbl_uword_t)result_ptr[2 * i]) + a_ptr_i * a_ptr_i + ((flea_dbl_uword_t)carry);
    result_ptr[2 * i] = (flea_uword_t)carry__res; // lower part
    carry = carry__res >> (sizeof(flea_uword_t) * 8);

    // add the carry to the following higher word with an odd index, which
    // doesn't receive a product directly
    carry__res =  a_ptr_i_next_odd + carry;
    result_ptr[2 * i + 1] = (flea_uword_t)carry__res; // lower part
    carry = carry__res >> (sizeof(flea_uword_t) * 8);
  }


  flea_mpi_t__set_used_words(p_result);
  FLEA_THR_FIN_SEC();
}
/*
 * @param lowest_word_of_n integer to invert modulo FLEA_UWORD_MAX + 1. n must be odd
 */
flea_uword_t flea_montgomery_compute_n_prime (flea_uword_t lowest_word_of_n)
{
  // accounting for the sign in t:
  flea_dbl_sword_t q, r0, r1, r2, t0, t1, t2; // q,r0 need to be double words only before the loop!

  lowest_word_of_n |= 1;                      // make it odd to prevent control flow problems
  t0 = 0;
  t1 = 1;
  r0 = ((flea_dbl_sword_t)FLEA_UWORD_MAX) + 1;
  r1 = lowest_word_of_n;
  while(r1 > 0)
  {
    q = r0 / r1;
    t2 = t1;
    t1 = t0 - q * t1;
    t0 = t2;
    r2 = r1;
    r1 = r0 - q * r1;
    r0 = r2;

  }
  if(t0 < 0)
  {
    t0 += (FLEA_UWORD_MAX + 1);
  }
  return ((FLEA_UWORD_MAX)-t0) + 1;
}

/**
 * adds word to the word in *p_mpi at word_idx and propagates the carry.
 */
static flea_err_t THR_flea_mpi_t__montgm_mul_add_to_mpi_arr (flea_mpi_t* p_mpi, flea_uword_t word, flea_mpi_ulen_t word_idx)
{
  FLEA_THR_BEG_FUNC();
  flea_dbl_uword_t carry__res;
  flea_uword_t carry = word;
  while(carry != 0)
  {
    if(word_idx >= p_mpi->m_nb_alloc_words)
    {
      FLEA_THROW("integer array too short", FLEA_ERR_INV_ARG);
    }
    carry__res = ((flea_dbl_uword_t)p_mpi->m_words[word_idx]) + ((flea_dbl_uword_t)carry);
    p_mpi->m_words[word_idx] = (flea_uword_t)carry__res;
    carry = carry__res >> (sizeof(flea_uword_t) * 8);
    if(carry != 0)
    {
      word_idx++;
    }
  }
  // now word_idx points to the last updated word
  if(word_idx > p_mpi->m_nb_used_words - 1)
  {
    p_mpi->m_nb_used_words = word_idx + 1;
  }
  FLEA_THR_FIN_SEC();
}

// result must have double mod size + 1 allocated
flea_err_t THR_flea_mpi_t__montgm_mul (flea_mpi_t* p_result, const flea_mpi_t* p_a, const flea_mpi_t* p_b, flea_montgm_mul_ctx_t* p_ctx)
{
  FLEA_THR_BEG_FUNC();
  flea_uword_t * restrict result_ptr = p_result->m_words;
  flea_uword_t * restrict ws_ptr = p_ctx->p_ws->m_words;
  flea_uword_t * restrict mod_ptr = p_ctx->p_mod->m_words;
  flea_uword_t sub_res;
  flea_uword_t borrow;
  flea_uword_t n_prime_zero = p_ctx->mod_prime;
  flea_mpi_ulen_t i, j;
  const flea_mpi_ulen_t mod_len = p_ctx->p_mod->m_nb_used_words;
  if(p_result->m_nb_alloc_words < 2 * mod_len + 1)
  {
    FLEA_THROW("result size insufficient", FLEA_ERR_INV_ARG);
  }
  if(p_a != p_b)
  {
    FLEA_CCALL(THR_flea_mpi_t__mul(p_result, p_a, p_b)); // compute t
  }
  else
  {
    FLEA_CCALL(THR_flea_mpi_square(p_result, p_a)); // compute t
  }


  for(i = 0; i < mod_len; i++) // calculate length demands exactly here
  {
    flea_uword_t carry = 0;
    flea_uword_t m = result_ptr[i] * n_prime_zero;
    for(j = 0; j < mod_len; j++)
    {
      flea_dbl_uword_t carry__res = ((flea_dbl_uword_t)result_ptr[i + j]) + ((flea_dbl_uword_t)m) * ((flea_dbl_uword_t)mod_ptr[j]) + ((flea_dbl_uword_t)carry);
      result_ptr[i + j] = (flea_uword_t)carry__res; // assign lower part
      carry = carry__res >> (sizeof(flea_uword_t) * 8);
    }
    FLEA_CCALL(THR_flea_mpi_t__montgm_mul_add_to_mpi_arr(p_result, carry, i + mod_len));
  }
  if(p_ctx->p_ws->m_nb_alloc_words < mod_len + 1)
  {
    FLEA_THROW("workspace size insufficient", FLEA_ERR_INV_ARG);
  }

  p_ctx->p_ws->m_nb_used_words = mod_len + 1;
  p_ctx->p_ws->m_sign = 1;
  memcpy(p_ctx->p_ws->m_words, &result_ptr[mod_len], (mod_len + 1) * sizeof(result_ptr[0]));
  memset(p_result->m_words, 0, p_result->m_nb_alloc_words * sizeof(flea_uword_t));
  p_result->m_nb_used_words = mod_len;
  borrow = 0;
  for(i = 0; i < mod_len; i++)
  {
    flea_uword_t new_borrow = 0;
    flea_uword_t sub_res = ( ws_ptr[i]) -  ( mod_ptr[i]);
    if(sub_res > ws_ptr[i])
    {
      new_borrow = 1;
    }
    result_ptr[i] = sub_res - borrow;
    if(result_ptr[i] > sub_res)
    {
      new_borrow = 1;
    }
    borrow = new_borrow;
  }

  sub_res = ws_ptr[mod_len] - borrow;
  if(sub_res > result_ptr[mod_len])
  {
    borrow = 1;
  }
  else
  {
    borrow = 0;
  }

  if(borrow == 0)
  {
  }
  else
  {
    FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(p_result, p_ctx->p_ws));
  }
  flea_mpi_t__set_used_words(p_result);
  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_mpi_t__quick_reduce_smaller_zero (flea_mpi_t* p_in_out, const flea_mpi_t* p_mod, flea_mpi_t* p_ws)
{
  FLEA_THR_BEG_FUNC();
  while(0 > flea_mpi_t__compare_with_uword(p_in_out, 0 ))
  {
    FLEA_CCALL(THR_flea_mpi_t__add_in_place(p_in_out, p_mod, p_ws));
  }

  FLEA_THR_FIN_SEC_empty();
}
flea_err_t THR_flea_mpi_t__quick_reduce_greater_zero (flea_mpi_t* p_in_out, const flea_mpi_t* p_mod, flea_mpi_t* p_ws)
{
  FLEA_THR_BEG_FUNC();
  while(0 < flea_mpi_t__compare(p_in_out, p_mod))
  {
    FLEA_CCALL(THR_flea_mpi_t__subtract(p_ws, p_in_out, p_mod));
    FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(p_in_out, p_ws));
  }

  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_mpi_t__set_pow_2 (flea_mpi_t* p_result, flea_al_u16_t exp)
{
  FLEA_THR_BEG_FUNC();
  flea_mpi_ulen_t word_len = (exp + FLEA_WORD_BIT_SIZE) / FLEA_WORD_BIT_SIZE;
  flea_mpi_ulen_t one_index = word_len - 1; // for exp = 0 corrected later
  if(word_len > p_result->m_nb_alloc_words)
  {
    FLEA_THROW("pow 2 setter for mpi: result does not fit in array", FLEA_ERR_INV_ARG);
  }
  if(exp != 0)
  {
    // zero low words
    memset(&p_result->m_words[0], 0, (word_len - 1) * sizeof(flea_uword_t) );
  }
  else
  {
    one_index = 0;
  }

  p_result->m_words[one_index] = 1 << (exp % FLEA_WORD_BIT_SIZE);
  p_result->m_nb_used_words = word_len;
  FLEA_THR_FIN_SEC_empty();
}

// decode a big-endian encoded integer
flea_err_t THR_flea_mpi_t__decode (flea_mpi_t* p_result, const flea_u8_t* encoded, flea_mpi_ulen_t encoded_len)
{
  flea_mpi_slen_t i;
  unsigned int inv_i;

  FLEA_THR_BEG_FUNC();
  // strip leading zero bytes in encoded:
  while(*encoded == 0 && encoded_len > 1)
  {
    encoded++;
    encoded_len--;
  }
  flea_mpi_ulen_t new_word_len = (encoded_len + sizeof(flea_uword_t) - 1) / sizeof(flea_uword_t);
  if(p_result->m_nb_alloc_words < new_word_len)
  {
    FLEA_THROW("result size insufficient", FLEA_ERR_BUFF_TOO_SMALL);
  }
  p_result->m_nb_used_words = new_word_len;
  memset(p_result->m_words, 0, p_result->m_nb_used_words * sizeof(p_result->m_words[0]));

  inv_i = 0;
  for(i = encoded_len - 1; i >= 0; i--)
  {
    p_result->m_words[inv_i / sizeof(flea_uword_t)] |= encoded[i] << ((inv_i % sizeof(flea_uword_t)) * 8 );
    inv_i++;
  }
  p_result->m_sign = +1;
  FLEA_THR_FIN_SEC();
}
flea_al_u8_t flea_bin_util__get_sig_bytes_of_word (flea_uword_t word)
{
  flea_al_s8_t i;

  for(i = sizeof(word) - 1; i >= 0; i--)
  {
    if(word & (0xFF << (i * 8)))
    {
      return i + 1;
    }
  }
  return 0; // zero in case the word is zero
}

flea_err_t THR_flea_mpi_t__encode (flea_u8_t * p_result, flea_al_u16_t result_len, const flea_mpi_t * p_mpi)
{

  FLEA_THR_BEG_FUNC();
  flea_al_u16_t nb_bytes, offset;
  flea_mpi_slen_t i;
  nb_bytes = flea_mpi_t__get_byte_size(p_mpi);
  if(nb_bytes > result_len)
  {
    FLEA_THROW("not enough bytes in result array to encode integer", FLEA_ERR_BUFF_TOO_SMALL);
  }
  offset = result_len - nb_bytes;
  memset(p_result, 0, offset);
  for(i = nb_bytes - 1; i >= 0; i--)
  {
    flea_mpi_ulen_t out_pos = offset + (nb_bytes - i - 1);
    p_result[out_pos] = flea_mpi_t__get_byte(p_mpi, i);
  }
  FLEA_THR_FIN_SEC();
}

void flea_mpi_t__init (flea_mpi_t* p_result, flea_uword_t* word_array, flea_mpi_ulen_t nb_words)
{
  p_result->m_words = word_array;
  p_result->m_nb_used_words = 0;
  p_result->m_nb_alloc_words = nb_words;
  p_result->m_sign = 1;
  memset(word_array, 0, sizeof(word_array[0]) * nb_words);
}


// vn must have twice the size of the divisor
// un must have 2(m+1) words, where m is the size of the dividend
flea_err_t THR_flea_mpi_t__divide (flea_mpi_t* p_quotient, flea_mpi_t* p_remainder, const flea_mpi_t* p_dividend, const flea_mpi_t* p_divisor, flea_mpi_div_ctx_t* p_div_ctx)
{
  flea_mpi_ulen_t m, n;
  flea_mpi_slen_t j, i;
  const flea_uword_t* u = p_dividend->m_words;
  const flea_uword_t* v = p_divisor->m_words;
  flea_hlf_uword_t* vn = p_div_ctx->vn;
  flea_hlf_uword_t* un = p_div_ctx->un;

  flea_uword_t* q = NULL;

  flea_uword_t* r = p_remainder->m_words;

  const flea_uword_t b = FLEA_HLF_UWORD_MAX + 1;
  flea_sword_t t;
  flea_uword_t qhat, rhat, p;
  flea_uword_t k, s;


  FLEA_THR_BEG_FUNC();

  flea_s8_t result_sign = p_dividend->m_sign * p_divisor->m_sign;

  m = p_dividend->m_nb_used_words * 2;
  n = p_divisor->m_nb_used_words * 2;

  if(((m + 1) > p_div_ctx->un_len) ||  (n > p_div_ctx->vn_len))
  {
    FLEA_THROW("division context buffer too small", FLEA_ERR_BUFF_TOO_SMALL);
  }
  if(p_quotient != NULL)
  {
    flea_mpi_ulen_t quotient_min_word_len__ulen;
    flea_mpi_ubil_t dividend_bit_len__ubil, divisor_bit_len__ubil;
    dividend_bit_len__ubil = flea_mpi_t__get_bit_size(p_dividend);
    divisor_bit_len__ubil = flea_mpi_t__get_bit_size(p_divisor);
    quotient_min_word_len__ulen = FLEA_CEIL_WORD_LEN_FROM_BIT_LEN(dividend_bit_len__ubil - divisor_bit_len__ubil + 1);
    if(dividend_bit_len__ubil == divisor_bit_len__ubil)
    {
      quotient_min_word_len__ulen = p_dividend->m_nb_used_words;
    }
    else if(divisor_bit_len__ubil > dividend_bit_len__ubil)
    {
      quotient_min_word_len__ulen = 1;
    }
    if(p_quotient->m_nb_alloc_words < quotient_min_word_len__ulen)
    {
      FLEA_THROW("quotient nb allocated words too small in division", FLEA_ERR_BUFF_TOO_SMALL);
    }

    q = p_quotient->m_words;
  }
  if(p_remainder->m_nb_alloc_words < p_divisor->m_nb_used_words)
  {
    FLEA_THROW("remainder nb allocated words too small in division", FLEA_ERR_BUFF_TOO_SMALL);
  }
  if(0 > flea_mpi_t__compare_absolute(p_dividend, p_divisor))
  {
    if(p_quotient != NULL)
    {
      flea_mpi_t__set_to_word_value(p_quotient, 0);
    }
    FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(p_remainder, p_dividend));
    p_remainder->m_sign = result_sign;
    FLEA_THR_RETURN();
  }
  if(q != NULL)
  {
    memset(p_quotient->m_words, 0, p_quotient->m_nb_alloc_words * sizeof(flea_uword_t));
  }
  memset(p_remainder->m_words, 0, p_remainder->m_nb_alloc_words * sizeof(flea_uword_t));

  if(m == 0 || n == 0)
  {
    FLEA_THROW("invalid size for division: dividend or divisor", FLEA_ERR_INV_ARG);
  }
  // correct the "half-word" size of the arrays
  if(u[m / 2 - 1] <= FLEA_HLF_UWORD_MAX)
  {
    m--;
  }
  if(v[n / 2 - 1] <= FLEA_HLF_UWORD_MAX)
  {
    n--;
  }
  if(m < n || FLEA_GET_HLF_UWORD(v, n - 1) == 0)
  {
    FLEA_THROW("invalid size for division: divisor too large", FLEA_ERR_INV_ARG);
  }
  if( n == 1)
  {
    k = 0;
    flea_hlf_uword_t v_0 = FLEA_GET_HLF_UWORD(v, 0);
    for( j = m - 1; j >= 0; j--)
    {
      flea_hlf_uword_t u_j = FLEA_GET_HLF_UWORD(u, j);
      flea_hlf_uword_t q_j = (k * b + u_j) / v_0;
      if(q != NULL)
      {
        FLEA_SET_HLF_UWORD(q, j, q_j);
      }
      k = (k * b + u_j) - q_j * v_0;
    }
    FLEA_SET_HLF_UWORD(r, 0, k);
    p_remainder->m_nb_used_words = 1;
    if(p_quotient != NULL)
    {
      flea_mpi_t__set_used_words(p_quotient);
    }
    p_remainder->m_sign = result_sign;
    FLEA_THR_RETURN();
  }
  s = flea__nlz_uword(FLEA_GET_HLF_UWORD(v, n - 1)) - sizeof(flea_hlf_uword_t) * 8; // subtract the unused half of the full words bits
  for(i = n - 1; i > 0; i--)
  {
    vn[i] =
      (FLEA_GET_HLF_UWORD(v, i) << s) |
      (FLEA_GET_HLF_UWORD(v, i - 1) >> (16 - s));
  }
  vn[0] = FLEA_GET_HLF_UWORD(v, 0) << s;

  un[m] = FLEA_GET_HLF_UWORD(u, m - 1) >> (16 - s);

  for(i = m - 1; i > 0; i--)
  {
    un[i] = (FLEA_GET_HLF_UWORD(u, i) << s) | (FLEA_GET_HLF_UWORD(u, i - 1) >> (16 - s));
  }
  un[0] = (FLEA_GET_HLF_UWORD(u, 0) << s);
  for(j = m - n; j >= 0; j--)
  {
    qhat = (un[j + n] * b + un[j + n - 1]) / vn[n - 1];
    rhat = (un[j + n] * b + un[j + n - 1]) - qhat * vn[n - 1];
    while(qhat >= b || qhat * vn[n - 2] > b * rhat + un[j + n - 2])
    {
      qhat = qhat - 1;
      rhat = rhat + vn[n - 1];
      if(rhat < b)
      {
        continue;
      }
      break;
    }

    k = 0;
    for(i = 0; i < n; i++)
    {
      p = qhat * vn[i];
      t = un[i + j] - k - (p & FLEA_HLF_UWORD_MAX);
      un[i + j] = t;
      k = (p >> 16) - (t >> 16);
    }
    t = un[j + n] - k;
    un[j + n] = t;

    if(q != NULL)
    {
      FLEA_SET_HLF_UWORD(q, j, qhat);
    }
    if(t < 0)
    {

      if(q != NULL)
      {
        flea_hlf_uword_t q_j = FLEA_GET_HLF_UWORD(q, j) - 1;
        FLEA_SET_HLF_UWORD(q, j, q_j);
      }
      k = 0;
      for(i = 0; i < n; i++)
      {
        t = un[i + j] + vn[i] + k;
        un[i + j] = t;
        k = t >> 16;
      }
      un[j + n] = un[j + n] + k;
    }
  } // end j-loop
  if(p_remainder != NULL)
  {
    for(i = 0; i < n; i++)
    {
      flea_hlf_uword_t r_i = (un[i] >> s) | un[i + 1] << (16 - s);
      FLEA_SET_HLF_UWORD(p_remainder->m_words, i, r_i);
      flea_mpi_t__set_used_words(p_remainder);
    }
  }
  if(p_quotient != NULL)
  {
    flea_mpi_t__set_used_words(p_quotient);
  }

  p_remainder->m_sign = result_sign;
  FLEA_THR_FIN_SEC_empty();
}

flea_al_s8_t flea_mpi_t__compare (const flea_mpi_t* p_a, const flea_mpi_t* p_b)
{
  if(flea_mpi_t__is_zero(p_a) && flea_mpi_t__is_zero(p_b))
  {
    return 0;
  }
  if(p_a->m_sign > p_b->m_sign)
  {
    return 1;
  }
  if(p_a->m_sign < p_b->m_sign)
  {
    return -1;
  }
  // both signs are equal
  return p_a->m_sign * flea_mpi_t__compare_absolute(p_a, p_b);
}

flea_al_s8_t flea_mpi_t__compare_absolute (const flea_mpi_t* p_a, const flea_mpi_t* p_b)
{
  flea_mpi_slen_t i;

  if(p_a->m_nb_used_words > p_b->m_nb_used_words)
  {
    return 1;
  }
  else if(p_a->m_nb_used_words < p_b->m_nb_used_words)
  {
    return -1;
  }

  for(i = p_a->m_nb_used_words - 1; i >= 0; i--)
  {
    if(p_a->m_words[i] > p_b->m_words[i])
    {
      return 1;
    }
    else if(p_a->m_words[i] < p_b->m_words[i])
    {
      return -1;
    }

  }
  return 0;

}
flea_bool_t flea_mpi_t__equal (const flea_mpi_t* p_a, const flea_mpi_t* p_b)
{

  if(p_a->m_sign != p_b->m_sign)
  {
    if(flea_mpi_t__is_zero(p_a) && flea_mpi_t__is_zero(p_b))
    {
      return FLEA_TRUE;
    }
    return FLEA_FALSE;
  }
  if(p_a->m_nb_used_words != p_b->m_nb_used_words)
  {
    return FLEA_FALSE;
  }
  if(memcmp(p_a->m_words, p_b->m_words, p_a->m_nb_used_words * sizeof(p_a->m_words[0])))
  {
    return FLEA_FALSE;
  }
  return FLEA_TRUE;

}

void flea_mpi_t__print (const flea_mpi_t* p_mpi)
{
  flea_s16_t i;

  if(p_mpi->m_sign < 0)
  {
    FLEA_PRINTF_1_SWITCHTED("-");
  }
  else
  {
    FLEA_PRINTF_1_SWITCHTED("+");
  }
  for(i = p_mpi->m_nb_used_words - 1; i >= 0; i--)
  {
    FLEA_PRINTF_2_SWITCHTED("%08X", p_mpi->m_words[i]);
  }
  FLEA_PRINTF_2_SWITCHTED(" (%u words)", p_mpi->m_nb_used_words);
  FLEA_PRINTF_1_SWITCHTED("\n");
}

/**
 * p_quotient_ws must at least satisfy the requirements of the workspace for montg_mul
 */
#if FLEA_CRT_RSA_WINDOW_SIZE > 1
static flea_err_t THR_flea_mpi_t__precompute_window (
  flea_mpi_t* p_this,
  flea_mpi_t* p_previous,
  flea_mpi_t * p_base_trf,
  flea_montgm_mul_ctx_t* p_mm_ctx,
  flea_mpi_t* p_workspace_double_plus_one_sized
  )
{

  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_mpi_t__montgm_mul(p_workspace_double_plus_one_sized, p_base_trf, p_previous, p_mm_ctx ));
  FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(p_this, p_workspace_double_plus_one_sized));


  FLEA_THR_FIN_SEC();
}
#endif

/**
 * quotient_ws must satisfy at least the requirements of montgm mul ws
 */
flea_err_t THR_flea_mpi_t__mod_exp_window (
  flea_mpi_t* p_result,
  flea_mpi_t* p_exp,
  flea_mpi_t* p_base,
  flea_mpi_t* p_mod,
  flea_mpi_t* p_workspace_double_plus_one_sized,
  flea_mpi_div_ctx_t * p_div_ctx,
  flea_mpi_t* p_ws_trf_base,
  flea_mpi_t* p_quotient_ws,
  flea_al_u8_t window_size
  )
{
  flea_uword_t one_arr[1];
  flea_u8_t one_enc[] = { 1 };
  flea_u16_t exp_bit_size;
  flea_s32_t i;
  flea_mpi_t one;

#if FLEA_CRT_RSA_WINDOW_SIZE > 1
  const flea_al_u16_t precomp_arr_dynamic_word_len = p_mod->m_nb_used_words;
#endif
  const flea_al_u16_t R_dynamic_word_len = p_mod->m_nb_used_words + 1; // R is one word longer than mod

#if FLEA_CRT_RSA_WINDOW_SIZE > 1
  const flea_mpi_ulen_t precomp_dynamic_size = (1 << window_size) - 2;
#endif

  FLEA_DECL_BUF(R_arr, flea_uword_t, ((FLEA_RSA_MAX_KEY_BIT_SIZE / 8) + sizeof(flea_uword_t) - 1) / sizeof(flea_uword_t) + 2); // for RSA (CRT/SF) ; + 1 because R potentially longer than mod and another +1 for p-q diff; this array must account for non CRT usage also!
#if defined FLEA_USE_HEAP_BUF && FLEA_CRT_RSA_WINDOW_SIZE > 1
  FLEA_DECL_BUF(precomp_arrs, flea_uword_t *, (1 << FLEA_CRT_RSA_WINDOW_SIZE) - 2);
#elif FLEA_CRT_RSA_WINDOW_SIZE > 1
  flea_uword_t precomp_arrs[(1 << FLEA_CRT_RSA_WINDOW_SIZE) - 2][FLEA_RSA_MAX_KEY_BIT_SIZE / 8 / 2 / sizeof(flea_uword_t) + 1]; // plus one because of p-q-diff
#endif

#if FLEA_CRT_RSA_WINDOW_SIZE > 1
  FLEA_DECL_BUF(precomp, flea_mpi_t, (1 << FLEA_CRT_RSA_WINDOW_SIZE) - 2);
#endif

  flea_mpi_t R;
  flea_montgm_mul_ctx_t mm_ctx;

  FLEA_THR_BEG_FUNC();

  if(window_size > FLEA_CRT_RSA_WINDOW_SIZE)
  {
    window_size = FLEA_CRT_RSA_WINDOW_SIZE;
  }

  mm_ctx.mod_prime = flea_montgomery_compute_n_prime(p_mod->m_words[0]);
  mm_ctx.p_mod = p_mod;
  mm_ctx.p_ws = p_quotient_ws;

  FLEA_ALLOC_BUF(R_arr, R_dynamic_word_len);
#if defined FLEA_USE_HEAP_BUF && FLEA_CRT_RSA_WINDOW_SIZE > 1
  FLEA_ALLOC_BUF(precomp_arrs, precomp_dynamic_size);
  FLEA_ALLOC_BUF(precomp, precomp_dynamic_size);

  memset(precomp_arrs, 0, precomp_dynamic_size);
  for(i = 0; i < precomp_dynamic_size; i++)
  {
    FLEA_ALLOC_MEM_ARR(precomp_arrs[i], precomp_arr_dynamic_word_len);
  }
#endif
#if FLEA_CRT_RSA_WINDOW_SIZE > 1
  for(i = 0; i < precomp_dynamic_size; i++)
  {
    flea_mpi_t__init(&precomp[i], precomp_arrs[i], precomp_arr_dynamic_word_len);
  }
#endif
  flea_mpi_t__init(&R, R_arr, R_dynamic_word_len);
  FLEA_CCALL(THR_flea_mpi_t__set_pow_2(&R, p_mod->m_nb_used_words * FLEA_WORD_BIT_SIZE));
  // window method precomputations


  flea_mpi_t__init(&one, one_arr, sizeof(one_arr) / sizeof(flea_uword_t));
  FLEA_CCALL(THR_flea_mpi_t__decode(&one, one_enc, sizeof(one_enc)));

  FLEA_CCALL(THR_flea_mpi_t__mul(p_workspace_double_plus_one_sized, &R, p_base));
  FLEA_CCALL(THR_flea_mpi_t__divide(NULL, p_ws_trf_base, p_workspace_double_plus_one_sized, p_mod, p_div_ctx)); //a_bar = a * R mod n

#if FLEA_CRT_RSA_WINDOW_SIZE > 1
  if(window_size > 1)
  {
    FLEA_CCALL(THR_flea_mpi_t__precompute_window(&precomp[0],  p_ws_trf_base, p_ws_trf_base, &mm_ctx, p_workspace_double_plus_one_sized ));
    for(i = 1; i < (1 << window_size) - 2; i++)
    {
      FLEA_CCALL(THR_flea_mpi_t__precompute_window(&precomp[i],  &precomp[i - 1], p_ws_trf_base, &mm_ctx, p_workspace_double_plus_one_sized));
    }
  }
#endif


  // first, transform base

  // transformed base x_bar^0 in p_result:

  FLEA_CCALL(THR_flea_mpi_t__divide(NULL, p_result, &R, p_mod, p_div_ctx)); //x_bar = 1 * R mod n

  exp_bit_size = flea_mpi_t__get_bit_size(p_exp);

  i = exp_bit_size - 1;
  if(window_size > 1)
  {
    while((i + 1) % window_size)
    {
      flea_u8_t exp_bit = flea_mpi_t__get_bit(p_exp, i);

      i--;
      FLEA_CCALL(THR_flea_mpi_t__montgm_mul(p_workspace_double_plus_one_sized, p_result, p_result, &mm_ctx)); // NOTE: last arg needs only mod size
      // copy contents from large ws to result
      FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(p_result, p_workspace_double_plus_one_sized));

      if(exp_bit == 0x1)
      {
        FLEA_CCALL(THR_flea_mpi_t__montgm_mul(p_workspace_double_plus_one_sized, p_result, p_ws_trf_base, &mm_ctx));
        FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(p_result, p_workspace_double_plus_one_sized));
      }
      // p_result is the running variable

    }
  }

  for(; i >= 0; i -= window_size)
  {
    flea_al_u8_t j;
    flea_mpi_t* p_base_power;
    flea_u8_t exp_bit = flea_mpi_t__get_bit(p_exp, i);
    for(j = 1; j < window_size; j++)
    {
      exp_bit <<= 1;
      exp_bit |= flea_mpi_t__get_bit(p_exp, i - j);
    }
    FLEA_CCALL(THR_flea_mpi_t__montgm_mul(p_workspace_double_plus_one_sized, p_result, p_result, &mm_ctx));  // NOTE: last arg needs only mod size
    // copy contents from large ws to result
    FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(p_result, p_workspace_double_plus_one_sized));
    // perform the squarings
    for(j = 1; j < window_size; j++)
    {
      FLEA_CCALL(THR_flea_mpi_t__montgm_mul(p_workspace_double_plus_one_sized, p_result, p_result, &mm_ctx));  // NOTE: last arg needs only mod size
      // copy contents from large ws to result
      FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(p_result, p_workspace_double_plus_one_sized));
    }
    if(exp_bit == 0)
    {
      continue;
    }
    else if(exp_bit == 0x1)
    {
      p_base_power = p_ws_trf_base;
    }
#if FLEA_CRT_RSA_WINDOW_SIZE > 1
    else
    {
      p_base_power = &precomp[exp_bit - 2];
    }
#endif

    FLEA_CCALL(THR_flea_mpi_t__montgm_mul(p_workspace_double_plus_one_sized, p_result, p_base_power, &mm_ctx));
    FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(p_result, p_workspace_double_plus_one_sized));
  }
  FLEA_CCALL(THR_flea_mpi_t__montgm_mul(p_workspace_double_plus_one_sized, p_result, &one, &mm_ctx));
  FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(p_result, p_workspace_double_plus_one_sized));
  FLEA_THR_FIN_SEC(
    FLEA_DO_IF_RSA_CRT_WINDOW_SIZE_GREATER_ONE(FLEA_DO_IF_USE_HEAP_BUF(
                                                 if(precomp_arrs)
                                                 {
                                                   for(i = 0; i < precomp_dynamic_size; i++)
                                                   {
                                                     FLEA_FREE_MEM_CHK_NULL(precomp_arrs[i]);
                                                   }
                                                 }
                                                 FLEA_FREE_BUF_FINAL(precomp_arrs);
                                                 );
                                               );
    FLEA_DO_IF_RSA_CRT_WINDOW_SIZE_GREATER_ONE(
      FLEA_FREE_BUF_FINAL(precomp);
      );
    FLEA_FREE_BUF_FINAL(R_arr);
    );

}
flea_u16_t flea_mpi_t__get_bit_size (const flea_mpi_t* p_mpi)
{
  // take the highest word and count the unused bits
  flea_al_u16_t i;
  flea_uword_t word;

  if(p_mpi->m_nb_used_words == 0)
  {
    return 0;
  }
  word = p_mpi->m_words[p_mpi->m_nb_used_words - 1];
  i = flea__nlz_uword(word);
  i = FLEA_WORD_BIT_SIZE - i;
  return i + (p_mpi->m_nb_used_words - 1) * sizeof(p_mpi->m_words[0]) * 8;

}

flea_u16_t flea_mpi_t__get_byte_size (const flea_mpi_t* p_mpi)
{
  return FLEA_CEIL_BYTE_LEN_FROM_BIT_LEN(flea_mpi_t__get_bit_size(p_mpi));
}

flea_u8_t flea_mpi_t__get_bit (const flea_mpi_t* p_mpi, flea_u16_t bit_pos)
{
  flea_uword_t result;

  if(bit_pos > 8 * sizeof(flea_uword_t) * p_mpi->m_nb_used_words)
  {
    return 0;
  }

  result = p_mpi->m_words[bit_pos >> FLEA_LOG2_WORD_BIT_SIZE] &  (1 << (bit_pos % (sizeof(flea_uword_t) * 8)));
  if(result != 0)
  {
    result = 1;
  }
  return (flea_u8_t)result;
}

flea_err_t THR_flea_mpi_t__copy_no_realloc (flea_mpi_t* p_target, const flea_mpi_t* p_source)
{
  FLEA_THR_BEG_FUNC();

  if(p_target->m_nb_alloc_words < p_source->m_nb_used_words)
  {
    FLEA_THROW("mpi_t__copy_no_realloc: not enough space in destination", FLEA_ERR_INV_ARG);
  }
  FLEA_CP_ARR(p_target->m_words, p_source->m_words, p_source->m_nb_used_words);
  p_target->m_nb_used_words = p_source->m_nb_used_words;
  p_target->m_sign = p_source->m_sign;

  FLEA_THR_FIN_SEC();
}
static flea_err_t THR_flea_mpi_t__subtract_ignore_sign (flea_mpi_t* p_result, const flea_mpi_t * p_larger, const flea_mpi_t* p_smaller)
{
  flea_uword_t borrow;
  flea_mpi_ulen_t i;

  FLEA_THR_BEG_FUNC();
  memset(p_result->m_words, 0, p_result->m_nb_alloc_words * sizeof(p_result->m_words[0]));
  // length of a >= length of b
  borrow = 0;
  for(i = 0; i < p_smaller->m_nb_used_words; i++)
  {
    flea_uword_t new_borrow = 0;
    flea_uword_t new_word;
    flea_uword_t sub_res =  p_larger->m_words[i] -   p_smaller->m_words[i];

    if(sub_res > p_larger->m_words[i])
    {
      new_borrow = 1;
    }

    new_word = sub_res - borrow;
    if(new_word != 0)
    {
      if(p_result->m_nb_alloc_words < i + 1)
      {
        FLEA_THROW("error with size of result", FLEA_ERR_BUFF_TOO_SMALL);
      }
      p_result->m_words[i] = new_word;
    }
    if(new_word > sub_res)
    {
      new_borrow = 1;
    }
    borrow = new_borrow;
  }
  // handle remaining borrow (because a is not smaller than b, there must be
  // another word in a if there is a borrow pending after processing the highest word of b)
  for(; i < p_larger->m_nb_used_words; i++)
  {
    flea_uword_t sub_res =  p_larger->m_words[i] - borrow;
    flea_uword_t new_borrow = 0;

    if(sub_res > p_larger->m_words[i])
    {
      new_borrow = 1;
    }

    if(sub_res != 0 && p_result->m_nb_alloc_words < i + 1)
    {
      FLEA_THROW("error with size of result", FLEA_ERR_BUFF_TOO_SMALL);
    }
    p_result->m_words[i] = sub_res;
    borrow = new_borrow;
  }
  flea_mpi_t__set_used_words(p_result);
  FLEA_THR_FIN_SEC();
}

flea_err_t THR_flea_mpi_t__subtract (flea_mpi_t* p_result, const flea_mpi_t * p_a, const flea_mpi_t* p_b)
{

  const flea_mpi_t* tmp;

  FLEA_THR_BEG_FUNC();
  p_result->m_sign = +1;
  if(p_a->m_sign == -1)
  {
    // this applies to both subtraction and addition case
    p_result->m_sign *= -1;
  }

  if(p_a->m_sign == p_b->m_sign)
  {
    if(-1 == flea_mpi_t__compare_absolute(p_a, p_b))
    {
      // a < b
      p_result->m_sign *= -1;
      tmp = p_a;
      p_a = p_b;
      p_b = tmp;
    }
    FLEA_CCALL(THR_flea_mpi_t__subtract_ignore_sign(p_result, p_a, p_b));
    FLEA_THR_RETURN();
  }
  // signs differ, thus we have an addition.
  // the sign was already treated in the beginning of the function
  FLEA_CCALL(THR_flea_mpi_t__add_ignore_sign(p_result, p_a, p_b));
  if(flea_mpi_t__is_zero(p_result))
  {
    p_result->m_sign = +1;
  }
  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_mpi_t__subtract_mod (flea_mpi_t* p_result, const flea_mpi_t* p_a, const flea_mpi_t* p_b, const flea_mpi_t* p_mod, flea_mpi_t* p_workspace_mod_size)
{
  FLEA_THR_BEG_FUNC();

  FLEA_CCALL(THR_flea_mpi_t__subtract(p_workspace_mod_size, p_a, p_b));
  if(p_workspace_mod_size->m_sign < 0)
  {
    // result contains absolute value of what is negative to be reduced by p

    FLEA_CCALL(THR_flea_mpi_t__subtract_ignore_sign(p_result, p_mod, p_workspace_mod_size));
  }
  else if(0 < flea_mpi_t__compare_absolute(p_workspace_mod_size, p_mod))
  {
    FLEA_CCALL(THR_flea_mpi_t__subtract(p_result, p_workspace_mod_size, p_mod));
  }
  else
  {
    FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(p_result, p_workspace_mod_size));
  }
  p_result->m_sign = +1;
  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_mpi_t__add_ignore_sign (flea_mpi_t* p_result, const flea_mpi_t* p_a, const flea_mpi_t * p_b)
{
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(p_result, p_a));
  FLEA_CCALL(THR_flea_mpi_t__add_in_place_ignore_sign(p_result, p_b));
  FLEA_THR_FIN_SEC_empty();
}
flea_err_t THR_flea_mpi_t__add_in_place_ignore_sign (flea_mpi_t* p_in_out, const flea_mpi_t * p_b)
{

  flea_uword_t carry = 0;
  flea_mpi_ulen_t i;

  FLEA_THR_BEG_FUNC();
  if(p_in_out->m_nb_alloc_words < p_b->m_nb_used_words)
  {
    FLEA_THROW("error: addition result mpi too small to hold result value", FLEA_ERR_BUFF_TOO_SMALL);
  }
  // prepare result for expansion
  memset(&p_in_out->m_words[p_in_out->m_nb_used_words], 0, sizeof(p_in_out->m_words[0]) * (p_in_out->m_nb_alloc_words - p_in_out->m_nb_used_words));
  // from here on we can process the words of b
  for(i = 0; i < p_b->m_nb_used_words; i++)
  {
    flea_dbl_uword_t carry_res;
    carry_res =  ((flea_dbl_uword_t)p_in_out->m_words[i]) +   p_b->m_words[i] + carry;

    p_in_out->m_words[i] = ((flea_uword_t)carry_res);

    carry = carry_res >> (sizeof(flea_uword_t) * 8);

  }
  // handle remaining borrow (because a is not smaller than b, there must be
  // another word in a if there is a borrow pending after processing the highest word of b)
  while(carry) // maximally two iterations
  {
    flea_uword_t orig_word = 0;
    flea_dbl_uword_t carry_res;
    if(i >= p_in_out->m_nb_used_words)
    {
      if(i >= p_in_out->m_nb_alloc_words)
      {
        FLEA_THROW("addition result too large", FLEA_ERR_BUFF_TOO_SMALL);
      }
    }
    else
    {
      orig_word = p_in_out->m_words[i];
    }
    carry_res =  ((flea_dbl_uword_t)orig_word) + carry;
    p_in_out->m_words[i] = ((flea_uword_t)carry_res);

    carry = carry_res >> (sizeof(flea_uword_t) * 8);
    i++;
  }
  flea_mpi_t__set_used_words(p_in_out);
  FLEA_THR_FIN_SEC();
}

// ws must have the same size allocated as in_out uses
flea_err_t THR_flea_mpi_t__add_in_place (flea_mpi_t* p_in_out, const flea_mpi_t * p_b, flea_mpi_t* p_ws)
{
  FLEA_THR_BEG_FUNC();
  if(p_in_out->m_sign == p_b->m_sign)
  {
    FLEA_CCALL(THR_flea_mpi_t__add_in_place_ignore_sign(p_in_out, p_b));
    FLEA_THR_RETURN();
  }
  if(0 < flea_mpi_t__compare_absolute(p_b, p_in_out))
  {
    // caculate -(b - a)
    flea_s8_t old_sign = p_in_out->m_sign;
    FLEA_CCALL(THR_flea_mpi_t__subtract_ignore_sign(p_ws, p_b, p_in_out));
    FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(p_in_out, p_ws));
    p_in_out->m_sign = old_sign * -1;
  }
  else
  {
    // calculate a - b
    flea_s8_t old_sign = p_in_out->m_sign;
    FLEA_CCALL(THR_flea_mpi_t__subtract_ignore_sign(p_ws, p_in_out, p_b));
    FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(p_in_out, p_ws));
    p_in_out->m_sign = old_sign;
  }
  if(flea_mpi_t__is_zero(p_in_out))
  {
    p_in_out->m_sign = +1;
  }
  FLEA_THR_FIN_SEC_empty();
}
void flea_mpi_t__shift_right (flea_mpi_t * p_mpi, flea_al_u16_t shift)
{
  flea_mpi_slen_t i;
  flea_uword_t carry = 0;
  flea_al_u8_t shift_in_word = shift % FLEA_WORD_BIT_SIZE;
  flea_mpi_ulen_t shift_words = shift / FLEA_WORD_BIT_SIZE;

  if(shift_words > p_mpi->m_nb_used_words)
  {
    flea_mpi_t__set_to_word_value(p_mpi, 0);
    return;
  }
  memmove(&p_mpi->m_words[0], &p_mpi->m_words[shift_words], shift_words * sizeof(flea_uword_t));
  p_mpi->m_nb_used_words -= shift_words;

  flea_al_u8_t shift_left = FLEA_WORD_BIT_SIZE - shift_in_word;
  flea_uword_t low_mask = (1 << shift_in_word) - 1;
  for(i = p_mpi->m_nb_used_words - 1; i >= 0; i--)
  {
    flea_uword_t this_word = p_mpi->m_words[i];
    flea_uword_t new_carry = this_word & low_mask; // mask in the low part
    p_mpi->m_words[i] = (carry << shift_left ) | (this_word >> shift_in_word);
    carry = new_carry;
  }
  // check whether the leading word became unpopulated:
  if(p_mpi->m_nb_used_words && p_mpi->m_words[p_mpi->m_nb_used_words - 1] == 0)
  {
    p_mpi->m_nb_used_words -= 1;
  }
}

flea_mpi_ulen_t flea_mpi_t__nb_trailing_zero_bits (flea_mpi_t* p_mpi)
{
  // implementation optimized for integers appearing as random
  flea_mpi_ulen_t i, result = 0;

  for(i = 0; i < p_mpi->m_nb_used_words; i++)
  {
    flea_mpi_ulen_t j;
    flea_uword_t word = p_mpi->m_words[i];
    for(j = 0; j < FLEA_WORD_BIT_SIZE; j++)
    {
      if((1 << j) & word)
      {
        return result + j;
      }
    }
    result += FLEA_WORD_BIT_SIZE;
  }
  return 0;  // the integer is in fact zero
}

void flea_mpi_t__set_to_word_value (flea_mpi_t* p_result, flea_uword_t w)
{
  p_result->m_nb_used_words = 1;
  p_result->m_words[0] = w;
}

flea_bool_t flea_mpi_t__is_zero (const flea_mpi_t* p_mpi)
{
  flea_mpi_ulen_t i = p_mpi->m_nb_used_words;

  while(i > 0)
  {
    if(p_mpi->m_words[--i] != 0)
    {
      return FLEA_FALSE;
    }
  }
  return FLEA_TRUE;
}

// shift left mpi by less than the word size (i.e. in general 0-7 is allowed as
// shift value)
flea_err_t THR_flea_mpi_t__shift_left_small (flea_mpi_t* p_mpi, flea_al_u16_t shift)
{
  flea_mpi_ulen_t i;
  flea_uword_t carry = 0;

  FLEA_THR_BEG_FUNC();
  if(shift > 7)
  {
    FLEA_THROW("'small' left shift by more than 7 bits", FLEA_ERR_INV_ARG);
  }



  for(i = 0; i < p_mpi->m_nb_used_words; i++)
  {
    flea_dbl_uword_t shifted = ((flea_dbl_uword_t)p_mpi->m_words[i] << shift);
    p_mpi->m_words[i] = shifted | carry;
    carry = shifted >> (sizeof(flea_uword_t) * 8);
  }
  // place the newly populated word
  if(carry != 0)
  {
    if(!(p_mpi->m_nb_alloc_words > p_mpi->m_nb_used_words))
    {
      FLEA_THROW("shift target mpi doesn't have enough allocated words", FLEA_ERR_BUFF_TOO_SMALL);
    }
    p_mpi->m_nb_used_words += 1;
    p_mpi->m_words[i] = carry;
  }
  FLEA_THR_FIN_SEC_empty();
}

flea_al_s8_t flea_mpi_t__compare_with_uword (const flea_mpi_t* p_mpi, flea_uword_t w)
{
  if(p_mpi->m_sign < 0)
  {
    return -1;
  }
  if(p_mpi->m_nb_used_words > 1)
  {
    return 1;
  }
  if(p_mpi->m_words[0] > w)
  {
    return 1;
  }
  if(p_mpi->m_words[0] < w)
  {
    return -1;
  }
  return 0;
}

flea_err_t THR_flea_mpi_t__invert_odd_mod (flea_mpi_t* p_result, const flea_mpi_t* p_mpi, const flea_mpi_t* p_mod, flea_mpi_t ws_mod_size[4] )
{
  flea_mpi_t *u = &ws_mod_size[0];
  flea_mpi_t *v = &ws_mod_size[1];
  flea_mpi_t *B = &ws_mod_size[2];
  flea_mpi_t *D = p_result;
  flea_mpi_t *ws = &ws_mod_size[3];

  FLEA_THR_BEG_FUNC();
  if(flea_mpi_t__is_zero(p_mpi))
  {
    FLEA_THROW("attempt to invert 0", FLEA_ERR_INV_ARG);
  }
  FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(u, p_mod));
  FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(v, p_mpi));
  flea_mpi_t__set_to_word_value(B, 0);
  flea_mpi_t__set_to_word_value(D, 1);


  while(!flea_mpi_t__is_zero(u))
  {
    flea_al_u16_t i;
    flea_mpi_ulen_t trailing_zeroes = flea_mpi_t__nb_trailing_zero_bits(u);
    flea_mpi_t__shift_right(u, trailing_zeroes);
    for(i = 0; i < trailing_zeroes; i++)
    {
      if(flea_mpi_t__get_bit(B, 0)) // if odd
      {
        FLEA_CCALL(THR_flea_mpi_t__subtract(ws, B, p_mod));
        FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(B, ws));
      }
      flea_mpi_t__shift_right(B, 1);
    }
    trailing_zeroes = flea_mpi_t__nb_trailing_zero_bits(v);
    flea_mpi_t__shift_right(v, trailing_zeroes);

    for(i = 0; i < trailing_zeroes; i++)
    {
      if(flea_mpi_t__get_bit(D, 0)) // if odd
      {
        FLEA_CCALL(THR_flea_mpi_t__subtract(ws, D, p_mod));
        FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(D, ws));
      }
      flea_mpi_t__shift_right(D, 1);

    }


    if(0 <= flea_mpi_t__compare(u, v)) // if u >= v
    {
      FLEA_CCALL(THR_flea_mpi_t__subtract(ws, u, v));
      FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(u, ws));
      FLEA_CCALL(THR_flea_mpi_t__subtract(ws, B, D));
      FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(B, ws));
    }
    else
    {
      FLEA_CCALL(THR_flea_mpi_t__subtract(ws, v, u));
      FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(v, ws));
      FLEA_CCALL(THR_flea_mpi_t__subtract(ws, D, B));
      FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(D, ws));

    }

  }
  if(flea_mpi_t__compare_with_uword(v, 1))
  {
    flea_mpi_t__set_to_word_value(p_result, 0);
    FLEA_THR_RETURN();
  }
  while(0 > flea_mpi_t__compare_with_uword(D, 0))
  {
    FLEA_CCALL(THR_flea_mpi_t__add_in_place(D, p_mod, ws));
  }
  // absolute comparison is fine after making D positive
  while(0 <= flea_mpi_t__compare_absolute(D, p_mod))
  {
    FLEA_CCALL(THR_flea_mpi_t__subtract_ignore_sign(ws, D, p_mod));
    FLEA_CCALL(THR_flea_mpi_t__copy_no_realloc(D, ws));
  }

  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_mpi_t__random_integer (flea_mpi_t* p_result, const flea_mpi_t* p_limit)
{
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_mpi_t__random_integer_no_flush(p_result, p_limit));
  flea_rng__flush();
  FLEA_THR_FIN_SEC(
    );
}
flea_err_t THR_flea_mpi_t__random_integer_no_flush (flea_mpi_t* p_result, const flea_mpi_t* p_limit)
{

  flea_u16_t byte_size, bit_size, word_size;

  FLEA_THR_BEG_FUNC();
  // create as many bytes as those in p_limit
  bit_size = flea_mpi_t__get_bit_size(p_limit);
  byte_size = FLEA_CEIL_BYTE_LEN_FROM_BIT_LEN(bit_size);
  word_size = FLEA_CEIL_WORD_LEN_FROM_BYTE_LEN(byte_size);
  if(word_size > p_result->m_nb_alloc_words)
  {
    FLEA_THROW("random integer: target memory too small", FLEA_ERR_INV_ARG);
  }
  bit_size %= FLEA_BITS_PER_WORD;
  p_result->m_nb_used_words = word_size;
  do
  {
    flea_rng__randomize_no_flush((flea_u8_t*)p_result->m_words, word_size * sizeof(p_result->m_words[0]));
    // mask out the excess bits in the highest word
    if(bit_size)
    {
      p_result->m_words[p_result->m_nb_used_words - 1] &= FLEA_UWORD_MAX >> (FLEA_BITS_PER_WORD - bit_size);
    }
    flea_mpi_t__set_used_words(p_result);
  }
  while(0 <= flea_mpi_t__compare_absolute(p_result, p_limit));
  FLEA_THR_FIN_SEC_empty();
}
