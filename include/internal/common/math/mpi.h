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


#ifndef _flea_mpi__H_
#define _flea_mpi__H_

#include "flea/types.h"

typedef struct
{
  flea_uword_t* m_words;
  flea_mpi_ulen_t m_nb_alloc_words;
  flea_mpi_ulen_t m_nb_used_words;
  flea_s8_t m_sign;
} flea_mpi_t;


#define FLEA_WORD_BIT_SIZE  (sizeof(flea_uword_t) * 8)

typedef struct
{
  flea_hlf_uword_t* vn;
  flea_mpi_ulen_t vn_len;
  flea_hlf_uword_t* un;
  flea_mpi_ulen_t un_len;
} flea_mpi_div_ctx_t;

typedef struct
{
  const flea_mpi_t* p_mod;
  /**
   * workspace, must have one more word allocated than mod
   */
  flea_mpi_t* p_ws;
  flea_uword_t mod_prime;
} flea_montgm_mul_ctx_t;
#define FLEA_MPI_DIV_UN_HLFW_LEN_FROM_DIVIDENT_W_LEN(__divident_word_len) \
  ((2 * (__divident_word_len) + 1) )

#define FLEA_MPI_DIV_VN_HLFW_LEN_FROM_DIVISOR_W_LEN(__divisor_word_len) \
  (2 * (__divisor_word_len))




flea_uword_t flea_montgomery_compute_n_prime(flea_uword_t lowest_word_of_n);

void flea_mpi_t__init(flea_mpi_t* p_result, flea_uword_t* word_array, flea_mpi_ulen_t nb_words);

void flea_mpi_t__set_to_word_value(flea_mpi_t* p_result, flea_uword_t w);

flea_err_t THR_flea_mpi_t__decode(flea_mpi_t* p_result, const flea_u8_t* encoded, flea_mpi_ulen_t encoded_len);

flea_err_t THR_flea_mpi_t__encode(flea_u8_t * p_result, flea_al_u16_t result_len, const flea_mpi_t * p_mpi);

flea_err_t THR_flea_mpi_t__montgm_mul(flea_mpi_t* p_result, const flea_mpi_t* p_a, const flea_mpi_t* p_b, flea_montgm_mul_ctx_t* p_ctx);

flea_err_t THR_flea_mpi_t__divide(flea_mpi_t* p_quotient, flea_mpi_t* p_remainder, const flea_mpi_t* p_divident, const flea_mpi_t* p_divisor, flea_mpi_div_ctx_t* p_div_ctx);

flea_al_s8_t flea_mpi_t__compare_absolute(const flea_mpi_t* p_a, const flea_mpi_t* p_b);

flea_al_s8_t flea_mpi_t__compare(const flea_mpi_t* p_a, const flea_mpi_t* p_b);

flea_al_s8_t flea_mpi_t__compare_with_uword(const flea_mpi_t* p_mpi, flea_uword_t w);

flea_bool_t flea_mpi_t__equal(const flea_mpi_t* p_a, const flea_mpi_t* p_b);

flea_err_t THR_flea_mpi_t__mul(flea_mpi_t* p_result, const flea_mpi_t* p_a, const flea_mpi_t* p_b);

/*
 * p_result must be different from p_a and p_b
 */
flea_err_t THR_flea_mpi_t__subtract(flea_mpi_t* p_result, const flea_mpi_t * p_a, const flea_mpi_t* p_b);

/**
 *  both a and b must be between 0 and p-1
 * p_result is allowed to be equal to  p_a or p_b
 */
flea_err_t THR_flea_mpi_t__subtract_mod(flea_mpi_t* p_result, const flea_mpi_t* p_a, const flea_mpi_t* p_b, const flea_mpi_t* p_mod, flea_mpi_t* p_workspace_mod_size);

flea_err_t THR_flea_mpi_t__add_in_place_ignore_sign(flea_mpi_t* p_in_out, const flea_mpi_t * p_b);

flea_err_t THR_flea_mpi_t__add_ignore_sign(flea_mpi_t* p_result, const flea_mpi_t* p_a, const flea_mpi_t * p_b);

flea_err_t THR_flea_mpi_t__add_in_place(flea_mpi_t* p_in_out, const flea_mpi_t * p_b, flea_mpi_t* p_ws);

flea_err_t THR_flea_mpi_square(flea_mpi_t* p_result, const flea_mpi_t* p_a);

flea_u16_t flea_mpi_t__get_bit_size(const flea_mpi_t* p_mpi);

flea_u16_t flea_mpi_t__get_byte_size(const flea_mpi_t* p_mpi);

flea_u8_t flea_mpi_t__get_bit(const flea_mpi_t* p_mpi, flea_u16_t bit_pos);

flea_err_t THR_flea_mpi_t__copy_no_realloc(flea_mpi_t* p_target, const flea_mpi_t* p_source);

flea_err_t THR_flea_mpi_t__mod_exp_window(flea_mpi_t* p_result, flea_mpi_t* p_exp, flea_mpi_t* p_base, flea_mpi_t* p_mod, flea_mpi_t* p_workspace_double_plus_one_sized, flea_mpi_div_ctx_t* p_div_ctx,  flea_mpi_t* p_ws_trf_base, flea_mpi_t* p_quotient_ws, flea_al_u8_t window_size);

flea_mpi_ulen_t flea_mpi_t__nb_trailing_zero_bits(flea_mpi_t* p_mpi);

void flea_mpi_t__shift_right(flea_mpi_t * p_mpi, flea_al_u16_t shift);

flea_err_t THR_flea_mpi_t__set_pow_2(flea_mpi_t* p_result, flea_al_u16_t exp);

flea_bool_t flea_mpi_t__is_zero(const flea_mpi_t* p_mpi);

flea_err_t THR_flea_mpi_t__shift_left_small(flea_mpi_t* p_mpi, flea_al_u16_t shift);

flea_err_t THR_flea_mpi_t__invert_odd_mod(flea_mpi_t * p_result, const flea_mpi_t * p_mpi, const flea_mpi_t * p_mod, flea_mpi_t ws_mod_size[4] );

flea_err_t THR_flea_mpi_t__random_integer(flea_mpi_t* p_result, const flea_mpi_t* p_limit);

flea_err_t THR_flea_mpi_t__random_integer_no_flush(flea_mpi_t* p_result, const flea_mpi_t* p_limit);

flea_err_t THR_flea_mpi_t__quick_reduce_greater_zero(flea_mpi_t* p_in_out, const flea_mpi_t* p_mod, flea_mpi_t* p_ws);

flea_err_t THR_flea_mpi_t__quick_reduce_smaller_zero(flea_mpi_t* p_in_out, const flea_mpi_t* p_mod, flea_mpi_t* p_ws);

void flea_mpi_t__print(const flea_mpi_t* p_mpi);

#endif /* h-guard */
