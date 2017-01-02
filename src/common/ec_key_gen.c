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


#include "flea/ec_key_gen.h"
#include "internal/common/default.h"
#include "flea/error_handling.h"
#include <stdlib.h>
#include <string.h>
#include "internal/common/math/mpi.h"
#include "flea/error.h"
#include "flea/alloc.h"
#include "flea/array_util.h"
#include "flea/util.h"
#include "internal/common/math/curve_gfp.h"
#include "flea/ec_gfp_dom_par.h"
#include "flea/ecdsa.h"
#include "internal/common/math/point_gfp.h"
#include "flea/algo_config.h"
#include "internal/common/ecc_int.h"

#ifdef FLEA_HAVE_ECC
flea_err_t THR_flea_generate_ecc_key (flea_u8_t* result_public__p_u8, flea_al_u8_t* result_public_len__p_al_u8, flea_u8_t* result_private__p_u8, flea_al_u8_t* result_private_len__p_al_u8, const flea_u8_t* dp__p_u8)
{
  flea_curve_gfp_t curve;
  flea_point_gfp_t pub_point;
  flea_mpi_t sk_mpi, n;
  flea_al_u8_t private_byte_len__al_u8, order_byte_len__al_u8;

  FLEA_DECL_BUF(pub_point_arr, flea_uword_t, 2 * FLEA_ECC_MAX_MOD_WORD_SIZE + 1);
  FLEA_DECL_BUF(sk_mpi_arr, flea_uword_t, FLEA_ECC_MAX_ORDER_WORD_SIZE);
  FLEA_DECL_BUF(order_word_arr, flea_uword_t, FLEA_ECC_MAX_ORDER_WORD_SIZE);
  FLEA_DECL_BUF(curve_word_arr, flea_uword_t, 3 * FLEA_ECC_MAX_MOD_WORD_SIZE);

  flea_al_u8_t prime_byte_len, prime_word_len__al_u8, curve_word_arr_word_len, pub_point_word_arr_len, order_word_len;

  FLEA_THR_BEG_FUNC();
  prime_byte_len = flea_ec_dom_par__get_elem_len(dp__p_u8, flea_dp__p);
  order_byte_len__al_u8 = flea_ec_dom_par__get_elem_len(dp__p_u8, flea_dp__n);
  prime_word_len__al_u8 = FLEA_CEIL_WORD_LEN_FROM_BYTE_LEN(prime_byte_len);
  curve_word_arr_word_len = 3 * prime_word_len__al_u8;
  pub_point_word_arr_len = 2 * prime_word_len__al_u8;
  order_word_len = FLEA_CEIL_WORD_LEN_FROM_BYTE_LEN(order_byte_len__al_u8);

  FLEA_ALLOC_BUF(pub_point_arr, pub_point_word_arr_len);
  FLEA_ALLOC_BUF(sk_mpi_arr, order_word_len);
  FLEA_ALLOC_BUF(curve_word_arr, curve_word_arr_word_len);
  FLEA_ALLOC_BUF(order_word_arr, order_word_len);


  flea_mpi_t__init(&sk_mpi, sk_mpi_arr, order_word_len);
  flea_mpi_t__init(&n, order_word_arr, order_word_len);
  FLEA_CCALL(THR_flea_mpi_t__decode(&n, flea_ec_dom_par__get_ptr_to_elem(dp__p_u8, flea_dp__n), order_byte_len__al_u8));
  FLEA_CCALL(THR_flea_mpi_t__random_integer(&sk_mpi, &n));
  FLEA_CCALL(THR_flea_point_gfp_t__init(&pub_point, flea_ec_dom_par__get_ptr_to_elem(dp__p_u8, flea_dp__Gx), prime_byte_len, flea_ec_dom_par__get_ptr_to_elem(dp__p_u8, flea_dp__Gy), prime_byte_len, pub_point_arr, pub_point_word_arr_len));

  FLEA_CCALL(THR_flea_curve_gfp_t__init_dp_array(&curve, dp__p_u8, curve_word_arr, curve_word_arr_word_len));


  FLEA_CCALL(THR_flea_point_gfp_t__mul(&pub_point, &sk_mpi, &curve));
  FLEA_CCALL(THR_flea_point_gfp_t__encode(result_public__p_u8, result_public_len__p_al_u8, &pub_point, &curve));
  private_byte_len__al_u8 = flea_mpi_t__get_byte_size(&sk_mpi);
  FLEA_CCALL(THR_flea_mpi_t__encode(result_private__p_u8, private_byte_len__al_u8, &sk_mpi ));
  *result_private_len__p_al_u8 = private_byte_len__al_u8;
  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF(pub_point_arr );
    FLEA_FREE_BUF(sk_mpi_arr );
    FLEA_FREE_BUF(order_word_arr );
    FLEA_FREE_BUF(curve_word_arr );
    );
}

#endif // #ifdef FLEA_HAVE_ECC
