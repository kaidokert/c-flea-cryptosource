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
#include "internal/common/math/curve_gfp.h"
#include "flea/ec_gfp_dom_par.h"
#include "flea/error.h"
#include "flea/error_handling.h"

#ifdef FLEA_HAVE_ECC

#ifdef __cplusplus
extern "C" {
#endif

flea_err_t THR_flea_curve_gfp_t__init_dp_array (flea_curve_gfp_t* p_curve, const flea_u8_t* enc_dp, flea_uword_t* memory, flea_al_u16_t memory_word_len)
{
  FLEA_THR_BEG_FUNC();
  flea_al_u8_t enc_field_len = flea_ec_dom_par__get_elem_len(enc_dp, flea_dp__p);
  FLEA_CCALL(THR_flea_curve_gfp_t__init(
               p_curve,
               flea_ec_dom_par__get_ptr_to_elem(enc_dp, flea_dp__a), 
               enc_field_len,
               flea_ec_dom_par__get_ptr_to_elem(enc_dp, flea_dp__b),
               enc_field_len,
               flea_ec_dom_par__get_ptr_to_elem(enc_dp, flea_dp__p),
               enc_field_len,
               memory,
               memory_word_len));


  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_curve_gfp_t__init (flea_curve_gfp_t* p_curve, const flea_u8_t* a_enc, flea_al_u16_t a_enc_len, const flea_u8_t* b_enc, flea_al_u16_t b_enc_len, const flea_u8_t* p_enc, flea_al_u16_t p_enc_len, flea_uword_t* memory, flea_al_u16_t memory_word_len)
{
  flea_mpi_ulen_t p_word_len = (p_enc_len + sizeof(flea_uword_t) - 1) / sizeof(flea_uword_t);
  flea_mpi_ulen_t a_word_len = (a_enc_len + sizeof(flea_uword_t) - 1) / sizeof(flea_uword_t);
  flea_mpi_ulen_t b_word_len = (b_enc_len + sizeof(flea_uword_t) - 1) / sizeof(flea_uword_t);

  FLEA_THR_BEG_FUNC();
  if(memory_word_len < p_word_len + a_word_len + b_word_len)
  {
    FLEA_THROW("curve gfp ctor called with too small memory for mpi storage", FLEA_ERR_BUFF_TOO_SMALL);
  }

  flea_mpi_t__init(&p_curve->m_a, memory, a_word_len);
  flea_mpi_t__init(&p_curve->m_b, memory + a_word_len, b_word_len);
  flea_mpi_t__init(&p_curve->m_p, memory + a_word_len + b_word_len, p_word_len);


  FLEA_CCALL(THR_flea_mpi_t__decode(&p_curve->m_a, a_enc, a_enc_len));
  FLEA_CCALL(THR_flea_mpi_t__decode(&p_curve->m_b, b_enc, b_enc_len));
  FLEA_CCALL(THR_flea_mpi_t__decode(&p_curve->m_p, p_enc, p_enc_len));

  if((0 <= flea_mpi_t__compare(&p_curve->m_a, &p_curve->m_p)) ||
     (0 <= flea_mpi_t__compare(&p_curve->m_b, &p_curve->m_p)) ||
     !flea_mpi_t__get_bit(&p_curve->m_p, 0))
  {
    FLEA_THROW("invalid EC domain parameters", FLEA_ERR_INV_ARG);
  }
  FLEA_THR_FIN_SEC_empty();
}
#ifdef __cplusplus
}
#endif

#endif // #ifdef FLEA_HAVE_ECC
