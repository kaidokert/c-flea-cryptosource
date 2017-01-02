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


#ifndef _flea_curve_gfp__H_
#define _flea_curve_gfp__H_

#include "internal/common/math/mpi.h"

typedef struct
{
  flea_mpi_t m_a;
  flea_mpi_t m_b;
  flea_mpi_t m_p;

} flea_curve_gfp_t;

flea_err_t THR_flea_curve_gfp_t__init(flea_curve_gfp_t* p_curve, const flea_u8_t* a_enc, flea_al_u16_t a_enc_len, const flea_u8_t* b_enc, flea_al_u16_t b_enc_len, const flea_u8_t* p_enc, flea_al_u16_t p_enc_len, flea_uword_t* memory, flea_al_u16_t memory_word_len);

flea_err_t THR_flea_curve_gfp_t__init_dp_array(flea_curve_gfp_t* p_curve, const flea_u8_t* enc_cp, flea_uword_t* memory, flea_al_u16_t memory_word_len);

#endif /* h-guard */
