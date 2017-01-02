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


#ifndef _flea_oaep__H_
#define _flea_oaep__H_

#include "flea/types.h"
#include "flea/hash.h"


flea_err_t THR_flea_pkcs1_mgf1(flea_u8_t* output__pu8, flea_al_u16_t output_len__alu16, const flea_u8_t* seed__pu8, flea_al_u16_t seed_len__alu16, flea_hash_id_t hash_id__t);

flea_err_t THR_flea_pk_api__encode_message__oaep(flea_u8_t* input_output__pu8, flea_al_u16_t input_len__alu16, flea_al_u16_t* output_len__palu16, flea_al_u16_t bit_size__alu16, flea_hash_id_t hash_id__t);

flea_err_t THR_flea_pk_api__decode_message__oaep(flea_u8_t* result__pu8, flea_al_u16_t* result_len__palu16, flea_u8_t* input__pu8, flea_al_u16_t input_len__alu16, flea_al_u16_t bit_size__alu16, flea_hash_id_t hash_id__t);

#endif /* h-guard */
