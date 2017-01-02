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



#ifndef _flea_pk_api_int__H_
#define _flea_pk_api_int__H_


flea_err_t THR_flea_pk_api__encode_message__emsa1(flea_u8_t* input_output, flea_al_u16_t input_len, flea_al_u16_t* output_len, flea_al_u16_t bit_size);

flea_err_t THR_flea_pk_api__verify_message__pkcs1_v1_5(const flea_u8_t* encoded, flea_al_u16_t encoded_len, const flea_u8_t* digest, flea_al_u16_t digest_len, flea_al_u16_t bit_size, flea_hash_id_t hash_id);

flea_err_t THR_flea_pk_api__encode_message__pkcs1_v1_5_encr(flea_u8_t* input_output__pu8, flea_al_u16_t input_len__alu16, flea_al_u16_t* output_len__palu16, flea_al_u16_t bit_size, flea_hash_id_t hash_id__t);

flea_err_t THR_flea_pk_api__encode_message__pkcs1_v1_5_sign(flea_u8_t* input_output__pu8, flea_al_u16_t input_len__alu16, flea_al_u16_t* output_len__palu16, flea_al_u16_t bit_size, flea_hash_id_t hash_id__t);

flea_err_t THR_flea_pk_api__decode_message__pkcs1_v1_5(const flea_u8_t* encoded__pcu8, flea_al_u16_t encoded_len__alu16, flea_u8_t* output_message__pu8, flea_al_u16_t* output_message_len__palu16, flea_al_u16_t bit_size__alu16);

#endif /* h-guard */
