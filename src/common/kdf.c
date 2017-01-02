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


#include "flea/kdf.h"
#include "flea/error_handling.h"
#include "flea/alloc.h"
#include "flea/bin_utils.h"

flea_err_t THR_flea_kdf_X9_63 (flea_hash_id_t id__t, const flea_u8_t* input__pcu8, flea_al_u16_t input_len__alu16, const flea_u8_t* shared_info__pcu8, flea_al_u16_t shared_info_len__alu16, flea_u8_t* output__pu8, flea_al_u16_t output_len__alu16 )
{
  FLEA_DECL_OBJ(ctx__t, flea_hash_ctx_t);
  flea_u8_t counter__au8[4] = { 0, 0, 0, 1 };
  flea_al_u8_t hash_out_len__alu8;
  flea_al_u16_t nb_full_blocks__alu16, i;
  FLEA_THR_BEG_FUNC();
  FLEA_CCALL(THR_flea_hash_ctx_t__ctor(&ctx__t, id__t));
  hash_out_len__alu8 = flea_hash_ctx_t__get_output_length(&ctx__t);
  nb_full_blocks__alu16 = output_len__alu16 / hash_out_len__alu8;
  for(i = 0; i < nb_full_blocks__alu16; i++)
  {
    FLEA_CCALL(THR_flea_hash_ctx_t__update(&ctx__t, input__pcu8, input_len__alu16));
    FLEA_CCALL(THR_flea_hash_ctx_t__update(&ctx__t, &counter__au8[0], sizeof(counter__au8)));
    FLEA_CCALL(THR_flea_hash_ctx_t__update(&ctx__t, shared_info__pcu8, shared_info_len__alu16));
    FLEA_CCALL(THR_flea_hash_ctx_t__final(&ctx__t, output__pu8));
    output__pu8 += hash_out_len__alu8;
    output_len__alu16 -= hash_out_len__alu8;
    flea_hash_ctx_t__reset(&ctx__t);
    flea__increment_encoded_BE_int(counter__au8, sizeof(counter__au8));
  }
  FLEA_CCALL(THR_flea_hash_ctx_t__update(&ctx__t, input__pcu8, input_len__alu16));
  FLEA_CCALL(THR_flea_hash_ctx_t__update(&ctx__t, &counter__au8[0], sizeof(counter__au8)));
  FLEA_CCALL(THR_flea_hash_ctx_t__update(&ctx__t, shared_info__pcu8, shared_info_len__alu16));
  FLEA_CCALL(THR_flea_hash_ctx_t__final_with_length_limit(&ctx__t, output__pu8, output_len__alu16 ));

  FLEA_THR_FIN_SEC(
    flea_hash_ctx_t__dtor(&ctx__t);
    );
}
