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


#include "internal/common/build_config.h"
#include "flea/rng.h"
#include "internal/common/rng_int.h"
#include "flea/ctr_mode_prng.h"
#include "flea/bin_utils.h"
#include "flea/util.h"
#include "flea/alloc.h"
#include "flea/error_handling.h"
#include "flea/hash.h"
#include "string.h"

static flea_ctr_mode_prng_t gl_rng_ctx__t;

void flea_rng__randomize_volatile (flea_u8_t* mem__pu8, flea_dtl_t mem_len__dtl)
{
  flea_ctr_mode_prng_t__randomize(&gl_rng_ctx__t, mem__pu8, mem_len__dtl);
}

void flea_rng__deinit ()
{
  flea_ctr_mode_prng_t__dtor(&gl_rng_ctx__t);
}

flea_err_t THR_flea_rng__init ()
{
  FLEA_DECL_BUF(loaded_state__bu8, flea_u8_t, FLEA_AES256_KEY_BYTE_LENGTH);
  FLEA_THR_BEG_FUNC();
  flea_ctr_mode_prng_t__INIT(&gl_rng_ctx__t);
  FLEA_CCALL(THR_flea_ctr_mode_prng_t__ctor(&gl_rng_ctx__t, NULL, 0));

  FLEA_ALLOC_BUF(loaded_state__bu8, FLEA_AES256_KEY_BYTE_LENGTH);
  // load the state from the flash
  FLEA_CCALL(THR_flea_user__rng__load_prng_state(loaded_state__bu8, FLEA_AES256_KEY_BYTE_LENGTH));
  // update persistent key
  FLEA_CCALL(THR_flea_rng__reseed_persistent(loaded_state__bu8, FLEA_AES256_KEY_BYTE_LENGTH));

  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(loaded_state__bu8);
    );
}

flea_err_t THR_flea_rng__reseed_persistent (const flea_u8_t* seed__pcu8, flea_dtl_t seed_len__dtl)
{
  FLEA_DECL_BUF(new_persistent_key__bu8, flea_u8_t, FLEA_AES256_KEY_BYTE_LENGTH);
  FLEA_DECL_BUF(compare__bu8, flea_u8_t, FLEA_AES256_KEY_BYTE_LENGTH);
  FLEA_THR_BEG_FUNC();
  FLEA_ALLOC_BUF(new_persistent_key__bu8, FLEA_AES256_KEY_BYTE_LENGTH);
  FLEA_ALLOC_BUF(compare__bu8, FLEA_AES256_KEY_BYTE_LENGTH);
  FLEA_CCALL(THR_flea_ctr_mode_prng_t__reseed(&gl_rng_ctx__t, seed__pcu8, seed_len__dtl));
  flea_ctr_mode_prng_t__randomize(&gl_rng_ctx__t, new_persistent_key__bu8, FLEA_AES256_KEY_BYTE_LENGTH);
  FLEA_CCALL(THR_flea_user__rng__save_prng_state(new_persistent_key__bu8, FLEA_AES256_KEY_BYTE_LENGTH));
  FLEA_CCALL(THR_flea_user__rng__load_prng_state(compare__bu8, FLEA_AES256_KEY_BYTE_LENGTH));
  if(memcmp(new_persistent_key__bu8, compare__bu8, FLEA_AES256_KEY_BYTE_LENGTH))
  {
    FLEA_THROW("error saving PRNG state in NVM", FLEA_ERR_PRNG_NVM_WRITE_ERROR);
  }
  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_SECRET_ARR(new_persistent_key__bu8, FLEA_AES256_KEY_BYTE_LENGTH);
    FLEA_FREE_BUF_SECRET_ARR(compare__bu8, FLEA_AES256_KEY_BYTE_LENGTH);
    );
}

flea_err_t THR_flea_rng__reseed_volatile (const flea_u8_t* seed__pcu8, flea_dtl_t seed_len__dtl)
{
  return THR_flea_ctr_mode_prng_t__reseed(&gl_rng_ctx__t, seed__pcu8, seed_len__dtl);
}

void flea_rng__flush ()
{
  flea_ctr_mode_prng_t__flush(&gl_rng_ctx__t);
}

void flea_rng__randomize_no_flush (flea_u8_t* mem__pu8, flea_dtl_t mem_len__dtl)
{
  flea_ctr_mode_prng_t__randomize_no_flush(&gl_rng_ctx__t, mem__pu8, mem_len__dtl);
}

void flea_rng__randomize (flea_u8_t* mem__pu8, flea_dtl_t mem_len__dtl)
{
  flea_ctr_mode_prng_t__randomize_no_flush(&gl_rng_ctx__t, mem__pu8, mem_len__dtl);
  flea_rng__flush();
}

