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


#include "flea/types.h"
#include "internal/common/block_cipher/aes.h"
#include "flea/error.h"
#include "flea/error_handling.h"
#include "flea/alloc.h"
static flea_u8_t gl_prng_state__au8[FLEA_AES256_KEY_BYTE_LENGTH] = { 0 };

flea_err_t THR_flea_user__rng__load_prng_state (flea_u8_t* result__bu8, flea_al_u8_t result_len__alu8)
{
  FLEA_THR_BEG_FUNC();
  if(result_len__alu8 != sizeof(gl_prng_state__au8))
  {
    FLEA_THROW("wrong length of PRNG state", FLEA_ERR_INT_ERR);
  }
  // must be implemented by user: load the last saved PRNG state from the NVM.
  // The reserved area must have size sizeof(gl_prng_state__au8).
  #error for the security of your implementation, you have to implement this function for loading of the PRNG state
  // comment in the following line FOR TESTING PURPOSES ONLY, this leads to completely INSECURE
  // behaviour of random number generation:
  // memcpy(result__bu8, gl_prng_state__au8, sizeof(gl_prng_state__au8));
  FLEA_THR_FIN_SEC_empty();
}

flea_err_t THR_flea_user__rng__save_prng_state (const flea_u8_t* state__pcu8, flea_al_u8_t state_len__alu8)
{
  FLEA_THR_BEG_FUNC();
  if(state_len__alu8 != sizeof(gl_prng_state__au8))
  {
    FLEA_THROW("wrong length of PRNG state", FLEA_ERR_INT_ERR);
  }
  // must be implemented by user: store the current PRNG state in NVM.
  #error for the security of your implementation, you have to implement this function for saving of the PRNG state
  // comment in the following line FOR TESTING PURPOSES ONLY, this leads to completely INSECURE
  // behaviour of random number generation:
  // memcpy(gl_prng_state__au8, state__pcu8, state_len__alu8);  // comment in for testing purposes only
  FLEA_THR_FIN_SEC_empty();
}
