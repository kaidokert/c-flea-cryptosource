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
#include "flea/hash.h"
#include "self_test.h"
#include "flea/error_handling.h"
#include "flea/alloc.h"
#include "flea/ctr_mode_prng.h"
#include "flea/algo_config.h"
#include <string.h>

static flea_err_t THR_flea_test_ctr_mode_prng_init_dtor ()
{
  FLEA_DECL_OBJ(prng_ctx__t, flea_ctr_mode_prng_t);
  flea_ctr_mode_prng_t prng_ctx2__t;
  FLEA_THR_BEG_FUNC();
  flea_ctr_mode_prng_t__INIT(&prng_ctx2__t);

  FLEA_THR_FIN_SEC(
    flea_ctr_mode_prng_t__dtor(&prng_ctx__t);
    flea_ctr_mode_prng_t__dtor(&prng_ctx2__t);
    );
}

flea_err_t THR_flea_test_ctr_mode_prng ()
{
  FLEA_DECL_BUF(rnd__bu8, flea_u8_t, 17);
  FLEA_DECL_OBJ(prng_ctx__t, flea_ctr_mode_prng_t);
  flea_u8_t seed__au8[] = { 0xd6, 0x93, 0x35, 0xb9, 0x33, 0x25, 0x19, 0x2e,  0x51, 0x6a, 0x91, 0x2e, 0x6d, 0x19, 0xa1, 0x5c,  0xb5, 0x1c, 0x6e, 0xd5, 0xc1, 0x52, 0x43, 0xe7,  0xa7, 0xfd, 0x65, 0x3c };
  FLEA_THR_BEG_FUNC();
  FLEA_ALLOC_BUF(rnd__bu8, 17);

  FLEA_CCALL(THR_flea_ctr_mode_prng_t__ctor(&prng_ctx__t, NULL, 0));
  FLEA_CCALL(THR_flea_ctr_mode_prng_t__reseed(&prng_ctx__t, seed__au8, sizeof(seed__au8)));

  FLEA_CCALL(THR_flea_ctr_mode_prng_t__reseed(&prng_ctx__t, seed__au8, 1));
  flea_ctr_mode_prng_t__randomize_no_flush(&prng_ctx__t, rnd__bu8, 17);
  flea_ctr_mode_prng_t__randomize(&prng_ctx__t, rnd__bu8, 17);
  FLEA_CCALL(THR_flea_ctr_mode_prng_t__reseed(&prng_ctx__t, rnd__bu8, 17));

  FLEA_CCALL(THR_flea_test_ctr_mode_prng_init_dtor());

  FLEA_THR_FIN_SEC(
    flea_ctr_mode_prng_t__dtor(&prng_ctx__t);
    FLEA_FREE_BUF_FINAL(rnd__bu8);
    );
}
