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


#include "flea/hash.h"
#include "flea/error_handling.h"
#include "flea/error.h"
#include <string.h>
#include <stdio.h>

flea_err_t THR_flea_test_davies_meyer_aes128_hash_hash ()
{
#ifndef FLEA_HAVE_DAVIES_MEYER_HASH
  return FLEA_ERR_FINE;
#else // #ifndef FLEA_HAVE_DAVIES_MEYER_HASH
  flea_hash_ctx_t ctx;
  flea_u8_t digest[16];
  const flea_u8_t exp_digest_empty_message[] = {
    0x0e, 0xdd, 0x33, 0xd3, 0xc6, 0x21, 0xe5, 0x46, 0x45, 0x5b, 0xd8, 0xba, 0x14, 0x18, 0xbe, 0xc8
  };

  const flea_u8_t message2[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
  const flea_u8_t exp_digest_2[] = {
    0x71, 0x09, 0xAD, 0xAF, 0xA6, 0xC7, 0x27, 0xD5, 0x43, 0xC6, 0xA4, 0xBB, 0x33, 0x2B, 0xE8, 0x7D
  };
  const flea_u8_t exp_digest_2_shortened[] = {
    0x71, 0x09, 0xAD, 0xAF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  };

  FLEA_THR_BEG_FUNC();
  flea_hash_ctx_t__INIT(&ctx);

  FLEA_CCALL(THR_flea_hash_ctx_t__ctor(&ctx, flea_davies_meyer_aes128));

  FLEA_CCALL(THR_flea_hash_ctx_t__final(&ctx, digest));

  if(memcmp(digest, exp_digest_empty_message, sizeof(digest)))
  {
    FLEA_THROW("error with davies_meyer_aes128_hash_hash", FLEA_ERR_FAILED_TEST);
  }

  flea_hash_ctx_t__dtor(&ctx);

  FLEA_CCALL(THR_flea_hash_ctx_t__ctor(&ctx, flea_davies_meyer_aes128));

  FLEA_CCALL(THR_flea_hash_ctx_t__update(&ctx, message2, sizeof(message2)));

  FLEA_CCALL(THR_flea_hash_ctx_t__final(&ctx, digest));

  if(memcmp(digest, exp_digest_2, sizeof(digest)))
  {
    FLEA_THROW("error with davies_meyer_aes128_hash_hash", FLEA_ERR_FAILED_TEST);
  }

  flea_hash_ctx_t__dtor(&ctx);

  FLEA_CCALL(THR_flea_hash_ctx_t__ctor(&ctx, flea_davies_meyer_aes128));

  FLEA_CCALL(THR_flea_hash_ctx_t__update(&ctx, message2, 2));
  FLEA_CCALL(THR_flea_hash_ctx_t__update(&ctx, &message2[2], sizeof(message2) - 2));

  FLEA_CCALL(THR_flea_hash_ctx_t__final(&ctx, digest));

  if(memcmp(digest, exp_digest_2, sizeof(digest)))
  {
    FLEA_THROW("error with davies_meyer_aes128_hash_hash (update)", FLEA_ERR_FAILED_TEST);
  }


  FLEA_CCALL(THR_flea_compute_hash(flea_davies_meyer_aes128, message2, sizeof(message2), digest, 16));
  if(memcmp(digest, exp_digest_2, sizeof(digest)))
  {
    FLEA_THROW("error with davies_meyer_aes128_hash_hash ('compute hash' function full length)", FLEA_ERR_FAILED_TEST);
  }

  // compute-hash function with shortening of output
  memset(digest, 0, sizeof(digest));
  FLEA_CCALL(THR_flea_compute_hash(flea_davies_meyer_aes128, message2, sizeof(message2), digest, 4));
  if(memcmp(digest, exp_digest_2_shortened, sizeof(digest)))
  {
    FLEA_THROW("error with davies_meyer_aes128_hash_hash ('compute hash' function shortened)", FLEA_ERR_FAILED_TEST);
  }

  if(FLEA_ERR_INV_ARG != THR_flea_compute_hash(flea_davies_meyer_aes128, message2, sizeof(message2), digest, 17))
  {
    FLEA_THROW("did not refuse request for digest exceeding natural digest length", FLEA_ERR_FAILED_TEST);
  }
  FLEA_THR_FIN_SEC(
    flea_hash_ctx_t__dtor(&ctx);
    );


#endif // #else of #ifdef FLEA_HAVE_DAVIES_MEYER_HASH
}

