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
#include "internal/common/hash/sha1.h"
#include "flea/alloc.h"
#include "flea/util.h"
#include "flea/types.h"
#include "flea/error_handling.h"

#ifdef FLEA_HAVE_SHA1
#define ROL(x, y) ( ((x) << (y)) | ((x) >> (32 - (y))) )
#define ROR(x, y) ( ((x) >> (y)) | ((x) << (32 - (y))) )

#define F0(x, y, z)  ( (x & y) | ((~x) & z) )
#define F1(x, y, z)  (x ^ y ^ z)
#define F2(x, y, z)  ((x & y) | (z & (x | y)))
#define F3(x, y, z)  (x ^ y ^ z)

#ifdef FLEA_USE_SHA1_ROUND_MACRO
#define SHA1_ROUND(F, a, b, c, d, e, k, o) \
  do { \
    e += ROL(a, 5) + F(b, c, d) + W__bu8[i + o] + k; \
    b = ROL(b, 30); \
  } while(0)

#else

typedef flea_u32_t (*F_f)(flea_u32_t x, flea_u32_t y, flea_u32_t z);

flea_u32_t F0_f (flea_u32_t x, flea_u32_t y, flea_u32_t z)
{
  return F0(x, y, z);
}
flea_u32_t F1_f (flea_u32_t x, flea_u32_t y, flea_u32_t z)
{
  return F1(x, y, z);
}
flea_u32_t F2_f (flea_u32_t x, flea_u32_t y, flea_u32_t z)
{
  return F2(x, y, z);
}
flea_u32_t F3_f (flea_u32_t x, flea_u32_t y, flea_u32_t z)
{
  return F3(x, y, z);
}

static void flea_sha1_20_rounds ( flea_u32_t* abcde, flea_u32_t k, flea_u32_t* W, F_f func )
{
  flea_al_u8_t i;
  flea_u32_t a = abcde[0];
  flea_u32_t b = abcde[1];
  flea_u32_t c = abcde[2];
  flea_u32_t d = abcde[3];
  flea_u32_t e = abcde[4];
  flea_u32_t j;

  for(i = 0; i < 20; i++)
  {
    j = ROL(a, 5) + func(b, c, d) + e + W[i] + k;
    e = d;
    d = c;
    c = ROL(b, 30);
    b = a;
    a = j;
  }
  abcde[0] = a;
  abcde[1] = b;
  abcde[2] = c;
  abcde[3] = d;
  abcde[4] = e;
}

#endif


#define FLEA_LOAD_U32_BE(y)       \
  (((flea_u32_t)((&y)[0] ) << 24) | \
   ((flea_u32_t)((&y)[1] ) << 16) | \
   ((flea_u32_t)((&y)[2] ) << 8)  | \
   ((flea_u32_t)((&y)[3] )))
flea_err_t THR_flea_sha1_compression_function (flea_hash_ctx_t* ctx__pt, const flea_u8_t* input__pc_u8)
{
  flea_u32_t i, j;

#ifdef FLEA_USE_SHA1_ROUND_MACRO
  flea_u32_t a, b, c, d, e;
#else
  flea_u32_t abcde[5];
#endif
  flea_u32_t* state__p_u32;
  FLEA_DECL_BUF(W__bu8, flea_u32_t, 80);
  FLEA_THR_BEG_FUNC();
  FLEA_ALLOC_BUF(W__bu8, 80);
  for(i = 0; i < 16; i++)
  {
    W__bu8[i] = FLEA_LOAD_U32_BE(input__pc_u8[i * 4]);
  }
  state__p_u32 = (flea_u32_t*)ctx__pt->hash_state;
#ifdef FLEA_USE_SHA1_ROUND_MACRO
  a = state__p_u32[0];
  b = state__p_u32[1];
  c = state__p_u32[2];
  d = state__p_u32[3];
  e = state__p_u32[4];
#else
  abcde[0] = state__p_u32[0];
  abcde[1] = state__p_u32[1];
  abcde[2] = state__p_u32[2];
  abcde[3] = state__p_u32[3];
  abcde[4] = state__p_u32[4];
#endif

  for(i = 16; i < 80; i++)
  {
    j = W__bu8[i - 3] ^ W__bu8[i - 8] ^ W__bu8[i - 14] ^ W__bu8[i - 16];
    W__bu8[i] = ROL(j, 1);
  }

#ifdef FLEA_USE_SHA1_ROUND_MACRO
  for(i = 0; i < 20; i += 5)
  {
    SHA1_ROUND(F0, a, b, c, d, e, 0x5a827999UL, 0);
    SHA1_ROUND(F0, e, a, b, c, d, 0x5a827999UL, 1);
    SHA1_ROUND(F0, d, e, a, b, c, 0x5a827999UL, 2);
    SHA1_ROUND(F0, c, d, e, a, b, 0x5a827999UL, 3);
    SHA1_ROUND(F0, b, c, d, e, a, 0x5a827999UL, 4);
  }
  for(i = 20; i < 40; i += 5)
  {
    SHA1_ROUND(F1, a, b, c, d, e, 0x6ed9eba1UL, 0);
    SHA1_ROUND(F1, e, a, b, c, d, 0x6ed9eba1UL, 1);
    SHA1_ROUND(F1, d, e, a, b, c, 0x6ed9eba1UL, 2);
    SHA1_ROUND(F1, c, d, e, a, b, 0x6ed9eba1UL, 3);
    SHA1_ROUND(F1, b, c, d, e, a, 0x6ed9eba1UL, 4);
  }
  for(i = 40; i < 60; i += 5)
  {
    SHA1_ROUND(F2, a, b, c, d, e, 0x8f1bbcdcUL, 0);
    SHA1_ROUND(F2, e, a, b, c, d, 0x8f1bbcdcUL, 1);
    SHA1_ROUND(F2, d, e, a, b, c, 0x8f1bbcdcUL, 2);
    SHA1_ROUND(F2, c, d, e, a, b, 0x8f1bbcdcUL, 3);
    SHA1_ROUND(F2, b, c, d, e, a, 0x8f1bbcdcUL, 4);
  }
  for(i = 60; i < 80; i += 5)
  {
    SHA1_ROUND(F3, a, b, c, d, e, 0xca62c1d6UL, 0);
    SHA1_ROUND(F3, e, a, b, c, d, 0xca62c1d6UL, 1);
    SHA1_ROUND(F3, d, e, a, b, c, 0xca62c1d6UL, 2);
    SHA1_ROUND(F3, c, d, e, a, b, 0xca62c1d6UL, 3);
    SHA1_ROUND(F3, b, c, d, e, a, 0xca62c1d6UL, 4);
  }
  state__p_u32[0] += a;
  state__p_u32[1] += b;
  state__p_u32[2] += c;
  state__p_u32[3] += d;
  state__p_u32[4] += e;
#else
  flea_sha1_20_rounds(abcde, 0x5a827999UL, W__bu8, F0_f);
  flea_sha1_20_rounds(abcde, 0x6ed9eba1UL, W__bu8 + 20, F1_f);
  flea_sha1_20_rounds(abcde, 0x8f1bbcdcUL, W__bu8 + 40, F2_f);
  flea_sha1_20_rounds(abcde, 0xca62c1d6UL, W__bu8 + 60, F3_f);
  state__p_u32[0] += abcde[0];
  state__p_u32[1] += abcde[1];
  state__p_u32[2] += abcde[2];
  state__p_u32[3] += abcde[3];
  state__p_u32[4] += abcde[4];
#endif
  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_SECRET_ARR(W__bu8, 80);
    );
}

void flea_sha1_init (flea_hash_ctx_t* ctx__pt)
{
  flea_u32_t* state__p_u32 = (flea_u32_t*)ctx__pt->hash_state;

  state__p_u32[0] = 0x67452301;
  state__p_u32[1] = 0xefcdab89;
  state__p_u32[2] = 0x98badcfe;
  state__p_u32[3] = 0x10325476;
  state__p_u32[4] = 0xc3d2e1f0;
}

#endif // #ifdef FLEA_HAVE_SHA1
