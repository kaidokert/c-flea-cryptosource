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
#include "internal/common/hash/md5.h"
#include "flea/error.h"
#include "flea/error_handling.h"
#include "flea/bin_utils.h"

#ifdef FLEA_HAVE_MD5

#define F( x, y, z )      ( (z) ^ ((x) & ((y) ^ (z))) )
#define G( x, y, z )      ( (y) ^ ((z) & ((x) ^ (y))) )
#define H( x, y, z )      ( (x) ^ (y) ^ (z) )
#define I( x, y, z )      ( (y) ^ ((x) | ~(z)) )

#define STEP( f, a, b, c, d, x, t, s )                          \
  (a) += f((b), (c), (d)) + (x) + (t);                        \
  (a) = (((a) << (s)) | (((a) & 0xffffffff) >> (32 - (s))));  \
  (a) += (b);

#define SET(n)    ((ptr[(n) * 4]) | (((flea_u32_t)ptr[(n) * 4 + 1]) << 8) | (((flea_u32_t)ptr[(n) * 4 + 2]) << 16) | (((flea_u32_t)ptr[(n) * 4 + 3]) << 24) )
#define GET(n)    SET(n)

#ifndef FLEA_USE_MD5_ROUND_MACRO
typedef flea_u32_t (*flea_md5_round_arithm_f)(flea_u32_t x, flea_u32_t y, flea_u32_t z);
static flea_u32_t flea_md5_round_arithm_1 (flea_u32_t x, flea_u32_t y, flea_u32_t z)
{
  return F(x, y, z);
}
static flea_u32_t flea_md5_round_arithm_2 (flea_u32_t x, flea_u32_t y, flea_u32_t z)
{
  return G(x, y, z);
}
static flea_u32_t flea_md5_round_arithm_3 (flea_u32_t x, flea_u32_t y, flea_u32_t z)
{
  return H(x, y, z);
}
static flea_u32_t flea_md5_round_arithm_4 (flea_u32_t x, flea_u32_t y, flea_u32_t z)
{
  return I(x, y, z);
}
const flea_u32_t flea_md5_table__au32[] =
{
  0xd76aa478UL, 0xe8c7b756UL, 0x242070dbUL, 0xc1bdceeeUL,
  0xf57c0fafUL, 0x4787c62aUL, 0xa8304613UL, 0xfd469501UL,
  0x698098d8UL, 0x8b44f7afUL, 0xffff5bb1UL, 0x895cd7beUL,
  0x6b901122UL, 0xfd987193UL, 0xa679438eUL, 0x49b40821UL,

  0xf61e2562UL, 0xc040b340UL, 0x265e5a51UL, 0xe9b6c7aaUL,
  0xd62f105dUL, 0x02441453UL, 0xd8a1e681UL, 0xe7d3fbc8UL,
  0x21e1cde6UL, 0xc33707d6UL, 0xf4d50d87UL, 0x455a14edUL,
  0xa9e3e905UL, 0xfcefa3f8UL, 0x676f02d9UL, 0x8d2a4c8aUL,

  0xfffa3942UL, 0x8771f681UL, 0x6d9d6122UL, 0xfde5380cUL,
  0xa4beea44UL, 0x4bdecfa9UL, 0xf6bb4b60UL, 0xbebfbc70UL,
  0x289b7ec6UL, 0xeaa127faUL, 0xd4ef3085UL, 0x04881d05UL,
  0xd9d4d039UL, 0xe6db99e5UL, 0x1fa27cf8UL, 0xc4ac5665UL,

  0xf4292244UL, 0x432aff97UL, 0xab9423a7UL, 0xfc93a039UL,
  0x655b59c3UL, 0x8f0ccc92UL, 0xffeff47dUL, 0x85845dd1UL,
  0x6fa87e4fUL, 0xfe2ce6e0UL, 0xa3014314UL, 0x4e0811a1UL,
  0xf7537e82UL, 0xbd3af235UL, 0x2ad7d2bbUL, 0xeb86d391UL

};

const flea_u8_t flea_md5_s_table__au8[] =
{
  7, 12, 17,	22,
  5, 9,	 14,	20,
  4, 11, 16,	23,
  6, 10, 15,	21
};

const flea_u8_t flea_md5_idx_table__au8[] =
{
  0x16, 0xb0, 0x5a, 0xf4, 0x9e, 0x38, 0xd2, 0x7c,
  0x58, 0xbe, 0x14, 0x7a, 0xd0, 0x36, 0x9c, 0xf2,
  0x07, 0xe5, 0xc3, 0xa1, 0x8f, 0x6d, 0x4b, 0x29
};

static void flea_md5_round (flea_u32_t abcd[4], const flea_u8_t* ptr, flea_md5_round_arithm_f func, const flea_u32_t* t_table__pcu32, const flea_u8_t* s_table__pcu8, const flea_u8_t* idx_table__pcu8)
{
  flea_u32_t a = abcd[0];
  flea_u32_t b = abcd[1];
  flea_u32_t c = abcd[2];
  flea_u32_t d = abcd[3];
  flea_al_u8_t i;

  for(i = 0; i < 16; i++)
  {
    flea_u32_t tmp;
    flea_al_u8_t idx;
    if(func == flea_md5_round_arithm_1)
    {
      idx = i;
    }
    else
    {
      idx = (idx_table__pcu8[i / 2] >> (((i + 1) % 2) * 4)) & 0xF;
    }
    STEP(func, a, b, c, d, SET(idx), t_table__pcu32[i], s_table__pcu8[i % 4]);
    tmp = a;
    a = d;
    d = c;
    c = b;
    b = tmp;
  }
  abcd[0] = a;
  abcd[1] = b;
  abcd[2] = c;
  abcd[3] = d;
}

#endif

flea_err_t THR_flea_md5_compression_function ( flea_hash_ctx_t* ctx__pt, const flea_u8_t* input)
{
  const flea_u8_t*     ptr;
  flea_u32_t* state;

#ifdef FLEA_USE_MD5_ROUND_MACRO
  flea_u32_t a;
  flea_u32_t b;
  flea_u32_t c;
  flea_u32_t d;
#else
  flea_u32_t abcd[4];
#endif

  FLEA_THR_BEG_FUNC();

  ptr = (const flea_u8_t*)input;
  state = (flea_u32_t*)ctx__pt->hash_state;
#ifdef FLEA_USE_MD5_ROUND_MACRO
  a = state[0];
  b = state[1];
  c = state[2];
  d = state[3];
#else
  memcpy(abcd, state, sizeof(abcd));
#endif

#ifndef FLEA_USE_MD5_ROUND_MACRO
  flea_md5_round(abcd, ptr, flea_md5_round_arithm_1, flea_md5_table__au32, flea_md5_s_table__au8, NULL);
  flea_md5_round(abcd, ptr, flea_md5_round_arithm_2, flea_md5_table__au32 + 16, flea_md5_s_table__au8 + 4, flea_md5_idx_table__au8);
  flea_md5_round(abcd, ptr, flea_md5_round_arithm_3, flea_md5_table__au32 + 32, flea_md5_s_table__au8 + 8, flea_md5_idx_table__au8 + 8);
  flea_md5_round(abcd, ptr, flea_md5_round_arithm_4, flea_md5_table__au32 + 48, flea_md5_s_table__au8 + 12, flea_md5_idx_table__au8 + 16);

  state[0] += abcd[0];
  state[1] += abcd[1];
  state[2] += abcd[2];
  state[3] += abcd[3];
#else

  STEP( F, a, b, c, d, SET(0),    0xd76aa478, 7 )
  STEP( F, d, a, b, c, SET(1),  0xe8c7b756, 12 )
  STEP( F, c, d, a, b, SET(2),  0x242070db, 17 )
  STEP( F, b, c, d, a, SET(3),  0xc1bdceee, 22 )
  STEP( F, a, b, c, d, SET(4),  0xf57c0faf, 7 )
  STEP( F, d, a, b, c, SET(5),  0x4787c62a, 12 )
  STEP( F, c, d, a, b, SET(6),  0xa8304613, 17 )
  STEP( F, b, c, d, a, SET(7),  0xfd469501, 22 )
  STEP( F, a, b, c, d, SET(8 ),  0x698098d8, 7 )
  STEP( F, d, a, b, c, SET(9 ),  0x8b44f7af, 12 )
  STEP( F, c, d, a, b, SET(10 ), 0xffff5bb1, 17 )
  STEP( F, b, c, d, a, SET(11 ), 0x895cd7be, 22 )
  STEP( F, a, b, c, d, SET(12 ), 0x6b901122, 7 )
  STEP( F, d, a, b, c, SET(13 ), 0xfd987193, 12 )
  STEP( F, c, d, a, b, SET(14 ), 0xa679438e, 17 )
  STEP( F, b, c, d, a, SET(15 ), 0x49b40821, 22 )
  // Round 2
  STEP( G, a, b, c, d, GET(1),  0xf61e2562, 5 )
  STEP( G, d, a, b, c, GET(6),  0xc040b340, 9 )
  STEP( G, c, d, a, b, GET(11), 0x265e5a51, 14 )
  STEP( G, b, c, d, a, GET(0),  0xe9b6c7aa, 20 )
  STEP( G, a, b, c, d, GET(5),  0xd62f105d, 5 )
  STEP( G, d, a, b, c, GET(10), 0x02441453, 9 )
  STEP( G, c, d, a, b, GET(15), 0xd8a1e681, 14 )
  STEP( G, b, c, d, a, GET(4),  0xe7d3fbc8, 20 )
  STEP( G, a, b, c, d, GET(9),  0x21e1cde6, 5 )
  STEP( G, d, a, b, c, GET(14), 0xc33707d6, 9 )
  STEP( G, c, d, a, b, GET(3),  0xf4d50d87, 14 )
  STEP( G, b, c, d, a, GET(8),  0x455a14ed, 20 )
  STEP( G, a, b, c, d, GET(13), 0xa9e3e905, 5 )
  STEP( G, d, a, b, c, GET(2),  0xfcefa3f8, 9 )
  STEP( G, c, d, a, b, GET(7),  0x676f02d9, 14 )
  STEP( G, b, c, d, a, GET(12), 0x8d2a4c8a, 20 )

  // Round 3
  STEP( H, a, b, c, d, GET(5),  0xfffa3942, 4 )
  STEP( H, d, a, b, c, GET(8),  0x8771f681, 11 )
  STEP( H, c, d, a, b, GET(11), 0x6d9d6122, 16 )
  STEP( H, b, c, d, a, GET(14), 0xfde5380c, 23 )
  STEP( H, a, b, c, d, GET(1),  0xa4beea44, 4 )
  STEP( H, d, a, b, c, GET(4),  0x4bdecfa9, 11 )
  STEP( H, c, d, a, b, GET(7),  0xf6bb4b60, 16 )
  STEP( H, b, c, d, a, GET(10), 0xbebfbc70, 23 )
  STEP( H, a, b, c, d, GET(13), 0x289b7ec6, 4 )
  STEP( H, d, a, b, c, GET(0),  0xeaa127fa, 11 )
  STEP( H, c, d, a, b, GET(3),  0xd4ef3085, 16 )
  STEP( H, b, c, d, a, GET(6),  0x04881d05, 23 )
  STEP( H, a, b, c, d, GET(9),  0xd9d4d039, 4 )
  STEP( H, d, a, b, c, GET(12), 0xe6db99e5, 11 )
  STEP( H, c, d, a, b, GET(15), 0x1fa27cf8, 16 )
  STEP( H, b, c, d, a, GET(2),  0xc4ac5665, 23 )

  // Round 4
  STEP( I, a, b, c, d, GET(0),  0xf4292244, 6 )
  STEP( I, d, a, b, c, GET(7),  0x432aff97, 10 )
  STEP( I, c, d, a, b, GET(14), 0xab9423a7, 15 )
  STEP( I, b, c, d, a, GET(5),  0xfc93a039, 21 )
  STEP( I, a, b, c, d, GET(12), 0x655b59c3, 6 )
  STEP( I, d, a, b, c, GET(3),  0x8f0ccc92, 10 )
  STEP( I, c, d, a, b, GET(10), 0xffeff47d, 15 )
  STEP( I, b, c, d, a, GET(1),  0x85845dd1, 21 )
  STEP( I, a, b, c, d, GET(8),  0x6fa87e4f, 6 )
  STEP( I, d, a, b, c, GET(15), 0xfe2ce6e0, 10 )
  STEP( I, c, d, a, b, GET(6),  0xa3014314, 15 )
  STEP( I, b, c, d, a, GET(13), 0x4e0811a1, 21 )
  STEP( I, a, b, c, d, GET(4),  0xf7537e82, 6 )
  STEP( I, d, a, b, c, GET(11), 0xbd3af235, 10 )
  STEP( I, c, d, a, b, GET(2),  0x2ad7d2bb, 15 )
  STEP( I, b, c, d, a, GET(9),  0xeb86d391, 21 )

  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
#endif


  FLEA_THR_FIN_SEC_empty();
}


void flea_md5_init ( flea_hash_ctx_t* ctx__pt)
{

  flea_u32_t* state = (flea_u32_t*)ctx__pt->hash_state;

  state[0] = 0x67452301UL;
  state[1] = 0xefcdab89UL;
  state[2] = 0x98badcfeUL;
  state[3] = 0x10325476UL;

}


void flea_md5_encode_hash_state (const flea_hash_ctx_t* ctx__pt, flea_u8_t* output,  flea_al_u8_t output_len)
{
  flea_al_u8_t i;
  flea_u32_t* state = (flea_u32_t*)ctx__pt->hash_state;

  output_len = (output_len + 3) / 4;
  for( i = 0; i < output_len; i++ )
  {
    flea__encode_U32_LE( state[i], output + (4 * i) );
  }
}

#endif // #ifdef FLEA_HAVE_MD5
