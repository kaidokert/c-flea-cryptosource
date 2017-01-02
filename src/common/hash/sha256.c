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
#include "internal/common/hash/sha256.h"
#include <string.h>
#include "flea/error.h"
#include "flea/util.h"
#include "flea/alloc.h"
#include "flea/error_handling.h"
#include "flea/types.h"
#include "flea/hash.h"

#ifdef FLEA_HAVE_SHA224_256

#define FLEA_ROTATE_RIGHT_U32(word, rot) \
  (((word) >> (rot)) | ((word) << (32 - (rot))))

#define FLEA_SHA256_RHO(word, r1, r2, r3) \
  (FLEA_ROTATE_RIGHT_U32(word, r1) ^ FLEA_ROTATE_RIGHT_U32(word, r2) ^ FLEA_ROTATE_RIGHT_U32(word, r3))

#define FLEA_SHA256_RHO1(word) FLEA_SHA256_RHO(word, 2, 13, 22)

#define FLEA_SHA256_RHO2(word) FLEA_SHA256_RHO(word, 6, 11, 25)

#define FLEA_SHA256_SIGMA(word, r1, r2, s) \
  (FLEA_ROTATE_RIGHT_U32(word, r1) ^ FLEA_ROTATE_RIGHT_U32(word, r2) ^ ((word) >> (s)))

#define FLEA_SHA256_SIGMA1(word) FLEA_SHA256_SIGMA(word, 7, 18, 3)

#define FLEA_SHA256_SIGMA2(word) FLEA_SHA256_SIGMA(word, 17, 19, 10)

#define FLEA_SHA256_CH(x, y, z) (((x) & (y)) ^ ((~x) & z))

#define FLEA_SHA256_MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#define ror(value, bits) (((value) >> (bits)) | ((value) << (32 - (bits))))

#define LOAD32H(x, y)                            \
  { x = ((flea_u32_t)((y)[0] & 255) << 24) | \
        ((flea_u32_t)((y)[1] & 255) << 16) | \
        ((flea_u32_t)((y)[2] & 255) << 8)  | \
        ((flea_u32_t)((y)[3] & 255)); }


static const flea_u32_t K[64] = {
  0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL, 0x3956c25bUL,
  0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL, 0xd807aa98UL, 0x12835b01UL,
  0x243185beUL, 0x550c7dc3UL, 0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL,
  0xc19bf174UL, 0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
  0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL, 0x983e5152UL,
  0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL, 0xc6e00bf3UL, 0xd5a79147UL,
  0x06ca6351UL, 0x14292967UL, 0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL,
  0x53380d13UL, 0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
  0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL, 0xd192e819UL,
  0xd6990624UL, 0xf40e3585UL, 0x106aa070UL, 0x19a4c116UL, 0x1e376c08UL,
  0x2748774cUL, 0x34b0bcb5UL, 0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL,
  0x682e6ff3UL, 0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
  0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL
};


#define Ch( x, y, z )     (z ^ (x & (y ^ z)))
#define Maj( x, y, z )    (((x | y) & z) | (x & y))
#define S( x, n )         ror((x), (n))
#define R( x, n )         (((x) & 0xFFFFFFFFUL) >> (n))
#define Sigma0( x )       (S(x, 2) ^ S(x, 13) ^ S(x, 22))
#define Sigma1( x )       (S(x, 6) ^ S(x, 11) ^ S(x, 25))
#define Gamma0( x )       (S(x, 7) ^ S(x, 18) ^ R(x, 3))
#define Gamma1( x )       (S(x, 17) ^ S(x, 19) ^ R(x, 10))

#ifdef FLEA_USE_SHA256_ROUND_MACRO
#define Sha256Round( a, b, c, d, e, f, g, h, i )       \
  t0 = h + Sigma1(e) + Ch(e, f, g) + K[i] + W[i];   \
  t1 = Sigma0(a) + Maj(a, b, c);                    \
  d += t0;                                          \
  h  = t0 + t1;
#else
static void Sha256Round ( flea_u32_t* a__pu32, flea_u32_t* b__pu32, flea_u32_t* c__pu32, flea_u32_t* d__pu32, flea_u32_t* e__pu32, flea_u32_t* f__pu32, flea_u32_t* g__pu32, flea_u32_t* h__pu32, flea_al_u8_t i, flea_u32_t* W )
{
  flea_u32_t t0, t1;
  flea_u32_t a = *a__pu32, b = *b__pu32, c = *c__pu32, d = *d__pu32, e = *e__pu32, f = *f__pu32, g = *g__pu32, h = *h__pu32;

  t0 = h + Sigma1(e) + Ch(e, f, g) + K[i] + W[i];
  t1 = Sigma0(a) + Maj(a, b, c);
  d += t0;
  h  = t0 + t1;
  *a__pu32 = a; *b__pu32 = b; *c__pu32 = c; *d__pu32 = d; *e__pu32 = e; *f__pu32 = f; *g__pu32 = g; *h__pu32 = h;
}


#endif

flea_err_t THR_flea_sha256_compression_function (flea_hash_ctx_t* ctx__pt, const flea_u8_t* input)
{

  FLEA_DECL_BUF(S_and_W, flea_u32_t, 8 + 64);
  flea_u32_t    *S;
  flea_u32_t   * W;
  int i;
  flea_u32_t* state =  ctx__pt->hash_state;

  FLEA_THR_BEG_FUNC();
  FLEA_ALLOC_BUF(S_and_W, 8 + 64);
  S = S_and_W;
  W = S_and_W + 8;
  // Copy state into S
  for( i = 0; i < 8; i++ )
  {
    S[i] = state[i];
  }

  // Copy the state into 512-bits into W[0..15]
  for( i = 0; i < 16; i++ )
  {
    LOAD32H( W[i], input + (4 * i) );
  }

  // Fill W[16..63]
  for( i = 16; i < 64; i++ )
  {
    W[i] = Gamma1( W[i - 2]) + W[i - 7] + Gamma0( W[i - 15] ) + W[i - 16];
  }

  // Compress
#ifdef FLEA_USE_SHA256_ROUND_MACRO
  for( i = 0; i < 64; i += 8 )
  {
    flea_u32_t t0;
    flea_u32_t t1;
    Sha256Round( S[0], S[1], S[2], S[3], S[4], S[5], S[6], S[7], i );
    Sha256Round( S[7], S[0], S[1], S[2], S[3], S[4], S[5], S[6], i + 1 );
    Sha256Round( S[6], S[7], S[0], S[1], S[2], S[3], S[4], S[5], i + 2 );
    Sha256Round( S[5], S[6], S[7], S[0], S[1], S[2], S[3], S[4], i + 3 );
    Sha256Round( S[4], S[5], S[6], S[7], S[0], S[1], S[2], S[3], i + 4 );
    Sha256Round( S[3], S[4], S[5], S[6], S[7], S[0], S[1], S[2], i + 5 );
    Sha256Round( S[2], S[3], S[4], S[5], S[6], S[7], S[0], S[1], i + 6 );
    Sha256Round( S[1], S[2], S[3], S[4], S[5], S[6], S[7], S[0], i + 7 );
  }
#else
  for( i = 0; i < 64; i++ )
  {

    flea_u32_t t;
    Sha256Round( &S[0], &S[1], &S[2], &S[3], &S[4], &S[5], &S[6], &S[7], i, W );
    t = S[7];
    S[7] = S[6];
    S[6] = S[5];
    S[5] = S[4];
    S[4] = S[3];
    S[3] = S[2];
    S[2] = S[1];
    S[1] = S[0];
    S[0] = t;
  }
#endif

  for( i = 0; i < 8; i++ )
  {
    state[i] = state[i] + S[i];
  }
  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_SECRET_ARR(S_and_W, 8 + 64);
    );
}

void flea_sha256_init ( flea_hash_ctx_t* ctx__pt)
{
  flea_u32_t* state = ctx__pt->hash_state;

  state[0] = 0x6A09E667UL;
  state[1] = 0xBB67AE85UL;
  state[2] = 0x3C6EF372UL;
  state[3] = 0xA54FF53AUL;
  state[4] = 0x510E527FUL;
  state[5] = 0x9B05688CUL;
  state[6] = 0x1F83D9ABUL;
  state[7] = 0x5BE0CD19UL;
}
void flea_sha224_init ( flea_hash_ctx_t* ctx__pt)
{
  flea_u32_t* state =  ctx__pt->hash_state;

  state[0] = 0xc1059ed8UL;
  state[1] = 0x367cd507UL;
  state[2] = 0x3070dd17UL;
  state[3] = 0xf70e5939UL;
  state[4] = 0xffc00b31UL;
  state[5] = 0x68581511UL;
  state[6] = 0x64f98fa7UL;
  state[7] = 0xbefa4fa4UL;

}

void flea_sha256_encode_hash_state (const flea_hash_ctx_t* ctx__t, flea_u8_t* output,  flea_al_u8_t output_len)
{
  flea_al_u8_t i;
  flea_u32_t* state = (flea_u32_t*)ctx__t->hash_state;

  for( i = 0; i < output_len; i++ )
  {
    output[i] = state[i / 4] >> ((3 - (i % 4)) * 8);
  }
}


#endif // #ifdef FLEA_HAVE_SHA224_256
