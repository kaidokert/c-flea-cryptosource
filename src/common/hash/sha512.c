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
#include "internal/common/hash/sha512.h"
#include <string.h>
#include "flea/error.h"
#include "flea/bin_utils.h"
#include "flea/alloc.h"
#include "flea/util.h"
#include "flea/error_handling.h"
#include "flea/types.h"
#include "flea/hash.h"



static const flea_u32_t K[160] = {
  0x428a2f98UL, 0xd728ae22UL, 0x71374491UL, 0x23ef65cdUL, 0xb5c0fbcfUL, 0xec4d3b2fUL, 0xe9b5dba5UL, 0x8189dbbcUL,
  0x3956c25bUL, 0xf348b538UL, 0x59f111f1UL, 0xb605d019UL, 0x923f82a4UL, 0xaf194f9bUL, 0xab1c5ed5UL, 0xda6d8118UL,
  0xd807aa98UL, 0xa3030242UL, 0x12835b01UL, 0x45706fbeUL, 0x243185beUL, 0x4ee4b28cUL, 0x550c7dc3UL, 0xd5ffb4e2UL,
  0x72be5d74UL, 0xf27b896fUL, 0x80deb1feUL, 0x3b1696b1UL, 0x9bdc06a7UL, 0x25c71235UL, 0xc19bf174UL, 0xcf692694UL,
  0xe49b69c1UL, 0x9ef14ad2UL, 0xefbe4786UL, 0x384f25e3UL, 0x0fc19dc6UL, 0x8b8cd5b5UL, 0x240ca1ccUL, 0x77ac9c65UL,
  0x2de92c6fUL, 0x592b0275UL, 0x4a7484aaUL, 0x6ea6e483UL, 0x5cb0a9dcUL, 0xbd41fbd4UL, 0x76f988daUL, 0x831153b5UL,
  0x983e5152UL, 0xee66dfabUL, 0xa831c66dUL, 0x2db43210UL, 0xb00327c8UL, 0x98fb213fUL, 0xbf597fc7UL, 0xbeef0ee4UL,
  0xc6e00bf3UL, 0x3da88fc2UL, 0xd5a79147UL, 0x930aa725UL, 0x06ca6351UL, 0xe003826fUL, 0x14292967UL, 0x0a0e6e70UL,
  0x27b70a85UL, 0x46d22ffcUL, 0x2e1b2138UL, 0x5c26c926UL, 0x4d2c6dfcUL, 0x5ac42aedUL, 0x53380d13UL, 0x9d95b3dfUL,
  0x650a7354UL, 0x8baf63deUL, 0x766a0abbUL, 0x3c77b2a8UL, 0x81c2c92eUL, 0x47edaee6UL, 0x92722c85UL, 0x1482353bUL,
  0xa2bfe8a1UL, 0x4cf10364UL, 0xa81a664bUL, 0xbc423001UL, 0xc24b8b70UL, 0xd0f89791UL, 0xc76c51a3UL, 0x0654be30UL,
  0xd192e819UL, 0xd6ef5218UL, 0xd6990624UL, 0x5565a910UL, 0xf40e3585UL, 0x5771202aUL, 0x106aa070UL, 0x32bbd1b8UL,
  0x19a4c116UL, 0xb8d2d0c8UL, 0x1e376c08UL, 0x5141ab53UL, 0x2748774cUL, 0xdf8eeb99UL, 0x34b0bcb5UL, 0xe19b48a8UL,
  0x391c0cb3UL, 0xc5c95a63UL, 0x4ed8aa4aUL, 0xe3418acbUL, 0x5b9cca4fUL, 0x7763e373UL, 0x682e6ff3UL, 0xd6b2b8a3UL,
  0x748f82eeUL, 0x5defb2fcUL, 0x78a5636fUL, 0x43172f60UL, 0x84c87814UL, 0xa1f0ab72UL, 0x8cc70208UL, 0x1a6439ecUL,
  0x90befffaUL, 0x23631e28UL, 0xa4506cebUL, 0xde82bde9UL, 0xbef9a3f7UL, 0xb2c67915UL, 0xc67178f2UL, 0xe372532bUL,
  0xca273eceUL, 0xea26619cUL, 0xd186b8c7UL, 0x21c0c207UL, 0xeada7dd6UL, 0xcde0eb1eUL, 0xf57d4f7fUL, 0xee6ed178UL,
  0x06f067aaUL, 0x72176fbaUL, 0x0a637dc5UL, 0xa2c898a6UL, 0x113f9804UL, 0xbef90daeUL, 0x1b710b35UL, 0x131c471bUL,
  0x28db77f5UL, 0x23047d84UL, 0x32caab7bUL, 0x40c72493UL, 0x3c9ebe0aUL, 0x15c9bebcUL, 0x431d67c4UL, 0x9c100d4cUL,
  0x4cc5d4beUL, 0xcb3e42b6UL, 0x597f299cUL, 0xfc657e2aUL, 0x5fcb6fabUL, 0x3ad6faecUL, 0x6c44198cUL, 0x4a475817UL
};


#define BLOCK_SIZE          128

#ifdef FLEA_USE_SHA512_ROUND_MACRO
#define ROR64_n(r, value, w) \
  do { \
    flea_al_u8_t v, u; \
    v = w - 32;  \
    u = 32 - v;  \
    (r)[1] ^= ((flea_u32_t)(((value)[1] << u))) | ((flea_u32_t)(((value)[0] ) >> v)); \
    (r)[0] ^= ((value)[0] << u) | (((value)[1] ) >> v); \
  } while(0)

#define ROR64_n_small(r, value, w) \
  do { \
    flea_al_u8_t u = 32 - w; \
    (r)[1] ^= ((value)[1] >> w) | ((value)[0] << u);  \
    (r)[0] ^= ((value)[0] >> w) | ((value)[1] << u); \
  } while(0)



#else
void ROR64_n (flea_u32_t r[2], const flea_u32_t value[2], flea_al_u8_t w)
{
  flea_al_u8_t v, u;

  v = w - 32;
  u = 32 - v;
  r[1] ^= ((flea_u32_t)((value[1] << u))) | ((flea_u32_t)((value[0] ) >> v));
  r[0] ^= (value[0] << u) | ((value[1] ) >> v);
}
void ROR64_n_small (flea_u32_t r[2], const flea_u32_t value[2], flea_al_u8_t w)
{
  flea_al_u8_t u = 32 - w;

  r[1] ^= (value[1] >> w) | (value[0] << u);
  r[0] ^= (value[0] >> w) | (value[1] << u);
}

#endif

#define R_n(r, x, w )        \
  do { \
    (r)[0] ^= (x)[0] >> w; \
    (r)[1] ^= ((x)[1] >> w) | (x)[0] << (32 - w); \
  } while(0)



#define Ch_n(r, x, y, z )     \
  do { \
    (r)[0] = ((z)[0] ^ ((x)[0] & ((y)[0] ^ (z)[0]))); \
    (r)[1] = ((z)[1] ^ ((x)[1] & ((y)[1] ^ (z)[1]))); \
  } while(0)

#define Maj_n(r, x, y, z )    \
  do { \
    (r)[0] = ((((x)[0] | (y)[0]) & (z)[0]) | ((x)[0] & (y)[0])); \
    (r)[1] = ((((x)[1] | (y)[1]) & (z)[1]) | ((x)[1] & (y)[1])); \
  } while(0)


#define Sigma1_n(r, x) \
  do { \
    (r)[0] = 0; (r)[1] = 0; \
    ROR64_n_small(r, x, 14); \
    ROR64_n_small(r, x, 18); \
    ROR64_n(r, x, 41); \
  } while(0)

#define Sigma0_n(r, x) \
  do { \
    (r)[0] = 0; (r)[1] = 0; \
    ROR64_n_small(r, x, 28); \
    ROR64_n(r, x, 34); \
    ROR64_n(r, x, 39); \
  } while(0)

#define Gamma1_n(r, x )    \
  do { \
    flea_u32_t G_sum[2] = { 0, 0 }; \
    ROR64_n_small(G_sum, x, 19); \
    ROR64_n(G_sum, x, 61); \
    R_n(G_sum, x, 6); \
    assn64(r, G_sum); \
  } while(0)

#define Gamma0_n_add(r, x )    \
  do { \
    flea_u32_t G_sum[2] = { 0, 0 }; \
    ROR64_n_small(G_sum, x, 1); \
    ROR64_n_small(G_sum, x, 8); \
    R_n(G_sum, x, 7); \
    add64(r, G_sum); \
  } while(0)
#define Gamma1_old(r, x ) r = Gamma1(x)

#define add64_old(io, b) io += b
#define assn64_old(o, b) o = b

#define assn64(o, b) do { (o)[0] = (b)[0]; (o)[1] = (b)[1]; } while(0)

#define add64(io, b) do { \
    flea_u32_t old; \
    flea_al_u8_t carry = 0; \
    old = (io)[1]; \
    (io)[1] += (b)[1]; \
    if((io)[1] < old) \
    { carry = 1; } \
    (io)[0] += carry + (b)[0]; \
} while(0)

#ifdef FLEA_USE_SHA512_ROUND_MACRO

#define FLEA_SHA_512_ROUND( a, b, c, d, e, f, g, h, i )       \
  Sigma1_n(t0, e); \
  add64(t0, h); \
  Ch_n(tmp, e, f, g); \
  add64(t0, tmp); \
  W_p = &W[2 * (i)]; \
  K_p = &K[2 * (i)]; \
  add64(t0, K_p); \
  add64(t0, W_p); \
  Sigma0_n(t1, a); \
  Maj_n(tmp, a, b, c); \
  add64(t1, tmp); \
  add64(d, t0); \
  assn64(h, t0); \
  add64(h, t1);

#else
static void Sha512Round ( flea_u32_t a[2], flea_u32_t b[2], flea_u32_t c[2], flea_u32_t d[2], flea_u32_t e[2], flea_u32_t f[2], flea_u32_t g[2], flea_u32_t h[2], flea_al_u8_t i, const flea_u32_t* W )
{
  flea_u32_t t0[2] = { 0, 0 };
  flea_u32_t t1[2] = { 0, 0 };
  flea_u32_t tmp[2] = { 0, 0 };
  const flea_u32_t* W_p, *K_p;

  Sigma1_n(t0, e);
  add64(t0, h);
  Ch_n(tmp, e, f, g);
  add64(t0, tmp);
  W_p = &W[2 * (i)];
  K_p = &K[2 * (i)];
  add64(t0, K_p);
  add64(t0, W_p);
  Sigma0_n(t1, a);
  Maj_n(tmp, a, b, c);
  add64(t1, tmp);
  add64(d, t0);
  assn64(h, t0);
  add64(h, t1);
}
#endif


flea_err_t THR_flea_sha512_compression_function ( flea_hash_ctx_t* ctx__pt, const flea_u8_t* input)
{

  FLEA_DECL_BUF(S_and_W, flea_u32_t, 16 + 160);
  flea_u32_t* W;
  flea_u32_t *S;
  int i;

  flea_u32_t* state = (flea_u32_t*)ctx__pt->hash_state;
  FLEA_THR_BEG_FUNC();
  FLEA_ALLOC_BUF(S_and_W, 16 + 160);
  S = (flea_u32_t*)S_and_W;
  W = (flea_u32_t*)&S_and_W[16];
  for( i = 0; i < 16; i += 1 )
  {
    S[i] = state[i];
  }

  for( i = 0; i < 32; i++)
  {
    W[i] = flea__decode_U32_BE(input + 4 * i);
  }

  for( i = 32; i < 160; i += 2 )
  {
    Gamma1_n(&W[i], &W[i - 4]);
    Gamma0_n_add(&W[i], &W[i - 30]);
    add64(&W[i], &W[i - 14]);
    add64(&W[i], &W[i - 32]);
  }


#ifdef FLEA_USE_SHA512_ROUND_MACRO
  for( i = 0; i < 80; i += 8 )
  {

    flea_u32_t tmp[2];
    flea_u32_t t0[2];
    flea_u32_t t1[2];
    flea_u32_t* W_p;
    const flea_u32_t* K_p;
    FLEA_SHA_512_ROUND(&S[0], &S[2], &S[4], &S[6], &S[8], &S[10], &S[12], &S[14], i + 0);
    FLEA_SHA_512_ROUND(&S[14], &S[0], &S[2], &S[4], &S[6], &S[8], &S[10], &S[12], i + 1);
    FLEA_SHA_512_ROUND(&S[12], &S[14], &S[0], &S[2], &S[4], &S[6], &S[8], &S[10], i + 2);
    FLEA_SHA_512_ROUND(&S[10], &S[12], &S[14], &S[0], &S[2], &S[4], &S[6], &S[8], i + 3);
    FLEA_SHA_512_ROUND(&S[8], &S[10], &S[12], &S[14], &S[0], &S[2], &S[4], &S[6], i + 4);
    FLEA_SHA_512_ROUND(&S[6], &S[8], &S[10], &S[12], &S[14], &S[0], &S[2], &S[4], i + 5);
    FLEA_SHA_512_ROUND(&S[4], &S[6], &S[8], &S[10], &S[12], &S[14], &S[0], &S[2], i + 6);
    FLEA_SHA_512_ROUND(&S[2], &S[4], &S[6], &S[8], &S[10], &S[12], &S[14], &S[0], i + 7);
  }
#else
  for( i = 0; i < 80; i += 1 )
  {
    flea_u32_t tmp[2];
    Sha512Round(&S[0], &S[2], &S[4], &S[6], &S[8], &S[10], &S[12], &S[14], i, W);
    assn64(tmp, &S[0]);
    assn64(&S[0], &S[14]);
    assn64(&S[14], &S[12]);
    assn64(&S[12], &S[10]);
    assn64(&S[10], &S[8]);
    assn64(&S[8], &S[6]);
    assn64(&S[6], &S[4]);
    assn64(&S[4], &S[2]);
    assn64(&S[2], tmp);
  }
#endif

  for( i = 0; i < 8; i++ )
  {
    add64((&state[2 * i]), &S[2 * i]);
  }
  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_SECRET_ARR(S_and_W, 16 + 160);
    );
}

void flea_sha512_init ( flea_hash_ctx_t* ctx__pt)
{

  flea_u32_t* state =  ctx__pt->hash_state;

  state[0] = 0x6a09e667UL; state[1] = 0xf3bcc908UL;
  state[2] = 0xbb67ae85UL; state[3] = 0x84caa73bUL;
  state[4] = 0x3c6ef372UL; state[5] = 0xfe94f82bUL;
  state[6] = 0xa54ff53aUL; state[7] = 0x5f1d36f1UL;
  state[8] = 0x510e527fUL; state[9] = 0xade682d1UL;
  state[10] = 0x9b05688cUL; state[11] = 0x2b3e6c1fUL;
  state[12] = 0x1f83d9abUL; state[13] = 0xfb41bd6bUL;
  state[14] = 0x5be0cd19UL; state[15] = 0x137e2179UL;
}

void flea_sha384_init ( flea_hash_ctx_t* ctx__pt)
{

  flea_u32_t* state =  ctx__pt->hash_state;

  state[0] = 0xcbbb9d5dUL; state[1] = 0xc1059ed8UL;
  state[2] = 0x629a292aUL; state[3] = 0x367cd507UL;
  state[4] = 0x9159015aUL; state[5] = 0x3070dd17UL;
  state[6] = 0x152fecd8UL; state[7] = 0xf70e5939UL;
  state[8] = 0x67332667UL; state[9] = 0xffc00b31UL;
  state[10] = 0x8eb44a87UL; state[11] = 0x68581511UL;
  state[12] = 0xdb0c2e0dUL; state[13] = 0x64f98fa7UL;
  state[14] = 0x47b5481dUL; state[15] = 0xbefa4fa4UL;

}
void flea_sha512_encode_hash_state (const flea_hash_ctx_t* ctx__pt, flea_u8_t* output,  flea_al_u8_t output_len)
{
  flea_al_u8_t i;
  flea_u32_t* state = (flea_u32_t*)ctx__pt->hash_state;

  for( i = 0; i < output_len; i++ )
  {
    output[i] = state[i / 4] >> ((3 - (i % 4)) * 8);
  }
}

