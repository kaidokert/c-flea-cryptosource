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
#include "internal/common/block_cipher/des.h"
#include "flea/alloc.h"
#include "flea/bin_utils.h"
#include "flea/error_handling.h"
#include "flea/block_cipher.h"
#include <string.h>

#ifdef FLEA_HAVE_DES
const flea_u32_t Spbox[8][64] =
{
  { 0x01010400, 0x00000000, 0x00010000, 0x01010404,
    0x01010004, 0x00010404, 0x00000004, 0x00010000,
    0x00000400, 0x01010400, 0x01010404, 0x00000400,
    0x01000404, 0x01010004, 0x01000000, 0x00000004,
    0x00000404, 0x01000400, 0x01000400, 0x00010400,
    0x00010400, 0x01010000, 0x01010000, 0x01000404,
    0x00010004, 0x01000004, 0x01000004, 0x00010004,
    0x00000000, 0x00000404, 0x00010404, 0x01000000,
    0x00010000, 0x01010404, 0x00000004, 0x01010000,
    0x01010400, 0x01000000, 0x01000000, 0x00000400,
    0x01010004, 0x00010000, 0x00010400, 0x01000004,
    0x00000400, 0x00000004, 0x01000404, 0x00010404,
    0x01010404, 0x00010004, 0x01010000, 0x01000404,
    0x01000004, 0x00000404, 0x00010404, 0x01010400,
    0x00000404, 0x01000400, 0x01000400, 0x00000000,
    0x00010004, 0x00010400, 0x00000000, 0x01010004 },
  { 0x80108020, 0x80008000, 0x00008000, 0x00108020,
    0x00100000, 0x00000020, 0x80100020, 0x80008020,
    0x80000020, 0x80108020, 0x80108000, 0x80000000,
    0x80008000, 0x00100000, 0x00000020, 0x80100020,
    0x00108000, 0x00100020, 0x80008020, 0x00000000,
    0x80000000, 0x00008000, 0x00108020, 0x80100000,
    0x00100020, 0x80000020, 0x00000000, 0x00108000,
    0x00008020, 0x80108000, 0x80100000, 0x00008020,
    0x00000000, 0x00108020, 0x80100020, 0x00100000,
    0x80008020, 0x80100000, 0x80108000, 0x00008000,
    0x80100000, 0x80008000, 0x00000020, 0x80108020,
    0x00108020, 0x00000020, 0x00008000, 0x80000000,
    0x00008020, 0x80108000, 0x00100000, 0x80000020,
    0x00100020, 0x80008020, 0x80000020, 0x00100020,
    0x00108000, 0x00000000, 0x80008000, 0x00008020,
    0x80000000, 0x80100020, 0x80108020, 0x00108000 },
  { 0x00000208, 0x08020200, 0x00000000, 0x08020008,
    0x08000200, 0x00000000, 0x00020208, 0x08000200,
    0x00020008, 0x08000008, 0x08000008, 0x00020000,
    0x08020208, 0x00020008, 0x08020000, 0x00000208,
    0x08000000, 0x00000008, 0x08020200, 0x00000200,
    0x00020200, 0x08020000, 0x08020008, 0x00020208,
    0x08000208, 0x00020200, 0x00020000, 0x08000208,
    0x00000008, 0x08020208, 0x00000200, 0x08000000,
    0x08020200, 0x08000000, 0x00020008, 0x00000208,
    0x00020000, 0x08020200, 0x08000200, 0x00000000,
    0x00000200, 0x00020008, 0x08020208, 0x08000200,
    0x08000008, 0x00000200, 0x00000000, 0x08020008,
    0x08000208, 0x00020000, 0x08000000, 0x08020208,
    0x00000008, 0x00020208, 0x00020200, 0x08000008,
    0x08020000, 0x08000208, 0x00000208, 0x08020000,
    0x00020208, 0x00000008, 0x08020008, 0x00020200 },
  { 0x00802001, 0x00002081, 0x00002081, 0x00000080,
    0x00802080, 0x00800081, 0x00800001, 0x00002001,
    0x00000000, 0x00802000, 0x00802000, 0x00802081,
    0x00000081, 0x00000000, 0x00800080, 0x00800001,
    0x00000001, 0x00002000, 0x00800000, 0x00802001,
    0x00000080, 0x00800000, 0x00002001, 0x00002080,
    0x00800081, 0x00000001, 0x00002080, 0x00800080,
    0x00002000, 0x00802080, 0x00802081, 0x00000081,
    0x00800080, 0x00800001, 0x00802000, 0x00802081,
    0x00000081, 0x00000000, 0x00000000, 0x00802000,
    0x00002080, 0x00800080, 0x00800081, 0x00000001,
    0x00802001, 0x00002081, 0x00002081, 0x00000080,
    0x00802081, 0x00000081, 0x00000001, 0x00002000,
    0x00800001, 0x00002001, 0x00802080, 0x00800081,
    0x00002001, 0x00002080, 0x00800000, 0x00802001,
    0x00000080, 0x00800000, 0x00002000, 0x00802080 },
  { 0x00000100, 0x02080100, 0x02080000, 0x42000100,
    0x00080000, 0x00000100, 0x40000000, 0x02080000,
    0x40080100, 0x00080000, 0x02000100, 0x40080100,
    0x42000100, 0x42080000, 0x00080100, 0x40000000,
    0x02000000, 0x40080000, 0x40080000, 0x00000000,
    0x40000100, 0x42080100, 0x42080100, 0x02000100,
    0x42080000, 0x40000100, 0x00000000, 0x42000000,
    0x02080100, 0x02000000, 0x42000000, 0x00080100,
    0x00080000, 0x42000100, 0x00000100, 0x02000000,
    0x40000000, 0x02080000, 0x42000100, 0x40080100,
    0x02000100, 0x40000000, 0x42080000, 0x02080100,
    0x40080100, 0x00000100, 0x02000000, 0x42080000,
    0x42080100, 0x00080100, 0x42000000, 0x42080100,
    0x02080000, 0x00000000, 0x40080000, 0x42000000,
    0x00080100, 0x02000100, 0x40000100, 0x00080000,
    0x00000000, 0x40080000, 0x02080100, 0x40000100 },
  { 0x20000010, 0x20400000, 0x00004000, 0x20404010,
    0x20400000, 0x00000010, 0x20404010, 0x00400000,
    0x20004000, 0x00404010, 0x00400000, 0x20000010,
    0x00400010, 0x20004000, 0x20000000, 0x00004010,
    0x00000000, 0x00400010, 0x20004010, 0x00004000,
    0x00404000, 0x20004010, 0x00000010, 0x20400010,
    0x20400010, 0x00000000, 0x00404010, 0x20404000,
    0x00004010, 0x00404000, 0x20404000, 0x20000000,
    0x20004000, 0x00000010, 0x20400010, 0x00404000,
    0x20404010, 0x00400000, 0x00004010, 0x20000010,
    0x00400000, 0x20004000, 0x20000000, 0x00004010,
    0x20000010, 0x20404010, 0x00404000, 0x20400000,
    0x00404010, 0x20404000, 0x00000000, 0x20400010,
    0x00000010, 0x00004000, 0x20400000, 0x00404010,
    0x00004000, 0x00400010, 0x20004010, 0x00000000,
    0x20404000, 0x20000000, 0x00400010, 0x20004010 },
  { 0x00200000, 0x04200002, 0x04000802, 0x00000000,
    0x00000800, 0x04000802, 0x00200802, 0x04200800,
    0x04200802, 0x00200000, 0x00000000, 0x04000002,
    0x00000002, 0x04000000, 0x04200002, 0x00000802,
    0x04000800, 0x00200802, 0x00200002, 0x04000800,
    0x04000002, 0x04200000, 0x04200800, 0x00200002,
    0x04200000, 0x00000800, 0x00000802, 0x04200802,
    0x00200800, 0x00000002, 0x04000000, 0x00200800,
    0x04000000, 0x00200800, 0x00200000, 0x04000802,
    0x04000802, 0x04200002, 0x04200002, 0x00000002,
    0x00200002, 0x04000000, 0x04000800, 0x00200000,
    0x04200800, 0x00000802, 0x00200802, 0x04200800,
    0x00000802, 0x04000002, 0x04200802, 0x04200000,
    0x00200800, 0x00000000, 0x00000002, 0x04200802,
    0x00000000, 0x00200802, 0x04200000, 0x00000800,
    0x04000002, 0x04000800, 0x00000800, 0x00200002 },
  { 0x10001040, 0x00001000, 0x00040000, 0x10041040,
    0x10000000, 0x10001040, 0x00000040, 0x10000000,
    0x00040040, 0x10040000, 0x10041040, 0x00041000,
    0x10041000, 0x00041040, 0x00001000, 0x00000040,
    0x10040000, 0x10000040, 0x10001000, 0x00001040,
    0x00041000, 0x00040040, 0x10040040, 0x10041000,
    0x00001040, 0x00000000, 0x00000000, 0x10040040,
    0x10000040, 0x10001000, 0x00041040, 0x00040000,
    0x00041040, 0x00040000, 0x10041000, 0x00001000,
    0x00000040, 0x10040040, 0x00001000, 0x00041040,
    0x10001000, 0x00000040, 0x10000040, 0x10040000,
    0x10040040, 0x10000000, 0x00040000, 0x10001040,
    0x00000000, 0x10041040, 0x00040040, 0x10000040,
    0x10040000, 0x10001000, 0x10001040, 0x00000000,
    0x10041040, 0x00041000, 0x00041000, 0x00001040,
    0x00001040, 0x00040040, 0x10000000, 0x10041000 }
};



/* Richard Outerbridge's clever initial permutation algorithm
 * (see Schneier p 478)
 *
 * The convention here is to rotate each half left by 1 bit, i.e.,
 * so that "left" contains permuted input bits 2, 3, 4, ... 1 and
 * "right" contains 33, 34, 35, ... 32 (using origin-1 numbering as
 * in the FIPS). This allows us to avoid one of the two
 * rotates that would otherwise be required in each of the 16 rounds.
 */
static void flea_des_iperm (flea_u32_t* p_left, flea_u32_t* p_right)
{
  unsigned long work;
  flea_u32_t left = *p_left;
  flea_u32_t right = *p_right;

  work = ((left >> 4) ^ right) & 0x0f0f0f0f;
  right ^= work;
  left ^= work << 4;
  work = ((left >> 16) ^ right) & 0xffff;
  right ^= work;
  left ^= work << 16;
  work = ((right >> 2) ^ left) & 0x33333333;
  left ^= work;
  right ^= (work << 2);
  work = ((right >> 8) ^ left) & 0xff00ff;
  left ^= work;
  right ^= (work << 8);
  right = (right << 1) | (right >> 31);
  work = (left ^ right) & 0xaaaaaaaa;
  left ^= work;
  right ^= work;
  left = (left << 1) | (left >> 31);
  *p_left = left;
  *p_right = right;
}

/* Inverse permutation, also from Outerbridge via Schneier */
static void flea_des_fperm (flea_u32_t* p_left, flea_u32_t* p_right)
{
  flea_u32_t left = *p_left;
  flea_u32_t right = *p_right;
  flea_u32_t work;

  right = (right << 31) | (right >> 1);
  work = (left ^ right) & 0xaaaaaaaa;
  left ^= work;
  right ^= work;
  left = (left >> 1) | (left << 31);
  work = ((left >> 8) ^ right) & 0xff00ff;
  right ^= work;
  left ^= work << 8;
  work = ((left >> 2) ^ right) & 0x33333333;
  right ^= work;
  left ^= work << 2;
  work = ((right >> 16) ^ left) & 0xffff;
  left ^= work;
  right ^= work << 16;
  work = ((right >> 4) ^ left) & 0x0f0f0f0f;
  left ^= work;
  right ^= work << 4;
  *p_left = left;
  *p_right = right;
}

/* Primitive function F.
 * Input is r, subkey array in keys, output is XORed into l.
 * Each round consumes eight 6-bit subkeys, one for
 * each of the 8 S-boxes, 2 longs for each round.
 * Each long contains four 6-bit subkeys, each taking up a byte.
 * The first long contains, from high to low end, the subkeys for
 * S-boxes 1, 3, 5 & 7; the second contains the subkeys for S-boxes
 * 2, 4, 6 & 8 (using the origin-1 S-box numbering in the standard,
 * not the origin-0 numbering used elsewhere in this code)
 * See comments elsewhere about the pre-rotated values of r and Spbox.
 */
void flea_des_f (flea_u32_t* p_l, flea_u32_t* p_r, const flea_u32_t* keys )
{
  flea_u32_t l = *p_l;
  flea_u32_t r = *p_r;
  flea_u32_t work;

  work = (((r >> 4) | (r << 28)) ^ *keys++);
  l ^= Spbox[6][work & 0x3f];
  l ^= Spbox[4][(work >> 8) & 0x3f];
  l ^= Spbox[2][(work >> 16) & 0x3f];
  l ^= Spbox[0][(work >> 24) & 0x3f];
  work = (r ^ *keys);
  l ^= Spbox[7][work & 0x3f];
  l ^= Spbox[5][(work >> 8) & 0x3f];
  l ^= Spbox[3][(work >> 16) & 0x3f];
  l ^= Spbox[1][(work >> 24) & 0x3f];
  *p_l = l;
  *p_r = r;
}

/* permuted choice table (key) */
static flea_u8_t pc1[] = {
  57, 49,	 41,	 33,	 25,	17, 9,
  1,	58,	 50,	 42,	 34,	26, 18,
  10, 2,	 59,	 51,	 43,	35, 27,
  19, 11,	 3,		 60,	 52,	44, 36,

  63, 55,	 47,	 39,	 31,	23, 15,
  7,	62,	 54,	 46,	 38,	30, 22,
  14, 6,	 61,	 53,	 45,	37, 29,
  21, 13,	 5,		 28,	 20,	12, 4
};

/* number left rotations of pc1 */
static flea_u8_t totrot[] = {
  1, 2, 4, 6, 8, 10, 12, 14, 15, 17, 19, 21, 23, 25, 27, 28
};

/* permuted choice key (table) */
static flea_u8_t pc2[] = {
  14, 17,	 11,	 24,	1,	 5,
  3,	28,	 15,	 6,		21,	 10,
  23, 19,	 12,	 4,		26,	 8,
  16, 7,	 27,	 20,	13,	 2,
  41, 52,	 31,	 37,	47,	 55,
  30, 40,	 51,	 45,	33,	 48,
  44, 49,	 39,	 56,	34,	 53,
  46, 42,	 50,	 36,	29,	 32
};

static int bytebit[] = {
  0200, 0100, 040, 020, 010, 04, 02, 01
};

flea_err_t THR_flea_single_des_setup_key (flea_ecb_mode_ctx_t* ctx__pt, const flea_u8_t *key)
{
  return THR_flea_single_des_setup_key_with_key_offset(ctx__pt, 0, key);
}

flea_err_t THR_flea_single_des_setup_key_with_key_offset (flea_ecb_mode_ctx_t* ctx__p_t, flea_al_u16_t expanded_key_offset__alu16,  const flea_u8_t *key)
{
  flea_u8_t* pc1m;
  flea_u8_t* pcr;
  flea_u8_t* ks;
  const flea_al_u16_t work_buf_len = 2 * 56 + 8;

  FLEA_DECL_BUF(work__b_u8, flea_u8_t, work_buf_len);

  FLEA_THR_BEG_FUNC();
  FLEA_ALLOC_BUF(work__b_u8, work_buf_len);

  pc1m = work__b_u8;
  pcr = work__b_u8 + 56;
  ks = pcr + 56;

  register int i, j, l;
  int m;

  flea_u32_t* k = ctx__p_t->expanded_key__bu8 + expanded_key_offset__alu16;
  for(j = 0; j < 56; j++)
  {                           /* convert pc1 to bits of key */
    l = pc1[j] - 1;           /* integer bit location	 */
    m = l & 07;               /* find bit		 */
    pc1m[j] = (key[l >> 3] &  /* find which key byte l is in */
               bytebit[m])    /* and which bit of that byte */
              ? 1 : 0;        /* and store 1-bit result */
  }
  for(i = 0; i < 16; i++)
  {                   /* key chunk for each iteration */
    memset(ks, 0, 8); /* Clear key schedule */
    for(j = 0; j < 56; j++)
    {                 /* rotate pc1 the right amount */
      pcr[j] = pc1m[(l = j + totrot[i]) < (j < 28 ? 28 : 56) ? l : l - 28];
    }
    /* rotate left and right halves independently */
    for(j = 0; j < 48; j++)
    { /* select bits individually */
      /* check bit that goes to ks[j] */
      if(pcr[pc2[j] - 1])
      {
        /* mask it in if it's there */
        l = j % 6;
        ks[j / 6] |= bytebit[l] >> 2;
      }
    }
    /* Now convert to odd/even interleaved form for use in F */
    k[i * 2] = (((flea_u32_t)ks[0]) << 24)
               | (((flea_u32_t)ks[2]) << 16)
               | (((flea_u32_t)ks[4]) << 8)
               | ((flea_u32_t)ks[6]);
    k[i * 2 + 1] = ((flea_u32_t)ks[1] << 24)
                   | (((flea_u32_t)ks[3]) << 16)
                   | (((flea_u32_t)ks[5]) << 8)
                   | ((flea_u32_t)ks[7]);
  }
  FLEA_THR_FIN_SEC(
    FLEA_FREE_BUF_FINAL(work__b_u8);
    );
}

void flea_single_des_encrypt_block (const flea_ecb_mode_ctx_t* ctx__pt, const flea_u8_t* input__pcu8, flea_u8_t* output__pu8)
{
  flea_single_des_encrypt_block_with_key_offset(ctx__pt, 0, input__pcu8, output__pu8);
}

void flea_single_des_encrypt_block_with_key_offset (const flea_ecb_mode_ctx_t* ctx__p_t, flea_al_u16_t expanded_key_offset__alu16, const flea_u8_t* input__pc_u8, flea_u8_t* output__p_u8)
{
  flea_al_u8_t i;
  flea_u32_t left, right;
  const flea_u32_t *keys;

  left = flea__decode_U32_BE(input__pc_u8);
  right = flea__decode_U32_BE(input__pc_u8 + 4);

  flea_des_iperm(&left, &right);

  keys = &ctx__p_t->expanded_key__bu8[expanded_key_offset__alu16];
  for(i = 0; i < 8; i++)
  {
    flea_des_f(&left, &right, keys + 0);
    flea_des_f(&right, &left, keys + 2);
    keys += 4;
  }

  flea_des_fperm(&left, &right);
  flea__encode_U32_BE(right, output__p_u8);
  flea__encode_U32_BE(left, output__p_u8 + 4);
}

void flea_single_des_decrypt_block (const flea_ecb_mode_ctx_t* ctx__pt, const flea_u8_t* input__pcu8, flea_u8_t* output__pu8)
{
  flea_single_des_decrypt_block_with_key_offset(ctx__pt, 0, input__pcu8, output__pu8);
}

void flea_single_des_decrypt_block_with_key_offset (const flea_ecb_mode_ctx_t* ctx__p_t, flea_al_u16_t expanded_key_offset__alu16, const flea_u8_t* input__pc_u8, flea_u8_t* output__p_u8)
{
  flea_al_u8_t i;
  flea_u32_t left, right;
  const flea_u32_t *keys;


  left = flea__decode_U32_BE(input__pc_u8);
  right = flea__decode_U32_BE(input__pc_u8 + 4);
  flea_des_iperm(&left, &right);

  keys = &ctx__p_t->expanded_key__bu8[30 + expanded_key_offset__alu16];

  for(i = 0; i < 8; i++)
  {
    flea_des_f(&left, &right, keys - 0);
    flea_des_f(&right, &left, keys - 2);
    keys -= 4;
  }

  flea_des_fperm(&left, &right);

  flea__encode_U32_BE(right, output__p_u8);
  flea__encode_U32_BE(left, output__p_u8 + 4);
}

#endif // #ifdef FLEA_HAVE_DES
