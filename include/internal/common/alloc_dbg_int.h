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



#ifndef _flea_alloc_dbg_int__H_
#define _flea_alloc_dbg_int__H_

#include "internal/common/default.h"
#include "flea/types.h"

extern flea_u8_t flea_dbg_canaries_flag;

#ifdef FLEA_USE_BUF_DBG_CANARIES
#define __FLEA_SIGNAL_DBG_CANARY_ERROR() do { flea_dbg_canaries_flag = 1; } while(0)

#define FLEA_CLEAR_DBG_CANARY_ERROR() do { flea_dbg_canaries_flag = 0; } while(0)

#define FLEA_IS_DBG_CANARY_ERROR_SIGNALLED() (flea_dbg_canaries_flag != 0)
#endif

#ifdef FLEA_USE_BUF_DBG_CANARIES

#   define FLEA_BUF_DBG_CANARIES_ARE_NOT_OK(__name) \
  (((flea_u8_t*)(__name ## _FLEA_DBG_CANARIES__RAW))[0] != 0xDE || \
   ((flea_u8_t*)(__name ## _FLEA_DBG_CANARIES__RAW))[1] != 0xAD || \
   ((flea_u8_t*)(__name ## _FLEA_DBG_CANARIES__RAW))[2] != 0xBE || \
   ((flea_u8_t*)(__name ## _FLEA_DBG_CANARIES__RAW))[3] != 0xEF || \
   ((flea_u8_t*)(&__name[__name ## _FLEA_DBG_CANARIES_DYNAMIC_SIZE]))[ 0] != 0xA5 || \
   ((flea_u8_t*)(&__name[__name ## _FLEA_DBG_CANARIES_DYNAMIC_SIZE]))[ 1] != 0xAF || \
   ((flea_u8_t*)(&__name[__name ## _FLEA_DBG_CANARIES_DYNAMIC_SIZE]))[ 2] != 0x49 || \
   ((flea_u8_t*)(&__name[__name ## _FLEA_DBG_CANARIES_DYNAMIC_SIZE]))[ 3] != 0x73)

#   define FLEA_NB_STACK_BUF_ENTRIES(__name) ((sizeof(__name ## _FLEA_DBG_CANARIES__RAW) - 8) / sizeof(__name[0]))
#   define __FLEA_GET_ALLOCATED_BUF_NAME(__name)  __name ## _FLEA_DBG_CANARIES__RAW
#   define FLEA_BUF_SET_CANANRIES(__name, __size) \
  do { \
    ((flea_u8_t*)(__name ## _FLEA_DBG_CANARIES__RAW))[0] = 0xDE; \
    ((flea_u8_t*)(__name ## _FLEA_DBG_CANARIES__RAW))[1] = 0xAD; \
    ((flea_u8_t*)(__name ## _FLEA_DBG_CANARIES__RAW))[2] = 0xBE; \
    ((flea_u8_t*)(__name ## _FLEA_DBG_CANARIES__RAW))[3] = 0xEF; \
    ((flea_u8_t*)(&__name[__size]))[ 0] = 0xA5; \
    ((flea_u8_t*)(&__name[__size]))[ 1] = 0xAF; \
    ((flea_u8_t*)(&__name[__size]))[ 2] = 0x49; \
    ((flea_u8_t*)(&__name[__size]))[ 3] = 0x73; \
  } while(0)

#   define FLEA_BUF_CHK_DBG_CANARIES(__name) \
  do { \
    if( FLEA_BUF_DBG_CANARIES_ARE_NOT_OK(__name)) \
    { __FLEA_FREE_BUF_SET_NULL(__name ## _FLEA_DBG_CANARIES__RAW);  /*s.th. tests don't show leak */ \
      __FLEA_SIGNAL_DBG_CANARY_ERROR(); }                           /* we are in the cleanup section and cannot use THROW*/ \
  } while(0)

#ifdef FLEA_USE_HEAP_BUF
#     define FLEA_DECL_BUF(__name, __type, __static_size) \
  __type * __name ## _FLEA_DBG_CANARIES__RAW = NULL; \
  __type* __name = NULL; \
  typedef __type __name ## _DBG_CANARIES_HELP_TYPE; \
  flea_u32_t __name ## _FLEA_DBG_CANARIES_DYNAMIC_SIZE = 0

#     define FLEA_ALLOC_BUF(__name, __dynamic_size) \
  do { \
    __name ## _FLEA_DBG_CANARIES_DYNAMIC_SIZE = __dynamic_size; \
    FLEA_ALLOC_MEM(__name ## _FLEA_DBG_CANARIES__RAW, sizeof(__name[0]) * (__dynamic_size) + 8); \
    __name = (__name ## _DBG_CANARIES_HELP_TYPE*)  & (((flea_u8_t*)__name ## _FLEA_DBG_CANARIES__RAW)[4]); \
    FLEA_BUF_SET_CANANRIES(__name, __dynamic_size); \
  } while(0)

#     define FLEA_FREE_BUF_FINAL(__name) \
  do { \
    if(__name) { \
      if( FLEA_BUF_DBG_CANARIES_ARE_NOT_OK(__name)) \
      { __FLEA_SIGNAL_DBG_CANARY_ERROR(); }        /* we are in the cleanup section and cannot use THROW*/ \
      FLEA_FREE_MEM(__name ## _FLEA_DBG_CANARIES__RAW); \
    } \
  } while(0)

#     define FLEA_FREE_BUF_FINAL_SECRET_ARR(__name, __type_len) \
  do { \
    if(__name) { \
      flea_memzero_secure((flea_u8_t*)__name, (__type_len) * sizeof(__name[0])); \
      if( FLEA_BUF_DBG_CANARIES_ARE_NOT_OK(__name)) \
      { __FLEA_SIGNAL_DBG_CANARY_ERROR(); }        /* we are in the cleanup section and cannot use THROW*/ \
      FLEA_FREE_MEM(__name ## _FLEA_DBG_CANARIES__RAW); \
    } \
  } while(0)

#     define FLEA_FREE_BUF(__name) \
  do { \
    if(__name) { \
      if( FLEA_BUF_DBG_CANARIES_ARE_NOT_OK(__name)) \
      {  __FLEA_SIGNAL_DBG_CANARY_ERROR(); }  /* we are in the cleanup section and cannot use THROW*/ \
      FLEA_FREE_MEM_SET_NULL(__name ## _FLEA_DBG_CANARIES__RAW); \
      __name = NULL;                          /*s. th. user buffer is also NULL */ \
    } \
  } while(0)

#elif defined FLEA_USE_STACK_BUF // #ifdef FLEA_USE_HEAP_BUF

#     define FLEA_DECL_BUF(__name, __type, __static_size) \
  flea_u32_t __name ## _FLEA_DBG_CANARIES_DYNAMIC_SIZE = __static_size; \
  flea_u8_t __name ## _FLEA_DBG_CANARIES__RAW[(__static_size) * sizeof(__type) + 8]; \
  __type* __name = (__type*)&(((flea_u8_t*)__name ## _FLEA_DBG_CANARIES__RAW)[4]); \
  FLEA_BUF_SET_CANANRIES(__name, __static_size)

#     define FLEA_STACK_BUF_NB_ENTRIES(__name) ((sizeof(__name ## _FLEA_DBG_CANARIES__RAW) - 8) / sizeof(__name[0]))

#     define FLEA_ALLOC_BUF(__name, __dynamic_size) \

#      define FLEA_FREE_BUF_FINAL(__name) \
  do { \
    if( FLEA_BUF_DBG_CANARIES_ARE_NOT_OK(__name)) \
    { __FLEA_SIGNAL_DBG_CANARY_ERROR(); } \
  } while(0)


#      define FLEA_FREE_BUF(__name) FLEA_FREE_BUF_FINAL(__name)

#     define FLEA_FREE_BUF_FINAL_SECRET_ARR(__name, __type_len) \
  do { \
    if(__name) { \
      flea_memzero_secure((flea_u8_t*)__name, (__type_len) * sizeof(__name[0])); \
      if( FLEA_BUF_DBG_CANARIES_ARE_NOT_OK(__name)) \
      { __FLEA_SIGNAL_DBG_CANARY_ERROR(); } \
    } \
  } while(0)
#else
#error neither heap nor stack buf defined
#endif  //  #ifdef FLEA_USE_HEAP_BUF

#endif  // #ifdef FLEA_USE_BUF_DBG_CANARIES

#endif  /* h-guard */
