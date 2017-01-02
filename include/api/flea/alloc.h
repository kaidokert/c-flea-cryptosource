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


#ifndef _flea_alloc_H_
#define _flea_alloc_H_

#include <stdlib.h> // for malloc
#include "internal/common/alloc_dbg_int.h"
#include "internal/common/alloc_int.h"
/**
 * use standard malloc and free
 */
#define MY_FLEA_ALLOC_MEM(__ptr, __size) \
  do { (__ptr) = malloc(__size); } while(0)

#define MY_FLEA_FREE_MEM(__ptr) \
  free(__ptr)

/***********************************/

#define FLEA_ALLOC_MEM(__ptr, __size) \
  do { \
    MY_FLEA_ALLOC_MEM(__ptr, __size); \
    if(!(__ptr)) { \
      FLEA_THROW("could not aquire memory", FLEA_ERR_OUT_OF_MEM); } \
  } while(0)

#define FLEA_ALLOC_MEM_ARR(__ptr, __size) FLEA_ALLOC_MEM((__ptr), sizeof((__ptr)[0]) * (__size))

#define FLEA_ALLOC_TYPE(__ptr) FLEA_ALLOC_MEM((__ptr), sizeof((__ptr)[0]))

#define FLEA_FREE_MEM(__ptr) \
  do { \
    MY_FLEA_FREE_MEM(__ptr); \
  } while(0)

#define FLEA_FREE_MEM_SET_NULL(__ptr) \
  do { \
    FLEA_FREE_MEM(__ptr); \
    (__ptr) = 0; \
  } while(0)

#define FLEA_FREE_MEM_CHK_NULL(__ptr) \
  do { \
    if(__ptr) { \
      FLEA_FREE_MEM(__ptr); \
    } \
  } while(0)

#define FLEA_FREE_MEM_CHK_SET_NULL(__ptr) \
  do { \
    FLEA_FREE_MEM_CHK_NULL(__ptr); \
    (__ptr) = 0; \
  } while(0)

#if defined FLEA_USE_HEAP_BUF && defined FLEA_USE_STACK_BUF
#error only FLEA_USE_HEAP_BUF or FLEA_USE_STACK_BUF may be defined, not both
#endif


#ifdef FLEA_USE_HEAP_BUF
#define FLEA_HEAP_OR_STACK_CODE(__heap, __stack) __heap
#define FLEA_DO_IF_USE_HEAP_BUF(__x) do { __x } while(0)
#define __FLEA_FREE_BUF_SET_NULL(__name) FLEA_FREE_MEM_SET_NULL(__name)
#define FLEA_DECL_DYN_LEN(__name, __type, __value) __len_type __dyn_len_name = __static_len
#else
#define FLEA_HEAP_OR_STACK_CODE(__heap, __stack) __stack
#define FLEA_DO_IF_USE_HEAP_BUF(__x)
#define __FLEA_FREE_BUF_SET_NULL(__name)
#endif

#define FLEA_FREE_MEM_SET_NULL_IF_USE_HEAP_BUF(__x)  __FLEA_FREE_BUF_SET_NULL(__x)

#define FLEA_DECL_OBJ(__name, __type) __type __name = __type ## __INIT_VALUE
#ifdef FLEA_USE_HEAP_BUF

#     define FLEA_FREE_MEM_CHECK_SET_NULL_SECRET_ARR(__name, __type_len) \
  do { \
    if(__name) { \
      flea_memzero_secure((flea_u8_t*)__name, (__type_len) * sizeof(__name[0])); \
      FLEA_FREE_MEM_SET_NULL(__name); \
    } \
  } while(0)


#     define FLEA_FREE_BUF_SECRET_ARR(__name, __type_len) \
  do { \
    if(__name) { \
      flea_memzero_secure((flea_u8_t*)__name, (__type_len) * sizeof(__name[0])); \
      FLEA_BUF_CHK_DBG_CANARIES(__name); \
      FLEA_FREE_MEM_SET_NULL(__FLEA_GET_ALLOCATED_BUF_NAME(__name)); \
      __name = NULL;         /*s. th. user buffer is also NULL */ \
    } \
  } while(0)


#elif defined FLEA_USE_STACK_BUF // #ifdef FLEA_USE_HEAP_BUF

#     define FLEA_FREE_BUF_SECRET_ARR(__name, __type_len) \
  do { \
    flea_memzero_secure((flea_u8_t*)__name, (__type_len) * sizeof(__name[0])); \
    FLEA_BUF_CHK_DBG_CANARIES(__name); \
  } while(0)
#     define FLEA_FREE_MEM_CHECK_SET_NULL_SECRET_ARR(__name, __type_len) \
  do { \
    flea_memzero_secure((flea_u8_t*)__name, (__type_len) * sizeof(__name[0])); \
  } while(0)

#else // #elif defined FLEA_USE_STACK_BUF
#error no buf type (heap or stack) defined for flea
#endif


#endif /* h-guard */
