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



#ifndef _flea_alloc_int__H_
#define _flea_alloc_int__H_

#ifndef FLEA_USE_BUF_DBG_CANARIES

#   define FLEA_NB_STACK_BUF_ENTRIES(__name) FLEA_NB_ARRAY_ENTRIES(__name)

#   define __FLEA_GET_ALLOCATED_BUF_NAME(__name)  __name

#   define FLEA_BUF_SET_CANANRIES(__name, __size)

#   define FLEA_BUF_CHK_DBG_CANARIES(__name)

#ifdef FLEA_USE_HEAP_BUF

#   define FLEA_DECL_BUF(__name, __type, __static_size) \
  __type * __name = NULL

#   define FLEA_ALLOC_BUF(__name, __dynamic_size) \
  FLEA_ALLOC_MEM_ARR(__name, __dynamic_size)

#   define FLEA_FREE_BUF_FINAL(__name) \
  FLEA_FREE_MEM_CHK_NULL(__name)

#   define FLEA_FREE_BUF(__name) \
  FLEA_FREE_MEM_CHK_SET_NULL(__name)

#   define FLEA_FREE_BUF_FINAL_SECRET_ARR(__name, __type_len) \
  do { \
    if(__name) { \
      flea_memzero_secure((flea_u8_t*)__name, (__type_len) * sizeof(__name[0])); \
      FLEA_FREE_MEM(__name); \
    } \
  } while(0)

#elif defined FLEA_USE_STACK_BUF // #ifdef FLEA_USE_HEAP_BUF

#   define FLEA_DECL_BUF(__name, __type, __static_size) \
  __type __name [__static_size]

#   define FLEA_STACK_BUF_NB_ENTRIES(__name) (sizeof(__name) / sizeof(__name[0]))

#   define FLEA_ALLOC_BUF(__name, __dynamic_size)

#   define FLEA_FREE_BUF_FINAL(__name)

#   define FLEA_FREE_BUF(__name)

#   define FLEA_FREE_BUF_FINAL_SECRET_ARR(__name, __type_len) \
  do { \
    flea_memzero_secure((flea_u8_t*)__name, (__type_len) * sizeof(__name[0])); \
  } while(0)
#else
#   error neither heap nor stack buf defined
#endif  // #ifdef FLEA_USE_HEAP_BUF

#endif  // #ifndef FLEA_USE_BUF_DBG_CANARIES

#endif  /* h-guard */

