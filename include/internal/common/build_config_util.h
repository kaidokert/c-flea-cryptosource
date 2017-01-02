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



#ifndef _flea_build_config_util__H_
#define _flea_build_config_util__H_


#if defined FLEA_HAVE_ECDSA || defined FLEA_HAVE_ECKA
#define FLEA_HAVE_ECC
#endif

#ifdef FLEA_HAVE_RSA
#define FLEA_HAVE_PK_CS
#endif

#if defined FLEA_HAVE_RSA || defined FLEA_HAVE_ECDSA
#define FLEA_HAVE_ASYM_SIG
#endif

#ifndef FLEA_USE_HEAP_BUF
#define FLEA_USE_STACK_BUF
#endif

#ifdef FLEA_HAVE_AES_BLOCK_DECR
#define FLEA_DO_IF_HAVE_AES_BLOCK_DECR(x) x
#else
#define FLEA_DO_IF_HAVE_AES_BLOCK_DECR(x)
#endif

#if FLEA_CRT_RSA_WINDOW_SIZE > 1
#define FLEA_DO_IF_RSA_CRT_WINDOW_SIZE_GREATER_ONE(x) do { x } while(0)
#else
#define FLEA_DO_IF_RSA_CRT_WINDOW_SIZE_GREATER_ONE(x)
#endif

// fixed 32 bit difference so far
#define FLEA_RSA_CRT_PQ_BIT_DIFF 32
/************ Begin MAC and AE ************/

#ifdef FLEA_HAVE_EAX
#define FLEA_HAVE_AE
#define FLEA_HAVE_CMAC
#endif

#if defined FLEA_HAVE_HMAC || defined FLEA_HAVE_CMAC
#define FLEA_HAVE_MAC
#endif

/************ End MAC and AE ************/


#endif /* h-guard */
