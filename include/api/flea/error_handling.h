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


#ifndef __flea_error_handling_H_
#define __flea_error_handling_H_

#include "flea/error.h"
#include "internal/common/default.h"

/**
 * The flea error handling concept is based on return codes. Any function which
 * may throw errors is indicated by the prefix THR_ and has flea_err_t as return
 * value.
 * The programming approach taken in flea realizes maximal reliability of the
 * code. It is based on the the usage of the flea macro framework for memory
 * allocation (or potentially other types of resource allocations) and the calling of throwing functions.
 *
 * In such a function, all variables which manage resources (in most cases heap
 * memory is the only relevant resource) are initialized to specific values
 * prior to entering the function's code section. For pointers that potentially will point
 * to heap memory during the function execution, this means that they are
 * initialized to NULL; for flea objects which hold resources themselves in the
 * constructed state, specific initial values are defined. This ensures that in the
 * cleanup section at the end of the function it is alway possible to determine
 * whether the resources held by such a variable must be released or not.

 * The code section of each throwing function starts with the macro
 * FLEA_THR_BEG_FUNC()
 * which declares the return value variable of the function used by other macros
 * of the framework. In the code
 * section, calls to throwing functions are made with the macro FLEA_CCALL(),
 * i.e. as "checked calls". If the called function returns with an error, then
 * the macro causes a jump to the cleanup section. After the cleanup is
 * performed, the function returns the error code it has received from the
 * failing function call.
 * Heap memory allocations are done with the macros from the alloc.h header.
 * These macros also perform error handling, i.e. the treatment of a failing
 * allocation, in the same manner.
 *
 * Within the code section, flea objects that hold resources are constructed
 * with THR_flea_<type>__ctor...() functions. These function are the constructors
 * of these objects and perform the resource allocations and the update of other
 * fields of the object.
 *
 * Within the code section, the macro FLEA_THROW() can be used to raise
 * exceptions. In this case a specific error value provided as second argument
 * to that macro is set as the return value, and the execution jumps to the
 * cleanup section. The first argument to that macro is a string, which is only
 * used to print an error message using printf if the FLEA_DO_PRINTF_ERRS define
 * is set. This mechanism can be used in operating system environments to ease
 * debugging.
 *
 * If at any point in the code the return of the function is desired, the macro
 * FLEA_THR_RETURN() has to be used. This macro directly jumps to the cleanup
 * section with a return value indicating successful completion.
 *
 * The cleanup section is given by the code provided as the argument to FLEA_THR_FIN_SEC().
 * From the above explanations, it becomes clear that this code is
 * unconditionally executed. Thus, the freeing of pointers is done with macros
 * which first check whether the pointer is different from NULL before calling
 * the deallocation function. For flea objects that hold resources (have been
 * constructed using ctor-functions), this means that the corresponding ..._dtor
 * function has to be called. These destructor functions can always be called:
 * they determine themselves whether the object is still in its initial state or
 * has been constructed and thus resource deallocations are necessary. The
 * destructors are designed in such way that they can even handle partly
 * constructed objects, which could result from an error during the execution of a constructor.
 *
 *
 */

#define FLEA_THR_BEG_FUNC() \
  flea_err_t _flea_err_retval = FLEA_ERR_FINE
/**/


#ifdef FLEA_DO_PRINTF_ERRS
#define FLEA_PRINTF_1_SWITCHTED(__format) printf(__format)
#define FLEA_PRINTF_2_SWITCHTED(__format, __arg1) printf(__format, __arg1)
#define FLEA_PRINTF_3_SWITCHTED(__format, __arg1, __arg2) printf(__format, __arg1, __arg2)
#define __FLEA_EVTL_PRINT_ERR(__func, __str) printf("%s: %s\n", __func, __str)
#else
#define FLEA_PRINTF_1_SWITCHTED(__format)
#define FLEA_PRINTF_2_SWITCHTED(__format, __arg1)
#define FLEA_PRINTF_3_SWITCHTED(__format, __arg1, __arg2)
#define __FLEA_EVTL_PRINT_ERR(__func, __str) do { } while(0)
#endif

#define FLEA_THROW(__mess, __val) \
  do { \
    _flea_err_retval = __val; \
    __FLEA_EVTL_PRINT_ERR(__func__, __mess); \
    goto _flea_cleanup; \
  } while(0)
/**/

#define _FLEA_IS_ERR_(__val) \
  (__val != FLEA_ERR_FINE)
/**/

#define FLEA_CALL_THR(__f) \
  do { \
    _flea_err_retval = __f; \
    if(_FLEA_IS_ERR_(_flea_err_retval)) { goto _flea_cleanup; } \
  } while(0)
/**/

#define FLEA_CCALL(__call) FLEA_CALL_THR(__call)

#define FLEA_THR_RETURN() \
  goto _flea_cleanup \
  /**/
#define FLEA_CHK_ERR_COND(__cond, __reaction) \
  do { \
    if(__cond) { \
      __reaction; \
    } \
  } while(0)


#define FLEA_THR_FIN_SEC(__cleanup_code) \
_flea_cleanup: \
  __cleanup_code \
  return _flea_err_retval
/**/

#define FLEA_THR_FIN_SEC_empty() \
_flea_cleanup: \
  return _flea_err_retval

#endif /* h-guard */
