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


#include "test_data_rsa_key_internal_format.h"
#include "flea/types.h"

const flea_u8_t rsa_2048_crt_key_internal_format__acu8[2048 / 8 / 2 * 5] =  { 0xC4, 0x6B, 0x3C, 0xC1, 0xA8, 0x81, 0x8E, 0x7B, 0xB7, 0x07, 0xAB, 0xEC, 0x2E, 0x85, 0x47, 0xE9, 0xDC, 0x3A, 0x82, 0xAF, 0x8F, 0x8E, 0x0B, 0x31, 0xD3, 0x65, 0x6E, 0x12, 0x3F, 0xF3, 0x39, 0x4F, 0xA5, 0x07, 0x1B, 0x13, 0x36, 0x68, 0xC1, 0xCB, 0x16, 0xDB, 0x7E, 0x1F, 0x84, 0x6C, 0x3D, 0xFB, 0x7A, 0xEE, 0x0D, 0x6E, 0x05, 0xE0, 0x81, 0xF6, 0xBB, 0x93, 0x77, 0xB2, 0x4C, 0x9F, 0x4C, 0xEF, 0xB3, 0xAC, 0x24, 0xB0, 0x55, 0x82, 0x82, 0x5C, 0x6C, 0x6A, 0x17, 0x5B, 0xCA, 0x2C, 0x7A, 0xAB, 0x3E, 0x32, 0x5D, 0xF2, 0xA3, 0x38, 0xED, 0xE1, 0x0D, 0xA1, 0x4B, 0xBF, 0x85, 0x81, 0x1B, 0x4D, 0x9B, 0xE3, 0x40, 0x11, 0x41, 0x92, 0x7E, 0x89, 0x69, 0x87, 0x51, 0x84, 0xA9, 0x55, 0xAF, 0x19, 0xEF, 0x66, 0x05, 0x9F, 0xBD, 0xA0, 0xC6, 0x38, 0x11, 0x56, 0x9F, 0x7E, 0x63, 0xCD, 0x63, 0xED,
                                                                              0xE5, 0x74, 0x5B, 0xDA, 0x8A, 0xC7, 0x2A, 0xF9, 0xE6, 0xE4, 0xA5, 0xB0, 0x4F, 0xA3, 0xD2, 0xEC, 0x7A, 0xBD, 0x2A, 0x3B, 0xD9, 0xDA, 0xD4, 0x8B, 0xAD, 0x2A, 0x04, 0x41, 0x4C, 0xE8, 0xF3, 0xCB, 0x7B, 0x26, 0x84, 0x14, 0xB7, 0x3B, 0x49, 0x7D, 0xF3, 0x21, 0x87, 0xFC, 0x2C, 0xD7, 0x49, 0xA9, 0xF1, 0xCD, 0xCB, 0x11, 0xF8, 0x82, 0x68, 0xE8, 0x0B, 0xAC, 0xCD, 0x27, 0x56, 0x59, 0x7C, 0x3E, 0x3C, 0x94, 0x96, 0x55, 0xB8, 0x0A, 0xD4, 0x8D, 0x63, 0x26, 0x61, 0x48, 0xB6, 0xA2, 0x93, 0x37, 0x1D, 0xCE, 0x35, 0xF1, 0x17, 0x18, 0x11, 0x1B, 0x77, 0x94, 0xAB, 0xF8, 0xC3, 0x36, 0x33, 0x73, 0x4E, 0xAE, 0x25, 0x4C, 0x3C, 0xF8, 0xFB, 0x37, 0x7F, 0x83, 0xC8, 0xD5, 0xA2, 0x17, 0xC0, 0x86, 0xCD, 0xF8, 0xC3, 0x4E, 0x88, 0x5B, 0xDF, 0xDC, 0xC3, 0xB3, 0x58, 0x94, 0x1D, 0x15, 0x96, 0x25,
                                                                              0x2C, 0x66, 0x09, 0x1F, 0xC5, 0x55, 0x33, 0xBD, 0xE7, 0x4B, 0x86, 0xA3, 0x26, 0x88, 0xDE, 0x0E, 0x90, 0xC7, 0x71, 0x0E, 0xFA, 0x26, 0x23, 0x85, 0xA9, 0xC1, 0x3D, 0xB6, 0x46, 0x5A, 0x56, 0x54, 0x18, 0x7B, 0x98, 0xB5, 0x29, 0x11, 0x58, 0xEC, 0xED, 0x47, 0xC4, 0x24, 0x9F, 0xAC, 0x4F, 0xFE, 0x6E, 0x75, 0x2C, 0xF7, 0xF7, 0xC0, 0x1D, 0xE0, 0x85, 0xD9, 0xF9, 0xAE, 0x85, 0xFF, 0x64, 0x46, 0xB2, 0x98, 0x70, 0xDA, 0xA3, 0x19, 0x93, 0x1A, 0x0D, 0x2F, 0x96, 0x04, 0x1B, 0x99, 0x1E, 0x49, 0x63, 0x0F, 0xC3, 0x88, 0xBB, 0x38, 0x7D, 0x1C, 0xE8, 0x15, 0xD3, 0xA7, 0x81, 0x28, 0x03, 0xE1, 0xF1, 0x20, 0xD7, 0x34, 0x8F, 0x5B, 0xEB, 0xDA, 0x67, 0xCE, 0x3C, 0xB0, 0xFE, 0x0D, 0xEE, 0x3C, 0xB0, 0x8E, 0xA1, 0x2A, 0xD0, 0x94, 0x6C, 0xF9, 0xF3, 0x81, 0x5F, 0x20, 0x14, 0xB3, 0x32, 0xA9,
                                                                              0xB7, 0x13, 0x2A, 0x1E, 0xAA, 0xCF, 0xD2, 0xC8, 0x65, 0xA3, 0x55, 0x57, 0xE1, 0x93, 0x32, 0xBD, 0xA0, 0x08, 0xC2, 0x63, 0xD2, 0xA4, 0xB9, 0x25, 0x60, 0xDA, 0xBF, 0x5E, 0x62, 0xC1, 0x13, 0x93, 0xED, 0x04, 0x84, 0x2A, 0x0B, 0x30, 0x70, 0xA8, 0xDF, 0x8E, 0x87, 0x73, 0x7B, 0x4B, 0xA2, 0xE8, 0xC7, 0x97, 0x8D, 0x49, 0x1F, 0x60, 0xDD, 0xD7, 0x17, 0x49, 0x9E, 0xBE, 0x9E, 0x34, 0xF3, 0xDE, 0xAC, 0x73, 0x59, 0xA7, 0xB7, 0x1A, 0x5D, 0x11, 0x1A, 0x65, 0x0B, 0x05, 0xFB, 0x42, 0xA7, 0xF7, 0x37, 0xFE, 0xCA, 0x27, 0x3C, 0x67, 0xE5, 0x6E, 0x66, 0xF0, 0xE6, 0x6D, 0xAB, 0x43, 0xD9, 0xB5, 0x4C, 0xB7, 0xC1, 0xE6, 0x9C, 0x57, 0x84, 0x09, 0x79, 0xE2, 0x6A, 0x21, 0x9A, 0x1D, 0x1D, 0x6D, 0xF1, 0x75, 0x64, 0x4F, 0x8A, 0x98, 0xD3, 0x7A, 0xCF, 0x62, 0x8F, 0x70, 0x4D, 0xEC, 0x65, 0x49,
                                                                              0xBB, 0x35, 0x7D, 0x45, 0x1E, 0xB1, 0xF4, 0x6B, 0x06, 0xD5, 0x01, 0xE2, 0xDE, 0x93, 0x09, 0x3F, 0xAE, 0x58, 0x49, 0x88, 0x80, 0x7D, 0x9A, 0xB9, 0x1B, 0x1F, 0x4C, 0x5D, 0x2B, 0xD5, 0x97, 0xF8, 0x85, 0x1B, 0x50, 0x87, 0xB3, 0x91, 0x9A, 0x37, 0xB6, 0x1A, 0x48, 0xD2, 0x26, 0xC5, 0x07, 0x79, 0x1A, 0x43, 0xBA, 0x14, 0x8B, 0xA3, 0xF3, 0x72, 0xBD, 0x3F, 0x12, 0x03, 0x07, 0xEE, 0xAD, 0xE0, 0x96, 0x9D, 0x65, 0x36, 0xB5, 0x33, 0x41, 0x71, 0x5D, 0x61, 0xEE, 0xBE, 0x32, 0x60, 0x9B, 0x66, 0x5C, 0x9F, 0x29, 0x56, 0x3E, 0x4E, 0x62, 0x34, 0xA4, 0xB4, 0x3D, 0xBB, 0xFA, 0xF7, 0x0D, 0x79, 0xFA, 0xD2, 0x4C, 0x3F, 0x50, 0xFA, 0x1C, 0xDF, 0x19, 0x65, 0x06, 0x1B, 0xB8, 0xE7, 0x17, 0x64, 0x29, 0x8E, 0xF7, 0xDC, 0xBE, 0x51, 0xF7, 0x7D, 0x90, 0x6B, 0xCF, 0x44, 0xA4, 0x24, 0x02, 0x2B };

const flea_u8_t rsa_2048_pub_key_internal_format__acu8[2048 / 8] = { 0xB0, 0x0D, 0x34, 0x6A, 0x8F, 0xE1, 0x72, 0x0E, 0xBB, 0x8F, 0x94, 0x6C, 0xDC, 0x5C, 0xCF, 0x64, 0x46, 0x13, 0x76, 0xA2, 0xF3, 0x18, 0xEA, 0xF6, 0xF0, 0xBC, 0x01, 0xCD, 0xB5, 0x5B, 0x5B, 0x0F, 0xE6, 0x06, 0x96, 0x7A, 0x52, 0x54, 0x3E, 0x5B, 0x15, 0x79, 0x1A, 0xE0, 0x08, 0xC2, 0x83, 0x8A, 0x27, 0xB6, 0x5D, 0xE4, 0x36, 0x27, 0x12, 0x29, 0x6C, 0x03, 0xEF, 0x8E, 0xCE, 0x79, 0x14, 0xA5, 0x65, 0xA2, 0x60, 0x15, 0x1B, 0xEF, 0x41, 0x78, 0x72, 0x4F, 0x20, 0x4C, 0x1F, 0x55, 0x28, 0x97, 0xF2, 0xC5, 0x37, 0xF8, 0xEB, 0x38, 0x84, 0xB0, 0x4B, 0xB3, 0xC6, 0x99, 0x93, 0xB4, 0x61, 0x25, 0x5E, 0x14, 0x4D, 0x5E, 0xEE, 0x74, 0x1A, 0x13, 0x9E, 0x23, 0x41, 0xA5, 0x83, 0x58, 0x3C, 0xE9, 0x0A, 0x90, 0x51, 0x1C, 0xF8, 0x6F, 0xAB, 0xAF, 0x5E, 0x61, 0xDF, 0xFE, 0xCF, 0x38, 0x19, 0x10, 0x77, 0x6A, 0x13, 0x0B, 0xCC, 0xAC, 0x3E, 0xAD, 0x0A, 0x51, 0xE8, 0x93, 0xF3, 0xC3, 0x0A, 0x35, 0x13, 0x11, 0x49, 0xA2, 0x19, 0xE3, 0x39, 0xFD, 0x3F, 0xBA, 0xE5, 0x77, 0x09, 0x0D, 0x9A, 0xA0, 0xB3, 0x40, 0x7F, 0x46, 0xA1, 0x37, 0x5D, 0x36, 0xDE, 0xED, 0x10, 0x78, 0x93, 0xA8, 0x5F, 0xF1, 0x4E, 0xDE, 0xE3, 0xC2, 0x6B, 0xAE, 0x45, 0xAF, 0x62, 0xC2, 0x53, 0xD9, 0x8E, 0xFA, 0xC3, 0x32, 0x43, 0xCA, 0x89, 0x86, 0xB4, 0x45, 0xD9, 0xDB, 0xB9, 0x96, 0xF4, 0xBC, 0x13, 0x05, 0x92, 0xF8, 0x9D, 0xE4, 0x17, 0x6A, 0xE4, 0xBE, 0x70, 0x9B, 0xFA, 0xF2, 0xCB, 0xED, 0x11, 0x2C, 0xFC, 0x27, 0xDC, 0xD3, 0xAC, 0x66, 0xC0, 0x75, 0xD2, 0xAE, 0xFC, 0x94, 0xF0, 0xE4, 0x8B, 0x3E, 0x5D, 0x59, 0xC7, 0xBB, 0xE1, 0x21, 0xED, 0x0A, 0xF2, 0x36, 0x5C, 0x73, 0xCC, 0xED, 0xD0, 0xAD, 0x4F, 0x41 };
