//***************************************************************************************
// prng.h
// Pseudo random numbers generator (Windows specific)
//
// Copyright © 2021 Dmitry Schelkunov. All rights reserved.
// Contacts: <d.schelkunov@gmail.com>, <schelkunov@re-crypt.com>
//
// This file is part of wb_poc.
//
// wb_poc is free software : you can redistribute it and / or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// wb_poc is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with wb_poc. If not, see <http://www.gnu.org/licenses/>.
//***************************************************************************************

#ifndef PRNG_H
#define PRNG_H

#include <stdint.h>
#include "mpir.h"
#include <algorithm>


namespace NPrng
{
void get_rnd(void* buf, uint32_t size);
uint32_t get_rnd_32();
uint8_t get_rnd_8();
uint8_t get_rnd_4();

extern mpf_t seed;

void iterate_PLCM(mpf_t res, mpf_t x, mpf_t p);
void sha2(void* buf, uint32_t size, void* hsh, uint32_t hsh_size);

}

#endif // PRNG_H