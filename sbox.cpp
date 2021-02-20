//***************************************************************************************
// sbox.cpp
// A generator of chaotic S-box-es
//
// Copyright © 2021 Dmitry Schelkunov. All rights reserved.
// Contacts: <d.schelkunov@gmail.com>, <schelkunov@re-crypt.com>
//
// This file is a part of wb_poc
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

#include "sbox.h"
#include "prng.h"

namespace NWhiteBox
{

template<int N>
void create_Nbit_sboxes_chaotically(std::vector<uint8_t>& v)
{
	mpf_t x, p, left, right, s1, delta, immN;
	mpf_init2(x, 256);
	mpf_set(x, NPrng::seed);
	
	mpf_init_set_d(immN, N);
	mpf_init_set_d(p, 0.15);
	mpf_init_set_d(left, 0.1);
	mpf_init_set_d(right, 0.9);

	mpf_init2(s1, 256);
	mpf_init2(delta, 256);

	mpf_sub(s1, right, left);
	mpf_div(delta, s1, immN);

	v.clear();
	v.resize(N);
	uint32_t cnt(0);

	std::vector<bool> is_init;
	is_init.resize(N, false);

	for (; cnt < N;)
	{
		NPrng::iterate_PLCM(x, x, p);
		
		mpf_t mf_index, s2;
		mpf_init2(mf_index, 256);
		mpf_init2(s2, 256);

		mpf_sub(s2, x, left);
		mpf_div(mf_index, s2, delta);

		uint8_t index = (uint8_t)mpf_get_d(mf_index);
		
		if (index < 0 || index > N)
			continue;
		if (is_init[index])
			continue;

		is_init[index] = true;
		v[cnt++] = index;
	}

	mpf_set(NPrng::seed, x);
}

void create_8bit_sboxes_chaotically(std::vector<uint8_t>& v)
{
	create_Nbit_sboxes_chaotically<256>(v);
}
void create_4bit_sboxes_chaotically(std::vector<uint8_t>& v)
{
	create_Nbit_sboxes_chaotically<16>(v);
}

}