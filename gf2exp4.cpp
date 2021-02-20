//***************************************************************************************
// gf2exp4.cpp
// GF(2^4) fast operations
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

#include "gf2exp4.h"

namespace NGF2exp4
{

static const uint8_t mul_table0x13[16][16] = { { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
{ 0, 2, 4, 6, 8, 10, 12, 14, 3, 1, 7, 5, 11, 9, 15, 13 },
{ 0, 3, 6, 5, 12, 15, 10, 9, 11, 8, 13, 14, 7, 4, 1, 2 },
{ 0, 4, 8, 12, 3, 7, 11, 15, 6, 2, 14, 10, 5, 1, 13, 9 },
{ 0, 5, 10, 15, 7, 2, 13, 8, 14, 11, 4, 1, 9, 12, 3, 6 },
{ 0, 6, 12, 10, 11, 13, 7, 1, 5, 3, 9, 15, 14, 8, 2, 4 },
{ 0, 7, 14, 9, 15, 8, 1, 6, 13, 10, 3, 4, 2, 5, 12, 11 },
{ 0, 8, 3, 11, 6, 14, 5, 13, 12, 4, 15, 7, 10, 2, 9, 1 },
{ 0, 9, 1, 8, 2, 11, 3, 10, 4, 13, 5, 12, 6, 15, 7, 14 },
{ 0, 10, 7, 13, 14, 4, 9, 3, 15, 5, 8, 2, 1, 11, 6, 12 },
{ 0, 11, 5, 14, 10, 1, 15, 4, 7, 12, 2, 9, 13, 6, 8, 3 },
{ 0, 12, 11, 7, 5, 9, 14, 2, 10, 6, 1, 13, 15, 3, 4, 8 },
{ 0, 13, 9, 4, 1, 12, 8, 5, 2, 15, 11, 6, 3, 14, 10, 7 },
{ 0, 14, 15, 1, 13, 3, 2, 12, 9, 7, 6, 8, 4, 10, 11, 5 },
{ 0, 15, 13, 2, 9, 6, 4, 11, 1, 14, 12, 3, 8, 7, 5, 10 },
};

static const uint8_t inv_table0x13[16] = { 0, 1, 9, 14, 13, 11, 7, 6, 15, 2, 12, 5, 10, 4, 3, 8 };

static const uint8_t mul_table0x15[16][16] = { { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
{ 0, 2, 4, 6, 8, 10, 12, 14, 5, 7, 1, 3, 13, 15, 9, 11 },
{ 0, 3, 6, 5, 12, 15, 10, 9, 13, 14, 11, 8, 1, 2, 7, 4 },
{ 0, 4, 8, 12, 5, 1, 13, 9, 10, 14, 2, 6, 15, 11, 7, 3 },
{ 0, 5, 10, 15, 1, 4, 11, 14, 2, 7, 8, 13, 3, 6, 9, 12 },
{ 0, 6, 12, 10, 13, 11, 1, 7, 15, 9, 3, 5, 2, 4, 14, 8 },
{ 0, 7, 14, 9, 9, 14, 7, 0, 7, 0, 9, 14, 14, 9, 0, 7 },
{ 0, 8, 5, 13, 10, 2, 15, 7, 1, 9, 4, 12, 11, 3, 14, 6 },
{ 0, 9, 7, 14, 14, 7, 9, 0, 9, 0, 14, 7, 7, 14, 0, 9 },
{ 0, 10, 1, 11, 2, 8, 3, 9, 4, 14, 5, 15, 6, 12, 7, 13 },
{ 0, 11, 3, 8, 6, 13, 5, 14, 12, 7, 15, 4, 10, 1, 9, 2 },
{ 0, 12, 13, 1, 15, 3, 2, 14, 11, 7, 6, 10, 4, 8, 9, 5 },
{ 0, 13, 15, 2, 11, 6, 4, 9, 3, 14, 12, 1, 8, 5, 7, 10 },
{ 0, 14, 9, 7, 7, 9, 14, 0, 14, 0, 7, 9, 9, 7, 0, 14 },
{ 0, 15, 11, 4, 3, 12, 8, 7, 6, 9, 13, 2, 5, 10, 14, 1 },
};

static const uint8_t inv_table0x15[16] = { 0, 1, 10, 12, 5, 4, 6, 6, 8, 2, 2, 13, 3, 11, 3, 15 };

static const uint8_t irr_polynomials[] = {0x13, 0x15};

uint8_t get_poly_by_index(int i)
{
	if (i >= sizeof(irr_polynomials))
		return 0;

	return irr_polynomials[i];
}

uint8_t gmul_tab(uint8_t a, uint8_t b, uint8_t p)
{
	switch (p)
	{
	case 0x13:
		return mul_table0x13[a][b];
	case 0x15:
		return mul_table0x15[a][b];
	}

	return 0;
}

uint8_t inv_tab(uint8_t b, uint8_t p)
{
	switch (p)
	{
	case 0x13:
		return inv_table0x13[b];
	case 0x15:
		return inv_table0x15[b];
	}

	return 0;
}

uint8_t gdiv_tab(uint8_t a, uint8_t b, uint8_t p)
{
	return gmul_tab(a, inv_tab(b, p), p);
}

}