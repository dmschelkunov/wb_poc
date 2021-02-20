//***************************************************************************************
// savekeys.h
// Save/Load keys
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

#include "savekeys.h"
#include <stdio.h>

namespace NSaveKeys
{
bool save_public_key(const char *filename, const NCipher::CEncryption &e)
{
	FILE *f;
	errno_t err = fopen_s(&f, filename, "w+b");
	if (err)
		return false;

	fwrite(e.get_comb_tbxs(), sizeof(NCipher::CEncryption::comb_tbox_arrays), 1, f);

	fclose(f);

	return true;
}

bool save_private_key(const char *filename, const NCipher::CDecryption &d)
{
	FILE *f;
	errno_t err = fopen_s(&f, filename, "w+b");
	if (err)
		return false;

	fwrite(d.get_inv_comb_tbxs2(), sizeof(NCipher::CDecryption::mixed_comb_tbox_arrays), 1, f);
	fwrite(d.get_inv_comb_tbxs1(), sizeof(NCipher::CDecryption::clear_comb_tbox_arrays), 1, f);
	fwrite(d.get_final_tbxs(), sizeof(NCipher::CDecryption::clear_comb_tbox_arrays), 1, f);
	
	fclose(f);

	return true;
}


template<uint32_t SIZE>
uint8_t* load_key(const char *filename)
{
	uint8_t *buf = new uint8_t[SIZE];
		
	if (buf == nullptr)
		return nullptr;
	
	FILE *f;
	errno_t err = fopen_s(&f, filename, "r+b");
	if (err)
	{
		delete[] buf;
		return nullptr;
	}
	
	size_t s = fread_s(buf, SIZE, SIZE, 1, f);
	
	if (!s)
	{
		delete[] buf;
		return nullptr;
	}
	
	
	fclose(f);
	
	return buf;
}

uint8_t* load_public_key(const char *filename)
{
	return load_key<NCipher::CEncryption::tbls_size>(filename);
}

uint8_t* load_priv_key(const char *filename)
{
	return load_key<NCipher::CDecryption::tbls_size>(filename);
}

}