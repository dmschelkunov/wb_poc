//***************************************************************************************
// wb_poc.cpp
//
// Sample of usage
//
// Copyright © 2022 Dmitry Schelkunov. All rights reserved.
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

#include "stdafx.h"
#include "savekeys.h"

using namespace NCipher;
using namespace NSaveKeys;

// Source message
char msg[] = "This is fast white-box cipher!!";


/////////////////////////////////////////////////////////////////////////////////////////
// test_encr_decr()
//
// Generate a key pair, encrypt a source message with a public key, 
// decrypt message with a private key, check the result
/////////////////////////////////////////////////////////////////////////////////////////
bool test_encr_decr()
{
	CEncryption *e = new CEncryption();
	e->gen_key();

	CDecryption *d = new CDecryption(*e);
	d->init();

	uint8_t crpt[CEncryption::tbox_size];
	memset(crpt, 0, CEncryption::tbox_size);
	
	// Encrypt with a public key
	for (int j = 0; j < CEncryption::tbox_size; ++j)
	{
		for (int i = 0; i < CEncryption::comb_sbsts_num; ++i)
		{
			crpt[j] ^= e->get_comb_tbxs()[i][msg[i]][j];
		}
	}

	uint8_t t0[CEncryption::tbox_size];
	memset(t0, 0, CEncryption::tbox_size);
	// Decrypt with a private key
	for (int j = 0; j < CEncryption::tbox_size; ++j)
	{
		for (int i = 0; i < CEncryption::tbox_size; ++i)
		{
			t0[j] ^= d->get_inv_comb_tbxs2()[i][crpt[i]][j];
		}
	}

	uint8_t t1[CEncryption::comb_sbsts_num];
	memset(t1, 0, CEncryption::comb_sbsts_num);
	for (int j = 0; j < CEncryption::comb_sbsts_num; ++j)
	{
		for (int i = 0; i < CEncryption::comb_sbsts_num; ++i)
		{
			t1[j] ^= d->get_inv_comb_tbxs1()[i][t0[i]][j];
		}
	}

	uint8_t t2[CEncryption::comb_sbsts_num];
	memset(t2, 0, CEncryption::comb_sbsts_num);
	for (int j = 0; j < CEncryption::comb_sbsts_num; ++j)
	{
		for (int i = 0; i < CEncryption::comb_sbsts_num; ++i)
		{
			t2[j] ^= d->get_final_tbxs()[i][t1[i]][j];
		}
	}

	delete e;
	delete d;

	// Check
	return !memcmp(msg, t2, CEncryption::comb_sbsts_num);
}

/////////////////////////////////////////////////////////////////////////////////////////
// test_encr_decr_save_load()
//
// Generate a key pair, save the keys to disk, load the keys from disk,
// encrypt a message with a public key, 
// decrypt a message with a private key,
// check the result
/////////////////////////////////////////////////////////////////////////////////////////
bool test_encr_decr_save_load()
{
	// Generate a key pair
	CEncryption *e = new CEncryption();
	e->gen_key();

	CDecryption *d = new CDecryption(*e);
	d->init();

	char *efile = "encr.evh";
	char *dfile = "decr.evh";

	// Save a public key
	bool err = save_public_key(efile, *e);
	if (!err)
	{
		delete d;
		delete e;

		return false;
	}

	// Save a private key
	err = save_private_key(dfile, *d);
	if (!err)
	{
		delete d;
		delete e;

		return false;
	}

	// Load public and private keys
	uint8_t *pub = load_public_key(efile);
	uint8_t *prv = load_priv_key(dfile);

	const NCipher::CEncryption::comb_tbox_arrays &pub_tbxs = *((const NCipher::CEncryption::comb_tbox_arrays*)pub);
	const NCipher::CDecryption::mixed_comb_tbox_arrays &prv_tbxs2 = *((const NCipher::CDecryption::mixed_comb_tbox_arrays*)prv);
	const NCipher::CDecryption::clear_comb_tbox_arrays &prv_tbxs1 = *((const NCipher::CDecryption::clear_comb_tbox_arrays*)(prv + sizeof(NCipher::CDecryption::mixed_comb_tbox_arrays)));
	const NCipher::CDecryption::clear_comb_tbox_arrays &prv_tbxs0 = *((const NCipher::CDecryption::clear_comb_tbox_arrays*)(prv + sizeof(NCipher::CDecryption::mixed_comb_tbox_arrays) + sizeof(NCipher::CDecryption::clear_comb_tbox_arrays)));


	uint8_t crpt[CEncryption::tbox_size];
	memset(crpt, 0, CEncryption::tbox_size);

	// Encrypt with a public key
	for (int j = 0; j < CEncryption::tbox_size; ++j)
	{
		for (int i = 0; i < CEncryption::comb_sbsts_num; ++i)
		{
			crpt[j] ^= pub_tbxs[i][msg[i]][j];
		}
	}

	// Decrypt with a private key
	uint8_t t0[CEncryption::tbox_size];
	memset(t0, 0, CEncryption::tbox_size);
	for (int j = 0; j < CEncryption::tbox_size; ++j)
	{
		for (int i = 0; i < CEncryption::tbox_size; ++i)
		{
			t0[j] ^= prv_tbxs2[i][crpt[i]][j];
		}
	}

	uint8_t t1[CEncryption::comb_sbsts_num];
	memset(t1, 0, CEncryption::comb_sbsts_num);
	for (int j = 0; j < CEncryption::comb_sbsts_num; ++j)
	{
		for (int i = 0; i < CEncryption::comb_sbsts_num; ++i)
		{
			t1[j] ^= prv_tbxs1[i][t0[i]][j];
		}
	}

	uint8_t t2[CEncryption::comb_sbsts_num];
	memset(t2, 0, CEncryption::comb_sbsts_num);
	for (int j = 0; j < CEncryption::comb_sbsts_num; ++j)
	{
		for (int i = 0; i < CEncryption::comb_sbsts_num; ++i)
		{
			t2[j] ^= prv_tbxs0[i][t1[i]][j];
		}
	}

	delete[] pub;
	delete[] prv;

	delete d;
	delete e;

	// Check
	return !memcmp(msg, t2, CEncryption::comb_sbsts_num);
}

/////////////////////////////////////////////////////////////////////////////////////////
// test_sign()
//
// Sample of a digital signature algorithm
/////////////////////////////////////////////////////////////////////////////////////////
bool test_sign()
{
	// A size of msg_to_sign must be 3 bytes more than a size of msg (i.e. 16 + 3 = 19 bytes)
	// So, a size of an additional counter is 3 bytes
	char msg_to_sign[CEncryption::tbox_size + 1]; // +1
	memset(msg_to_sign, 0, sizeof(msg_to_sign));

	memcpy_s(msg_to_sign, sizeof(msg_to_sign), msg, sizeof(msg));
	uint8_t hsh[32];
	
	// Generate a key pair
	CEncryption *e = new CEncryption();
	e->gen_key();

	CDecryption *d = new CDecryption(*e);
	d->init();

	char *efile = "encr1.evh";
	char *dfile = "decr1.evh";

	// Save a public key
	bool err = save_public_key(efile, *e);
	if (!err)
	{
		delete d;
		delete e;

		return false;
	}

	// Save a private key
	err = save_private_key(dfile, *d);
	if (!err)
	{
		delete d;
		delete e;

		return false;
	}

	// Load keys
	uint8_t *pub = load_public_key(efile);
	uint8_t *prv = load_priv_key(dfile);

	const NCipher::CEncryption::comb_tbox_arrays &pub_tbxs = *((const NCipher::CEncryption::comb_tbox_arrays*)pub);
	const NCipher::CDecryption::mixed_comb_tbox_arrays &prv_tbxs2 = *((const NCipher::CDecryption::mixed_comb_tbox_arrays*)prv);
	const NCipher::CDecryption::clear_comb_tbox_arrays &prv_tbxs1 = *((const NCipher::CDecryption::clear_comb_tbox_arrays*)(prv + sizeof(NCipher::CDecryption::mixed_comb_tbox_arrays)));
	const NCipher::CDecryption::clear_comb_tbox_arrays &prv_tbxs0 = *((const NCipher::CDecryption::clear_comb_tbox_arrays*)(prv + sizeof(NCipher::CDecryption::mixed_comb_tbox_arrays) + sizeof(NCipher::CDecryption::clear_comb_tbox_arrays)));

	// Sign a source message
	// For this PoC we use low 18 bits of SHA-256
	for (unsigned int i = 0; i < 0x1000000; ++i)
	{
		msg_to_sign[32] = (unsigned char)i;
		msg_to_sign[33] = (unsigned char)(i >> 8);
		msg_to_sign[34] = (unsigned char)(i >> 16); // +1

		NPrng::sha2(msg_to_sign, sizeof(msg_to_sign), hsh, sizeof(hsh));

		
		// Decrypt low bits of hash
		uint8_t t0[CEncryption::tbox_size];
		memset(t0, 0, CEncryption::tbox_size);

		for (int j = 0; j < CEncryption::tbox_size; ++j)
		{
			for (int i = 0; i < CEncryption::tbox_size; ++i)
			{
				t0[j] ^= prv_tbxs2[i][hsh[i]][j];
			}
		}

		uint8_t t1[CEncryption::comb_sbsts_num];
		memset(t1, 0, CEncryption::comb_sbsts_num);
		for (int j = 0; j < CEncryption::comb_sbsts_num; ++j)
		{
			for (int i = 0; i < CEncryption::comb_sbsts_num; ++i)
			{
				t1[j] ^= prv_tbxs1[i][t0[i]][j];
			}
		}

		uint8_t t2[CEncryption::comb_sbsts_num];
		memset(t2, 0, CEncryption::comb_sbsts_num);
		for (int j = 0; j < CEncryption::comb_sbsts_num; ++j)
		{
			for (int i = 0; i < CEncryption::comb_sbsts_num; ++i)
			{
				t2[j] ^= prv_tbxs0[i][t1[i]][j];
			}
		}

		// try to encrypt t2
		uint8_t crpt[CEncryption::tbox_size];
		memset(crpt, 0, CEncryption::tbox_size);

		for (int j = 0; j < CEncryption::tbox_size; ++j)
		{
			for (int i = 0; i < CEncryption::comb_sbsts_num; ++i)
			{
				crpt[j] ^= pub_tbxs[i][t2[i]][j];
			}
		}

		// compare source bytes of hash and crpt
		if (!memcmp(hsh, crpt, CEncryption::tbox_size))
		{
			delete[] pub;
			delete[] prv;

			delete d;
			delete e;

			return true;
		}
	}

	delete[] pub;
	delete[] prv;

	delete d;
	delete e;

	return false;
}

int main(int argc, char* argv[])
{
	for (;;)
	{
		if (!test_sign())
		{
			printf_s("SIGNATURE ERROR!!!\n");
		}
		else
		{
			printf_s("SIGNATURE OK!!!\n");
		}

		if (!test_encr_decr())
		{
			printf_s("ENCR_DECR ERROR!!!\n");
		}
		else
		{
			printf_s("ENCR_DECR OK!!!\n");
		}

		if (!test_encr_decr_save_load())
		{
			printf_s("ENCR_DECR_SAVE_LOAD ERROR!!!\n");
		}
		else
		{
			printf_s("ENCR_DECR_SAVE_LOAD OK!!!\n");
		}
	}

	return 0;
}

