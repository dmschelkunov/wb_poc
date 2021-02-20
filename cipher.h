//***************************************************************************************
// cipher.h
// Generator of a random cipher
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
#include "bmatrix.h"
#include "prng.h"

#ifndef CIPHER_H
#define CIPHER_H

namespace NCipher
{

class CEncryption
{
public:
	enum
	{
		bit_size1 = 128,		// First binary matrix has 128x128 size
		bit_size2 = 144,		// Second binary matrix has 144x144 size
		sbst_size = 16,			// Volume of S-box (or T-box) table (2^sbx_elem_size)
		sbsts_num = 32,			// Number of S-box (or T-box) tables
		sbx_elem_size = 4,		// Size of S-box element (input word for every substitution)
		comb_elem_size = 8,		// Size of combined element (input word for every substitution)
		comb_sbsts_num = 16,	// Number of combined T-boxes
		comb_sbst_size = 256	// Volume of combined S-box (or T-box) table (2^comb_elem_size)
	};

	enum
	{
		tbox_clear_size = 16,		// Size of T-box element without mix(in bytes)
		tbox_size = 18				// Size of T-box element with mix(in bytes)
	};

	typedef uint8_t			subst_array[sbst_size];
	typedef subst_array		subst_arrays[sbsts_num];
	
	typedef uint8_t			tbox[tbox_size];
	typedef tbox			tbox_array[sbst_size];
	typedef tbox_array		tbox_arrays[sbsts_num];

	typedef tbox			comb_tbox_array[comb_sbst_size];
	typedef comb_tbox_array	comb_tbox_arrays[comb_sbsts_num];

	enum
	{
		tbls_size = sizeof(comb_tbox_arrays)
	};

public:
	CEncryption();
	CEncryption(const CEncryption&);
	~CEncryption();

public:
	const CEncryption& operator=(const CEncryption&);

public:
	void gen_key();

public:
	bool is_init() const;
	const NBMatrix::TBMatrix<bit_size1, bit_size1>& get_bmtrx1() const;
	const NBMatrix::TBMatrix<bit_size2, bit_size2>& get_bmtrx2() const;
	const subst_arrays&								get_substs() const;
	const tbox_arrays&								get_tbxs() const;
	const comb_tbox_arrays&							get_comb_tbxs() const;

private:
	void gen_sbox(uint8_t*, uint32_t);
	void gen_sboxes();
	void gen_mtrx1();
	void gen_mtrx2();
	void gen_tbox_elem(tbox&, uint8_t, int);
	void gen_tbox(tbox_array&, int);
	void gen_tboxes();
	void comb_tboxes();

private:
	NBMatrix::TBMatrix<bit_size1, bit_size1>		m_bmtrx1;
	subst_arrays									m_substs;
	NBMatrix::TBMatrix<bit_size2, bit_size2>		m_bmtrx2;
	tbox_arrays										m_tbxs;
	comb_tbox_arrays								m_comb_tbxs;
	bool											m_init;
};

void combine_tboxes(CEncryption::tbox&, const CEncryption::tbox&, const CEncryption::tbox&);

class CDecryption
{
public:
	typedef uint8_t							comb_subst_array[CEncryption::comb_sbst_size];
	typedef comb_subst_array				subst_arrays[CEncryption::comb_sbsts_num];
	typedef uint8_t							clear_tbox[CEncryption::tbox_clear_size];
	typedef clear_tbox						clear_comb_tbox_array[CEncryption::comb_sbst_size];
	typedef clear_comb_tbox_array			clear_comb_tbox_arrays[CEncryption::comb_sbsts_num];
	
	typedef CEncryption::comb_tbox_array	mixed_comb_tbox_arrays[CEncryption::tbox_size];

public:
	enum
	{
		tbls_size = sizeof(mixed_comb_tbox_arrays) + sizeof(clear_comb_tbox_arrays) + sizeof(clear_comb_tbox_arrays)
	};

public:
	CDecryption(const CEncryption&);
	CDecryption(const CDecryption&);
	~CDecryption();

public:
	const CDecryption& operator=(const CDecryption&);
	
public:
	bool init();
	
public:
	CEncryption& get_encr();
	const CEncryption& get_encr() const;
	bool is_init() const;
	const mixed_comb_tbox_arrays& get_inv_comb_tbxs2() const;
	const clear_comb_tbox_arrays& get_inv_comb_tbxs1() const;
	const clear_comb_tbox_arrays& get_final_tbxs() const;


private:
	void gen_inv_matricies();
	void gen_inv_sbox();
	void gen_inv_tbxs2();
	void gen_inv_tbxs1();
	void gen_final_tboxes();

	template <typename MTRX>
	void gen_tbox_elem(uint8_t*, int, uint8_t, int);

private:
	template <typename MTRX>
	const MTRX& get_mtrx()const;

	template<>
	const NBMatrix::TBMatrix<CEncryption::bit_size1, CEncryption::bit_size1>& get_mtrx()const{
		return m_inv_bmtrx1;
	}

	template<>
	const NBMatrix::TBMatrix<CEncryption::bit_size2, CEncryption::bit_size2>& get_mtrx()const{
		return m_inv_bmtrx2;
	}

private:
	CEncryption																m_e;
	bool																	m_init;
	NBMatrix::TBMatrix<CEncryption::bit_size1, CEncryption::bit_size1>		m_inv_bmtrx1;
	NBMatrix::TBMatrix<CEncryption::bit_size2, CEncryption::bit_size2>		m_inv_bmtrx2;
	mixed_comb_tbox_arrays													m_inv_comb_tbxs2;	// Use them for multiplying by m_inv_bmtrx2
	clear_comb_tbox_arrays													m_inv_comb_tbxs1;	// Use them for multiplying by m_inv_bmtrx1
	subst_arrays															m_inv_comb_substs;	// Use them to get decrypted message
	clear_comb_tbox_arrays													m_final_tbxs;
};

}

#endif // CIPHER_H