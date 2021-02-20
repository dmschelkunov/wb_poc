wb_poc
An approach for designing fast public key encryption systems using white-box cryptography techniques (Proof of Concept)
Paper: https://eprint.iacr.org/2021/136

bmatrix.h - operations with binary matrices
cipher.h, cipher.cpp - generator of a random cipher
gf2exp4.h, gf2exp4.cpp, gf2exp8.h, gf2exp8.h - fast operations over GF(2^4) and GF(2^8)
prng.h, prng.cpp - simple pseudorandom numbers generator using Chaos theory
savekeys.h, savekeys.cpp - save\load keys
sbox.h, sbox.cpp - generator of random S-box-es
wb_poc.cpp - examples of encryption, decryption and signing
mpir.h, mpir.lib, mpir.dll - external MPIR library (https://mpir.org/)
wb_poc.vcxproj - MSVC project


Compile with MS Visual Studio 2013 or later and run