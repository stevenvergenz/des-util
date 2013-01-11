#ifndef __DES_H
#define __DES_H

#include <cstdio>

typedef unsigned long long ull;

class DES {
public:
	static ull encrypt( ull input, ull key );
	static ull decrypt( ull input, ull key );
	static bool testKeyParity(ull key);

	static bool DEBUG;

private:
	static ull permute( ull input, int inSize, const int* mat );
	static ull feistel( ull input, ull subkey );
	static ull getSubkey( ull key, int keynum );

	// 64 -> 64
	static const int IP[65];

	// 64 -> 64
	static const int FP[65];

	// 32 -> 48
	static const int E[49]; 

	// 32 -> 32
	static const int P[33];

	// 64 -> 2x28
	static const int PC1[57];

	// 56 -> 48
	static const int PC2[49];

	// box / outside / inside
	static const int Sbox[8][4][16];

	static const int R[16];
};

#endif
