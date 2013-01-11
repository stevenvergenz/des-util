#include "des.h"

bool DES::DEBUG = false;

ull DES::encrypt( ull input, ull key )
{
	if(DEBUG) printf("Input:\t%016llx\n", input);

	// apply initial permutation
	input = permute( input, 64, IP );
	ull left = (input>>32) &0xffffffff;
	ull right = input &0xffffffff;

	if(DEBUG) printf("IP:\tL0=%08llx, R0=%08llx\n", left, right);

	// apply 16 rounds
	for(int i=0; i<16; i++)
	{
		// feistel and xor
		ull subkey = getSubkey(key, i);
		if(DEBUG) printf("Rnd%02d\tf(R%02d=%08llx, SK%02d=%012llx ) = %08llx\n", i+1, i+1, right, i+1, subkey, feistel(right, subkey) );
		left = left ^ feistel(right, subkey);

		// swap values
		ull temp = right;
		right = left;
		left = temp;
	}

	// apply final permutation
	input = permute( (right<<32)|left, 64, FP );
	if(DEBUG) printf("FP:\t%016llx\n\n", input);

	return input;
}

ull DES::decrypt( ull input, ull key )
{
	if(DEBUG) printf("Input:\t%016llx\n", input);

	// apply initial permutation
	input = permute( input, 64, IP );
	ull left = (input>>32) &0xffffffff;
	ull right = input &0xffffffff;

	if(DEBUG) printf("IP:\tL0=%08llx, R0=%08llx\n", left, right);

	// apply 16 rounds
	for(int i=15; i>=0; i--)
	{
		// feistel and xor
		ull subkey = getSubkey(key, i);
		if(DEBUG) printf("Rnd%02d\tf(R%02d=%08llx, SK%02d=%012llx ) = %08llx\n", i+1, i+1, right, i+1, subkey, feistel(right, subkey) );
		left = left ^ feistel(right, subkey);

		// swap values
		ull temp = right;
		right = left;
		left = temp;
	}

	// apply final permutation
	input = permute( (right<<32)|left, 64, FP );
	if(DEBUG) printf("FP:\t%016llx\n\n", input);

	return input;
}

// rearrange bits of input according to transformation array
ull DES::permute( ull input, int inSize, const int* mat )
{
	ull output = 0;
	for( int i=1; i<=mat[0]; i++ ){
		output |= ((input >> (inSize-mat[i]))&1) << (mat[0]-i);
	}
	return output;
}

// the Feistel function mixes the subkey bits in with input bits
ull DES::feistel( ull input, ull subkey )
{
	// 48-bit mix
	input = permute( input, 32, E ) ^ subkey;
	
	// apply S-boxes
	ull output = 0;
	for( int i=0; i<8; i++ )
	{
		// pull out relevant 6-bit block, starting from the left
		int temp = input>>(42-6*i)&0x3f;

		// pull relevant value from Sbox by box, outside bits, and inside bits
		// and append to output
		output = (output<<4) | Sbox [i] [ (temp>>4)&2 | temp&1 ] [ (temp>>1) &0xf ];
	}

	return permute( output, 32, P );
}

ull DES::getSubkey(ull key, int keynum)
{
	// apply PC-1
	key = permute( key, 64, PC1 );

	// split 56-bit key into two 28-bit halves
	ull left = (key>>28)&0xfffffff;
	ull right = key&0xfffffff;

	/*for(int i=0; i<=keynum; i++){
		left = ((left << R[i]) | (left >> (28-R[i]) )) & 0xfffffff;
		right = ((right << R[i]) | (right >> (28-R[i]) )) & 0xfffffff;
		//ret[i] = 0xffffffffffff & permute( (ull)(((ull)left << 28) | right), PC2, 56, 48 );
        }*/

	// total the shift count for the key number
	for( int i=0; i<keynum; i++ ){
		left = ((left<<R[i]) | (left>>(28-R[i]))) &0xfffffff;
		right = ((right<<R[i]) | (right>>(28-R[i]))) &0xfffffff;
	}

	// put back together and apply PC-2
	key = permute( (left<<28) | right, 56, PC2 );

	// put back together and apply PC-2
	return key;
}

// verify odd parity in 8-bit blocks of key
bool DES::testKeyParity(ull key)
{
	// break 64-bit key into 8-bit blocks
	for(int blockId=0; blockId<8; blockId++)
	{
		// pull out block
		int block = (key >> (8*blockId)) &0xff;

		// loop over bits
		int check=0;
		for(int bit=0; bit<8; bit++){
			check ^= (block>>bit) &1;
		}

		// verify odd parity
		if( check != 1 ) return false;
	}

	// all tests pass
	return true;
}

/*****************************************************
                 Permutation Matrices
*****************************************************/
// 64 -> 64
const int DES::IP[65] = { 64,
	58, 50, 42, 34, 26, 18, 10, 2,
	60, 52, 44, 36, 28, 20, 12, 4,
	62, 54, 46, 38, 30, 22, 14, 6,
	64, 56, 48, 40, 32, 24, 16, 8,
	57, 49, 41, 33, 25, 17,  9, 1,
	59, 51, 43, 35, 27, 19, 11, 3,
	61, 53, 45, 37, 29, 21, 13, 5,
	63, 55, 47, 39, 31, 23, 15, 7
};

// 64 -> 64
const int DES::FP[65] = { 64,
	40, 8, 48, 16, 56, 24, 64, 32,
	39, 7, 47, 15, 55, 23, 63, 31,
	38, 6, 46, 14, 54, 22, 62, 30,
	37, 5, 45, 13, 53, 21, 61, 29,
	36, 4, 44, 12, 52, 20, 60, 28,
	35, 3, 43, 11, 51, 19, 59, 27,
	34, 2, 42, 10, 50, 18, 58, 26,
	33, 1, 41,  9, 49, 17, 57, 25
};

// 32 -> 48
const int DES::E[49] = { 48, 
	32,  1,  2,  3,  4,  5,
	 4,  5,  6,  7,  8,  9,
	 8,  9, 10, 11, 12, 13,
	12, 13, 14, 15, 16, 17,
	16, 17, 18, 19, 20, 21,
	20, 21, 22, 23, 24, 25,
	24, 25, 26, 27, 28, 29,
	28, 29, 30, 31, 32,  1
};

// 32 -> 32
const int DES::P[33] = { 32,
	16,  7, 20, 21, 29, 12, 28, 17,
	 1, 15, 23, 26,  5, 18, 31, 10,
	 2,  8, 24, 14, 32, 27,  3,  9,
	19, 13, 30,  6, 22, 11,  4, 25
};

// 64 -> 2x28
const int DES::PC1[57] = { 56,
	57, 49, 41, 33, 25, 17,  9,
	 1, 58, 50, 42, 34, 26, 18,
	10,  2, 59, 51, 43, 35, 27,
	19, 11,  3, 60, 52, 44, 36,
	63, 55, 47, 39, 31, 23, 15,
	 7, 62, 54, 46, 38, 30, 22,
	14,  6, 61, 53, 45, 37, 29,
	21, 13,  5, 28, 20, 12,  4
};

// 56 -> 48
const int DES::PC2[49] = { 48,
	14, 17, 11, 24,  1,  5,
	 3, 28, 15,  6, 21, 10,
	23, 19, 12,  4, 26,  8,
	16,  7, 27, 20, 13,  2,
	41, 52, 31, 37, 47, 55,
	30, 40, 51, 45, 33, 48,
	44, 49, 39, 56, 34, 53,
	46, 42, 50, 36, 29, 32
};

// box / outside / inside
const int DES::Sbox[8][4][16] = {
	// sbox 1
	{{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
	{0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
	{4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
	{15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}},
	// sbox 2
	{{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
	{3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
	{0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
	{13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}},
	// sbox 3
	{{10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
	{13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
	{13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
	{1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}},
	// sbox 4
	{{7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
	{13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
	{10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
	{3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}},
	// sbox 5
	{{2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
	{14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
	{4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
	{11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}},
	// sbox 6
	{{12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
	{10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
	{9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
	{4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}},
	// sbox 7
	{{4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
	{13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
	{1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
	{6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}},
	// sbox 8
	{{13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
	{1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
	{7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
	{2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}}
};

const int DES::R[16] = {
	1, 1, 2, 2, 2, 2, 2, 2,
	1, 2, 2, 2, 2, 2, 2, 1
};

