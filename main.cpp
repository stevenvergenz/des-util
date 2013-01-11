#include <iostream>
#include <cstdio>
#include <string>

#include "main.h"

using namespace std;


// global variables
string inFile = "";
string strKey = "";
int mode = Main::MODE_UNSET;

int main(int argc, char** argv)
{
	ull block=0, key=0, result=0;
	FILE* ifp = NULL;
	FILE* ofp = NULL;
	string outFile = "";

	// parse arguments
	if( !Main::parseArguments( argc, argv ) ){
		return 1;
	}

	// convert key string to ull
	result = sscanf( strKey.c_str(), "%llx", &key );
	if( result != 1 ){
		cout 	<< "Could not convert key to integer." << endl
			<< "Make sure that it is a valid hexadecimal number and" << endl
			<< "that it is at most 64 bits (16 hex characters)." << endl;
		return 1;
	}

	// check key parity
	if( DES::testKeyParity(key) ){
		cout << "Key parity check PASSED" << endl;
	}
	else {
		cout << "Key parity check FAILED" << endl;
	}

	// file modes
	if( mode == Main::MODE_ENCRYPT || mode == Main::MODE_DECRYPT )
	{
		ifp = fopen( inFile.c_str(), "r" );
		if( !ifp ){
			cout << "File not found: " << inFile << endl;
			return 1;
		}
	
		// format output filename string
		if( mode == Main::MODE_ENCRYPT ){
			outFile = inFile + ".des";
		}
		else if( mode == Main::MODE_DECRYPT ){
			if( inFile.find(".des") == inFile.length()-4 ){
				outFile = inFile.substr( 0, inFile.length()-4 );
			}
			else {
				outFile = inFile + ".plain";
			}
		}

		ofp = fopen( outFile.c_str(), "w" );
		if( !ofp ){
			cout << "Failed to open output file: " << outFile << endl;
			return 1;
		}


		// loop over contents of the file, 8 bytes at a time
		// and encrypt one block behind
		Main::ByteBuffer buffer, lookahead;
		fread( buffer.bytewise, sizeof(unsigned char), 8, ifp );
		while( !feof(ifp) )
		{
			// 8 bytes in 1-byte chunks for partial reads
			result = fread( lookahead.bytewise, sizeof(unsigned char), 8, ifp );
			
			buffer.convert();

			// special handling for last decryption block
			if( result != 8 && mode == Main::MODE_DECRYPT ) break;

			if( mode == Main::MODE_ENCRYPT ){
				buffer.integral = DES::encrypt( buffer.integral, key );
			}
			else if( mode == Main::MODE_DECRYPT ){
				buffer.integral = DES::decrypt( buffer.integral, key );
			}

			fwrite( &(buffer.integral), sizeof(ull), 1, ofp );

			// rotate buffers
			buffer = lookahead;
		}

		// if eof while decrypting, strip padding and write
		if( mode == Main::MODE_DECRYPT ){
			buffer.integral = DES::decrypt( buffer.integral, key );
			int padcount = (buffer.integral >> 56) &0xff;
			fwrite( &(buffer.integral), 8-padcount, 1, ofp );
		}
		// if eof while encrypting, add padding and write final block
		else if( mode == Main::MODE_ENCRYPT ){
			for( int i=result; i<8; i++ ){
				lookahead.bytewise[i] = (8-result) &0xff;
			}
			lookahead.convert();
			lookahead.integral = DES::encrypt( lookahead.integral, key );
			fwrite( &(lookahead.integral), sizeof(ull), 1, ofp );
		}

		fclose(ifp);
		fclose(ofp);
		remove(inFile.c_str());
	}

	// single block modes
	else {
		// convert input string to ull
		result = sscanf( inFile.c_str(), "%llx", &block );
		if( result != 1 ){
			cout 	<< "Could not convert input block to integer." << endl
				<< "Make sure that it is a valid hexadecimal number and" << endl
				<< "that it is at most 64 bits (16 hex characters)." << endl;
			return 1;
		}

		if( mode == Main::MODE_ENCRYPT_SINGLE )
			result = DES::encrypt( block, key );
		else
			result = DES::decrypt( block, key );

		printf("Result: %016llx\n\n", result);
	}

	return 0;
}

