#ifndef __MAIN_H
#define __MAIN_H

#include <cstdio>
#include <iostream>
#include <string>

#include "des.h"

using namespace std;

// global variables
extern string inFile;
extern string strKey;
extern int mode;

namespace Main {

enum {
	MODE_UNSET,
	MODE_DECRYPT,
	MODE_ENCRYPT,
	MODE_DECRYPT_SINGLE,
	MODE_ENCRYPT_SINGLE
};

struct ByteBuffer{
	unsigned char bytewise[8];
	ull integral;
	ByteBuffer() : integral(0){}
	void convert(){
		integral = 0;
		// apparently this is the byte order used by files
		for(int i=7; i>=0; i--) integral = integral << 8 | (bytewise[i]&0xff);
	};
};


void printUsage()
{
	cout	<< "Data Encryption Standard (DES) algorithm" << endl
		<< "By Steven Vergenz" << endl
		<< "Usage: des --encrypt|--decrypt|--encrypt-single|--decrypt-single" << endl
		<< "           [--debug] --key K F" << endl
		<< "   F: The file to be encrypted/decrypted. If a single mode is selected," << endl
		<< "      this is interpreted as a 64-bit hexadecimal number." << endl
		<< "   K: The 64-bit encryption key in hexadecimal." << endl
		<< endl
		<< "This program will encrypt/decrypt the given file in place," << endl
		<< "and add/remove the .des file extension to indicate its" << endl
		<< "encryption status." << endl;
}


bool parseArguments(int argc, char** argv)
{
	string temp = "";
	int count = 1;

	// loop over arguments
	for( int count=1; count < argc; count++ ){
		temp = argv[count];
		
		if( temp == "--encrypt" ){
			if( mode != MODE_UNSET ){
				cout << "Only specify one of --decrypt and --encrypt" << endl;
				printUsage();
				return false;
			}
			else mode = MODE_ENCRYPT;
		}
		else if( temp == "--decrypt" ){
			if( mode != MODE_UNSET ){
				cout << "Only specify one of --decrypt and --encrypt" << endl;
				printUsage();
				return false;
			}
			else mode = MODE_DECRYPT;
		}
		else if( temp == "--encrypt-single" ){
			if( mode != MODE_UNSET ){
				cout << "Only specify one of --decrypt and --encrypt" << endl;
				printUsage();
				return false;
			}
			else mode = MODE_ENCRYPT_SINGLE;
		}
		else if( temp == "--decrypt-single" ){
			if( mode != MODE_UNSET ){
				cout << "Only specify one of --decrypt and --encrypt" << endl;
				printUsage();
				return false;
			}
			else mode = MODE_DECRYPT_SINGLE;
		}
		else if( temp == "--input" ){
			inFile = argv[count+1];
			count++;
		}
		else if( temp == "--key" ){
			strKey = argv[count+1];
			count++;
		}
		else if( temp == "--help" ){
			printUsage();
			return false;
		}
		else if( temp == "--debug" ){
			DES::DEBUG = true;
		}
		else if( inFile.empty() ){
			inFile = temp;
		}
		else {
			cout << "Unrecognized argument: " << temp << endl;
			printUsage();
			return false;
		}
	} // end arg loop

	// make sure all important fields got populated
	if( mode==MODE_UNSET || inFile.empty() || strKey.empty() ){
		cout << "Missing arguments." << endl;
		printUsage();
		return false;
	}
	
	return true;
}

}

#endif
