#pragma once

#include "stdafx.h"

#include "iostream"
#include "fstream"

#include "dll.h"
#include "pwdbased.h"
#include "md5.h"
#include "sha.h"
#include "cryptlib.h"
#include "modes.h"
#include "filters.h"
#include "aes.h"
#include "gost.h"

#define BUFFER_SIZE 65536
#define SALT_LEN 32

using namespace std;

class cryptoWorker {
	bool mode;
	string password;
	string input_file;
	string output_file;
	byte key_salt[32];
	byte iv_salt[32];
	int type_of_shifr;
	int mode_of_shifr;
	int hash_function;
	int k;
	FILE *in;
	ifstream inStream;
	FILE *out;
	ofstream outStream;
	byte key[32];
	byte IV[32];

public:
	string errorString;

	cryptoWorker(
		bool mode_out,
		string password_out,
		string input_file_out,
		string output_file_out,
		int type_of_shifr_out,
		int mode_of_shifr_out,
		int hash_function_out);

	int derive();
	int prepareFileContexts();
	void initializeCryptoModule();
	void encrypt();
	void dectypt();
	void doCrypto();
	int closeFileContexts();
};
