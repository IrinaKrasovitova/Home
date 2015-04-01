#pragma once

#include "stdafx.h"

#include "iostream"
#include "fstream"

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
	int keyk;
	int ivk;
	ifstream inStream;
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
	void encryptAES();
	void encryptGOST();
	void decrypt();
	void decryptAES();
	void decryptGOST();
	void doCrypto();
	int closeFileContexts();
};
