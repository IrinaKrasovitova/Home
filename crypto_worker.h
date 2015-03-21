#pragma once

#include "stdafx.h"
#include "cryptopp\Include\pwdbased.h"
#include "cryptopp\Include\md5.h"
#include "cryptopp\Include\sha.h"

class cryptoWorker {
	bool mode;
	_TCHAR password[64];
	_TCHAR input_file[256];
	_TCHAR output_file[256];
	int type_of_shifr;
	int mode_of_shifr;
	int hash_function;
	int k;

public:
	cryptoWorker(
		bool mode_out,
		_TCHAR password_out[64],
		_TCHAR input_file_out[256], 
		_TCHAR output_file_out[256],
		int type_of_shifr_out,
		int mode_of_shifr_out,
		int hash_function_out);
	void derive();

};
