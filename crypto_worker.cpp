#include "stdafx.h"
#include "crypto_worker.h"
using namespace CryptoPP;

cryptoWorker::cryptoWorker(
	bool mode_out,
	_TCHAR password_out[64],
	_TCHAR input_file_out[256],
	_TCHAR output_file_out[256],
	int type_of_shifr_out,
	int mode_of_shifr_out,
	int hash_function_out)
{
	mode = mode_out;
	_tcscpy_s(password, password_out);
	_tcscpy_s(input_file, input_file_out);
	_tcscpy_s(output_file, output_file_out);
	type_of_shifr = type_of_shifr_out;
	mode_of_shifr = mode_of_shifr_out;
	hash_function = hash_function_out;
}

void cryptoWorker::derive()
{
	if (hash_function == 1)
	{
		PKCS5_PBKDF2_HMAC<MD5> pbkdf2;
		//pbkdf2.DeriveKey()
	}
	else if (hash_function == 2)
	{
		PKCS5_PBKDF2_HMAC<SHA1> pbkdf2;
	}
}
