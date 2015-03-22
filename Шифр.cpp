#include "stdafx.h"
#include "crypto_worker.h"
#include <iostream>
using namespace std;

int _tmain(int argc, string argv[])
{
	int nomer_stroki = 1; 
	int nomer_klucha = 0;
	string password;
	password.clear();
	bool passwordEntered = false;
	string input_file;
	input_file.clear();
	bool inputFileSpecified = false;
	string output_file;
	output_file.clear();
	bool outputFileSpecified = false;
	int type_of_shifr = 0;
	int mode_of_shifr = 0; // режим шифра
	int hash_function = 0;
	bool encrypt_mode = false;
	bool decrypt_mode = false;
	bool error = false; 

	while (nomer_stroki < argc)
	{
		_tprintf(_T("%d %s \n"), nomer_stroki, argv[nomer_stroki]);
		if ((argv[nomer_stroki] == "-e") || (argv[nomer_stroki] == "--encrypt"))
			nomer_klucha = 1;

		else if ((argv[nomer_stroki] == "-d") || (argv[nomer_stroki] == "--decrypt"))
			nomer_klucha = 2;

		else if ((argv[nomer_stroki] == "-p") || (argv[nomer_stroki] == "--password"))
			nomer_klucha = 3;

		else if ((argv[nomer_stroki] == "-i") || (argv[nomer_stroki] == "--input"))
			nomer_klucha = 4;

		else if ((argv[nomer_stroki] == "-o") || (argv[nomer_stroki] == "--output"))
			nomer_klucha = 5;

		else if ((argv[nomer_stroki] == "-c") || (argv[nomer_stroki] == "--cipher"))
			nomer_klucha = 6;

		else if ((argv[nomer_stroki] == "-m") || (argv[nomer_stroki] == "--mode"))
			nomer_klucha = 7;

		else if ((argv[nomer_stroki] == "-f") || (argv[nomer_stroki] == "--function"))
			nomer_klucha = 8;

		else if ((argv[nomer_stroki] == "-h") || (argv[nomer_stroki] == "--help"))
			nomer_klucha = 9;

		switch (nomer_klucha)
		{
		case 1:
			if (encrypt_mode)
				error = true;
			else
				encrypt_mode = true;
			break;
		case 2:
			if (decrypt_mode)
				error = true;
			else
			    decrypt_mode = true;
			break;
		case 3:
			if (passwordEntered)
				error = true;
			else
			{
				password = argv[nomer_stroki + 1]; // строка не увеличивается на единицу 
				passwordEntered = true;
				nomer_stroki += 1; // строка увеличивается на единицу
			}
            break;
		case 4:
			
			if (inputFileSpecified)
				error = true;
			else
			{
				input_file = argv[nomer_stroki + 1]; 
				inputFileSpecified = true;
				nomer_stroki += 1;
			}
			break;
		case 5:
			if (outputFileSpecified)
				error = true;
			else
			{
				output_file = argv[nomer_stroki + 1]; 
				outputFileSpecified = true;
				nomer_stroki += 1;
			}
			break;
		case 6: 
			if (type_of_shifr != 0)
				error = true;
			else
			{
				if (argv[nomer_stroki + 1] == "AES")
					type_of_shifr = 1;
				else if (argv[nomer_stroki + 1] == "GOST")
					type_of_shifr = 2;
				else error = true;
				nomer_stroki += 1;
			}
			break;
		case 7: 
			if (mode_of_shifr != 0)
				error = true;
			else
			{
				if (argv[nomer_stroki + 1] == "ECB")
					mode_of_shifr = 1;
				else if (argv[nomer_stroki + 1] == "CBC")
					mode_of_shifr = 2;
				else if (argv[nomer_stroki + 1] == "CFB")
					mode_of_shifr = 3;
				else if (argv[nomer_stroki + 1] == "OFB")
					mode_of_shifr = 4;
				else error = true;
				nomer_stroki += 1;
			}
			break;
		case 8:
			if (hash_function != 0)
				error = true;
			else
			{
				if (argv[nomer_stroki + 1] == "MD5")
					hash_function = 1;
				else if (argv[nomer_stroki + 1] == "SHA-1")
					hash_function = 2;
				else error = true;
				nomer_stroki += 1;
			}
			break;
		default: 
			error = true;
			break;
		}
		nomer_stroki = nomer_stroki + 1;
		if (error)
			break;
	}

	// Логика достаточности введенных ключей 
	if ((encrypt_mode && decrypt_mode) || (!encrypt_mode && !decrypt_mode)); // error;
	if (!type_of_shifr || !mode_of_shifr || !hash_function || !inputFileSpecified || !outputFileSpecified || !passwordEntered); // error - insufficient keys;

	cryptoWorker letsDoSomeCrypto((encrypt_mode && !decrypt_mode), password, input_file, output_file, type_of_shifr, mode_of_shifr, hash_function);
	if (letsDoSomeCrypto.prepareFileContexts())
	{
		// error
	}
	if (letsDoSomeCrypto.derive())
	{
		// error
	}
	letsDoSomeCrypto.doCrypto();
	letsDoSomeCrypto.closeFileContexts();

	// проверка существования исходного файла.
	// доступность целевого файла.
	// соответствие режима шифрования алгоритму шифрования.
    // минимальная длина пароля.
	// 



	system("pause");


	return 0;
}

