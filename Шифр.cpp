// разбираются ключи, проверяются ошибки, избыточность, недостаточность ключей, при зашифровании в начало файла пишутся необходимые данные, при расшифровании - читаются оттуда. происходит и зашифрование и расшифрование. но только первый блок расшифровывается верно.
#include "stdafx.h"
#include "crypto_worker.h"
#include <iostream>
using namespace std;

int _tmain(int argc, char *argv[])
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

	//while (nomer_stroki < argc)
	//{
	//	string curr = argv[nomer_stroki];
	//	//curr = argv[nomer_stroki];
	//	//_tprintf(_T("%d %s \n"), nomer_stroki, argv[nomer_stroki]);
	//	int tmp = curr.length();
	//	cout << nomer_stroki << argv[nomer_stroki];
	//	nomer_stroki += 1;
	//}

	string current_str;

	while (nomer_stroki < argc)
	{

		current_str = argv[nomer_stroki];
		_tprintf(_T("%d %s \n"), nomer_stroki, argv[nomer_stroki]);
		if ((current_str == "-e") || (current_str == "--encrypt"))
			nomer_klucha = 1;

		else if ((current_str == "-d") || (current_str == "--decrypt"))
			nomer_klucha = 2;

		else if ((current_str == "-p") || (current_str == "--password"))
			nomer_klucha = 3;

		else if ((current_str == "-i") || (current_str == "--input"))
			nomer_klucha = 4;

		else if ((current_str == "-o") || (current_str == "--output"))
			nomer_klucha = 5;

		else if ((current_str == "-c") || (current_str == "--cipher"))
			nomer_klucha = 6;

		else if ((current_str == "-m") || (current_str == "--mode"))
			nomer_klucha = 7;

		else if ((current_str == "-f") || (current_str == "--function"))
			nomer_klucha = 8;

		else if ((current_str == "-h") || (current_str == "--help"))
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
				string nextArg = argv[nomer_stroki + 1];
				if (nextArg == "AES")
					type_of_shifr = 1;
				else if (nextArg == "GOST")
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
				string nextArg = argv[nomer_stroki + 1];
				if (nextArg == "ECB")
					mode_of_shifr = 1;
				else if (nextArg == "CBC")
					mode_of_shifr = 2;
				else if (nextArg == "CFB")
					mode_of_shifr = 3;
				else if (nextArg == "OFB")
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
				string nextArg = argv[nomer_stroki + 1];
				if (nextArg == "MD5")
					hash_function = 1;
				else if (nextArg == "SHA-1")
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

	// ЛОГИКА ДОСТАТОЧНОСТИ ВВЕДЁННЫХ КЛЮЧЕЙ
	if (encrypt_mode == decrypt_mode)
	{
		system("pause"); 
		return 1;// error;
	}
	if (!type_of_shifr || !mode_of_shifr || !hash_function || !inputFileSpecified || !outputFileSpecified || !passwordEntered)
	{
		system("pause");
		return 1;// error;
	}

	cryptoWorker letsDoSomeCrypto((encrypt_mode && !decrypt_mode), password, input_file, output_file, type_of_shifr, mode_of_shifr, hash_function);
	if (letsDoSomeCrypto.prepareFileContexts())
	{
		goto GO_TO_EXIT;
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


GO_TO_EXIT:
	system("pause");


	return 0;
}

