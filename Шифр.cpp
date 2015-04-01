#include "stdafx.h"
#include "defs.h"
#include "crypto_worker.h"
#include <iostream>
using namespace std;

void showHelp(string progName);

int _tmain(int argc, char *argv[])
{
	string programName = argv[0];
	if (argc < 2)
	{
		showHelp(programName);
		system("pause");
		return 2;
	}
	int nomer_stroki = 1; 
	int nomer_klucha = ARG_UNDEFINED;
	string password;
	password.clear();
	bool passwordEntered = false;
	string input_file;
	input_file.clear();
	bool inputFileSpecified = false;
	string output_file;
	output_file.clear();
	bool outputFileSpecified = false;
	int type_of_shifr = TYPE_UNDEFINED;
	int mode_of_shifr = MODE_UNDEFINED; // режим шифра
	int hash_function = HASH_TYPE_UNDEFINED;
	bool encrypt_mode = false;
	bool decrypt_mode = false;
	bool error = false; 
	bool help = false;

	string current_str;

	while (nomer_stroki < argc)
	{
		nomer_klucha = ARG_UNDEFINED;
		current_str = argv[nomer_stroki];
		_tprintf(_T("%d %s \n"), nomer_stroki, argv[nomer_stroki]);
		if ((current_str == "-e") || (current_str == "--encrypt"))
			nomer_klucha = ARG_ENC;

		else if ((current_str == "-d") || (current_str == "--decrypt"))
			nomer_klucha = ARG_DEC;

		else if ((current_str == "-p") || (current_str == "--password"))
			nomer_klucha = ARG_PASS;

		else if ((current_str == "-i") || (current_str == "--input"))
			nomer_klucha = ARG_IN;

		else if ((current_str == "-o") || (current_str == "--output"))
			nomer_klucha = ARG_OUT;

		else if ((current_str == "-c") || (current_str == "--cipher"))
			nomer_klucha = ARG_CIPHER;

		else if ((current_str == "-m") || (current_str == "--mode"))
			nomer_klucha = ARG_MODE;

		else if ((current_str == "-f") || (current_str == "--function"))
			nomer_klucha = ARG_HASH;

		else if ((current_str == "-h") || (current_str == "--help"))
			nomer_klucha = ARG_HELP;

		switch (nomer_klucha)
		{
		case ARG_ENC:
			if (encrypt_mode)
				error = true;
			else
				encrypt_mode = true;
			break;
		case ARG_DEC:
			if (decrypt_mode)
				error = true;
			else
			    decrypt_mode = true;
			break;
		case ARG_PASS:
			if (passwordEntered)
				error = true;
			else
			{
				password = argv[nomer_stroki + 1]; // строка не увеличивается на единицу 
				passwordEntered = true;
				nomer_stroki += 1; // строка увеличивается на единицу
			}
            break;
		case ARG_IN:
			
			if (inputFileSpecified)
				error = true;
			else
			{
				input_file = argv[nomer_stroki + 1]; 
				inputFileSpecified = true;
				nomer_stroki += 1;
			}
			break;
		case ARG_OUT:
			if (outputFileSpecified)
				error = true;
			else
			{
				output_file = argv[nomer_stroki + 1]; 
				outputFileSpecified = true;
				nomer_stroki += 1;
			}
			break;
		case ARG_CIPHER: 
			if (type_of_shifr != TYPE_UNDEFINED)
				error = true;
			else
			{
				string nextArg = argv[nomer_stroki + 1];
				if (nextArg == "AES")
					type_of_shifr = TYPE_AES;
				else if (nextArg == "GOST")
					type_of_shifr = TYPE_GOST;
				else error = true;
				nomer_stroki += 1;
			}
			break;
		case ARG_MODE: 
			if (mode_of_shifr != MODE_UNDEFINED)
				error = true;
			else
			{
				string nextArg = argv[nomer_stroki + 1];
				if (nextArg == "ECB")
					mode_of_shifr = MODE_ECB;
				else if (nextArg == "CBC")
					mode_of_shifr = MODE_CBC;
				else if (nextArg == "CFB")
					mode_of_shifr = MODE_CFB;
				else if (nextArg == "OFB")
					mode_of_shifr = MODE_OFB;
				else error = true;
				nomer_stroki += 1;
			}
			break;
		case ARG_HASH:
			if (hash_function != HASH_TYPE_UNDEFINED)
				error = true;
			else
			{
				string nextArg = argv[nomer_stroki + 1];
				if (nextArg == "MD5")
					hash_function = HASH_TYPE_MD5;
				else if (nextArg == "SHA-1")
					hash_function = HASH_TYPE_SHA1;
				else error = true;
				nomer_stroki += 1;
			}
			break;
		case ARG_HELP:
			help = true;
			error = true;
			break;
		default: 
			error = true;
			break;
		}
		nomer_stroki = nomer_stroki + 1;
		if (error)
			break;
	}

	if (help)
	{
		showHelp(programName);
		system("pause");
		return 0;
	}

	if (error)
	{
		cout << "\nSyntax error!\n";
		system("pause");
		return 1;// error;
	}

	if (encrypt_mode == decrypt_mode)
	{
		cout << "\nSyntax error!\n";
		system("pause"); 
		return 1;// error;
	}
	if (!inputFileSpecified || !outputFileSpecified || !passwordEntered)
	{
		cout << "\nSyntax error!\n";
		system("pause");
		return 1;// error;
	}

	if (encrypt_mode && (!type_of_shifr || !mode_of_shifr || !hash_function))
	{
		cout << "\nSyntax error!\n";
		system("pause");
		return 1;// error;
	}

	cryptoWorker letsDoSomeCrypto((encrypt_mode && !decrypt_mode), password, input_file, output_file, type_of_shifr, mode_of_shifr, hash_function);

	if (letsDoSomeCrypto.prepareFileContexts())
	{
		cout << "\nError. Can't open file(s)!\n";
		system("pause");
		return 2;
		// error
	}

	if (letsDoSomeCrypto.derive())
	{
		cout << "\nError. Wrong password!\n";
		system("pause");
		return 3;
		// error
	}

	letsDoSomeCrypto.doCrypto();
	letsDoSomeCrypto.closeFileContexts();

	cout << "\nSuccess!\n";
	system("pause");
	return 0;
}

void showHelp(string progName)
{
	int a = progName.find_last_of("\\");
	string pName;
	if (a != string::npos)
		pName = progName.substr(a+1);
	else
		pName = progName;
	cout << "Usage:" << "\n";
	cout << pName << " -e -p <password> -i <in_filename> -o <out_filename> -c <cipher> -m <mode> -f <hash>" << "\n";
	cout << pName << " -d -p <password> -i <in_filename> -o <out_filename>" << "\n";
	cout << pName << " -h" << "\n";
	cout << "-e, --encrypt - Sets encrypt mode" << "\n";
	cout << "-d, --decrypt - Sets decrypt mode" << "\n";
	cout << "-p <password>, --password <password> - Password" << "\n";
	cout << "-i <in_filename>, --input <in_filename> - Input file name" << "\n";
	cout << "-o <out_filename>, --output <out_filename> - Output file name" << "\n";
	cout << "-c <cipher>, --cipher <cipher> - Cipher algorithm" << "\n";
	cout << "-m <mode>, --mode <mode> - Cipher mode" << "\n";
	cout << "-f <hash>, --function <hash> - Hash function algoritm user to derive key" << "\n";
	cout << "-h, --help - Print this usage text" << "\n" << "\n";
	cout << "Availible cipher algorithms:\n" << "AES\n" << "GOST\n" << "\n";
	cout << "Availible cipher modes:\n" << "ECB\n" << "CFB\n" << "CBC\n" << "OFB\n" << "\n";
	cout << "Availible hash algorithms:\n" << "MD5\n" << "SHA-1\n" << "\n";
}
