// Пока только берутся ключи, разбираются и ищутся ошибки  
 #include "stdafx.h" 
 #include "crypto_worker.h" 
 #include <iostream> 
 using namespace std; 
 
 
 int _tmain(int argc, _TCHAR* argv[]) 
 { 
 	int nomer_stroki = 1;  
 	int nomer_klucha = 0; 
 	_TCHAR password[64]; 
 	memset(password, 0, sizeof(_TCHAR)* 64); 
 	bool passwordEntered = false; 
 	_TCHAR input_file[256]; 
 	memset(input_file, 0, sizeof(_TCHAR)* 256); 
 	bool inputFileSpecified = false; 
 	_TCHAR output_file[256]; 
 	memset(output_file, 0, sizeof(_TCHAR)* 256); 
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
 		if ((!(_tcscmp(argv[nomer_stroki], _T("-e")))) || (!(_tcscmp(argv[nomer_stroki], _T("--encrypt"))))) 
 			nomer_klucha = 1; 
 
 
 		else if ((!(_tcscmp(argv[nomer_stroki], _T("-d")))) || (!(_tcscmp(argv[nomer_stroki], _T("--decrypt"))))) 
 			nomer_klucha = 2; 
 
 
 		else if ((!(_tcscmp(argv[nomer_stroki], _T("-p")))) || (!(_tcscmp(argv[nomer_stroki], _T("--password"))))) 
 			nomer_klucha = 3; 
 
 
 		else if ((!(_tcscmp(argv[nomer_stroki], _T("-i")))) || (!(_tcscmp(argv[nomer_stroki], _T("--input"))))) 
 			nomer_klucha = 4; 
 
 
 		else if ((!(_tcscmp(argv[nomer_stroki], _T("-o")))) || (!(_tcscmp(argv[nomer_stroki], _T("--output"))))) 
 			nomer_klucha = 5; 
 
 
 		else if ((!(_tcscmp(argv[nomer_stroki], _T("-c")))) || (!(_tcscmp(argv[nomer_stroki], _T("--cipher"))))) 
 			nomer_klucha = 6; 
 
 
 		else if ((!(_tcscmp(argv[nomer_stroki], _T("-m")))) || (!(_tcscmp(argv[nomer_stroki], _T("--mode"))))) 
 			nomer_klucha = 7; 
 
 
 		else if ((!(_tcscmp(argv[nomer_stroki], _T("-f")))) || (!(_tcscmp(argv[nomer_stroki], _T("--function"))))) 
 			nomer_klucha = 8; 
 
 
 		else if ((!(_tcscmp(argv[nomer_stroki], _T("-h")))) || (!(_tcscmp(argv[nomer_stroki], _T("--help"))))) 
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
 				_tcscpy_s(password, argv[nomer_stroki + 1]); // строка не увеличивается на единицу  
 				passwordEntered = true; 
				nomer_stroki += 1; // строка увеличивается на единицу 
 			} 
 			break; 
 
 
 		case 4: 
 			 
 			if (inputFileSpecified) 
 				error = true; 
 			else 
 			{ 
 				_tcscpy_s(input_file, argv[nomer_stroki + 1]);  
 				inputFileSpecified = true; 
 				nomer_stroki += 1; 
 			} 
 			break; 
 
 
 		case 5: 
 			if (outputFileSpecified) 
 				error = true; 
 			else 
 			{ 
 				_tcscpy_s(output_file, argv[nomer_stroki + 1]);  
 				outputFileSpecified = true; 
 				nomer_stroki += 1; 
			} 
 			break; 
 
 
 		case 6:  
 			if (type_of_shifr != 0) 
 				error = true; 
 			else 
 			{ 
 				if (!(_tcscmp(argv[nomer_stroki + 1], _T("AES")))) 
 					type_of_shifr = 1; 
 				else if (!(_tcscmp(argv[nomer_stroki + 1], _T("GOST")))) 
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
 				if (!(_tcscmp(argv[nomer_stroki + 1], _T("ECB")))) 
 					mode_of_shifr = 1; 
 				else if (!(_tcscmp(argv[nomer_stroki + 1], _T("CBC")))) 
 					mode_of_shifr = 2; 
 				else if (!(_tcscmp(argv[nomer_stroki + 1], _T("CFB")))) 
 					mode_of_shifr = 3; 
 				else if (!(_tcscmp(argv[nomer_stroki + 1], _T("OFB")))) 
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
 				if (!(_tcscmp(argv[nomer_stroki + 1], _T("MD5")))) 
 					hash_function = 1; 
 				else if (!(_tcscmp(argv[nomer_stroki + 1], _T("SHA-1")))) 
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

 	system("pause"); 
 	return 0; 
} 

