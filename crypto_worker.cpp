#include "stdafx.h"
#include "defs.h"
#include "crypto_worker.h"
using namespace CryptoPP;
using namespace std;

int calculateK(int N, int M)  // Округление вверх
{
	if ((N%M) != 0)   // не делится нацело
		return ((N / M) + 1);     // Целая часть (N/M) - округление вниз. "+1" - вверх.
	else              // делится нацело
		return (N / M);
}

cryptoWorker::cryptoWorker(
	bool mode_out,
	string password_out,
	string input_file_out,
	string output_file_out,
	int type_of_shifr_out,
	int mode_of_shifr_out,
	int hash_function_out)
{
	mode = mode_out;
	password = password_out;
	input_file = input_file_out;
	output_file = output_file_out;
	type_of_shifr = type_of_shifr_out;
	mode_of_shifr = mode_of_shifr_out;
	hash_function = hash_function_out;
}

int cryptoWorker::derive() // Выработка ключа из пароля. В обоих алгоритмах (AES, GOST) используется ключ 256 бит.
{
	byte passwd[64] = {}, passDigest[SHA::DIGESTSIZE] = {}, passwordDigest[SHA::DIGESTSIZE] = {};
	int N = 32; // (длина ключа)
	int M = 0;
	keyk = 0;
	ivk = 0;

	if (!mode)
	{
		memcpy(passwd, password.data(), password.length());
		SHA hash;
		hash.Update(passwd, 64);
		hash.Final(passDigest);

		struct cryptoData decryptData;
		//FILE *infile;
		//fopen_s(&infile, input_file.data(), "wb");
		//fwrite(&decryptData, sizeof(decryptData), 1, infile);
		//fclose(infile);
		inStream.read((char *) &decryptData, sizeof(struct cryptoData));
		type_of_shifr = decryptData.type_of_shifr;
		mode_of_shifr = decryptData.mode_of_shifr;
		hash_function = decryptData.type_of_hash;
		keyk = decryptData.keyIterations;
		ivk = decryptData.ivIterations;
		
		for (int i = 0; i < SALT_LEN; i++)
		{
			key_salt[i] = decryptData.key_salt[i];
			iv_salt[i] = decryptData.iv_salt[i];
		}
		for (int i = 0; i < SHA::DIGESTSIZE; i++)
			passwordDigest[i] = decryptData.passDigest[i];

		if (!strcmp((char *)passDigest, (char *)passwordDigest))
			return 1;

		if (hash_function == 1)
		{
			PKCS5_PBKDF2_HMAC<MD5> pbkdf2; // M = 16
			pbkdf2.DeriveKey(key, KEY_LENGTH, 0, passwd, password.length(), key_salt, SALT_LEN, keyk, 0);
			pbkdf2.DeriveKey(IV, IV_LENGTH, 0, passwd, password.length(), iv_salt, SALT_LEN, ivk, 0);
		}
		else if (hash_function == 2)
		{
			PKCS5_PBKDF2_HMAC<SHA1> pbkdf2; // M = 20
			pbkdf2.DeriveKey(key, KEY_LENGTH, 0, passwd, password.length(), key_salt, SALT_LEN, keyk, 0);
			pbkdf2.DeriveKey(IV, IV_LENGTH, 0, passwd, password.length(), iv_salt, SALT_LEN, ivk, 0);
		}
	}
	else
	{
		OS_GenerateRandomBlock(true, key_salt, SALT_LEN);
		OS_GenerateRandomBlock(false, iv_salt, SALT_LEN);
		memcpy(passwd, password.data(), password.length());
		if (hash_function == 1)
		{
			PKCS5_PBKDF2_HMAC<MD5> pbkdf2; // M = 16
			M = 16;
			keyk = ivk = calculateK(N, M);
			keyk = pbkdf2.DeriveKey(key, KEY_LENGTH, 0, passwd, password.length(), key_salt, SALT_LEN, keyk, 0.5);
			ivk = pbkdf2.DeriveKey(IV, IV_LENGTH, 0, passwd, password.length(), iv_salt, SALT_LEN, ivk, 0.5);
		}
		else if (hash_function == 2)
		{
			PKCS5_PBKDF2_HMAC<SHA1> pbkdf2; // M = 20
			M = 20;
			keyk = ivk = calculateK(N, M);
			keyk = pbkdf2.DeriveKey(key, KEY_LENGTH, 0, passwd, password.length(), key_salt, SALT_LEN, keyk, 0.5);
			ivk = pbkdf2.DeriveKey(IV, IV_LENGTH, 0, passwd, password.length(), iv_salt, SALT_LEN, ivk, 0.5);
		}
	}
	return 0;
}

int cryptoWorker::prepareFileContexts()
{
	inStream.open(input_file.data(), ios_base::in | ios_base::binary);
	if (!(inStream.is_open()))
	{
		errorString = "Error. Input file is not accesible.";
		return 1;
	}
	if (!mode)
	{

	}
	outStream.open(output_file.data(), ios_base::out | ios_base::binary);
	if (!(outStream.is_open()))
	{
		errorString = "Error. Output file is not accesible.";
		return 2;
	}
	return 0;
}

void cryptoWorker::initializeCryptoModule()
{

}

void cryptoWorker::encrypt()
{
	struct cryptoData encryptData;
	int a = sizeof(encryptData);
	byte passwd[64] = {}, passDigest[SHA::DIGESTSIZE] = {};
	memcpy(passwd, password.data(), password.length());
	SHA hash;
	hash.Update(passwd, 64);
	hash.Final(passDigest);
	for (int i = 0; i < SHA::DIGESTSIZE; i++)
		encryptData.passDigest[i] = passDigest[i];
	encryptData.type_of_shifr = type_of_shifr;
	encryptData.mode_of_shifr = mode_of_shifr;
	encryptData.type_of_hash = hash_function;
	encryptData.keyIterations = keyk;
	encryptData.ivIterations = ivk;
	for (int i = 0; i < SALT_LEN; i++)
	{
		encryptData.key_salt[i] = key_salt[i];
		encryptData.iv_salt[i] = iv_salt[i];
	}

	//FILE *outfile;
	//fopen_s(&outfile, output_file.data(), "wb");
	//fwrite(&encryptData, sizeof(encryptData), 1, outfile);
	//fclose(outfile);
	outStream.write((char *) &encryptData, sizeof(struct cryptoData));

	outStream.flush();



	//if (prepareFileContexts())
	//	return;

	encryptAES();
	encryptGOST();
}

void cryptoWorker::encryptAES()
{
	if (type_of_shifr == TYPE_AES)
	{
		byte inbuffer[AES_BUFFER_SIZE] = {};
		byte outbuffer[AES_BUFFER_SIZE] = {};
		AES::Encryption aesEncryptor;
		aesEncryptor.SetKey(key, KEY_LENGTH);

		if (mode_of_shifr == MODE_ECB)
		{
			while (!inStream.eof())
			{
				inStream.read((char*)inbuffer, AES_BUFFER_SIZE*sizeof(byte));
				aesEncryptor.ProcessBlock(inbuffer, outbuffer);
				outStream.write((char*)outbuffer, AES_BUFFER_SIZE*sizeof(byte));
				memset_z(inbuffer, '\0', AES_BUFFER_SIZE*sizeof(byte));
				memset_z(outbuffer, '\0', AES_BUFFER_SIZE*sizeof(byte));
			}
		}
		else if (mode_of_shifr == MODE_CBC)
		{
			while (!inStream.eof())
			{
				inStream.read((char*)inbuffer, AES_BUFFER_SIZE*sizeof(byte));
				for (int i = 0; i < AES_IV_LENGTH; i++)
					inbuffer[i] = inbuffer[i] ^ IV[i];
				aesEncryptor.ProcessBlock(inbuffer, outbuffer);
				for (int i = 0; i < AES_IV_LENGTH; i++)
					IV[i] = outbuffer[i];
				outStream.write((char*)outbuffer, AES_BUFFER_SIZE*sizeof(byte));
				memset_z(inbuffer, '\0', AES_BUFFER_SIZE*sizeof(byte));
				memset_z(outbuffer, '\0', AES_BUFFER_SIZE*sizeof(byte));
			}
		}
		else if (mode_of_shifr == MODE_CFB)
		{
			while (!inStream.eof())
			{
				inStream.read((char*)inbuffer, AES_BUFFER_SIZE*sizeof(byte));
				aesEncryptor.ProcessBlock(IV, outbuffer);
				for (int i = 0; i < AES_IV_LENGTH; i++)
				{
					outbuffer[i] = inbuffer[i] ^ outbuffer[i];  // Получаем шифротекст (равен синхропосылке)
					IV[i] = outbuffer[i];  // Сохраняем синхропосылку следующего блока
				}
				outStream.write((char*)outbuffer, AES_BUFFER_SIZE*sizeof(byte));
				memset_z(inbuffer, '\0', AES_BUFFER_SIZE*sizeof(byte));
				memset_z(outbuffer, '\0', AES_BUFFER_SIZE*sizeof(byte));
			}
		}
		else if (mode_of_shifr == MODE_OFB)
		{
			while (!inStream.eof())
			{
				inStream.read((char*)inbuffer, AES_BUFFER_SIZE*sizeof(byte));
				aesEncryptor.ProcessBlock(IV, outbuffer);
				for (int i = 0; i < AES_IV_LENGTH; i++)
				{
					IV[i] = outbuffer[i];  // Сохраняем синхропосылку следующего блока
					outbuffer[i] = inbuffer[i] ^ outbuffer[i];  // Получаем шифротекст (не равен синхропосылке)
				}
				outStream.write((char*)outbuffer, AES_BUFFER_SIZE*sizeof(byte));
				memset_z(inbuffer, '\0', AES_BUFFER_SIZE*sizeof(byte));
				memset_z(outbuffer, '\0', AES_BUFFER_SIZE*sizeof(byte));
			}
		}
	}
}

void cryptoWorker::encryptGOST()
{
	if (type_of_shifr == TYPE_GOST)
	{
		byte inbuffer[GOST_BUFFER_SIZE] = {};
		byte outbuffer[GOST_BUFFER_SIZE] = {};
		GOST::Encryption gostEncryptor;
		gostEncryptor.SetKey(key, GOST::KEYLENGTH);
		if (mode_of_shifr == MODE_ECB)
		{
			while (!inStream.eof())
			{
				inStream.read((char*)inbuffer, GOST_BUFFER_SIZE*sizeof(byte));
				gostEncryptor.ProcessBlock(inbuffer, outbuffer);
				outStream.write((char*)outbuffer, GOST_BUFFER_SIZE*sizeof(byte));
				memset_z(inbuffer, '\0', GOST_BUFFER_SIZE*sizeof(byte));
				memset_z(outbuffer, '\0', GOST_BUFFER_SIZE*sizeof(byte));
			}
		}
		else if (mode_of_shifr == MODE_CBC)
		{
			while (!inStream.eof())
			{
				inStream.read((char*)inbuffer, GOST_BUFFER_SIZE*sizeof(byte));
				for (int i = 0; i < GOST_IV_LENGTH; i++)
					inbuffer[i] = inbuffer[i] ^ IV[i];
				gostEncryptor.ProcessBlock(inbuffer, outbuffer);
				for (int i = 0; i < GOST_IV_LENGTH; i++)
					IV[i] = outbuffer[i];
				outStream.write((char*)outbuffer, GOST_BUFFER_SIZE*sizeof(byte));
				memset_z(inbuffer, '\0', GOST_BUFFER_SIZE*sizeof(byte));
				memset_z(outbuffer, '\0', GOST_BUFFER_SIZE*sizeof(byte));
			}
		}
		else if (mode_of_shifr == MODE_CFB) // Гаммирование с обратной связью
		{
			while (!inStream.eof())
			{
				inStream.read((char*)inbuffer, GOST_BUFFER_SIZE*sizeof(byte));
				gostEncryptor.ProcessBlock(IV, outbuffer);
				for (int i = 0; i < GOST_IV_LENGTH; i++)
				{
					outbuffer[i] = inbuffer[i] ^ outbuffer[i];  // Получаем шифротекст (равен синхропосылке)
					IV[i] = outbuffer[i];  // Сохраняем синхропосылку следующего блока
				}
				outStream.write((char*)outbuffer, GOST_BUFFER_SIZE*sizeof(byte));
				memset_z(inbuffer, '\0', GOST_BUFFER_SIZE*sizeof(byte));
				memset_z(outbuffer, '\0', GOST_BUFFER_SIZE*sizeof(byte));
			}
		}
		else if (mode_of_shifr == MODE_OFB)
		{
			while (!inStream.eof())
			{
				inStream.read((char*)inbuffer, GOST_BUFFER_SIZE*sizeof(byte));
				gostEncryptor.ProcessBlock(IV, outbuffer);
				for (int i = 0; i < GOST_IV_LENGTH; i++)
				{
					IV[i] = outbuffer[i];  // Сохраняем синхропосылку следующего блока
					outbuffer[i] = inbuffer[i] ^ outbuffer[i];  // Получаем шифротекст (не равен синхропосылке)
				}
				outStream.write((char*)outbuffer, GOST_BUFFER_SIZE*sizeof(byte));
				memset_z(inbuffer, '\0', GOST_BUFFER_SIZE*sizeof(byte));
				memset_z(outbuffer, '\0', GOST_BUFFER_SIZE*sizeof(byte));
			}
		}
	}
	
	return;
}

void cryptoWorker::decrypt()
{
	decryptAES();
	decryptGOST();
}

void cryptoWorker::decryptAES()
{
	if (type_of_shifr == TYPE_AES)
	{
		byte inbuffer[AES_BUFFER_SIZE] = {};
		byte outbuffer[AES_BUFFER_SIZE] = {};
		if (mode_of_shifr == MODE_ECB)
		{
			AES::Decryption aesDecryptor;
			aesDecryptor.SetKey(key, KEY_LENGTH);
			while (!inStream.eof())
			{
				inStream.read((char*)inbuffer, AES_BUFFER_SIZE*sizeof(byte));
				aesDecryptor.ProcessBlock(inbuffer, outbuffer);
				outStream.write((char*)outbuffer, AES_BUFFER_SIZE*sizeof(byte));
				memset_z(inbuffer, '\0', AES_BUFFER_SIZE*sizeof(byte));
				memset_z(outbuffer, '\0', AES_BUFFER_SIZE*sizeof(byte));
			}
		}
		else if (mode_of_shifr == MODE_CBC)
		{
			AES::Decryption aesDecryptor;
			aesDecryptor.SetKeyWithIV(key, KEY_LENGTH, IV, IV_LENGTH);
			while (!inStream.eof())
			{
				inStream.read((char*)inbuffer, AES_BUFFER_SIZE*sizeof(byte));
				aesDecryptor.ProcessBlock(inbuffer, outbuffer);
				for (int i = 0; i < AES_IV_LENGTH; i++)
				{
					outbuffer[i] = outbuffer[i] ^ IV[i];
					IV[i] = inbuffer[i];
				}
				outStream.write((char*)outbuffer, AES_BUFFER_SIZE*sizeof(byte));
				memset_z(inbuffer, '\0', AES_BUFFER_SIZE*sizeof(byte));
				memset_z(outbuffer, '\0', AES_BUFFER_SIZE*sizeof(byte));
			}
		}
		else if (mode_of_shifr == MODE_CFB)
		{
			AES::Encryption aesEncryptor;
			aesEncryptor.SetKeyWithIV(key, KEY_LENGTH, IV, AES_IV_LENGTH);
			while (!inStream.eof())
			{
				inStream.read((char*)inbuffer, AES_BUFFER_SIZE*sizeof(byte));
				aesEncryptor.ProcessBlock(IV, outbuffer);
				for (int i = 0; i < AES_IV_LENGTH; i++)
				{
					outbuffer[i] = outbuffer[i] ^ inbuffer[i];
					IV[i] = inbuffer[i];
				}
				outStream.write((char*)outbuffer, AES_BUFFER_SIZE*sizeof(byte));
				memset_z(inbuffer, '\0', AES_BUFFER_SIZE*sizeof(byte));
				memset_z(outbuffer, '\0', AES_BUFFER_SIZE*sizeof(byte));
			}
		}
		else if (mode_of_shifr == MODE_OFB)
		{
			AES::Encryption aesEncryptor;
			aesEncryptor.SetKeyWithIV(key, KEY_LENGTH, IV, AES_IV_LENGTH);
			while (!inStream.eof())
			{
				inStream.read((char*)inbuffer, AES_BUFFER_SIZE*sizeof(byte));
				aesEncryptor.ProcessBlock(IV, outbuffer);
				for (int i = 0; i < AES_IV_LENGTH; i++)
				{
					IV[i] = outbuffer[i];
					outbuffer[i] = outbuffer[i] ^ inbuffer[i];
				}
				outStream.write((char*)outbuffer, AES_BUFFER_SIZE*sizeof(byte));
				memset_z(inbuffer, '\0', AES_BUFFER_SIZE*sizeof(byte));
				memset_z(outbuffer, '\0', AES_BUFFER_SIZE*sizeof(byte));
			}
		}
	}
}

void cryptoWorker::decryptGOST()
{
	if (type_of_shifr == TYPE_GOST)
	{
		byte inbuffer[GOST_BUFFER_SIZE] = {};
		byte outbuffer[GOST_BUFFER_SIZE] = {};
		if (mode_of_shifr == MODE_ECB)  // РЕжим простой замены
		{
			GOST::Decryption gostDecryptor;
			gostDecryptor.SetKey(key, 32);
			while (!inStream.eof())
			{
				inStream.read((char*)inbuffer, GOST_BUFFER_SIZE*sizeof(byte));
				gostDecryptor.ProcessBlock(inbuffer, outbuffer);
				outStream.write((char*)outbuffer, GOST_BUFFER_SIZE*sizeof(byte));
				memset_z(inbuffer, '\0', GOST_BUFFER_SIZE*sizeof(byte));
				memset_z(outbuffer, '\0', GOST_BUFFER_SIZE*sizeof(byte));
			}
		}
		else if (mode_of_shifr == MODE_CBC)
		{
			GOST::Decryption gostDecryptor;
			gostDecryptor.SetKeyWithIV(key, KEY_LENGTH, IV, GOST_IV_LENGTH);
			while (!inStream.eof())
			{
				inStream.read((char*)inbuffer, GOST_BUFFER_SIZE*sizeof(byte));
				gostDecryptor.ProcessBlock(inbuffer, outbuffer);
				for (int i = 0; i < GOST_IV_LENGTH; i++)
				{
					outbuffer[i] = outbuffer[i] ^ IV[i];
					IV[i] = inbuffer[i];
				}
				outStream.write((char*)outbuffer, GOST_BUFFER_SIZE*sizeof(byte));
				memset_z(inbuffer, '\0', GOST_BUFFER_SIZE*sizeof(byte));
				memset_z(outbuffer, '\0', GOST_BUFFER_SIZE*sizeof(byte));
			}
		}
		else if (mode_of_shifr == MODE_CFB) // Режим гаммирования с обратной связью
		{
			GOST::Encryption gostEncryptor;
			gostEncryptor.SetKey(key, KEY_LENGTH);
			while (!inStream.eof())
			{
				inStream.read((char*)inbuffer, GOST_BUFFER_SIZE*sizeof(byte));
				gostEncryptor.ProcessBlock(IV, outbuffer);
				for (int i = 0; i < GOST_IV_LENGTH; i++)
				{
					outbuffer[i] = outbuffer[i] ^ inbuffer[i];
					IV[i] = inbuffer[i];
				}
				outStream.write((char*)outbuffer, GOST_BUFFER_SIZE*sizeof(byte));
				memset_z(inbuffer, '\0', GOST_BUFFER_SIZE*sizeof(byte));
				memset_z(outbuffer, '\0', GOST_BUFFER_SIZE*sizeof(byte));
			}
		}
		else if (mode_of_shifr == MODE_OFB)
		{
			GOST::Encryption gostEncryptor;
			gostEncryptor.SetKeyWithIV(key, KEY_LENGTH, IV, GOST_IV_LENGTH);
			while (!inStream.eof())
			{
				inStream.read((char*)inbuffer, GOST_BUFFER_SIZE*sizeof(byte));
				gostEncryptor.ProcessBlock(IV, outbuffer);
				for (int i = 0; i < GOST_IV_LENGTH; i++)
				{
					IV[i] = outbuffer[i];
					outbuffer[i] = outbuffer[i] ^ inbuffer[i];
				}
				outStream.write((char*)outbuffer, GOST_BUFFER_SIZE*sizeof(byte));
				memset_z(inbuffer, '\0', GOST_BUFFER_SIZE*sizeof(byte));
				memset_z(outbuffer, '\0', GOST_BUFFER_SIZE*sizeof(byte));
			}
		}
	}
	return;
}

void cryptoWorker::doCrypto()
{
	//-e -p 1234567890 -i infile.txt -o out.enc -c AES -m ECB -f MD5
	if (mode)
		encrypt();
	//-d -p 1234567890 -i out.enc -o decrypted.txt
	else
		decrypt();
}

int cryptoWorker::closeFileContexts()
{
	inStream.close();
	outStream.flush();
	outStream.close();
	return 0;
}
