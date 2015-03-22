#include "stdafx.h"
#include "crypto_worker.h"
using namespace CryptoPP;
using namespace std;

int calculateK(int N, int M)
{
	if ((N%M) != 0)
		return ((N / M) + 1);
	else
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
	byte passwd[64] = { '0' }, passDigest[SHA::DIGESTSIZE] = { '0' }, passwordDigest[SHA::DIGESTSIZE] = { '0' };
	int N = 32; // (длина ключа)
	int M = 0;
	keyk = 0;
	ivk = 0;
	// key = 0x001cf8f4 "\x1fе7ZeШh\x3;хA@QїлРThОmИ\x1a.†\n\x1c‰k–хГХ...
	// IV = 0x001cf914 "њK\x1гjЎUЏ\nzyМ]Ј?<—\x18ЇЯZ±чёжТЖ\x15гff\b...

	if (!mode)
	{
		unsigned char buf[128] = { '0' };
		inStream.read((char*)buf, 128);
		type_of_shifr = buf[0];
		mode_of_shifr = buf[1];
		hash_function = buf[2];
		keyk = buf[3];
		keyk <<= 8;
		keyk += buf[4];
		keyk <<= 8;
		keyk += buf[5];
		keyk <<= 8;
		keyk += buf[6];

		ivk = buf[7];
		ivk <<= 8;
		ivk += buf[8];
		ivk <<= 8;
		ivk += buf[9];
		ivk <<= 8;
		ivk += buf[10];

		for (int i = 0; i < SALT_LEN; i++)
			key_salt[i] = buf[i + 11];
		for (int i = 0; i < SALT_LEN; i++)
			iv_salt[i] = buf[i + 43];
		memcpy(passwd, password.data(), password.length());
		SHA hash;
		hash.Update(passwd, 64);
		hash.Final(passDigest);
		for (int i = 0; i < SHA::DIGESTSIZE; i++)
			passwordDigest[i] = buf[i + 75];
		if (!strcmp((char *)passDigest, (char *)passwordDigest))
			return 999;

		if (hash_function == 1)
		{
			PKCS5_PBKDF2_HMAC<MD5> pbkdf2; // M = 16
			pbkdf2.DeriveKey(key, 32, 0, passwd, password.length(), key_salt, SALT_LEN, keyk, 0);
			pbkdf2.DeriveKey(IV, 32, 0, passwd, password.length(), iv_salt, SALT_LEN, ivk, 0);
		}
		else if (hash_function == 2)
		{
			PKCS5_PBKDF2_HMAC<SHA1> pbkdf2; // M = 20
			pbkdf2.DeriveKey(key, 32, 0, passwd, password.length(), key_salt, SALT_LEN, keyk, 0);
			pbkdf2.DeriveKey(IV, 32, 0, passwd, password.length(), iv_salt, SALT_LEN, ivk, 0);
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
			keyk = pbkdf2.DeriveKey(key, 32, 0, passwd, password.length(), key_salt, SALT_LEN, keyk, 0.5);
			ivk = pbkdf2.DeriveKey(IV, 32, 0, passwd, password.length(), iv_salt, SALT_LEN, ivk, 0.5);
		}
		else if (hash_function == 2)
		{
			PKCS5_PBKDF2_HMAC<SHA1> pbkdf2; // M = 20
			M = 20;
			keyk = ivk = calculateK(N, M);
			keyk = pbkdf2.DeriveKey(key, 32, 0, passwd, password.length(), key_salt, SALT_LEN, keyk, 0.5);
			ivk = pbkdf2.DeriveKey(IV, 32, 0, passwd, password.length(), iv_salt, SALT_LEN, ivk, 0.5);
		}
	}
	return 0;
}

int cryptoWorker::prepareFileContexts()
{
	//in = fopen(input_file.data(), "rb");
	inStream.open(input_file.data()/*, ios_base::in | ios_base::binary*/);
	if (!(inStream.is_open()))
	{
		errorString = "Error. Input file is not accesible.";
		return 1;
	}
	//out = fopen(output_file.data(), "wb");
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
	byte inbuffer[BUFFER_SIZE] = { '0' };
	byte outbuffer[BUFFER_SIZE] = { '0' };
	//string outbuffer;
	//outbuffer.clear();

	unsigned char buf[128] = { '0' };
	buf[0] = type_of_shifr;
	buf[1] = mode_of_shifr;
	buf[2] = hash_function;
	buf[3] = (keyk >> 24) & 255;
	buf[4] = (keyk >> 16) & 255;
	buf[5] = (keyk >> 8) & 255;
	buf[6] = keyk & 255;
	buf[7] = (ivk >> 24) & 255;
	buf[8] = (ivk >> 16) & 255;
	buf[9] = (ivk >> 8) & 255;
	buf[10] = ivk & 255;
	for (int i = 0; i < 32; i++)
		buf[i + 11] = key_salt[i];
	for (int i = 0; i < 32; i++)
		buf[i + 43] = iv_salt[i];
	password;
	byte passwd[64] = { '0' }, passDigest[SHA::DIGESTSIZE] = { '0' };
	memcpy(passwd, password.data(), password.length());
	SHA hash;
	hash.Update(passwd, 64);
	hash.Final(passDigest);
	for (int i = 0; i < SHA::DIGESTSIZE; i++)
		buf[i + 75] = passDigest[i];

	outStream.write((char*)buf, 128);

	if (type_of_shifr == 1)
	{

		//byte outbuffer[BUFFER_SIZE] = { '0' };

		if (mode_of_shifr == 1)
		{
			AES::Encryption aesEncryptor(key, 32);
			ECB_Mode_ExternalCipher::Encryption cipher(aesEncryptor, IV);
			//StreamTransformationFilter streamCipher(cipher, new StringSink(outbuffer));
			while (!inStream.eof())
			{
				inStream.read((char*)inbuffer, BUFFER_SIZE*sizeof(byte));
				//streamCipher.Put(inbuffer, BUFFER_SIZE*sizeof(byte));
				cipher.ProcessData(outbuffer, inbuffer, BUFFER_SIZE*sizeof(byte));
				outStream.write((char*)outbuffer, BUFFER_SIZE*sizeof(byte));
				memset_z(inbuffer, 0, BUFFER_SIZE*sizeof(byte));
			}
			//streamCipher.MessageEnd();
		}
		else if (mode_of_shifr == 2)
		{
			AES::Encryption aesEncryptor(key, 32);
			CBC_Mode_ExternalCipher::Encryption cipher(aesEncryptor, IV);
			//StreamTransformationFilter streamCipher(cipher, new StringSink(outbuffer));
			while (!inStream.eof())
			{
				inStream.read((char*)inbuffer, BUFFER_SIZE*sizeof(byte));
				//streamCipher.Put(inbuffer, BUFFER_SIZE*sizeof(byte));
				cipher.ProcessData(outbuffer, inbuffer, BUFFER_SIZE*sizeof(byte));
				outStream.write((char*)outbuffer, BUFFER_SIZE*sizeof(byte));
				memset_z(inbuffer, 0, BUFFER_SIZE*sizeof(byte));
			}
			//streamCipher.MessageEnd();
		}
		else if (mode_of_shifr == 3)
		{
			AES::Encryption aesEncryptor(key, 32);
			CFB_Mode_ExternalCipher::Encryption cipher(aesEncryptor, IV);
			//StreamTransformationFilter streamCipher(cipher, new StringSink(outbuffer));
			while (!inStream.eof())
			{
				inStream.read((char*)inbuffer, BUFFER_SIZE*sizeof(byte));
				//streamCipher.Put(inbuffer, BUFFER_SIZE*sizeof(byte));
				cipher.ProcessData(outbuffer, inbuffer, BUFFER_SIZE*sizeof(byte));
				outStream.write((char*)outbuffer, BUFFER_SIZE*sizeof(byte));
				memset_z(inbuffer, 0, BUFFER_SIZE*sizeof(byte));
			}
			//streamCipher.MessageEnd();
		}
		else if (mode_of_shifr == 4)
		{
			AES::Encryption aesEncryptor(key, 32);
			OFB_Mode_ExternalCipher::Encryption cipher(aesEncryptor, IV);
			//StreamTransformationFilter streamCipher(cipher, new StringSink(outbuffer));
			while (!inStream.eof())
			{
				inStream.read((char*)inbuffer, BUFFER_SIZE*sizeof(byte));
				//streamCipher.Put(inbuffer, BUFFER_SIZE*sizeof(byte));
				cipher.ProcessData(outbuffer, inbuffer, BUFFER_SIZE*sizeof(byte));
				outStream.write((char*)outbuffer, BUFFER_SIZE*sizeof(byte));
				memset_z(inbuffer, 0, BUFFER_SIZE*sizeof(byte));
			}
			//streamCipher.MessageEnd();
		}
		else
			goto ERROR;
	}
	else if (type_of_shifr == 2)
	{
		//GOST::Encryption gostEncryptor(key, 32);
		CBC_Mode<GOST>::Encryption cipher(key, GOST::DEFAULT_KEYLENGTH, IV);
		//StreamTransformationFilter streamCipher(cipher, new StringSink(outbuffer));
		while (!inStream.eof())
		{
			inStream.read((char*)inbuffer, BUFFER_SIZE*sizeof(byte));
			//streamCipher.Put(inbuffer, BUFFER_SIZE*sizeof(byte));
			cipher.ProcessData(outbuffer, inbuffer, BUFFER_SIZE*sizeof(byte));
			outStream.write((char*)outbuffer, BUFFER_SIZE*sizeof(byte));
			memset_z(inbuffer, 0, BUFFER_SIZE*sizeof(byte));
		}
	}
	else
		goto ERROR;

	goto GO_TO_EXIT;
	
ERROR:

GO_TO_EXIT :
	return;
}
void cryptoWorker::dectypt()
{
	byte inbuffer[BUFFER_SIZE] = { '0' };
	//string outbuffer;
	//outbuffer.clear();
	byte outbuffer[BUFFER_SIZE] = { '0' };
	if (type_of_shifr == 1)
	{
		AES::Decryption aesDecryptor(key, 32);

		//byte outbuffer[BUFFER_SIZE] = { '0' };

		if (mode_of_shifr == 1)
		{
			ECB_Mode_ExternalCipher::Decryption cipher(aesDecryptor, IV);
			//StreamTransformationFilter streamCipher(cipher, new StringSink(outbuffer));
			while (!inStream.eof())
			{
				inStream.read((char*)inbuffer, BUFFER_SIZE*sizeof(byte));
				//streamCipher.Put(inbuffer, BUFFER_SIZE*sizeof(byte));
				cipher.ProcessData(outbuffer, inbuffer, BUFFER_SIZE*sizeof(byte));
				outStream.write((char*)outbuffer, BUFFER_SIZE*sizeof(byte));
				memset_z(inbuffer, 0, BUFFER_SIZE*sizeof(byte));
			}
			//streamCipher.MessageEnd();
		}
		else if (mode_of_shifr == 2)
		{
			CBC_Mode_ExternalCipher::Decryption cipher(aesDecryptor, IV);
			//StreamTransformationFilter streamCipher(cipher, new StringSink(outbuffer));
			while (!inStream.eof())
			{
				inStream.read((char*)inbuffer, BUFFER_SIZE*sizeof(byte));
				//streamCipher.Put(inbuffer, BUFFER_SIZE*sizeof(byte));
				cipher.ProcessData(outbuffer, inbuffer, BUFFER_SIZE*sizeof(byte));
				outStream.write((char*)outbuffer, BUFFER_SIZE*sizeof(byte));
				memset_z(inbuffer, 0, BUFFER_SIZE*sizeof(byte));
			}
			//streamCipher.MessageEnd();
		}
		else if (mode_of_shifr == 3)
		{
			CFB_Mode_ExternalCipher::Decryption cipher(aesDecryptor, IV);
			//StreamTransformationFilter streamCipher(cipher, new StringSink(outbuffer));
			while (!inStream.eof())
			{
				inStream.read((char*)inbuffer, BUFFER_SIZE*sizeof(byte));
				//streamCipher.Put(inbuffer, BUFFER_SIZE*sizeof(byte));
				cipher.ProcessData(outbuffer, inbuffer, BUFFER_SIZE*sizeof(byte));
				outStream.write((char*)outbuffer, BUFFER_SIZE*sizeof(byte));
				memset_z(inbuffer, 0, BUFFER_SIZE*sizeof(byte));
			}
			//streamCipher.MessageEnd();
		}
		else if (mode_of_shifr == 4)
		{
			OFB_Mode_ExternalCipher::Decryption cipher(aesDecryptor, IV);
			//StreamTransformationFilter streamCipher(cipher, new StringSink(outbuffer));
			while (!inStream.eof())
			{
				inStream.read((char*)inbuffer, BUFFER_SIZE*sizeof(byte));
				//streamCipher.Put(inbuffer, BUFFER_SIZE*sizeof(byte));
				cipher.ProcessData(outbuffer, inbuffer, BUFFER_SIZE*sizeof(byte));
				outStream.write((char*)outbuffer, BUFFER_SIZE*sizeof(byte));
				memset_z(inbuffer, 0, BUFFER_SIZE*sizeof(byte));
			}
			//streamCipher.MessageEnd();
		}
		else
			goto ERROR;
	}
	else if (type_of_shifr == 2)
	{
		//GOST::Encryption gostEncryptor(key, 32);
		CBC_Mode<GOST>::Decryption cipher(key, GOST::DEFAULT_KEYLENGTH, IV);
		//StreamTransformationFilter streamCipher(cipher, new StringSink(outbuffer));
		while (!inStream.eof())
		{
			inStream.read((char*)inbuffer, BUFFER_SIZE*sizeof(byte));
			//streamCipher.Put(inbuffer, BUFFER_SIZE*sizeof(byte));
			cipher.ProcessData(outbuffer, inbuffer, BUFFER_SIZE*sizeof(byte));
			outStream.write((char*)outbuffer, BUFFER_SIZE*sizeof(byte));
			memset_z(inbuffer, 0, BUFFER_SIZE*sizeof(byte));
		}
	}
	else
		goto ERROR;

	goto GO_TO_EXIT;

ERROR:

GO_TO_EXIT :
	return;
}

void cryptoWorker::doCrypto()
{
	//-e -p 1234567890 -i infile.txt -o out.enc -c AES -m ECB -f MD5
	if (mode)
		encrypt();
	//-d -p 1234567890 -i out.enc -o decrypted.txt -c AES -m ECB -f MD5
	else
		dectypt();
}

int cryptoWorker::closeFileContexts()
{
	inStream.close();
	outStream.close();
	return 0;
}
