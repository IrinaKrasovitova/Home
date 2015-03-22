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
	byte passwd[64], passDigest[SHA::DIGESTSIZE], passwordDigest[SHA::DIGESTSIZE];
	int N = 32; // (длина ключа)
	int M = 0;
	k = 0;
	if (mode)
	{
		char buf[128] = { '0' };
		inStream.read(buf, 128);
		type_of_shifr = buf[1];
		mode_of_shifr = buf[2];
		hash_function = buf[3];
		k = buf[4];
		for (int i = 0; i < SALT_LEN; i++)
			key_salt[i] = buf[i + 4];
		for (int i = 0; i < SALT_LEN; i++)
			iv_salt[i] = buf[i + 36];
		memcpy(passwd, password.data(), password.length());
		SHA hash;
		hash.Update(passwd, 64);
		hash.Final(passDigest);
		for (int i = 0; i < SHA::DIGESTSIZE; i++)
			passwordDigest[i] = buf[i + 68];
		if (!strcmp((char *)passDigest, (char *)passwordDigest))
			return 999;

		if (hash_function == 1)
		{
			PKCS5_PBKDF2_HMAC<MD5> pbkdf2; // M = 16
			pbkdf2.DeriveKey(key, 32, 0, passwd, password.length(), key_salt, SALT_LEN, k, 0.5);
			pbkdf2.DeriveKey(IV, 32, 0, passwd, password.length(), iv_salt, SALT_LEN, k, 0.5);
		}
		else if (hash_function == 2)
		{
			PKCS5_PBKDF2_HMAC<SHA1> pbkdf2; // M = 20
			pbkdf2.DeriveKey(key, 32, 0, passwd, password.length(), key_salt, SALT_LEN, k, 0.5);
			pbkdf2.DeriveKey(IV, 32, 0, passwd, password.length(), iv_salt, SALT_LEN, k, 0.5);
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
			k = calculateK(N, M);
			pbkdf2.DeriveKey(key, 32, 0, passwd, password.length(), key_salt, SALT_LEN, k, 0.5);
			pbkdf2.DeriveKey(IV, 32, 0, passwd, password.length(), iv_salt, SALT_LEN, k, 0.5);
		}
		else if (hash_function == 2)
		{
			PKCS5_PBKDF2_HMAC<SHA1> pbkdf2; // M = 20
			M = 20;
			k = calculateK(N, M);
			pbkdf2.DeriveKey(key, 32, 0, passwd, password.length(), key_salt, SALT_LEN, k, 0.5);
			pbkdf2.DeriveKey(IV, 32, 0, passwd, password.length(), iv_salt, SALT_LEN, k, 0.5);
		}
	}
	return 0;
}

int cryptoWorker::prepareFileContexts()
{
	//in = fopen(input_file.data(), "rb");
	inStream.open(input_file.data(), ios_base::in | ios_base::binary);
	if (!(inStream.is_open()))
	{
		errorString = "Error. Input file is not accesible.";
		return 1;
	}
	//out = fopen(output_file.data(), "wb");
	outStream.open(output_file.data(), ios_base::in | ios_base::binary);
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
	string outbuffer;
	outbuffer.clear();

	char buf[128] = { '0' };
	buf[0] = type_of_shifr;
	buf[1] = mode_of_shifr;
	buf[2] = hash_function;
	buf[3] = k;
	for (int i = 0; i < 32; i++)
		buf[i + 4] = key_salt[i];
	for (int i = 0; i < 32; i++)
		buf[i + 36] = iv_salt[i];
	password;
	byte passwd[64], passDigest[SHA::DIGESTSIZE];
	memcpy(passwd, password.data(), password.length());
	SHA hash;
	hash.Update(passwd, 64);
	hash.Final(passDigest);
	for (int i = 0; i < SHA::DIGESTSIZE; i++)
		buf[i + 68] = passDigest[i];

	outStream.write(buf, 128);

	if (type_of_shifr == 1)
	{
		AES::Encryption aesEncryptor(key, 32);

		//byte outbuffer[BUFFER_SIZE] = { '0' };

		if (mode_of_shifr == 1)
		{
			ECB_Mode_ExternalCipher::Encryption cipher(aesEncryptor, IV);
			StreamTransformationFilter streamCipher(cipher, new StringSink(outbuffer));
			while (!inStream.eof())
			{
				inStream.read((char*)inbuffer, BUFFER_SIZE*sizeof(byte));
				streamCipher.Put(inbuffer, BUFFER_SIZE*sizeof(byte));
				//cipher.ProcessData(outbuffer, inbuffer, BUFFER_SIZE*sizeof(byte));
				outStream.write(outbuffer.data(), BUFFER_SIZE*sizeof(byte));
				memset_z(inbuffer, 0, BUFFER_SIZE*sizeof(byte));
			}
			streamCipher.MessageEnd();
		}
		else if (mode_of_shifr == 2)
		{
			CBC_Mode_ExternalCipher::Encryption cipher(aesEncryptor, IV);
			StreamTransformationFilter streamCipher(cipher, new StringSink(outbuffer));
			while (!inStream.eof())
			{
				inStream.read((char*)inbuffer, BUFFER_SIZE*sizeof(byte));
				streamCipher.Put(inbuffer, BUFFER_SIZE*sizeof(byte));
				//cipher.ProcessData(outbuffer, inbuffer, BUFFER_SIZE*sizeof(byte));
				outStream.write(outbuffer.data(), BUFFER_SIZE*sizeof(byte));
				memset_z(inbuffer, 0, BUFFER_SIZE*sizeof(byte));
			}
			streamCipher.MessageEnd();
		}
		else if (mode_of_shifr == 3)
		{
			CFB_Mode_ExternalCipher::Encryption cipher(aesEncryptor, IV);
			StreamTransformationFilter streamCipher(cipher, new StringSink(outbuffer));
			while (!inStream.eof())
			{
				inStream.read((char*)inbuffer, BUFFER_SIZE*sizeof(byte));
				streamCipher.Put(inbuffer, BUFFER_SIZE*sizeof(byte));
				//cipher.ProcessData(outbuffer, inbuffer, BUFFER_SIZE*sizeof(byte));
				outStream.write(outbuffer.data(), BUFFER_SIZE*sizeof(byte));
				memset_z(inbuffer, 0, BUFFER_SIZE*sizeof(byte));
			}
			streamCipher.MessageEnd();
		}
		else if (mode_of_shifr == 4)
		{
			OFB_Mode_ExternalCipher::Encryption cipher(aesEncryptor, IV);
			StreamTransformationFilter streamCipher(cipher, new StringSink(outbuffer));
			while (!inStream.eof())
			{
				inStream.read((char*)inbuffer, BUFFER_SIZE*sizeof(byte));
				streamCipher.Put(inbuffer, BUFFER_SIZE*sizeof(byte));
				//cipher.ProcessData(outbuffer, inbuffer, BUFFER_SIZE*sizeof(byte));
				outStream.write(outbuffer.data(), BUFFER_SIZE*sizeof(byte));
				memset_z(inbuffer, 0, BUFFER_SIZE*sizeof(byte));
			}
			streamCipher.MessageEnd();
		}
		else
			goto ERROR;
	}
	else if (type_of_shifr == 2)
	{
		//GOST::Encryption gostEncryptor(key, 32);
		CBC_Mode<GOST>::Encryption cipher(key, GOST::DEFAULT_KEYLENGTH, IV);
		StreamTransformationFilter streamCipher(cipher, new StringSink(outbuffer));
		while (!inStream.eof())
		{
			inStream.read((char*)inbuffer, BUFFER_SIZE*sizeof(byte));
			streamCipher.Put(inbuffer, BUFFER_SIZE*sizeof(byte));
			//cipher.ProcessData(outbuffer, inbuffer, BUFFER_SIZE*sizeof(byte));
			outStream.write(outbuffer.data(), BUFFER_SIZE*sizeof(byte));
			memset_z(inbuffer, 0, BUFFER_SIZE*sizeof(byte));
		}
	}
	else
		goto ERROR;

	goto GO_TO_EXIT;
	
ERROR:

GO_TO_EXIT:
	return;

}
void cryptoWorker::dectypt()
{
	byte inbuffer[BUFFER_SIZE] = { '0' };
	string outbuffer;
	outbuffer.clear();
	if (type_of_shifr == 1)
	{
		AES::Decryption aesDecryptor(key, 32);

		//byte outbuffer[BUFFER_SIZE] = { '0' };

		if (mode_of_shifr == 1)
		{
			ECB_Mode_ExternalCipher::Decryption cipher(aesDecryptor, IV);
			StreamTransformationFilter streamCipher(cipher, new StringSink(outbuffer));
			while (!inStream.eof())
			{
				inStream.read((char*)inbuffer, BUFFER_SIZE*sizeof(byte));
				streamCipher.Put(inbuffer, BUFFER_SIZE*sizeof(byte));
				//cipher.ProcessData(outbuffer, inbuffer, BUFFER_SIZE*sizeof(byte));
				outStream.write(outbuffer.data(), BUFFER_SIZE*sizeof(byte));
				memset_z(inbuffer, 0, BUFFER_SIZE*sizeof(byte));
			}
			streamCipher.MessageEnd();
		}
		else if (mode_of_shifr == 2)
		{
			CBC_Mode_ExternalCipher::Decryption cipher(aesDecryptor, IV);
			StreamTransformationFilter streamCipher(cipher, new StringSink(outbuffer));
			while (!inStream.eof())
			{
				inStream.read((char*)inbuffer, BUFFER_SIZE*sizeof(byte));
				streamCipher.Put(inbuffer, BUFFER_SIZE*sizeof(byte));
				//cipher.ProcessData(outbuffer, inbuffer, BUFFER_SIZE*sizeof(byte));
				outStream.write(outbuffer.data(), BUFFER_SIZE*sizeof(byte));
				memset_z(inbuffer, 0, BUFFER_SIZE*sizeof(byte));
			}
			streamCipher.MessageEnd();
		}
		else if (mode_of_shifr == 3)
		{
			CFB_Mode_ExternalCipher::Decryption cipher(aesDecryptor, IV);
			StreamTransformationFilter streamCipher(cipher, new StringSink(outbuffer));
			while (!inStream.eof())
			{
				inStream.read((char*)inbuffer, BUFFER_SIZE*sizeof(byte));
				streamCipher.Put(inbuffer, BUFFER_SIZE*sizeof(byte));
				//cipher.ProcessData(outbuffer, inbuffer, BUFFER_SIZE*sizeof(byte));
				outStream.write(outbuffer.data(), BUFFER_SIZE*sizeof(byte));
				memset_z(inbuffer, 0, BUFFER_SIZE*sizeof(byte));
			}
			streamCipher.MessageEnd();
		}
		else if (mode_of_shifr == 4)
		{
			OFB_Mode_ExternalCipher::Decryption cipher(aesDecryptor, IV);
			StreamTransformationFilter streamCipher(cipher, new StringSink(outbuffer));
			while (!inStream.eof())
			{
				inStream.read((char*)inbuffer, BUFFER_SIZE*sizeof(byte));
				streamCipher.Put(inbuffer, BUFFER_SIZE*sizeof(byte));
				//cipher.ProcessData(outbuffer, inbuffer, BUFFER_SIZE*sizeof(byte));
				outStream.write(outbuffer.data(), BUFFER_SIZE*sizeof(byte));
				memset_z(inbuffer, 0, BUFFER_SIZE*sizeof(byte));
			}
			streamCipher.MessageEnd();
		}
		else
			goto ERROR;
	}
	else if (type_of_shifr == 2)
	{
		//GOST::Encryption gostEncryptor(key, 32);
		CBC_Mode<GOST>::Decryption cipher(key, GOST::DEFAULT_KEYLENGTH, IV);
		StreamTransformationFilter streamCipher(cipher, new StringSink(outbuffer));
		while (!inStream.eof())
		{
			inStream.read((char*)inbuffer, BUFFER_SIZE*sizeof(byte));
			streamCipher.Put(inbuffer, BUFFER_SIZE*sizeof(byte));
			//cipher.ProcessData(outbuffer, inbuffer, BUFFER_SIZE*sizeof(byte));
			outStream.write(outbuffer.data(), BUFFER_SIZE*sizeof(byte));
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
	if (mode)
		encrypt();
	else
		dectypt();
}

int cryptoWorker::closeFileContexts()
{
	inStream.close();
	outStream.close();
	return 0;
}
