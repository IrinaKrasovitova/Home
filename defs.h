#define AES_BUFFER_SIZE 16
#define GOST_BUFFER_SIZE 8
#define INFO_BUFFER_SIZE 128
#define SALT_LEN 32
#define KEY_LENGTH 32
#define IV_LENGTH 16
#define AES_IV_LENGTH 16
#define GOST_IV_LENGTH 8

enum argument_type {
	ARG_UNDEFINED,
	ARG_ENC = 1,
	ARG_DEC,
	ARG_PASS,
	ARG_IN,
	ARG_OUT,
	ARG_CIPHER,
	ARG_MODE,
	ARG_HASH,
	ARG_HELP,

	ARG_LAST = ARG_HELP
};

enum shifr_type {
	TYPE_UNDEFINED = 0,
	TYPE_AES = 1,
	TYPE_GOST = 2,

	TYPE_LAST = TYPE_GOST
};

enum shifr_mode {
	MODE_UNDEFINED = 0,
	MODE_ECB = 1,
	MODE_CBC = 2,
	MODE_CFB = 3,
	MODE_OFB = 4,

	MODE_LAST = MODE_OFB
};

enum hash_type {
	HASH_TYPE_UNDEFINED = 0,
	HASH_TYPE_MD5 = 1,
	HASH_TYPE_SHA1 = 2,

	HASH_TYPE_LAST = HASH_TYPE_SHA1
};

#pragma pack(push, 1)
struct cryptoData {
	int type_of_shifr;
	int mode_of_shifr;
	int type_of_hash;
	int keyIterations;
	int ivIterations;
	byte key_salt[SALT_LEN];
	byte iv_salt[SALT_LEN];
	byte passDigest[CryptoPP::SHA1::DIGESTSIZE];
};
#pragma pack(pop)
