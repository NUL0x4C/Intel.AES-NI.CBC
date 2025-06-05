#pragma once


#include <Windows.h>

#ifndef AES_INTRINSIC_H
#define AES_INTRINSIC_H


extern void Aes256Encrypt(
	IN		const unsigned char*		pPlainText,				// Pointer to the plaintext data to be encrypted
	IN		unsigned __int64		uPlainTextSize,				// Size of the plaintext data in bytes (must be a multiple of 16)
	IN		unsigned char*			pCipherText,				// Pointer to the buffer where the encrypted data will be stored (must be at least uPlainTextSize bytes long)
	IN		unsigned char*			pAesKey, 				// Pointer to the AES key (must be 32 bytes)
	IN		unsigned char*			pAesIv, 				// Pointer to the AES IV (must be 16 bytes)
	OUT		PBOOLEAN			pbEncrypted				// Pointer to a BOOLEAN variable that will be set to TRUE if encryption was successful
);


extern void Aes256Decrypt(
	IN		const unsigned char*		pCipherText,				// Pointer to the encrypted data to be decrypted
	IN		unsigned __int64		uCipherTextSize,			// Size of the encrypted data in bytes (must be a multiple of 16)
	IN		unsigned char*			pPlainText, 				// Pointer to the buffer where the decrypted data will be stored (must be at least uCipherTextSize bytes long)
	IN		unsigned char*			pAesKey,				// Pointer to the AES key (must be 32 bytes)
	IN		unsigned char*			pAesIv,					// Pointer to the AES IV (must be 16 bytes)
	OUT		PBOOLEAN			pbDecrypted				// Pointer to a BOOLEAN variable that will be set to TRUE if decryption was successful
);


#endif // !AES_INTRINSIC_H
