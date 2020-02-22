/*******************************************************************************
** @Author:					Thomas Bouder <Tbouder>
** @Email:					Tbouder@protonmail.com
** @Date:					Tuesday 28 January 2020 - 22:29:42
** @Filename:				Hash.go
**
** @Last modified by:		Tbouder
** @Last modified time:		Wednesday 19 February 2020 - 15:28:08
*******************************************************************************/

package			main

import			"os"
import			"crypto/aes"
import			"crypto/cipher"
import			"encoding/base64"
import			"golang.org/x/crypto/argon2"
import			"github.com/microgolang/logs"
import			"errors"
import			"bytes"

var (
	ErrInvalidBlockSize		= errors.New("invalid blocksize")
	ErrInvalidPKCS7Data		= errors.New("invalid PKCS7 data (empty or not padded)")
	ErrInvalidPKCS7Padding	= errors.New("invalid padding on input")
	ErrInvalidHash			= errors.New("the encoded hash is not in the correct format")
    ErrIncompatibleVersion	= errors.New("incompatible version of argon2")
)

func	pkcs7Pad(b []byte, blocksize int) ([]byte, error) {
	if blocksize <= 0 {
		return nil, ErrInvalidBlockSize
	}
	if b == nil || len(b) == 0 {
		return nil, ErrInvalidPKCS7Data
	}
	n := blocksize - (len(b) % blocksize)
	pb := make([]byte, len(b)+n)
	copy(pb, b)
	copy(pb[len(b):], bytes.Repeat([]byte{byte(n)}, n))
	return pb, nil
}

func	pkcs7Unpad(b []byte, blocksize int) ([]byte, error) {
	if blocksize <= 0 {
		return nil, ErrInvalidBlockSize
	}
	if b == nil || len(b) == 0 {
		return nil, ErrInvalidPKCS7Data
	}
	if len(b)%blocksize != 0 {
		return nil, ErrInvalidPKCS7Padding
	}
	c := b[len(b)-1]
	n := int(c)
	if n == 0 || n > len(b) {
		return nil, ErrInvalidPKCS7Padding
	}
	for i := 0; i < n; i++ {
		if b[len(b)-n+i] != c {
			return nil, ErrInvalidPKCS7Padding
		}
	}
	return b[:len(b)-n], nil
}

/******************************************************************************
**	Convert a password to two hashes, argon2 and scrypt
**	which will later be used to log-in the member by a comparison between
**	it's password and the hashes
******************************************************************************/
func	GeneratePasswordHash(password string) ([]byte, []byte, cipher.Block, error) {
	/**************************************************************************
	**	Get the master key from the .env file
	**************************************************************************/
	MasterKey, err := base64.RawStdEncoding.DecodeString(os.Getenv("MASTER_KEY"))
	if (err != nil) {
		logs.Error(err)
		return nil, nil, nil, err
	}

	/**************************************************************************
	**	Create a Cipher with the master key
	**************************************************************************/
	block, err := aes.NewCipher(MasterKey)
	if (err != nil) {
		logs.Error(err)
		return nil, nil, nil, err
	}

	/**************************************************************************
	**	Generate the argon2 and scrypt hash from the password
	**************************************************************************/
	argon2Hash, scryptHash, err := hashMemberPassword(password)
	if (err != nil) {
		logs.Error(err)
		return nil, nil, nil, err
	}

	/**************************************************************************
	**	Add the padding to the hash to avoid decryption issues
	**************************************************************************/
	argon2Hash, err = pkcs7Pad(argon2Hash, block.BlockSize())
	if (err != nil) {
		logs.Error(err)
		return nil, nil, nil, err
	}
	scryptHash, err = pkcs7Pad(scryptHash, block.BlockSize())
	if (err != nil) {
		logs.Error(err)
		return nil, nil, nil, err
	}
	return argon2Hash, scryptHash, block, nil
}

/******************************************************************************
**	Symetric encryption. Encrypt the hashes with a MasterKey to ensure database
**	security
******************************************************************************/
func	EncryptPasswordHash(plainArgon2Hash, plainScryptHash []byte, block cipher.Block) ([]byte, []byte, []byte, []byte, error){
	/**************************************************************************
	**	Generate an Initialization Vector to perform the CTR AES Encryption
	**************************************************************************/
	argon2IV, err := generateNonce(aes.BlockSize)
	if (err != nil) {
		logs.Error(err)
		return nil, nil, nil, nil, err
	}
	scryptIV, err := generateNonce(aes.BlockSize)
	if (err != nil) {
		logs.Error(err)
		return nil, nil, nil, nil, err
	}

	/**************************************************************************
	**	Perform the actual encryption
	**************************************************************************/
	argon2Hash := make([]byte, len(plainArgon2Hash))
	argon2Enc := cipher.NewCBCEncrypter(block, argon2IV)
	argon2Enc.CryptBlocks(argon2Hash, plainArgon2Hash)
	scryptHash := make([]byte, len(plainScryptHash))
	scryptEnc := cipher.NewCBCEncrypter(block, scryptIV)
	scryptEnc.CryptBlocks(scryptHash, plainScryptHash)

	return argon2Hash, argon2IV, scryptHash, scryptIV, nil
}

/******************************************************************************
**	Symetric encryption. Decrypt the hashes, from the database, with the
**	MasterKey to get the plain hashes
******************************************************************************/
func	DecryptPasswordHash(argon2Hash, argon2IV, scryptHash, scryptIV []byte) ([]byte, []byte, error) {
	/**************************************************************************
	**	Get the master key from the .env file
	**************************************************************************/
	MasterKey, err := base64.RawStdEncoding.DecodeString(os.Getenv("MASTER_KEY"))
	if (err != nil) {
		logs.Error(err)
		return nil, nil, err
	}

	/**************************************************************************
	**	Create a Cipher with the master key
	**************************************************************************/
	block, err := aes.NewCipher(MasterKey)
	if (err != nil) {
		logs.Error(err)
		return nil, nil, err
	}

	/**************************************************************************
	**	Decrypt the ciphertext
	**************************************************************************/
	argon2UnHash := make([]byte, len(argon2Hash))
	argon2Dec := cipher.NewCBCDecrypter(block, argon2IV)
	argon2Dec.CryptBlocks(argon2UnHash, argon2Hash)

	scryptUnHash := make([]byte, len(scryptHash))
	scryptDec := cipher.NewCBCDecrypter(block, scryptIV)
	scryptDec.CryptBlocks(scryptUnHash, scryptHash)

	/**************************************************************************
	**	Unpad the result
	**************************************************************************/
	argon2UnHash, _ = pkcs7Unpad(argon2UnHash, aes.BlockSize)
	scryptUnHash, _ = pkcs7Unpad(scryptUnHash, aes.BlockSize)

	return argon2UnHash, scryptUnHash, nil
}

/******************************************************************************
**	Take a key (the user password) and a salt to get the encryption hash used
**	to encrypt files
******************************************************************************/
func	GetHashFromKey(key, salt []byte) ([]byte) {
	return argon2.IDKey(key, salt, argon2Parameters.iterations, argon2Parameters.memory, argon2Parameters.parallelism, argon2Parameters.keyLength)
}