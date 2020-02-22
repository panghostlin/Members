/*******************************************************************************
** @Author:					Thomas Bouder <Tbouder>
** @Email:					Tbouder@protonmail.com
** @Date:					Tuesday 07 January 2020 - 14:13:47
** @Filename:				service.go
**
** @Last modified by:		Tbouder
** @Last modified time:		Friday 21 February 2020 - 17:33:34
*******************************************************************************/

package			main

import			"time"
import			"context"
import			"strconv"
import			"errors"
import			"strings"
import			"encoding/base64"
import			"github.com/microgolang/logs"
import			"github.com/panghostlin/SDK/Members"
import			P "github.com/microgolang/postgre"

func (s *server) CheckAccessToken(ctx context.Context, req *members.CheckAccessTokenRequest) (*members.CheckAccessTokenResponse, error) {
	var	isTokenExpiredByError bool
	var	isTokenExpired bool

	var	memberID string
	var	memberAccessToken string
	var	memberAccessExp int64
	var	memberRefreshToken string

	accessToken, accessClaims, err := GetAccessToken(req.GetAccessToken())
	if (err != nil) {
		if (strings.Contains(err.Error(), `token is expired by`)) {
			isTokenExpiredByError = true
		} else {
			return &members.CheckAccessTokenResponse{Success: false}, err
		}
	}

	/**************************************************************************
	**	Check if the JWT is valid : if it has not expired according to the
	**	expiry time we set on sign in and if the signature does match
	**************************************************************************/
	isTokenExpired = time.Now().Unix() > accessClaims.ExpiresAt
	if (isTokenExpiredByError || isTokenExpired) {
		/**************************************************************************
		**	The accessToken is no longer valid : we should get the refresh token
		**	from the database, check if it's valid, and regenerate a new access
		**	token if it's valid
		**************************************************************************/
		err = P.NewSelector(PGR).Select(`RefreshToken`).From(`members`).Where(
			P.S_SelectorWhere{Key: `ID`, Value: accessClaims.MemberID},
		).One(&memberRefreshToken)
		if (err != nil) {
			return &members.CheckAccessTokenResponse{Success: false}, err
		}

		refreshToken, refreshClaims, err := GetRefreshToken(memberRefreshToken)
		if (err != nil) {
			return &members.CheckAccessTokenResponse{Success: false}, err
		} else if (!refreshToken.Valid) {
			logs.Error(`AccessToken & refreshtoken are no longer valids`)
			return &members.CheckAccessTokenResponse{Success: false}, nil
		} else if (refreshClaims.MemberID == accessClaims.MemberID) {
			/******************************************************************
			**	Check if the JWT memberID is the same as in the Database
			*******************************************************************/
			err = P.NewSelector(PGR).Select(`ID`).From(`members`).Where(
				P.S_SelectorWhere{Key: `ID`, Value: refreshClaims.MemberID},
			).One(&memberID)
			if (err != nil) {
				return &members.CheckAccessTokenResponse{Success: false}, err
			} else if (memberRefreshToken != refreshToken.Raw) {
				logs.Error(memberRefreshToken, refreshToken.Raw)
				return &members.CheckAccessTokenResponse{Success: false}, nil
			}

			/******************************************************************
			**	If the refresh token is valid, we refresh the access token
			******************************************************************/
			authCookie, expTime, err := SetAccessToken(memberID)
			if (err != nil) {
				return &members.CheckAccessTokenResponse{Success: false}, err
			}

			P.NewUpdator(PGR).Set(
				P.S_UpdatorSetter{Key: `AccessToken`, Value: authCookie},
				P.S_UpdatorSetter{Key: `AccessExp`, Value: strconv.FormatInt(expTime, 10)},
			).Where(
				P.S_UpdatorWhere{Key: `ID`, Value: memberID},
			).Into(`members`).Do()
			return &members.CheckAccessTokenResponse{
				Success: true,
				MemberID: memberID,
				AccessToken: &members.Cookie{Value: authCookie, Expiration: expTime},
			}, nil
		} else {
			return &members.CheckAccessTokenResponse{Success: false}, nil
		}
	} else if (!accessToken.Valid) {
		return &members.CheckAccessTokenResponse{Success: false}, err
	} else {
		/**********************************************************************
		**	Check if the JWT memberID is the same as in the Database
		***********************************************************************/
		err = P.NewSelector(PGR).Select(`ID`, `AccessToken`, `AccessExp`).From(`members`).Where(
			P.S_SelectorWhere{Key: `ID`, Value: accessClaims.MemberID},
		).One(&memberID, &memberAccessToken, &memberAccessExp)
		if (err != nil) {
			return &members.CheckAccessTokenResponse{Success: false}, err
		} else if (memberAccessToken != req.GetAccessToken()) {
			return &members.CheckAccessTokenResponse{Success: false}, nil
		}
		/**********************************************************************
		**	If the access token is valid, we refresh the access token
		**********************************************************************/
		// authCookie, expTime, err := SetAccessToken(member.ID.Hex())
		// if (err != nil) {
		// 	return &members.CheckAccessTokenResponse{Success: false}, err
		// }
		// member.AccessToken = sMemberToken{}
		// memberAccessToken = authCookie
		// member.AccessToken.Expiration = expTime
		// Collection.UpdateId(member.ID, member)

		return &members.CheckAccessTokenResponse{
			Success: true,
			MemberID: memberID,
			AccessToken: &members.Cookie{Value: memberAccessToken, Expiration: memberAccessExp},
		}, nil
	}
}

func (s *server) CreateMember(ctx context.Context, req *members.CreateMemberRequest) (*members.CreateMemberResponse, error) {
	ID, err := P.NewInsertor(PGR).Values(P.S_InsertorWhere{Key: `Email`, Value: req.GetEmail()}).Into(`members`).Do()
	if (err != nil) {
		return &members.CreateMemberResponse{}, err
	}

	/**************************************************************************
	**	Create an access token for this user
	**************************************************************************/
	refreshToken, refreshExpiration, err := SetRefreshToken(ID)
	if (err != nil) {
		return &members.CreateMemberResponse{}, err
	}

	/**************************************************************************
	**	Create a refresh token for this user
	**************************************************************************/
	accessToken, accessExpiration, err := SetAccessToken(ID)
	if (err != nil) {
		return &members.CreateMemberResponse{}, err
	}
	
	/**************************************************************************
	**	Generate the hashes for this user
	**************************************************************************/
	plainArgon2Hash, plainScryptHash, block, err := GeneratePasswordHash(req.GetPassword())
	argon2Hash, argon2IV, scryptHash, scryptIV, err := EncryptPasswordHash(plainArgon2Hash, plainScryptHash, block)
	if (err != nil) {
		return &members.CreateMemberResponse{}, err
	}

	/**************************************************************************
	**	Insert the new user in the database
	**************************************************************************/
	err = P.NewUpdator(PGR).Set(
		P.S_UpdatorSetter{Key: `AccessToken`, Value: accessToken},
		P.S_UpdatorSetter{Key: `AccessExp`, Value: strconv.FormatInt(accessExpiration, 10)},
		P.S_UpdatorSetter{Key: `RefreshToken`, Value: refreshToken},
		P.S_UpdatorSetter{Key: `RefreshExp`, Value: strconv.FormatInt(refreshExpiration, 10)},
		P.S_UpdatorSetter{Key: `PublicKey`, Value: req.GetPublicKey()},
		P.S_UpdatorSetter{Key: `PrivateKey`, Value: req.GetPrivateKey().GetKey()},
		P.S_UpdatorSetter{Key: `PrivateKeyIV`, Value: req.GetPrivateKey().GetIV()},
		P.S_UpdatorSetter{Key: `PrivateKeySalt`, Value: req.GetPrivateKey().GetSalt()},
		P.S_UpdatorSetter{Key: `PasswordArgon2Hash`, Value: base64.RawStdEncoding.EncodeToString(argon2Hash)},
		P.S_UpdatorSetter{Key: `PasswordArgon2IV`, Value: base64.RawStdEncoding.EncodeToString(argon2IV)},
		P.S_UpdatorSetter{Key: `PasswordScryptHash`, Value: base64.RawStdEncoding.EncodeToString(scryptHash)},
		P.S_UpdatorSetter{Key: `PasswordScryptIV`, Value: base64.RawStdEncoding.EncodeToString(scryptIV)},

	).Where(
		P.S_UpdatorWhere{Key: `ID`, Value: ID},
	).Into(`members`).Do()

	if (err != nil) {
		P.NewDeletor(PGR).Into(`members`).Where(P.S_DeletorWhere{Key: `ID`, Value: ID}).Do()
		return &members.CreateMemberResponse{}, err
	}
	
	return &members.CreateMemberResponse{
		MemberID: ID,
		AccessToken: &members.Cookie{
			Value: accessToken,
			Expiration: accessExpiration,
		},
		Keys: &members.Keys{
			PrivateKey: req.GetPrivateKey().GetKey(),
			PrivateSalt: req.GetPrivateKey().GetSalt(),
			PrivateIV: req.GetPrivateKey().GetIV(),
			PublicKey: req.GetPublicKey(),
		},
	}, nil
}

func (s *server) LoginMember(ctx context.Context, req *members.LoginMemberRequest) (*members.LoginMemberResponse, error) {
	var	memberID string
	var	B64PasswordArgon2Hash string
	var	B64PasswordArgon2IV string
	var	B64PasswordScryptHash string
	var	B64PasswordScryptIV string
	var	PublicKey string
	var	PrivateKey string
	var	PrivateKeyIV string
	var	PrivateKeySalt string
	var	err error

	/**************************************************************************
	**	SELECT the member matching the requested Email from the member Table
	**	and get it's ID
	**************************************************************************/
	err = P.NewSelector(PGR).Select(
		`ID`,
		`PasswordArgon2Hash`,
		`PasswordArgon2IV`,
		`PasswordScryptHash`,
		`PasswordScryptIV`,
		`PublicKey`,
		`PrivateKey`,
		`PrivateKeyIV`,
		`PrivateKeySalt`,
	).From(`members`).Where(
		P.S_SelectorWhere{Key: `Email`, Value: req.GetEmail()},
	).One(
		&memberID,
		&B64PasswordArgon2Hash,
		&B64PasswordArgon2IV,
		&B64PasswordScryptHash,
		&B64PasswordScryptIV,
		&PublicKey,
		&PrivateKey,
		&PrivateKeyIV,
		&PrivateKeySalt,
	)
	if (err != nil) {
		return &members.LoginMemberResponse{}, err
	}

	/**************************************************************************
	**	We got the memberID, we can not check the password hash with the
	**	password send as argument
	**************************************************************************/
	PasswordArgon2Hash, _ := base64.RawStdEncoding.DecodeString(B64PasswordArgon2Hash)
	PasswordArgon2IV, _ := base64.RawStdEncoding.DecodeString(B64PasswordArgon2IV)
	PasswordScryptHash, _ := base64.RawStdEncoding.DecodeString(B64PasswordScryptHash)
	PasswordScryptIV, _ := base64.RawStdEncoding.DecodeString(B64PasswordScryptIV)

	argon2Hash, scryptHash, err := DecryptPasswordHash(PasswordArgon2Hash, PasswordArgon2IV, PasswordScryptHash, PasswordScryptIV)
	if (err != nil) {
		return &members.LoginMemberResponse{}, err
	}

	hashMatches := verifyMemberPasswordHash(req.GetPassword(), string(argon2Hash), string(scryptHash))
	if (!hashMatches) {
		return &members.LoginMemberResponse{}, errors.New(`The hashes does not matches`)
	}

	/**************************************************************************
	**	The password matches, we can now regenerate the member access token
	**	from it's memberID
	**************************************************************************/
	accessToken, accessExpiration, err := SetAccessToken(memberID)
	if (err != nil) {
		return &members.LoginMemberResponse{}, err
	}

	/**************************************************************************
	**	We can now update the user in the database
	**************************************************************************/
	err = P.NewUpdator(PGR).Set(
		P.S_UpdatorSetter{Key: `AccessToken`, Value: accessToken},
		P.S_UpdatorSetter{Key: `AccessExp`, Value: strconv.FormatInt(accessExpiration, 10)},
	).Where(
		P.S_UpdatorWhere{Key: `ID`, Value: memberID},
	).Into(`members`).Do()
	if (err != nil) {
		return &members.LoginMemberResponse{}, err
	}

	/**************************************************************************
	**	Send back the informations to the Proxy
	**************************************************************************/
	return &members.LoginMemberResponse{
		MemberID: memberID,
		AccessToken: &members.Cookie{
			Value: accessToken,
			Expiration: accessExpiration,
		},
		Keys: &members.Keys{
			PrivateKey: PrivateKey,
			PrivateSalt: PrivateKeySalt,
			PrivateIV: PrivateKeyIV,
			PublicKey: PublicKey,
		},
	}, nil
}
