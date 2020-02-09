/*******************************************************************************
** @Author:					Thomas Bouder <Tbouder>
** @Email:					Tbouder@protonmail.com
** @Date:					Saturday 11 January 2020 - 18:23:29
** @Filename:				Tokens.go
**
** @Last modified by:		Tbouder
** @Last modified time:		Tuesday 28 January 2020 - 18:15:52
*******************************************************************************/

package			main

import			"os"
import			"time"
import			"github.com/microgolang/logs"
import			jwtGo "github.com/dgrijalva/jwt-go"

const	ACCESS_TOKEN_EXPIRATION_DURATION = 5 * time.Minute
const	REFRESH_TOKEN_EXPIRATION_DURATION = (24 * time.Hour) * 15

type	JWTClaims struct {
	MemberID	string `json:"memberID"`
	jwtGo.StandardClaims
}

func	SetAccessToken(memberID string) (string, int64, error) {
	expirationTime := time.Now().Add(ACCESS_TOKEN_EXPIRATION_DURATION)
	claims := &JWTClaims{
		MemberID: memberID,
		StandardClaims: jwtGo.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	token := jwtGo.NewWithClaims(jwtGo.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(os.Getenv("JWT_ACCESS_TOKEN_KEY")))
	if (err != nil) {
		return ``, 0, err
	}
	return tokenString, expirationTime.Unix(), nil
}
func	GetAccessToken(accessTokenStr string) (*jwtGo.Token, *JWTClaims, error) {
	claims := &JWTClaims{}

	token, err := jwtGo.ParseWithClaims(accessTokenStr, claims, func(token *jwtGo.Token) (interface{}, error) {
		return []byte(os.Getenv("JWT_ACCESS_TOKEN_KEY")), nil
	})
	if (err != nil) {
		return token, claims, err
	}
	return token, claims, nil
}

func	SetRefreshToken(memberID string) (string, int64, error) {
	expirationTime := time.Now().Add(REFRESH_TOKEN_EXPIRATION_DURATION)
	claims := &JWTClaims{
		MemberID: memberID,
		StandardClaims: jwtGo.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	token := jwtGo.NewWithClaims(jwtGo.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(os.Getenv("JWT_REFRESH_TOKEN_KEY")))
	if (err != nil) {
		return ``, 0, err
	}
	return tokenString, expirationTime.Unix(), nil
}
func	GetRefreshToken(refreshTokenStr string) (*jwtGo.Token, *JWTClaims, error) {
	claims := &JWTClaims{}

	token, err := jwtGo.ParseWithClaims(refreshTokenStr, claims, func(token *jwtGo.Token) (interface{}, error) {
		return []byte(os.Getenv("JWT_REFRESH_TOKEN_KEY")), nil
	})
	if (err != nil) {
		logs.Error(err)
		return &jwtGo.Token{}, &JWTClaims{}, err
	}
	return token, claims, nil
}