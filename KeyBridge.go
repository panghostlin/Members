/*******************************************************************************
** @Author:					Thomas Bouder <Tbouder>
** @Email:					Tbouder@protonmail.com
** @Date:					Monday 10 February 2020 - 11:37:15
** @Filename:				KeyBridge.go
**
** @Last modified by:		Tbouder
** @Last modified time:		Friday 14 February 2020 - 18:11:08
*******************************************************************************/

package			main

import			"context"
import			"github.com/panghostlin/SDK/Keys"
import			_ "github.com/lib/pq"

func	generateMemberKeys(memberID, memberPassword string) (string, error) {
	request := &keys.CreateKeysRequest{Password: memberPassword, MemberID: memberID}
	result, err := clients.keys.CreateKeys(context.Background(), request)
	return result.GetHashKey(), err
}
func	checkMemberKeys(memberID, memberPassword string) (string, error) {
	request := &keys.CheckPasswordRequest{Password: memberPassword, MemberID: memberID}
	result, err := clients.keys.CheckPassword(context.Background(), request)
	return result.GetHashKey(), err
}
func	getMemberPublicKey(memberID string) (string, error) {
	request := &keys.GetPublicKeyRequest{MemberID: memberID}
	result, err := clients.keys.GetPublicKey(context.Background(), request)
	return result.GetPublicKey(), err
}
func	getMemberPrivateKey(memberID, hashKey string) (string, error) {
	request := &keys.GetPrivateKeyRequest{MemberID: memberID, HashKey: hashKey}
	result, err := clients.keys.GetPrivateKey(context.Background(), request)
	return result.GetPrivateKey(), err
}
func	getMemberKeys(memberID, hashKey string) (string, string, error) {
	request := &keys.GetKeysRequest{MemberID: memberID, HashKey: hashKey}
	result, err := clients.keys.GetKeys(context.Background(), request)
	return result.GetPublicKey(), result.GetPrivateKey(), err
}