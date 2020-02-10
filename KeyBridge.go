/*******************************************************************************
** @Author:					Thomas Bouder <Tbouder>
** @Email:					Tbouder@protonmail.com
** @Date:					Monday 10 February 2020 - 11:37:15
** @Filename:				KeyBridge.go
**
** @Last modified by:		Tbouder
** @Last modified time:		Monday 10 February 2020 - 13:09:30
*******************************************************************************/

package			main

import			"context"
import			"github.com/microgolang/logs"
import			"github.com/panghostlin/SDK/Keys"
import			_ "github.com/lib/pq"

func	generateMemberKeys(memberID, memberPassword string) (bool, string, error) {
	connection := bridgeMicroservice(`panghostlin-keys:8011`)
	defer connection.Close()

	client := keys.NewKeysServiceClient(connection)
	request := &keys.CreateKeysRequest{Password: memberPassword, MemberID: memberID}

	result, err := client.CreateKeys(context.Background(), request)
	if (err != nil) {
		logs.Error("Could not create keys", err)
		return false, ``, err
	}
	return result.GetSuccess(), result.GetHashKey(), nil
}
func	checkMemberKeys(memberID, memberPassword string) (bool, string, error) {
	connection := bridgeMicroservice(`panghostlin-keys:8011`)
	defer connection.Close()

	client := keys.NewKeysServiceClient(connection)
	request := &keys.CheckPasswordRequest{Password: memberPassword, MemberID: memberID}

	result, err := client.CheckPassword(context.Background(), request)
	if (err != nil) {
		logs.Error("Could not verify password", err)
		return false, ``, err
	}
	return result.GetSuccess(), result.GetHashKey(), nil
}