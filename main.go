/*******************************************************************************
** @Author:					Major Tom - Sacré Studio <Major>
** @Email:					sacrestudioparis@gmail.com
** @Date:					Monday 03 September 2018 - 18:13:51
** @Filename:				main.go
**
** @Last modified by:		Tbouder
** @Last modified time:		Friday 07 February 2020 - 12:30:00
*******************************************************************************/

package			main

import			"log"
import			"os"
import			"net"
import			"context"
import			"crypto/tls"
import			"crypto/x509"
import			"io/ioutil"
import			"database/sql"
import			"github.com/microgolang/logs"
import			"google.golang.org/grpc"
import			"google.golang.org/grpc/credentials"
import			"gitlab.com/betterpiwigo/sdk/Keys"
import			_ "github.com/lib/pq"

type server struct {}

var		PGR *sql.DB

func	connectToPostgre() {
	username := os.Getenv("POSTGRE_USERNAME")
	password := os.Getenv("POSTGRE_PWD")
	host := os.Getenv("POSTGRE_URI")
	dbName := os.Getenv("POSTGRE_DB")
	connStr := "user=" + username + " password=" + password + " dbname=" + dbName + " host=" + host + " sslmode=disable"
	PGR, _ = sql.Open("postgres", connStr)

	PGR.Exec(`CREATE extension if not exists "uuid-ossp";`)
	PGR.Exec(`CREATE TABLE if not exists members(
		ID uuid NOT NULL DEFAULT uuid_generate_v4(),
		Email varchar NULL,
		AccessToken varchar NULL,
		AccessExp bigint,
		RefreshToken varchar,
		RefreshExp bigint,

		CONSTRAINT members_pk PRIMARY KEY (ID),
		CONSTRAINT members_un UNIQUE (Email)
	);`)

	/**************************************************************************
	**	Create a function to transform all user emails to lowercase on insert
	**	or update
	**************************************************************************/
	PGR.Exec(`CREATE or REPLACE function tolowercase() RETURNS trigger language plpgsql as $$ BEGIN new.Email := lower(new.Email); return new; END; $$;;`)
	PGR.Exec(`CREATE trigger emailToLowerCase BEFORE INSERT or UPDATE on members for each row execute function tolowercase();`)

	logs.Success(`Connected to DB - Localhost`)
}
func	InitGRPCBridge(serverName string) (*grpc.ClientConn) {
	crt := `/env/client.crt`
    key := `/env/client.key`
	caCert  := `/env/ca.crt`

    // Load the client certificates from disk
    certificate, err := tls.LoadX509KeyPair(crt, key)
    if err != nil {
		logs.Error("Did not connect", err)
		return nil
    }

    // Create a certificate pool from the certificate authority
    certPool := x509.NewCertPool()
    ca, err := ioutil.ReadFile(caCert)
    if err != nil {
		logs.Error("Did not connect", err)
		return nil
    }

    // Append the certificates from the CA
    if ok := certPool.AppendCertsFromPEM(ca); !ok {
		logs.Error("Did not connect", err)
		return nil
    }

    creds := credentials.NewTLS(&tls.Config{
        ServerName:   serverName, // NOTE: this is required!
        Certificates: []tls.Certificate{certificate},
		RootCAs:      certPool,
		InsecureSkipVerify: true,
    })

    // Create a connection with the TLS credentials
	conn, err := grpc.Dial(serverName, grpc.WithTransportCredentials(creds))
    if err != nil {
		logs.Error("Did not connect", err)
		return nil
	}

	return conn
}

func	generateMemberKeys(memberID, memberPassword string) (bool, string, error) {
	connection := InitGRPCBridge(`piwigo-keys:8011`)
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
	connection := InitGRPCBridge(`piwigo-keys:8011`)
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

func	initGRPCConnection() {
	crt := `/env/server.crt`
    key := `/env/server.key`
	caCert  := `/env/ca.crt`
	
	certificate, err := tls.LoadX509KeyPair(crt, key)
    if err != nil {
        log.Fatalf("could not load server key pair: %s", err)
    }

    // Create a certificate pool from the certificate authority
    certPool := x509.NewCertPool()
    ca, err := ioutil.ReadFile(caCert)
    if err != nil {
        log.Fatalf("could not read ca certificate: %s", err)
    }

    // Append the client certificates from the CA
    if ok := certPool.AppendCertsFromPEM(ca); !ok {
        log.Fatalf("failed to append client certs")
    }

    // Create the channel to listen on
    lis, err := net.Listen(`tcp`, `:8010`)
    if err != nil {
		log.Fatalf("Failed to listen: %v", err)
    }

    // Create the TLS credentials
    creds := credentials.NewTLS(&tls.Config{
    	ClientAuth:   tls.RequireAndVerifyClientCert,
    	Certificates: []tls.Certificate{certificate},
    	ClientCAs:    certPool,
	})

    // Create the gRPC server with the credentials
    srv := grpc.NewServer(grpc.Creds(creds))

	// Register the handler object
	RegisterMembersServiceServer(srv, &server{})

    // Serve and Listen
	logs.Success(`Running on port: :8010`)
	if err := srv.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}

func	main()	{
	connectToPostgre()
	initGRPCConnection()
}
