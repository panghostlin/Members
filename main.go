/*******************************************************************************
** @Author:					Major Tom - Sacré Studio <Major>
** @Email:					sacrestudioparis@gmail.com
** @Date:					Monday 03 September 2018 - 18:13:51
** @Filename:				main.go
**
** @Last modified by:		Tbouder
** @Last modified time:		Friday 21 February 2020 - 17:49:37
*******************************************************************************/

package			main

import			"log"
import			"os"
import			"net"
import			"crypto/tls"
import			"crypto/x509"
import			"io/ioutil"
import			"database/sql"
import			"github.com/microgolang/logs"
import			"google.golang.org/grpc"
import			"google.golang.org/grpc/credentials"
import			"github.com/panghostlin/SDK/Members"
import			"github.com/panghostlin/SDK/Pictures"
import			_ "github.com/lib/pq"

type	server struct {}
var		PGR *sql.DB

type	sClients	struct {
	members		members.MembersServiceClient
	pictures	pictures.PicturesServiceClient
	albums		pictures.AlbumsServiceClient
}
var		bridges map[string](*grpc.ClientConn)
var		clients = &sClients{}

func	connectToDatabase() {
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

		PublicKey varchar NULL,
		PrivateKey varchar NULL,
		PrivateKeyIV varchar NULL,
		PrivateKeySalt varchar NULL,

		PasswordArgon2Hash varchar NULL,
		PasswordArgon2IV varchar NULL,
		PasswordScryptHash varchar NULL,
		PasswordScryptIV varchar NULL,

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
func	bridgeInsecureMicroservice(serverName string, clientMS string) (*grpc.ClientConn) {
	logs.Warning("Using insecure connection")
	conn, err := grpc.Dial(serverName, grpc.WithInsecure())
    if err != nil {
		logs.Error("Did not connect", err)
		return nil
	}

	if (clientMS == `members`) {
		clients.members = members.NewMembersServiceClient(conn)
	} else if (clientMS == `pictures`) {
		clients.pictures = pictures.NewPicturesServiceClient(conn)
		clients.albums = pictures.NewAlbumsServiceClient(conn)
	}

	return conn
}
func	bridgeMicroservice(serverName string, clientMS string) (*grpc.ClientConn) {
	crt := `/env/client.crt`
    key := `/env/client.key`
	caCert  := `/env/ca.crt`

    certificate, err := tls.LoadX509KeyPair(crt, key)
    if err != nil {
		logs.Warning("Did not connect: " + err.Error())
		return bridgeInsecureMicroservice(serverName, clientMS)
    }

    certPool := x509.NewCertPool()
    ca, err := ioutil.ReadFile(caCert)
    if err != nil {
		logs.Warning("Did not connect: " + err.Error())
		return bridgeInsecureMicroservice(serverName, clientMS)
    }

    if ok := certPool.AppendCertsFromPEM(ca); !ok {
		logs.Warning("Did not connect: " + err.Error())
		return bridgeInsecureMicroservice(serverName, clientMS)
    }

    creds := credentials.NewTLS(&tls.Config{
        ServerName:   serverName,
        Certificates: []tls.Certificate{certificate},
		RootCAs:      certPool,
		InsecureSkipVerify: true,
    })

	conn, err := grpc.Dial(serverName, grpc.WithTransportCredentials(creds))
    if err != nil {
		logs.Warning("Did not connect: " + err.Error())
		return bridgeInsecureMicroservice(serverName, clientMS)
	}

	if (clientMS == `members`) {
		clients.members = members.NewMembersServiceClient(conn)
	} else if (clientMS == `pictures`) {
		clients.pictures = pictures.NewPicturesServiceClient(conn)
	}

	return conn
}
func	serveInsecureMicroservice() {
    lis, err := net.Listen(`tcp`, `:8010`)
    if err != nil {
		log.Fatalf("Failed to listen: %v", err)
    }

	srv := grpc.NewServer()
	members.RegisterMembersServiceServer(srv, &server{})
	logs.Success(`Running on port: :8010`)
	if err := srv.Serve(lis); err != nil {
		logs.Error(err)
		log.Fatalf("failed to serve: %v", err)
	}
}
func	serveMicroservice() {
	crt := `/env/server.crt`
    key := `/env/server.key`
	caCert  := `/env/ca.crt`
	
	certificate, err := tls.LoadX509KeyPair(crt, key)
    if err != nil {
		logs.Warning("could not load server key pair : " + err.Error())
		logs.Warning("Using insecure connection")
		serveInsecureMicroservice()
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
	members.RegisterMembersServiceServer(srv, &server{})

    // Serve and Listen
	logs.Success(`Running on port: :8010`)
	if err := srv.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}

func	main()	{
	connectToDatabase()
	serveMicroservice()
}
