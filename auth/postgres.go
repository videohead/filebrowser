package auth

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	_ "github.com/jackc/pgx/v5/stdlib" // register the pgx driver for database/sql

	fberrors "github.com/filebrowser/filebrowser/v2/errors"
	"github.com/filebrowser/filebrowser/v2/settings"
	"github.com/filebrowser/filebrowser/v2/users"
)

// MethodPostgresAuth is used to identify postgres auth.
const MethodPostgresAuth settings.AuthMethod = "postgres"

const postgresQuery = `SELECT "password" FROM "User" WHERE lower("email") = lower($1) AND "isAuthorized" = true`

const maxPostgresAuthBodySize = 1 << 20 // 1 MiB

type postgresCred struct {
	Password string `json:"password"`
	Username string `json:"username"`
}

// PostgresAuth is a database-backed implementation of an Auther. It
// authenticates credentials against the chatbot project's "User" table
// (email + bcrypt password + isAuthorized), so both applications share a
// single account database.
type PostgresAuth struct {
	Host         string `json:"host"`
	Port         string `json:"port"`
	Database     string `json:"database"`
	User         string `json:"user"`
	Password     string `json:"password"`
	PasswordFile string `json:"passwordFile"`
	SSLMode      string `json:"sslmode"`
}
// password resolves the database password. An environment variable takes
// precedence over a mounted file, which in turn takes precedence over the
// stored value, so deployments can keep the secret in .env (passed via
// compose environment) instead of persisted files.
func (a *PostgresAuth) password() (string, error) {
	if env := os.Getenv("FB_POSTGRES_PASSWORD"); env != "" {
		return env, nil
	}

	if a.PasswordFile != "" {
		data, err := os.ReadFile(a.PasswordFile)
		if err != nil {
			return "", fmt.Errorf("postgres auth: reading password file: %w", err)
		}
		pwd := strings.TrimSpace(string(data))
		if pwd != "" {
			return pwd, nil
		}
		return "", fmt.Errorf("postgres auth: password file %q is empty", a.PasswordFile)
	}
	return a.Password, nil
}

func (a *PostgresAuth) dsn() (string, error) {
	if a.Host == "" || a.Database == "" || a.User == "" {
		return "", errors.New("postgres auth: host, database and user must be configured")
	}

	password, err := a.password()
	if err != nil {
		return "", err
	}

	port := a.Port
	if port == "" {
		port = "5432"
	}

	sslmode := a.SSLMode
	if sslmode == "" {
		sslmode = "disable"
	}

	return fmt.Sprintf(
		"host=%s port=%s dbname=%s user=%s password=%s sslmode=%s connect_timeout=5",
		a.Host, port, a.Database, a.User, password, sslmode,
	), nil
}

func (a *PostgresAuth) lookup(password string, username string) error {
	dsn, err := a.dsn()
	if err != nil {
		return err
	}

	// A fresh connection per login keeps the auther stateless and avoids
	// maintaining a pool in a login-only code path.
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return err
	}
	defer db.Close()

	var hash string
	err = db.QueryRow(postgresQuery, username).Scan(&hash)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		// Equalize timing so unknown emails don't leak account existence.
		users.CheckPwd(password, dummyHash)
		return errLoginFailed
	case err != nil:
		return err
	default:
	}

	if !users.CheckPwd(password, hash) {
		return errLoginFailed
	}

	return nil
}

var errLoginFailed = errors.New("invalid credentials")

// Auth authenticates the user against the chatbot User table.
func (a *PostgresAuth) Auth(r *http.Request, usr users.Store, setting *settings.Settings, srv *settings.Server) (*users.User, error) {
	var cred postgresCred

	if r.Body == nil {
		return nil, os.ErrPermission
	}

	if err := json.NewDecoder(r.Body).Decode(&cred); err != nil {
		return nil, os.ErrPermission
	}

	username := strings.ToLower(strings.TrimSpace(cred.Username))
	if username == "" || cred.Password == "" {
		return nil, os.ErrPermission
	}

	if err := a.lookup(cred.Password, username); err != nil {
		log.Printf("postgres auth: login failed for %q: %v", username, err)
		return nil, os.ErrPermission
	}

	// Credentials are valid in the chatbot database. Ensure a matching
	// filebrowser account exists (auto-provisioned on first login, in the
	// same spirit as ProxyAuth), then return it.
	user, err := usr.Get(srv.Root, srv.FollowExternalSymlinks, username)
	if errors.Is(err, fberrors.ErrNotExist) {
		return a.createUser(usr, setting, srv, username)
	}
	return user, err
}

func (a *PostgresAuth) createUser(usr users.Store, setting *settings.Settings, srv *settings.Server, username string) (*users.User, error) {
	const randomPasswordLength = settings.DefaultMinimumPasswordLength + 10
	pwd, err := users.RandomPwd(randomPasswordLength)
	if err != nil {
		return nil, err
	}

	hashedRandomPassword, err := users.ValidateAndHashPwd(pwd, setting.MinimumPasswordLength)
	if err != nil {
		return nil, err
	}

	user := &users.User{
		Username:     username,
		Password:     hashedRandomPassword,
		LockPassword: true,
	}
	setting.Defaults.Apply(user)
	user.Perm.Admin = false
	user.Perm.Execute = false
	user.Commands = []string{}

	var derivedScope bool
	if derivedScope, err = setting.CreateUserHome(user, srv.Root, false); err != nil {
		return nil, err
	}

	if err := usr.SaveProvisioned(user, derivedScope); err != nil {
		return nil, err
	}

	return user, nil
}

// LoginPage tells that postgres auth requires a login page.
func (a *PostgresAuth) LoginPage() bool {
	return true
}
