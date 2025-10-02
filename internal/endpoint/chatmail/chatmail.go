/*
Maddy Mail Server - Composable all-in-one email server.
Copyright © 2019-2020 Max Mazurov <fox.cpp@disroot.org>, Maddy Mail Server contributors

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

package chatmail

import (
	"crypto/rand"
	"crypto/tls"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/sadraiiali/maddy_chatmail/framework/config"
	tls2 "github.com/sadraiiali/maddy_chatmail/framework/config/tls"
	"github.com/sadraiiali/maddy_chatmail/framework/log"
	"github.com/sadraiiali/maddy_chatmail/framework/module"
	"github.com/sadraiiali/maddy_chatmail/internal/auth/pass_table"
	"github.com/skip2/go-qrcode"
	"golang.org/x/crypto/bcrypt"
)

//go:embed www/*
var wwwFiles embed.FS

const modName = "chatmail"

type Endpoint struct {
	addrs  []string
	logger log.Logger

	// Domain configuration
	mailDomain string // Domain for email addresses (e.g., something.com)
	mxDomain   string // MX domain for mail server (e.g., mx.something.com)
	webDomain  string // Web domain for chat interface (e.g., chat.something.com)

	authDB  module.PlainUserDB
	storage module.ManageableStorage

	listenersWg sync.WaitGroup
	serv        http.Server
	mux         *http.ServeMux

	// TLS configuration
	tlsConfig *tls.Config

	// Configuration options
	usernameLength int
	passwordLength int
}

type AccountResponse struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func New(_ string, args []string) (module.Module, error) {
	return &Endpoint{
		addrs:  args,
		logger: log.Logger{Name: modName, Debug: log.DefaultLogger.Debug},
	}, nil
}

func (e *Endpoint) Init(cfg *config.Map) error {
	cfg.Bool("debug", false, false, &e.logger.Debug)
	cfg.String("mail_domain", false, true, "", &e.mailDomain)
	cfg.String("mx_domain", false, true, "", &e.mxDomain)
	cfg.String("web_domain", false, true, "", &e.webDomain)
	cfg.Int("username_length", false, false, 8, &e.usernameLength)
	cfg.Int("password_length", false, false, 16, &e.passwordLength)

	// Get references to the authentication database and storage
	var authDBName, storageName string
	cfg.String("auth_db", false, true, "", &authDBName)
	cfg.String("storage", false, true, "", &storageName)

	// TLS configuration block
	cfg.Custom("tls", false, false, nil, tls2.TLSDirective, &e.tlsConfig)

	if _, err := cfg.Process(); err != nil {
		return err
	}

	if e.mailDomain == "" {
		return fmt.Errorf("%s: mail_domain is required", modName)
	}
	if e.mxDomain == "" {
		return fmt.Errorf("%s: mx_domain is required", modName)
	}
	if e.webDomain == "" {
		return fmt.Errorf("%s: web_domain is required", modName)
	}
	if authDBName == "" {
		return fmt.Errorf("%s: auth_db is required", modName)
	}
	if storageName == "" {
		return fmt.Errorf("%s: storage is required", modName)
	}

	// Get the authentication database instance
	authDBInst, err := module.GetInstance(authDBName)
	if err != nil {
		return fmt.Errorf("%s: failed to get auth DB instance: %v", modName, err)
	}

	var ok bool
	e.authDB, ok = authDBInst.(module.PlainUserDB)
	if !ok {
		return fmt.Errorf("%s: auth DB must implement PlainUserDB interface", modName)
	}

	// Get the storage instance
	storageInst, err := module.GetInstance(storageName)
	if err != nil {
		return fmt.Errorf("%s: failed to get storage instance: %v", modName, err)
	}

	e.storage, ok = storageInst.(module.ManageableStorage)
	if !ok {
		return fmt.Errorf("%s: storage must implement ManageableStorage interface", modName)
	}

	e.mux = http.NewServeMux()
	// Priority 1: API endpoints
	e.mux.HandleFunc("/new", e.handleNewAccount)
	e.mux.HandleFunc("/qr", e.handleQRCode)
	// Priority 2: Static files and templates
	e.mux.HandleFunc("/", e.handleStaticFiles)
	e.serv.Handler = e.mux

	for _, a := range e.addrs {
		endp, err := config.ParseEndpoint(a)
		if err != nil {
			return fmt.Errorf("%s: malformed endpoint: %v", modName, err)
		}

		l, err := net.Listen(endp.Network(), endp.Address())
		if err != nil {
			return fmt.Errorf("%s: %v", modName, err)
		}

		// Wrap listener with TLS if needed
		if endp.IsTLS() {
			if e.tlsConfig == nil {
				return fmt.Errorf("%s: TLS endpoint specified but no TLS configuration provided", modName)
			}
			l = tls.NewListener(l, e.tlsConfig)
		}

		e.listenersWg.Add(1)
		go func() {
			scheme := "http"
			if endp.IsTLS() {
				scheme = "https"
			}
			e.logger.Printf("listening on %s (%s)", endp.String(), scheme)
			err := e.serv.Serve(l)
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				e.logger.Error("serve failed", err, "endpoint", a)
			}
			e.listenersWg.Done()
		}()
	}

	return nil
}

func (e *Endpoint) Name() string {
	return modName
}

func (e *Endpoint) InstanceName() string {
	return ""
}

func (e *Endpoint) Close() error {
	if err := e.serv.Close(); err != nil {
		return err
	}
	e.listenersWg.Wait()
	return nil
}

// generateRandomString generates a random string of specified length using alphanumeric characters
func (e *Endpoint) generateRandomString(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = charset[b[i]%byte(len(charset))]
	}
	return string(b), nil
}

// generateRandomPassword generates a random password with special characters
func (e *Endpoint) generateRandomPassword(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?"
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = charset[b[i]%byte(len(charset))]
	}
	return string(b), nil
}

func (e *Endpoint) handleNewAccount(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Generate random username
	username, err := e.generateRandomString(e.usernameLength)
	if err != nil {
		e.logger.Error("failed to generate username", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Generate random password
	password, err := e.generateRandomPassword(e.passwordLength)
	if err != nil {
		e.logger.Error("failed to generate password", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Create full email address
	email := username + "@" + e.mailDomain

	// Create user in authentication database
	if authHash, ok := e.authDB.(*pass_table.Auth); ok {
		// Use bcrypt for password hashing
		err = authHash.CreateUserHash(email, password, "bcrypt", pass_table.HashOpts{
			BcryptCost: bcrypt.DefaultCost,
		})
	} else {
		err = e.authDB.CreateUser(email, password)
	}

	if err != nil {
		// Check if user already exists and retry
		if strings.Contains(err.Error(), "already exist") {
			// Retry with new username
			e.handleNewAccount(w, r)
			return
		}
		e.logger.Error("failed to create user in auth DB", err, "email", email)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Create IMAP account in storage
	err = e.storage.CreateIMAPAcct(email)
	if err != nil {
		e.logger.Error("failed to create IMAP account", err, "email", email)
		// Try to clean up the auth entry
		if delErr := e.authDB.DeleteUser(email); delErr != nil {
			e.logger.Error("failed to cleanup auth entry after storage failure", delErr, "email", email)
		}
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Return the generated credentials
	response := AccountResponse{
		Email:    email,
		Password: password,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		e.logger.Error("failed to encode response", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	e.logger.Printf("created new account: %s", email)
}

func (e *Endpoint) handleStaticFiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Clean the path to prevent directory traversal
	path := strings.TrimPrefix(r.URL.Path, "/")
	if path == "" {
		path = "index.html"
	}

	// Try to read the file from embedded filesystem
	filePath := "www/" + path
	fileData, err := wwwFiles.ReadFile(filePath)
	if err != nil {
		// File not found, return 404
		http.NotFound(w, r)
		return
	}

	// Determine content type based on file extension
	var contentType string
	switch {
	case strings.HasSuffix(path, ".html"):
		contentType = "text/html; charset=utf-8"
	case strings.HasSuffix(path, ".css"):
		contentType = "text/css"
	case strings.HasSuffix(path, ".js"):
		contentType = "application/javascript"
	case strings.HasSuffix(path, ".png"):
		contentType = "image/png"
	case strings.HasSuffix(path, ".jpg") || strings.HasSuffix(path, ".jpeg"):
		contentType = "image/jpeg"
	case strings.HasSuffix(path, ".gif"):
		contentType = "image/gif"
	case strings.HasSuffix(path, ".svg"):
		contentType = "image/svg+xml"
	case strings.HasSuffix(path, ".ico"):
		contentType = "image/x-icon"
	default:
		contentType = "application/octet-stream"
	}

	// For HTML files, process them as templates
	if strings.HasSuffix(path, ".html") {
		tmpl, err := template.New(path).Parse(string(fileData))
		if err != nil {
			e.logger.Error("failed to parse template", err, "file", path)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Template data
		data := struct {
			MailDomain string
			MXDomain   string
			WebDomain  string
		}{
			MailDomain: e.mailDomain,
			MXDomain:   e.mxDomain,
			WebDomain:  e.webDomain,
		}

		w.Header().Set("Content-Type", contentType)
		if err := tmpl.Execute(w, data); err != nil {
			e.logger.Error("failed to execute template", err, "file", path)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
	} else {
		// For non-HTML files, serve them as-is
		w.Header().Set("Content-Type", contentType)
		if _, err := w.Write(fileData); err != nil {
			e.logger.Error("failed to write file data", err, "file", path)
			return
		}
	}
}

func (e *Endpoint) handleQRCode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get the data parameter from query string
	data := r.URL.Query().Get("data")
	if data == "" {
		http.Error(w, "Missing 'data' parameter", http.StatusBadRequest)
		return
	}

	// Generate QR code
	qrCode, err := qrcode.Encode(data, qrcode.Medium, 256)
	if err != nil {
		e.logger.Error("failed to generate QR code", err, "data", data)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Set headers for PNG image
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")

	// Write the QR code image
	if _, err := w.Write(qrCode); err != nil {
		e.logger.Error("failed to write QR code response", err)
		return
	}
}

func init() {
	module.RegisterEndpoint(modName, New)
}
