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

package ctl

import (
	"bufio"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"
	"time"

	_ "embed" // for embedding templates

	maddycli "github.com/sadraiiali/maddy_chatmail/internal/cli"
	clitools2 "github.com/sadraiiali/maddy_chatmail/internal/cli/clitools"
	"github.com/urfave/cli/v2"
)

//go:embed dns.zone.j2
var dnsZoneTemplate string

//go:embed maddy.conf.j2
var maddyConfigTemplate string

// InstallConfig holds all configuration values for the installation
type InstallConfig struct {
	// Basic configuration
	Hostname      string
	PrimaryDomain string
	LocalDomains  string
	StateDir      string
	Generated     string

	// TLS configuration
	TLSCertPath string
	TLSKeyPath  string

	// Network configuration
	SMTPPort       string
	SubmissionPort string
	SubmissionTLS  string
	IMAPPort       string
	IMAPTLS        string

	// Chatmail configuration
	EnableChatmail      bool
	ChatmailHTTPPort    string
	ChatmailHTTPSPort   string
	ChatmailUsernameLen int
	ChatmailPasswordLen int

	// PGP Encryption configuration
	RequirePGPEncryption     bool
	AllowSecureJoin          bool
	PGPPassthroughSenders    []string
	PGPPassthroughRecipients []string

	// DNS configuration (for template)
	A             string
	AAAA          string
	DKIM_Entry    string
	STS_ID        string
	ACME_Account  string
	UseCloudflare bool // Add Cloudflare proxy disable tags

	// System configuration
	MaddyUser   string
	MaddyGroup  string
	ConfigDir   string
	SystemdPath string
	BinaryPath  string
	LibexecDir  string
	LogFile     string
}

// Default configuration values
func defaultConfig() *InstallConfig {
	return &InstallConfig{
		Hostname:                 "example.org",
		PrimaryDomain:            "example.org",
		LocalDomains:             "$(primary_domain)",
		StateDir:                 "/var/lib/maddy",
		Generated:                time.Now().Format("2006-01-02 15:04:05"),
		TLSCertPath:              "/etc/maddy/certs/fullchain.pem",
		TLSKeyPath:               "/etc/maddy/certs/privkey.pem",
		SMTPPort:                 "25",
		SubmissionPort:           "587",
		SubmissionTLS:            "465",
		IMAPPort:                 "143",
		IMAPTLS:                  "993",
		EnableChatmail:           false,
		ChatmailHTTPPort:         "80",
		ChatmailHTTPSPort:        "443",
		ChatmailUsernameLen:      8,
		ChatmailPasswordLen:      16,
		RequirePGPEncryption:     false,
		AllowSecureJoin:          true,
		PGPPassthroughSenders:    []string{},
		PGPPassthroughRecipients: []string{},
		UseCloudflare:            true, // Default to adding Cloudflare proxy disable tags
		MaddyUser:                "maddy",
		MaddyGroup:               "maddy",
		ConfigDir:                "/etc/maddy",
		SystemdPath:              "/etc/systemd/system",
		BinaryPath:               "/usr/local/bin/maddy",
		LibexecDir:               "/var/lib/maddy",
		LogFile:                  "/var/log/maddy-install.log",
	}
}

var logger *log.Logger

func init() {
	maddycli.AddSubcommand(
		&cli.Command{
			Name:  "install",
			Usage: "Install and configure maddy mail server",
			Description: `Install maddy mail server with interactive or non-interactive configuration.

This command will:
- Create maddy user and group
- Install systemd service files
- Generate configuration file
- Set up initial certificates (if needed)
- Configure DNS recommendations

Examples:
  maddy install                          # Interactive installation
  maddy install --non-interactive       # Non-interactive with defaults
  maddy install --domain example.org    # Non-interactive with domain
`,
			Action: installCommand,
			Flags: []cli.Flag{
				&cli.BoolFlag{
					Name:    "non-interactive",
					Aliases: []string{"n"},
					Usage:   "Run non-interactive installation with default values",
				},
				&cli.StringFlag{
					Name:  "domain",
					Usage: "Primary domain for the mail server",
				},
				&cli.StringFlag{
					Name:  "hostname",
					Usage: "Hostname for the mail server (MX record)",
				},
				&cli.StringFlag{
					Name:  "state-dir",
					Usage: "Directory for maddy state files",
					Value: "/var/lib/maddy",
				},
				&cli.StringFlag{
					Name:  "config-dir",
					Usage: "Directory for maddy configuration",
					Value: "/etc/maddy",
				},
				&cli.StringFlag{
					Name:  "libexec-dir",
					Usage: "Directory for maddy runtime files (same as state-dir by default)",
					Value: "/var/lib/maddy",
				},
				&cli.StringFlag{
					Name:  "cert-path",
					Usage: "Path to TLS certificate file",
				},
				&cli.StringFlag{
					Name:  "key-path",
					Usage: "Path to TLS private key file",
				},
				&cli.BoolFlag{
					Name:  "enable-chatmail",
					Usage: "Enable chatmail endpoint for user registration",
				},
				&cli.BoolFlag{
					Name:  "require-pgp-encryption",
					Usage: "Require PGP encryption for outgoing messages",
				},
				&cli.BoolFlag{
					Name:  "allow-secure-join",
					Usage: "Allow secure join requests even without encryption",
					Value: true,
				},
				&cli.StringSliceFlag{
					Name:  "pgp-passthrough-senders",
					Usage: "Sender addresses that bypass PGP encryption requirements",
				},
				&cli.StringSliceFlag{
					Name:  "pgp-passthrough-recipients",
					Usage: "Recipient addresses that bypass PGP encryption requirements",
				},
				&cli.StringFlag{
					Name:  "log-file",
					Usage: "Installation log file",
					Value: "/var/log/maddy-install.log",
				},
				&cli.BoolFlag{
					Name:  "dry-run",
					Usage: "Show what would be done without making changes",
				},
				&cli.BoolFlag{
					Name:  "skip-dns",
					Usage: "Skip interactive DNS configuration and verification",
				},
				&cli.BoolFlag{
					Name:  "cloudflare",
					Usage: "Add Cloudflare proxy disable tags to DNS records (default: true)",
					Value: true,
				},
			},
		})
}

func installCommand(ctx *cli.Context) error {
	// Initialize logger
	if err := initLogger(ctx.String("log-file")); err != nil {
		return fmt.Errorf("failed to initialize logger: %v", err)
	}

	logger.Println("Starting maddy installation process")
	fmt.Println("🚀 Maddy Mail Server Installation")
	fmt.Println("==================================")

	// Check if running as root
	if os.Geteuid() != 0 && !ctx.Bool("dry-run") {
		return fmt.Errorf("installation must be run as root (use sudo)")
	}

	config := defaultConfig()

	// Apply command line flags
	if ctx.IsSet("domain") {
		config.PrimaryDomain = ctx.String("domain")
		if !ctx.IsSet("hostname") {
			config.Hostname = ctx.String("domain")
		}
	}
	if ctx.IsSet("hostname") {
		config.Hostname = ctx.String("hostname")
	}
	if ctx.IsSet("state-dir") {
		config.StateDir = ctx.String("state-dir")
	}
	if ctx.IsSet("config-dir") {
		config.ConfigDir = ctx.String("config-dir")
	}
	if ctx.IsSet("libexec-dir") {
		config.LibexecDir = ctx.String("libexec-dir")
	} else {
		// If libexec-dir is not set, use the same as state-dir
		config.LibexecDir = config.StateDir
	}
	if ctx.IsSet("cert-path") {
		config.TLSCertPath = ctx.String("cert-path")
	}
	if ctx.IsSet("key-path") {
		config.TLSKeyPath = ctx.String("key-path")
	}
	if ctx.IsSet("enable-chatmail") {
		config.EnableChatmail = ctx.Bool("enable-chatmail")
	}
	if ctx.IsSet("require-pgp-encryption") {
		config.RequirePGPEncryption = ctx.Bool("require-pgp-encryption")
	}
	if ctx.IsSet("allow-secure-join") {
		config.AllowSecureJoin = ctx.Bool("allow-secure-join")
	}
	if ctx.IsSet("pgp-passthrough-senders") {
		config.PGPPassthroughSenders = ctx.StringSlice("pgp-passthrough-senders")
	}
	if ctx.IsSet("pgp-passthrough-recipients") {
		config.PGPPassthroughRecipients = ctx.StringSlice("pgp-passthrough-recipients")
	}
	if ctx.IsSet("log-file") {
		config.LogFile = ctx.String("log-file")
	}
	if ctx.IsSet("cloudflare") {
		config.UseCloudflare = ctx.Bool("cloudflare")
	}

	// Run interactive configuration if not in non-interactive mode
	if !ctx.Bool("non-interactive") {
		if err := runInteractiveConfig(config); err != nil {
			return fmt.Errorf("interactive configuration failed: %v", err)
		}
	}

	logger.Printf("Configuration: %+v", config)

	// Run installation steps
	steps := []struct {
		name string
		fn   func(*InstallConfig, bool) error
	}{
		{"Checking system requirements", checkSystemRequirements},
		{"Creating maddy user and group", createMaddyUser},
		{"Creating directories", createDirectories},
		{"Installing systemd service files", installSystemdFiles},
		{"Generating configuration file", generateConfigFile},
		{"Setting up permissions", setupPermissions},
		{"Installing binary", installBinary},
	}

	for i, step := range steps {
		fmt.Printf("\n[%d/%d] %s...\n", i+1, len(steps), step.name)
		logger.Printf("Step %d: %s", i+1, step.name)

		if err := step.fn(config, ctx.Bool("dry-run")); err != nil {
			logger.Printf("Step %d failed: %v", i+1, err)
			return fmt.Errorf("step '%s' failed: %v", step.name, err)
		}

		fmt.Printf("✅ %s completed\n", step.name)
		logger.Printf("Step %d completed successfully", i+1)
	}

	// DNS Configuration step (interactive)
	if !ctx.Bool("skip-dns") && !ctx.Bool("non-interactive") {
		fmt.Printf("\n🌐 DNS Configuration\n")
		fmt.Println("====================")
		if err := configureDNS(config, ctx.Bool("dry-run")); err != nil {
			logger.Printf("DNS configuration failed: %v", err)
			fmt.Printf("⚠️  DNS configuration failed: %v\n", err)
			fmt.Printf("You can continue and configure DNS manually later.\n")
		}
	} else if ctx.Bool("skip-dns") {
		fmt.Printf("\n⏭️  Skipping DNS configuration (--skip-dns flag provided)\n")
	} else {
		fmt.Printf("\n⏭️  Skipping DNS configuration (non-interactive mode)\n")
	}
	// Print next steps
	printNextSteps(config)

	// Log final summary
	logger.Println("=== INSTALLATION SUMMARY ===")
	logger.Printf("User created: %s with home directory %s", config.MaddyUser, config.StateDir)
	logger.Printf("Directories created: %s, %s, %s/certs, %s",
		config.StateDir, config.ConfigDir, config.ConfigDir, filepath.Dir(config.LogFile))
	logger.Printf("Files created: %s/maddy.conf, %s/maddy.service, %s/maddy@.service, %s",
		config.ConfigDir, config.SystemdPath, config.SystemdPath, config.BinaryPath)
	logger.Printf("Permissions set: %s owned by %s:%s", config.StateDir, config.MaddyUser, config.MaddyGroup)
	logger.Printf("Network ports configured: SMTP:%s, Submission:%s/%s, IMAP:%s/%s",
		config.SMTPPort, config.SubmissionPort, config.SubmissionTLS, config.IMAPPort, config.IMAPTLS)
	if config.EnableChatmail {
		logger.Printf("Chatmail enabled on ports HTTP:%s, HTTPS:%s", config.ChatmailHTTPPort, config.ChatmailHTTPSPort)
	}
	logger.Println("Installation completed successfully")
	fmt.Println("\n🎉 Installation completed successfully!")

	return nil
}

func initLogger(logFile string) error {
	// Create log directory if it doesn't exist
	logDir := filepath.Dir(logFile)
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return err
	}

	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}

	logger = log.New(file, "", log.LstdFlags)
	return nil
}

func runInteractiveConfig(config *InstallConfig) error {
	fmt.Println("\n📋 Interactive Configuration")
	fmt.Println("Please provide the following information (press Enter for defaults):")

	// Primary domain
	config.PrimaryDomain = promptString("Primary domain", config.PrimaryDomain)

	// Hostname (MX record)
	defaultHostname := config.PrimaryDomain
	config.Hostname = promptString("Hostname (MX record)", defaultHostname)

	// Additional domains
	additionalDomains := promptString("Additional domains (comma-separated, optional)", "")
	if additionalDomains != "" {
		config.LocalDomains = fmt.Sprintf("$(primary_domain) %s", strings.ReplaceAll(additionalDomains, ",", " "))
	}

	// State directory
	config.StateDir = promptString("State directory", config.StateDir)

	// Configuration directory
	config.ConfigDir = promptString("Configuration directory", config.ConfigDir)

	// TLS certificates
	fmt.Println("\n🔒 TLS Certificate Configuration")
	config.TLSCertPath = promptString("TLS certificate path", config.TLSCertPath)
	config.TLSKeyPath = promptString("TLS private key path", config.TLSKeyPath)

	// Network ports
	fmt.Println("\n🌐 Network Configuration")
	config.SMTPPort = promptString("SMTP port", config.SMTPPort)
	config.SubmissionPort = promptString("Submission port", config.SubmissionPort)
	config.SubmissionTLS = promptString("Submission TLS port", config.SubmissionTLS)
	config.IMAPPort = promptString("IMAP port", config.IMAPPort)
	config.IMAPTLS = promptString("IMAP TLS port", config.IMAPTLS)

	// Chatmail configuration
	fmt.Println("\n💬 Chatmail Configuration")
	config.EnableChatmail = clitools2.Confirmation("Enable chatmail endpoint for user registration", config.EnableChatmail)

	if config.EnableChatmail {
		config.ChatmailHTTPPort = promptString("Chatmail HTTP port", config.ChatmailHTTPPort)
		config.ChatmailHTTPSPort = promptString("Chatmail HTTPS port", config.ChatmailHTTPSPort)
		config.ChatmailUsernameLen = promptInt("Chatmail username length", config.ChatmailUsernameLen)
		config.ChatmailPasswordLen = promptInt("Chatmail password length", config.ChatmailPasswordLen)
	}

	// PGP Encryption configuration
	fmt.Println("\n🔐 PGP Encryption Configuration")
	config.RequirePGPEncryption = clitools2.Confirmation("Require PGP encryption for outgoing messages", config.RequirePGPEncryption)

	if config.RequirePGPEncryption {
		config.AllowSecureJoin = clitools2.Confirmation("Allow secure join requests without encryption", config.AllowSecureJoin)

		passthroughSenders := promptString("Passthrough senders (comma-separated email addresses that bypass encryption)", "")
		if passthroughSenders != "" {
			config.PGPPassthroughSenders = strings.Split(strings.ReplaceAll(passthroughSenders, " ", ""), ",")
		}

		passthroughRecipients := promptString("Passthrough recipients (comma-separated email addresses that bypass encryption)", "")
		if passthroughRecipients != "" {
			config.PGPPassthroughRecipients = strings.Split(strings.ReplaceAll(passthroughRecipients, " ", ""), ",")
		}
	}

	// DNS Provider Configuration
	fmt.Println("\n🌐 DNS Provider Configuration")
	config.UseCloudflare = clitools2.Confirmation("Add Cloudflare proxy disable tags to DNS records", config.UseCloudflare)

	return nil
}

func promptString(prompt, defaultValue string) string {
	fmt.Printf("%s [%s]: ", prompt, defaultValue)

	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		value := strings.TrimSpace(scanner.Text())
		if value == "" {
			return defaultValue
		}
		return value
	}

	return defaultValue
}

func promptInt(prompt string, defaultValue int) int {
	for {
		result := promptString(prompt, strconv.Itoa(defaultValue))
		if value, err := strconv.Atoi(result); err == nil {
			return value
		}
		fmt.Printf("Invalid number, please try again.\n")
	}
}

func checkSystemRequirements(config *InstallConfig, dryRun bool) error {
	logger.Println("Checking system requirements")

	fmt.Printf("   Checking systemd availability...\n")
	// Check if systemd is available
	if _, err := os.Stat("/bin/systemctl"); err != nil {
		if _, err := os.Stat("/usr/bin/systemctl"); err != nil {
			return fmt.Errorf("systemd not found - this installer requires systemd")
		}
	}
	fmt.Printf("     ✓ systemd found\n")

	fmt.Printf("   Checking system utilities...\n")
	// Check if we're on a supported system
	if _, err := exec.LookPath("useradd"); err != nil {
		return fmt.Errorf("useradd command not found - unsupported system")
	}
	fmt.Printf("     ✓ useradd command available\n")

	fmt.Printf("   Checking network ports...\n")
	// Check available ports
	ports := []string{config.SMTPPort, config.SubmissionPort, config.SubmissionTLS, config.IMAPPort, config.IMAPTLS}
	if config.EnableChatmail {
		ports = append(ports, config.ChatmailHTTPPort, config.ChatmailHTTPSPort)
	}

	portWarnings := 0
	for _, port := range ports {
		if err := checkPortAvailable(port, dryRun); err != nil {
			logger.Printf("Port check warning: %v", err)
			fmt.Printf("     ⚠️  Warning: %v\n", err)
			portWarnings++
		} else if !dryRun {
			fmt.Printf("     ✓ Port %s appears available\n", port)
		} else {
			fmt.Printf("     • Port %s (would check)\n", port)
		}
	}

	if portWarnings > 0 {
		fmt.Printf("   ⚠️  %d port warnings (installation can continue)\n", portWarnings)
	} else {
		fmt.Printf("   ✓ All ports appear available\n")
	}

	return nil
}

func checkPortAvailable(port string, dryRun bool) error {
	if dryRun {
		return nil
	}

	// Simple check using netstat or ss
	cmd := exec.Command("ss", "-tln", fmt.Sprintf("sport = :%s", port))
	output, err := cmd.Output()
	if err != nil {
		// Try with netstat if ss is not available
		cmd = exec.Command("netstat", "-tln")
		output, err = cmd.Output()
		if err != nil {
			return nil // Skip check if neither command is available
		}
	}

	if strings.Contains(string(output), ":"+port) {
		return fmt.Errorf("port %s appears to be in use", port)
	}

	return nil
}

func createMaddyUser(config *InstallConfig, dryRun bool) error {
	logger.Printf("Creating maddy user: %s", config.MaddyUser)

	// Check if user already exists
	if _, err := user.Lookup(config.MaddyUser); err == nil {
		logger.Printf("User %s already exists", config.MaddyUser)
		fmt.Printf("   ℹ️  User %s already exists\n", config.MaddyUser)
		return nil
	}

	if dryRun {
		fmt.Printf("   Would create user: %s with group: %s\n", config.MaddyUser, config.MaddyGroup)
		fmt.Printf("   Home directory: %s\n", config.StateDir)
		fmt.Printf("   Shell: /sbin/nologin (no login access)\n")
		return nil
	}

	fmt.Printf("   Creating user: %s\n", config.MaddyUser)
	fmt.Printf("   Creating group: %s\n", config.MaddyGroup)
	fmt.Printf("   Home directory: %s\n", config.StateDir)
	fmt.Printf("   Shell: /sbin/nologin (no login access)\n")

	// Create user and group
	cmd := exec.Command("useradd",
		"-mrU",                // create home directory and user group
		"-s", "/sbin/nologin", // no shell access
		"-d", config.StateDir, // home directory
		"-c", "maddy mail server", // comment
		config.MaddyUser,
	)

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create user %s: %v", config.MaddyUser, err)
	}

	// Get the created user info to show UID/GID
	createdUser, err := user.Lookup(config.MaddyUser)
	if err == nil {
		fmt.Printf("   ✓ User created: %s (UID: %s)\n", config.MaddyUser, createdUser.Uid)
		fmt.Printf("   ✓ Group created: %s (GID: %s)\n", config.MaddyGroup, createdUser.Gid)
	}

	logger.Printf("Successfully created user: %s with group: %s, home: %s, shell: /sbin/nologin",
		config.MaddyUser, config.MaddyGroup, config.StateDir)
	return nil
}

func createDirectories(config *InstallConfig, dryRun bool) error {
	dirs := []struct {
		path  string
		perm  os.FileMode
		owner string
	}{
		{config.StateDir, 0755, config.MaddyUser},
		{config.ConfigDir, 0755, "root"},
		{filepath.Join(config.ConfigDir, "certs"), 0755, "root"},
		{filepath.Dir(config.LogFile), 0755, "root"},
	}

	for _, dir := range dirs {
		logger.Printf("Creating directory: %s (owner: %s, permissions: %o)", dir.path, dir.owner, dir.perm)

		if dryRun {
			fmt.Printf("   Would create directory: %s\n", dir.path)
			fmt.Printf("     Owner: %s, Permissions: %o\n", dir.owner, dir.perm)
			continue
		}

		fmt.Printf("   Creating directory: %s\n", dir.path)
		fmt.Printf("     Owner: %s, Permissions: %o\n", dir.owner, dir.perm)

		if err := os.MkdirAll(dir.path, dir.perm); err != nil {
			return fmt.Errorf("failed to create directory %s: %v", dir.path, err)
		}

		// Set ownership
		if dir.owner != "root" {
			maddyUser, err := user.Lookup(dir.owner)
			if err != nil {
				return fmt.Errorf("failed to lookup user %s: %v", dir.owner, err)
			}

			uid, _ := strconv.Atoi(maddyUser.Uid)
			gid, _ := strconv.Atoi(maddyUser.Gid)

			if err := os.Chown(dir.path, uid, gid); err != nil {
				return fmt.Errorf("failed to set ownership for %s: %v", dir.path, err)
			}
			fmt.Printf("     ✓ Set ownership to %s:%s (UID:%d, GID:%d)\n", dir.owner, dir.owner, uid, gid)
			logger.Printf("Set ownership of %s to %s:%s (UID:%d, GID:%d)", dir.path, dir.owner, dir.owner, uid, gid)
		} else {
			fmt.Printf("     ✓ Owner: root (system default)\n")
		}
	}

	return nil
}

func installSystemdFiles(config *InstallConfig, dryRun bool) error {
	logger.Println("Installing systemd service files")

	systemdFiles := map[string]string{
		"maddy.service":  systemdServiceTemplate,
		"maddy@.service": systemdInstanceTemplate,
	}

	for filename, content := range systemdFiles {
		destPath := filepath.Join(config.SystemdPath, filename)
		logger.Printf("Installing %s to %s (permissions: 644)", filename, destPath)

		if dryRun {
			fmt.Printf("   Would install systemd file: %s\n", destPath)
			fmt.Printf("     Source: embedded template\n")
			fmt.Printf("     Permissions: 644\n")
			continue
		}

		fmt.Printf("   Installing: %s\n", destPath)
		fmt.Printf("     Source: embedded template\n")
		fmt.Printf("     Permissions: 644\n")

		// Execute template
		tmpl, err := template.New(filename).Parse(content)
		if err != nil {
			return fmt.Errorf("failed to parse template %s: %v", filename, err)
		}

		file, err := os.Create(destPath)
		if err != nil {
			return fmt.Errorf("failed to create %s: %v", destPath, err)
		}
		defer file.Close()

		if err := tmpl.Execute(file, config); err != nil {
			return fmt.Errorf("failed to execute template %s: %v", filename, err)
		}

		// Set permissions
		if err := os.Chmod(destPath, 0644); err != nil {
			return fmt.Errorf("failed to set permissions for %s: %v", destPath, err)
		}

		fmt.Printf("     ✓ Created successfully\n")
		logger.Printf("Successfully created %s with permissions 644", destPath)
	}

	// Reload systemd
	if !dryRun {
		fmt.Printf("   Reloading systemd daemon...\n")
		cmd := exec.Command("systemctl", "daemon-reload")
		if err := cmd.Run(); err != nil {
			logger.Printf("Warning: failed to reload systemd: %v", err)
			fmt.Printf("   ⚠️  Warning: failed to reload systemd daemon\n")
		} else {
			fmt.Printf("   ✓ Systemd daemon reloaded\n")
			logger.Println("Successfully reloaded systemd daemon")
		}
	} else {
		fmt.Printf("   Would reload systemd daemon\n")
	}

	return nil
}

func generateConfigFile(config *InstallConfig, dryRun bool) error {
	logger.Println("Generating configuration file")

	configPath := filepath.Join(config.ConfigDir, "maddy.conf")
	logger.Printf("Generating config file: %s (permissions: 644)", configPath)

	if dryRun {
		fmt.Printf("   Would generate config file: %s\n", configPath)
		fmt.Printf("     Domain: %s\n", config.PrimaryDomain)
		fmt.Printf("     Hostname: %s\n", config.Hostname)
		fmt.Printf("     State directory: %s\n", config.StateDir)
		if config.EnableChatmail {
			fmt.Printf("     Chatmail: enabled (HTTP:%s, HTTPS:%s)\n", config.ChatmailHTTPPort, config.ChatmailHTTPSPort)
		} else {
			fmt.Printf("     Chatmail: disabled\n")
		}
		fmt.Printf("     Permissions: 644\n")
		return nil
	}

	fmt.Printf("   Generating: %s\n", configPath)
	fmt.Printf("     Domain: %s\n", config.PrimaryDomain)
	fmt.Printf("     Hostname: %s\n", config.Hostname)
	fmt.Printf("     State directory: %s\n", config.StateDir)
	if config.EnableChatmail {
		fmt.Printf("     Chatmail: enabled (HTTP:%s, HTTPS:%s)\n", config.ChatmailHTTPPort, config.ChatmailHTTPSPort)
	} else {
		fmt.Printf("     Chatmail: disabled\n")
	}
	fmt.Printf("     Permissions: 644\n")

	// Execute template
	tmpl, err := template.New("maddy.conf").Parse(maddyConfigTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse config template: %v", err)
	}

	file, err := os.Create(configPath)
	if err != nil {
		return fmt.Errorf("failed to create config file: %v", err)
	}
	defer file.Close()

	if err := tmpl.Execute(file, config); err != nil {
		return fmt.Errorf("failed to execute config template: %v", err)
	}

	// Set permissions
	if err := os.Chmod(configPath, 0644); err != nil {
		return fmt.Errorf("failed to set permissions for config file: %v", err)
	}

	fmt.Printf("     ✓ Configuration file created successfully\n")
	logger.Printf("Successfully created configuration file %s with permissions 644", configPath)
	logger.Printf("Configuration includes: hostname=%s, domain=%s, state_dir=%s",
		config.Hostname, config.PrimaryDomain, config.StateDir)
	if config.EnableChatmail {
		logger.Printf("Chatmail enabled on HTTP:%s, HTTPS:%s", config.ChatmailHTTPPort, config.ChatmailHTTPSPort)
	}

	return nil
}

func setupPermissions(config *InstallConfig, dryRun bool) error {
	logger.Println("Setting up permissions")

	if dryRun {
		fmt.Printf("   Would set up file permissions for: %s\n", config.StateDir)
		fmt.Printf("     Owner: %s:%s (recursive)\n", config.MaddyUser, config.MaddyGroup)
		return nil
	}

	fmt.Printf("   Setting up permissions for: %s\n", config.StateDir)
	fmt.Printf("     Owner: %s:%s (recursive)\n", config.MaddyUser, config.MaddyGroup)

	// Set state directory ownership
	maddyUser, err := user.Lookup(config.MaddyUser)
	if err != nil {
		return fmt.Errorf("failed to lookup maddy user: %v", err)
	}

	uid, _ := strconv.Atoi(maddyUser.Uid)
	gid, _ := strconv.Atoi(maddyUser.Gid)

	// Count files for progress indication
	fileCount := 0
	if err := filepath.WalkDir(config.StateDir, func(path string, d fs.DirEntry, err error) error {
		if err == nil {
			fileCount++
		}
		return nil
	}); err != nil {
		return fmt.Errorf("failed to count files in state directory: %v", err)
	}

	fmt.Printf("     Processing %d files and directories...\n", fileCount)

	// Set ownership for state directory and its contents
	processedCount := 0
	if err := filepath.WalkDir(config.StateDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		processedCount++
		if processedCount%10 == 0 || processedCount == fileCount {
			fmt.Printf("     ✓ Processed %d/%d items\n", processedCount, fileCount)
		}
		return os.Chown(path, uid, gid)
	}); err != nil {
		return fmt.Errorf("failed to set ownership for state directory: %v", err)
	}

	fmt.Printf("     ✓ Permissions set successfully\n")

	return nil
}

func installBinary(config *InstallConfig, dryRun bool) error {
	logger.Printf("Installing binary to %s (permissions: 755)", config.BinaryPath)

	if dryRun {
		fmt.Printf("   Would install binary to: %s\n", config.BinaryPath)
		fmt.Printf("     Permissions: 755 (executable)\n")
		return nil
	}

	// Get current executable path
	currentBinary, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get current binary path: %v", err)
	}

	fmt.Printf("   Installing binary: %s\n", config.BinaryPath)
	fmt.Printf("     Source: %s\n", currentBinary)
	fmt.Printf("     Permissions: 755 (executable)\n")

	// Copy binary to target location
	sourceFile, err := os.Open(currentBinary)
	if err != nil {
		return fmt.Errorf("failed to open source binary: %v", err)
	}
	defer sourceFile.Close()

	// Create destination directory if it doesn't exist
	destDir := filepath.Dir(config.BinaryPath)
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return fmt.Errorf("failed to create binary directory: %v", err)
	}

	destFile, err := os.Create(config.BinaryPath)
	if err != nil {
		return fmt.Errorf("failed to create destination binary: %v", err)
	}
	defer destFile.Close()

	// Copy file contents
	if _, err := destFile.ReadFrom(sourceFile); err != nil {
		return fmt.Errorf("failed to copy binary: %v", err)
	}

	// Set executable permissions
	if err := os.Chmod(config.BinaryPath, 0755); err != nil {
		return fmt.Errorf("failed to set binary permissions: %v", err)
	}

	fmt.Printf("     ✓ Binary installed successfully\n")
	logger.Printf("Successfully installed binary from %s to %s with permissions 755", currentBinary, config.BinaryPath)

	return nil
}

// DNS Configuration Functions
func configureDNS(config *InstallConfig, dryRun bool) error {
	fmt.Printf("This step will help you configure DNS records for your mail server.\n")
	fmt.Printf("You will need to add DNS records to your domain registrar or DNS provider.\n\n")

	// Generate DKIM key and STS ID
	if err := prepareDNSData(config, dryRun); err != nil {
		return fmt.Errorf("failed to prepare DNS data: %v", err)
	}

	// Generate zone file
	zoneContent, err := generateDNSZoneFile(config)
	if err != nil {
		return fmt.Errorf("failed to generate DNS zone file: %v", err)
	}

	// Display zone file
	fmt.Printf("📄 Generated DNS Zone File for %s:\n", config.PrimaryDomain)
	fmt.Println("=" + strings.Repeat("=", len(config.PrimaryDomain)+30))
	fmt.Print(zoneContent)
	fmt.Println("=" + strings.Repeat("=", len(config.PrimaryDomain)+30))

	if dryRun {
		fmt.Printf("(Dry run mode - DNS verification skipped)\n")
		return nil
	}

	// Save zone file
	zoneFilePath := filepath.Join(config.ConfigDir, fmt.Sprintf("%s.zone", config.PrimaryDomain))
	if err := os.WriteFile(zoneFilePath, []byte(zoneContent), 0644); err != nil {
		logger.Printf("Warning: failed to save zone file: %v", err)
		fmt.Printf("⚠️  Warning: Could not save zone file to %s\n", zoneFilePath)
	} else {
		fmt.Printf("💾 Zone file saved to: %s\n", zoneFilePath)
	}

	// Interactive DNS setup
	fmt.Printf("\nNow you need to add these DNS records to your DNS provider (e.g., Cloudflare).\n")
	fmt.Printf("The zone file above is formatted for easy import into most DNS providers.\n")
	fmt.Printf("\n⚠️  IMPORTANT for Cloudflare users: Make sure to disable the proxy (set to 'DNS only')\n")
	fmt.Printf("   for all mail-related records (A, MX, and subdomains like mta-sts) to avoid\n")
	fmt.Printf("   mail delivery issues. Only the main domain and www can use the proxy.\n\n")

	for {
		fmt.Printf("Please choose an option:\n")
		fmt.Printf("1. I have added the DNS records and want to verify them\n")
		fmt.Printf("2. Skip DNS verification for now (I'll do it later)\n")
		fmt.Printf("3. Show the DNS records again\n")

		choice := promptString("Enter your choice (1-3)", "2")

		switch choice {
		case "1":
			fmt.Printf("\n🔍 Verifying DNS records...\n")
			if err := verifyDNSRecords(config); err != nil {
				fmt.Printf("❌ DNS verification failed: %v\n", err)
				fmt.Printf("Please check your DNS records and try again.\n\n")
				continue
			} else {
				fmt.Printf("✅ All required DNS records verified successfully!\n")
				return nil
			}
		case "2":
			fmt.Printf("⏭️  Skipping DNS verification. Remember to add the DNS records later.\n")
			return nil
		case "3":
			fmt.Printf("\n📄 DNS Zone File for %s:\n", config.PrimaryDomain)
			fmt.Println("=" + strings.Repeat("=", len(config.PrimaryDomain)+25))
			fmt.Print(zoneContent)
			fmt.Println("=" + strings.Repeat("=", len(config.PrimaryDomain)+25))
			continue
		default:
			fmt.Printf("Invalid choice. Please enter 1, 2, or 3.\n")
			continue
		}
	}
}

func prepareDNSData(config *InstallConfig, dryRun bool) error {
	// Generate STS ID if not set
	if config.STS_ID == "" {
		config.STS_ID = time.Now().Format("20060102150405")
	}

	// Check for existing DKIM keys generated by maddy
	dkimKeyPath := filepath.Join(config.StateDir, "dkim_keys", fmt.Sprintf("%s_default.key", config.PrimaryDomain))
	dkimDNSPath := filepath.Join(config.StateDir, "dkim_keys", fmt.Sprintf("%s_default.dns", config.PrimaryDomain))

	if dryRun {
		fmt.Printf("   Would check for DKIM key at: %s\n", dkimKeyPath)
		fmt.Printf("   Would check for DKIM DNS record at: %s\n", dkimDNSPath)
		config.DKIM_Entry = fmt.Sprintf("default._domainkey.%s.    300   TXT \"v=DKIM1; k=rsa; p=[will-be-generated-by-maddy]\"", config.PrimaryDomain)
		return nil
	}

	// Check if DKIM key and DNS record exist (generated by maddy)
	if _, err := os.Stat(dkimDNSPath); err == nil {
		// Read the DNS record directly from maddy's generated file
		dnsContent, err := os.ReadFile(dkimDNSPath)
		if err != nil {
			return fmt.Errorf("failed to read DKIM DNS file: %v", err)
		}
		config.DKIM_Entry = fmt.Sprintf("default._domainkey.%s.    300   TXT \"%s\"", config.PrimaryDomain, strings.TrimSpace(string(dnsContent)))
		fmt.Printf("   Using existing DKIM DNS record from: %s\n", dkimDNSPath)
	} else if _, err := os.Stat(dkimKeyPath); err == nil {
		// Key exists but no DNS file - generate DNS record from private key
		fmt.Printf("   DKIM key exists, generating DNS record...\n")
		if err := generateDKIMDNSRecord(dkimKeyPath, dkimDNSPath); err != nil {
			return fmt.Errorf("failed to generate DKIM DNS record: %v", err)
		}
		dnsContent, err := os.ReadFile(dkimDNSPath)
		if err != nil {
			return fmt.Errorf("failed to read generated DKIM DNS file: %v", err)
		}
		config.DKIM_Entry = fmt.Sprintf("default._domainkey.%s.    300   TXT \"%s\"", config.PrimaryDomain, strings.TrimSpace(string(dnsContent)))
	} else {
		// No DKIM key exists - generate new key and DNS record
		fmt.Printf("   Generating new DKIM key and DNS record...\n")
		if err := generateDKIMKeyPair(dkimKeyPath, dkimDNSPath, config.MaddyUser); err != nil {
			return fmt.Errorf("failed to generate DKIM key pair: %v", err)
		}
		dnsContent, err := os.ReadFile(dkimDNSPath)
		if err != nil {
			return fmt.Errorf("failed to read generated DKIM DNS file: %v", err)
		}
		config.DKIM_Entry = fmt.Sprintf("default._domainkey.%s.    300   TXT \"%s\"", config.PrimaryDomain, strings.TrimSpace(string(dnsContent)))
	}

	return nil
}

func generateDKIMKeyPair(keyPath, dnsPath, maddyUser string) error {
	fmt.Printf("     Generating new RSA 2048 DKIM key pair...\n")

	// Create directory if needed (matching maddy's internal logic)
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o777); err != nil {
		return fmt.Errorf("failed to create DKIM keys directory: %v", err)
	}

	// Generate RSA 2048 private key
	pkey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate RSA key: %v", err)
	}

	// Marshal private key to PKCS#8 format
	keyBlob, err := x509.MarshalPKCS8PrivateKey(pkey)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %v", err)
	}

	// Create private key file with proper permissions
	f, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("failed to create private key file: %v", err)
	}
	defer f.Close()

	// Write PEM-encoded private key
	if err := pem.Encode(f, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBlob,
	}); err != nil {
		return fmt.Errorf("failed to write private key: %v", err)
	}

	// Generate DNS record
	if err := generateDKIMDNSRecord(keyPath, dnsPath); err != nil {
		return fmt.Errorf("failed to generate DNS record: %v", err)
	}

	// Set proper ownership for both files
	maddyUserInfo, err := user.Lookup(maddyUser)
	if err != nil {
		return fmt.Errorf("failed to lookup maddy user: %v", err)
	}

	uid, _ := strconv.Atoi(maddyUserInfo.Uid)
	gid, _ := strconv.Atoi(maddyUserInfo.Gid)

	if err := os.Chown(keyPath, uid, gid); err != nil {
		return fmt.Errorf("failed to set ownership for DKIM key: %v", err)
	}

	if err := os.Chown(dnsPath, uid, gid); err != nil {
		return fmt.Errorf("failed to set ownership for DKIM DNS file: %v", err)
	}

	fmt.Printf("     ✓ DKIM key generated: %s\n", keyPath)
	fmt.Printf("     ✓ DKIM DNS record generated: %s\n", dnsPath)
	return nil
}

func generateDKIMDNSRecord(keyPath, dnsPath string) error {
	// Load private key
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("failed to read private key: %v", err)
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		return fmt.Errorf("invalid PEM block in key file")
	}

	var pkey crypto.Signer
	switch block.Type {
	case "PRIVATE KEY": // PKCS#8
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse PKCS8 private key: %v", err)
		}
		var ok bool
		pkey, ok = key.(crypto.Signer)
		if !ok {
			return fmt.Errorf("key is not a signer")
		}
	case "RSA PRIVATE KEY": // PKCS#1
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse PKCS1 private key: %v", err)
		}
		pkey = key
	default:
		return fmt.Errorf("unsupported key type: %s", block.Type)
	}

	// Extract public key and determine algorithm
	var keyBlob []byte
	var dkimAlgoName string
	pubkey := pkey.Public()

	switch pubkey := pubkey.(type) {
	case *rsa.PublicKey:
		dkimAlgoName = "rsa"
		keyBlob, err = x509.MarshalPKIXPublicKey(pubkey)
		if err != nil {
			return fmt.Errorf("failed to marshal RSA public key: %v", err)
		}
	case ed25519.PublicKey:
		dkimAlgoName = "ed25519"
		keyBlob = pubkey
	default:
		return fmt.Errorf("unsupported public key type: %T", pubkey)
	}

	// Create DNS record content (matching maddy's internal format)
	keyRecord := fmt.Sprintf("v=DKIM1; k=%s; p=%s", dkimAlgoName, base64.StdEncoding.EncodeToString(keyBlob))

	// Write DNS record file
	dnsFile, err := os.Create(dnsPath)
	if err != nil {
		return fmt.Errorf("failed to create DNS record file: %v", err)
	}
	defer dnsFile.Close()

	if _, err := io.WriteString(dnsFile, keyRecord); err != nil {
		return fmt.Errorf("failed to write DNS record: %v", err)
	}

	return nil
}

func generateDNSZoneFile(config *InstallConfig) (string, error) {
	// Auto-detect server IP
	if config.A == "" {
		if ip, err := getPublicIPv4(); err == nil {
			config.A = ip
		}
	}
	if config.AAAA == "" {
		if ip, err := getPublicIPv6(); err == nil {
			config.AAAA = ip
		}
	}

	tmpl, err := template.New("zone").Parse(dnsZoneTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse DNS zone template: %v", err)
	}

	var buf strings.Builder
	if err := tmpl.Execute(&buf, config); err != nil {
		return "", fmt.Errorf("failed to execute DNS zone template: %v", err)
	}

	return buf.String(), nil
}

func getPublicIPv4() (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil {
					return ipnet.IP.String(), nil
				}
			}
		}
	}
	return "", fmt.Errorf("no public IPv4 address found")
}

func getPublicIPv6() (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() == nil && ipnet.IP.To16() != nil {
					return ipnet.IP.String(), nil
				}
			}
		}
	}
	return "", fmt.Errorf("no public IPv6 address found")
}

func verifyDNSRecords(config *InstallConfig) error {
	requiredRecords := []struct {
		name        string
		recordType  string
		expected    string
		description string
	}{
		{config.PrimaryDomain, "MX", config.Hostname, "MX record"},
		{fmt.Sprintf("_mta-sts.%s", config.PrimaryDomain), "TXT", fmt.Sprintf("v=STSv1; id=%s", config.STS_ID), "MTA-STS policy"},
		{fmt.Sprintf("mta-sts.%s", config.PrimaryDomain), "CNAME", config.PrimaryDomain, "MTA-STS CNAME"},
		{config.PrimaryDomain, "TXT", "v=spf1 mx ~all", "SPF record"},
		{fmt.Sprintf("_dmarc.%s", config.PrimaryDomain), "TXT", "v=DMARC1;p=reject;adkim=s;aspf=s", "DMARC policy"},
	}

	if config.A != "" {
		requiredRecords = append(requiredRecords, struct {
			name        string
			recordType  string
			expected    string
			description string
		}{config.PrimaryDomain, "A", config.A, "A record"})
	}

	errors := []string{}
	verified := 0

	for _, record := range requiredRecords {
		fmt.Printf("   Checking %s (%s)...", record.description, record.recordType)

		if err := verifyDNSRecord(record.name, record.recordType, record.expected); err != nil {
			fmt.Printf(" ❌\n")
			errors = append(errors, fmt.Sprintf("%s: %v", record.description, err))
		} else {
			fmt.Printf(" ✅\n")
			verified++
		}
	}

	fmt.Printf("\nVerification Summary: %d/%d records verified\n", verified, len(requiredRecords))

	if len(errors) > 0 {
		fmt.Printf("\nMissing or incorrect DNS records:\n")
		for _, err := range errors {
			fmt.Printf("   • %s\n", err)
		}
		return fmt.Errorf("%d DNS records failed verification", len(errors))
	}

	return nil
}

func verifyDNSRecord(name, recordType, expected string) error {
	switch recordType {
	case "A":
		ips, err := net.LookupIP(name)
		if err != nil {
			return fmt.Errorf("lookup failed: %v", err)
		}
		for _, ip := range ips {
			if ip.To4() != nil && ip.String() == expected {
				return nil
			}
		}
		return fmt.Errorf("expected A record %s, but not found", expected)

	case "AAAA":
		ips, err := net.LookupIP(name)
		if err != nil {
			return fmt.Errorf("lookup failed: %v", err)
		}
		for _, ip := range ips {
			if ip.To4() == nil && ip.String() == expected {
				return nil
			}
		}
		return fmt.Errorf("expected AAAA record %s, but not found", expected)

	case "MX":
		mxRecords, err := net.LookupMX(name)
		if err != nil {
			return fmt.Errorf("lookup failed: %v", err)
		}
		for _, mx := range mxRecords {
			if strings.TrimSuffix(mx.Host, ".") == strings.TrimSuffix(expected, ".") {
				return nil
			}
		}
		return fmt.Errorf("expected MX record %s, but not found", expected)

	case "TXT":
		txtRecords, err := net.LookupTXT(name)
		if err != nil {
			return fmt.Errorf("lookup failed: %v", err)
		}

		// For TXT records, we do a partial match since formatting can vary
		expectedLower := strings.ToLower(strings.ReplaceAll(expected, " ", ""))
		for _, txt := range txtRecords {
			txtLower := strings.ToLower(strings.ReplaceAll(txt, " ", ""))
			if strings.Contains(txtLower, expectedLower) || strings.Contains(expectedLower, txtLower) {
				return nil
			}
		}
		return fmt.Errorf("expected TXT record containing %s, but not found", expected)

	case "CNAME":
		cname, err := net.LookupCNAME(name)
		if err != nil {
			return fmt.Errorf("lookup failed: %v", err)
		}
		if strings.TrimSuffix(cname, ".") == strings.TrimSuffix(expected+".", ".") {
			return nil
		}
		return fmt.Errorf("expected CNAME %s, got %s", expected, cname)

	default:
		return fmt.Errorf("unsupported record type: %s", recordType)
	}
}

func printNextSteps(config *InstallConfig) {
	// Print installation summary first
	printInstallationSummary(config)

	fmt.Println("\n📋 Next Steps")
	fmt.Println("=============")

	fmt.Printf("1. Configure DNS records for %s:\n", config.PrimaryDomain)

	zoneFilePath := filepath.Join(config.ConfigDir, fmt.Sprintf("%s.zone", config.PrimaryDomain))
	if _, err := os.Stat(zoneFilePath); err == nil {
		fmt.Printf("   📄 DNS zone file available at: %s\n", zoneFilePath)
		fmt.Printf("   Import this file into your DNS provider (e.g., Cloudflare)\n")
		fmt.Printf("   ⚠️  For Cloudflare: Disable proxy (set to 'DNS only') for mail records!\n")
		fmt.Printf("   Or manually add the following records:\n")
	} else {
		fmt.Printf("   Add the following DNS records at your DNS provider:\n")
		fmt.Printf("   ⚠️  For Cloudflare: Disable proxy (set to 'DNS only') for mail records!\n")
	}

	fmt.Printf("   - A record: %s → [your-server-ip]\n", config.PrimaryDomain)
	fmt.Printf("   - MX record: %s → %s\n", config.PrimaryDomain, config.Hostname)
	fmt.Printf("   - TXT record (SPF): %s → \"v=spf1 mx ~all\"\n", config.PrimaryDomain)
	fmt.Printf("   - TXT record (DMARC): _dmarc.%s → \"v=DMARC1; p=reject; adkim=s; aspf=s\"\n", config.PrimaryDomain)
	if config.STS_ID != "" {
		fmt.Printf("   - TXT record (MTA-STS): _mta-sts.%s → \"v=STSv1; id=%s\"\n", config.PrimaryDomain, config.STS_ID)
		fmt.Printf("   - CNAME record: mta-sts.%s → %s\n", config.PrimaryDomain, config.PrimaryDomain)
	}
	if config.DKIM_Entry != "" {
		fmt.Printf("   - DKIM record: %s\n", strings.SplitN(config.DKIM_Entry, "TXT", 2)[0]+"→ [DKIM public key]")
	}

	fmt.Printf("\n2. Set up TLS certificates:\n")
	fmt.Printf("   - Place certificate at: %s\n", config.TLSCertPath)
	fmt.Printf("   - Place private key at: %s\n", config.TLSKeyPath)
	fmt.Printf("   - Make certificates readable by maddy user:\n")
	fmt.Printf("     sudo setfacl -R -m u:%s:rX %s %s\n",
		config.MaddyUser, config.TLSCertPath, config.TLSKeyPath)

	fmt.Printf("\n3. Create first user account:\n")
	fmt.Printf("   sudo %s --config %s/maddy.conf creds create postmaster@%s\n",
		config.BinaryPath, config.ConfigDir, config.PrimaryDomain)
	fmt.Printf("   sudo %s --config %s/maddy.conf imap-acct create postmaster@%s\n",
		config.BinaryPath, config.ConfigDir, config.PrimaryDomain)

	fmt.Printf("\n4. Test configuration (optional):\n")
	fmt.Printf("   sudo %s --config %s/maddy.conf run --libexec %s\n",
		config.BinaryPath, config.ConfigDir, config.LibexecDir)
	fmt.Printf("   (Press Ctrl+C to stop test run)\n")

	fmt.Printf("\n5. Start maddy service:\n")
	fmt.Printf("   sudo systemctl enable maddy\n")
	fmt.Printf("   sudo systemctl start maddy\n")

	fmt.Printf("\n6. Check service status:\n")
	fmt.Printf("   sudo systemctl status maddy\n")
	fmt.Printf("   sudo journalctl -u maddy -f\n")

	if config.EnableChatmail {
		fmt.Printf("\n7. Chatmail is enabled:\n")
		fmt.Printf("   - HTTP endpoint: http://%s:%s\n", config.Hostname, config.ChatmailHTTPPort)
		fmt.Printf("   - HTTPS endpoint: https://%s:%s (if configured)\n", config.Hostname, config.ChatmailHTTPSPort)
	}

	fmt.Printf("\n📖 Documentation: https://maddy.email\n")
	fmt.Printf("📄 Configuration file: %s/maddy.conf\n", config.ConfigDir)
	fmt.Printf("📄 Installation log: %s\n", config.LogFile)
}

func printInstallationSummary(config *InstallConfig) {
	fmt.Println("\n📊 Installation Summary")
	fmt.Println("=======================")

	// Users and Groups Created
	fmt.Printf("👤 Users and Groups Created:\n")
	fmt.Printf("   - User: %s (UID: auto-assigned)\n", config.MaddyUser)
	fmt.Printf("   - Group: %s (GID: auto-assigned)\n", config.MaddyGroup)
	fmt.Printf("   - Home Directory: %s\n", config.StateDir)
	fmt.Printf("   - Shell: /sbin/nologin (no login access)\n")

	// Directories Created
	fmt.Printf("\n📁 Directories Created:\n")
	fmt.Printf("   - %s (owner: %s, permissions: 755)\n", config.StateDir, config.MaddyUser)
	fmt.Printf("   - %s (owner: root, permissions: 755)\n", config.ConfigDir)
	fmt.Printf("   - %s/certs (owner: root, permissions: 755)\n", config.ConfigDir)
	fmt.Printf("   - %s (owner: root, permissions: 755)\n", filepath.Dir(config.LogFile))

	// Files Created
	fmt.Printf("\n📄 Files Created:\n")
	fmt.Printf("   - %s/maddy.conf (owner: root, permissions: 644)\n", config.ConfigDir)
	fmt.Printf("   - %s/maddy.service (owner: root, permissions: 644)\n", config.SystemdPath)
	fmt.Printf("   - %s/maddy@.service (owner: root, permissions: 644)\n", config.SystemdPath)
	fmt.Printf("   - %s (owner: root, permissions: 755)\n", config.BinaryPath)
	fmt.Printf("   - %s (owner: root, permissions: 644)\n", config.LogFile)

	// Permissions Applied
	fmt.Printf("\n🔐 Permissions Applied:\n")
	fmt.Printf("   - %s and all contents: owner %s:%s\n", config.StateDir, config.MaddyUser, config.MaddyGroup)
	fmt.Printf("   - Configuration files: readable by all, writable by root\n")
	fmt.Printf("   - Binary: executable by all\n")
	fmt.Printf("   - Log file: writable by root\n")
	fmt.Printf("   - Systemd services: standard systemd permissions\n")

	// Network Configuration
	fmt.Printf("\n🌐 Network Ports Configured:\n")
	fmt.Printf("   - SMTP: %s (incoming mail)\n", config.SMTPPort)
	fmt.Printf("   - Submission: %s (outgoing mail)\n", config.SubmissionPort)
	fmt.Printf("   - Submission TLS: %s (secure outgoing mail)\n", config.SubmissionTLS)
	fmt.Printf("   - IMAP: %s (mail access)\n", config.IMAPPort)
	fmt.Printf("   - IMAP TLS: %s (secure mail access)\n", config.IMAPTLS)

	if config.EnableChatmail {
		fmt.Printf("   - Chatmail HTTP: %s (user registration)\n", config.ChatmailHTTPPort)
		fmt.Printf("   - Chatmail HTTPS: %s (secure user registration)\n", config.ChatmailHTTPSPort)
	}

	// System Integration
	fmt.Printf("\n⚙️  System Integration:\n")
	fmt.Printf("   - Systemd daemon reloaded\n")
	fmt.Printf("   - Service available as: systemctl {start|stop|status} maddy\n")
	fmt.Printf("   - Instance service available as: systemctl {start|stop|status} maddy@<config>\n")
	fmt.Printf("   - Binary available system-wide at: %s\n", config.BinaryPath)
	fmt.Printf("   - Service command: %s --config %s/maddy.conf run --libexec %s\n",
		config.BinaryPath, config.ConfigDir, config.LibexecDir)

	// Database and Storage
	fmt.Printf("\n💾 Database and Storage:\n")
	fmt.Printf("   - SQLite databases will be created in: %s\n", config.StateDir)
	fmt.Printf("   - credentials.db (user authentication)\n")
	fmt.Printf("   - imapsql.db (IMAP mail storage)\n")
	fmt.Printf("   - Message storage: %s/messages/\n", config.StateDir)
	fmt.Printf("   - DKIM keys: %s/dkim_keys/\n", config.StateDir)
	fmt.Printf("   - MTA-STS cache: %s/mtasts_cache/\n", config.StateDir)

	// Security Features
	fmt.Printf("\n🔒 Security Features Enabled:\n")
	fmt.Printf("   - Systemd sandboxing (PrivateTmp, ProtectSystem, etc.)\n")
	fmt.Printf("   - Non-root execution (runs as %s user)\n", config.MaddyUser)
	fmt.Printf("   - Capability dropping (only CAP_NET_BIND_SERVICE)\n")
	fmt.Printf("   - File permissions restricted (umask 0007)\n")
	fmt.Printf("   - Resource limits applied (FD: 131072, Processes: 512)\n")

	if config.EnableChatmail {
		fmt.Printf("\n💬 Chatmail Features:\n")
		fmt.Printf("   - Automatic user registration enabled\n")
		fmt.Printf("   - Username length: %d characters\n", config.ChatmailUsernameLen)
		fmt.Printf("   - Password length: %d characters\n", config.ChatmailPasswordLen)
		fmt.Printf("   - Only auto-generated usernames allowed\n")
	}
}

// Embedded templates
const systemdServiceTemplate = `[Unit]
Description=maddy mail server
Documentation=man:maddy(1)
Documentation=man:maddy.conf(5)
Documentation=https://maddy.email
After=network-online.target

[Service]
Type=notify
NotifyAccess=main

User={{.MaddyUser}}
Group={{.MaddyGroup}}

# cd to state directory to make sure any relative paths
# in config will be relative to it unless handled specially.
WorkingDirectory={{.StateDir}}

ConfigurationDirectory=maddy
RuntimeDirectory=maddy
StateDirectory=maddy
LogsDirectory=maddy
ReadOnlyPaths=/usr/lib/maddy
ReadWritePaths={{.StateDir}}

# Strict sandboxing. You have no reason to trust code written by strangers from GitHub.
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ProtectKernelTunables=true
ProtectHostname=true
ProtectClock=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6

# Additional sandboxing. You need to disable all of these options
# for privileged helper binaries (for system auth) to work correctly.
NoNewPrivileges=true
PrivateDevices=true
DeviceAllow=/dev/syslog
RestrictSUIDSGID=true
ProtectKernelModules=true
MemoryDenyWriteExecute=true
RestrictNamespaces=true
RestrictRealtime=true
LockPersonality=true

# Graceful shutdown with a reasonable timeout.
TimeoutStopSec=7s
KillMode=mixed
KillSignal=SIGTERM

# Required to bind on ports lower than 1024.
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

# Force all files created by maddy to be only readable by it
# and maddy group.
UMask=0007

# Bump FD limitations. Even idle mail server can have a lot of FDs open (think
# of idle IMAP connections, especially ones abandoned on the other end and
# slowly timing out).
LimitNOFILE=131072

# Limit processes count to something reasonable to
# prevent resources exhausting due to big amounts of helper
# processes launched.
LimitNPROC=512

# Restart server on any problem.
Restart=on-failure
# ... Unless it is a configuration problem.
RestartPreventExitStatus=2

ExecStart={{.BinaryPath}} --config {{.ConfigDir}}/maddy.conf run --libexec {{.LibexecDir}}

ExecReload=/bin/kill -USR1 $MAINPID
ExecReload=/bin/kill -USR2 $MAINPID

[Install]
WantedBy=multi-user.target
`

const systemdInstanceTemplate = `[Unit]
Description=maddy mail server (using %i.conf)
Documentation=man:maddy(1)
Documentation=man:maddy.conf(5)
Documentation=https://maddy.email
After=network-online.target

[Service]
Type=notify
NotifyAccess=main

User={{.MaddyUser}}
Group={{.MaddyGroup}}

ConfigurationDirectory=maddy
RuntimeDirectory=maddy
StateDirectory=maddy
LogsDirectory=maddy
ReadOnlyPaths=/usr/lib/maddy
ReadWritePaths={{.StateDir}}

# Strict sandboxing. You have no reason to trust code written by strangers from GitHub.
PrivateTmp=true
PrivateHome=true
ProtectSystem=strict
ProtectKernelTunables=true
ProtectHostname=true
ProtectClock=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
DeviceAllow=/dev/syslog

# Additional sandboxing. You need to disable all of these options
# for privileged helper binaries (for system auth) to work correctly.
NoNewPrivileges=true
PrivateDevices=true
RestrictSUIDSGID=true
ProtectKernelModules=true
MemoryDenyWriteExecute=true
RestrictNamespaces=true
RestrictRealtime=true
LockPersonality=true

# Graceful shutdown with a reasonable timeout.
TimeoutStopSec=7s
KillMode=mixed
KillSignal=SIGTERM

# Required to bind on ports lower than 1024.
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

# Force all files created by maddy to be only readable by it and
# maddy group.
UMask=0007

# Bump FD limitations. Even idle mail server can have a lot of FDs open (think
# of idle IMAP connections, especially ones abandoned on the other end and
# slowly timing out).
LimitNOFILE=131072

# Limit processes count to something reasonable to
# prevent resources exhausting due to big amounts of helper
# processes launched.
LimitNPROC=512

# Restart server on any problem.
Restart=on-failure
# ... Unless it is a configuration problem.
RestartPreventExitStatus=2

ExecStart={{.BinaryPath}} --config {{.ConfigDir}}/%i.conf run --libexec {{.LibexecDir}}

ExecReload=/bin/kill -USR1 $MAINPID
ExecReload=/bin/kill -USR2 $MAINPID

[Install]
WantedBy=multi-user.target
`
