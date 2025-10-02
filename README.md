# Maddy Chatmail Server
> Optimized all-in-one mail server for instant, secure messaging

This is a specialized fork of [Maddy Mail Server](https://github.com/foxcpp/maddy) optimized specifically for **chatmail** deployments. It provides a single binary solution for running secure, encrypted-only email servers designed for Delta Chat and similar messaging applications.

## What is Chatmail?

Chatmail servers are email servers optimized for secure messaging rather than traditional email. They prioritize:
- **Instant account creation** without personal information
- **Encryption-only messaging** to ensure privacy
- **Automatic cleanup** to minimize data retention
- **Low maintenance** for easy deployment

## Key Features

### ✅ Implemented
- **Passwordless onboarding**: Users can create accounts instantly via QR codes
- **Encrypted messages only (outbound)**: Prevents sending unencrypted messages to external recipients
- **Single binary deployment**: Everything needed in one executable
- **Delta Chat integration**: Native support for Delta Chat account creation
- **Web interface**: Simple account creation and management interface

### 🚧 Planned Features
- **Encrypted messages only (inbound)**: Filter incoming unencrypted messages
- **Automatic message cleanup**: Remove messages unconditionally after N days (currently 20 days)
- **Stale account cleanup**: Remove inactive addresses after M days without login
- **Push notifications**: Metadata support for real-time messaging
- **Enhanced monitoring**: Better observability for chatmail-specific metrics

## Live Example

See a working deployment at: **[inja.bid](https://inja.bid)**

This demonstrates the complete chatmail experience including:
- Instant account creation via QR code
- Web interface for account management
- Full Delta Chat integration

## Quick Start

### Docker Compose with Caddy Reverse Proxy

The easiest way to get started with automatic SSL management is using Docker Compose with Caddy as a reverse proxy. This setup handles SSL certificates automatically and proxies requests to Maddy Chatmail.

First, create a `Caddyfile`:

```
yourdomain.com, mail.yourdomain.com {
  # Proxy both the main and mail subdomain to the chatmail web endpoint
  reverse_proxy maddy-chatmail:8080
}
```

Then, create a `docker-compose.yml` file:

```yaml

services:
  caddy:
    image: caddy:latest
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile
      - caddy_data:/data
      - caddy_config:/config
    restart: unless-stopped

  maddy-chatmail:
    image: ghcr.io/sadraiiali/maddy_chatmail:latest
    environment:
      # MADDY_HOSTNAME: hostname used for SMTP/IMAP MX and TLS
      - MADDY_HOSTNAME=mail.yourdomain.com
      # MADDY_DOMAIN: primary domain served by this instance
      - MADDY_DOMAIN=yourdomain.com
    volumes:
      - maddy-data:/data
      - ./maddy.conf:/data/maddy.conf:ro  # put a custom maddy.conf here (chatmail endpoint on port 8080)
    depends_on:
      - caddy
    restart: unless-stopped

volumes:
  maddy-data:
  caddy_data:
  caddy_config:
```

Create a custom `maddy.conf` based on the setup guide, but change the chatmail endpoints to use port 8080:

```maddy
# ... (same as setup guide but modify chatmail endpoints)

# Chatmail endpoint for user registration
chatmail tcp://0.0.0.0:8080 {
    mail_domain $(primary_domain)
    mx_domain $(hostname)
    web_domain $(primary_domain)
    auth_db local_authdb
    storage local_mailboxes
}
```

Run it with:

```bash
docker-compose up -d
```

Caddy will automatically obtain SSL certificates for your domain and proxy requests to Maddy Chatmail.

### Notes

- Make sure DNS A/AAAA records for `yourdomain.com` and `mail.yourdomain.com` point to the server running Caddy.
- Open ports 80 and 443 on the host so Caddy can perform ACME challenges and serve TLS.
- The example expects the chatmail HTTP endpoint to listen on port 8080 inside the `maddy-chatmail` container (see the `chatmail` endpoint example below).

For detailed setup instructions including manual installation, TLS certificates, and DNS configuration, see the [Setup Guide](docs/chatmail-setup.md).

## Releases & Downloads

Pre-built release artifacts for common platforms are published on the repository's GitHub Releases page. Each release includes signed archives for the following targets (when available):
- linux (amd64, arm64)
- macOS (amd64, arm64)
- windows (amd64, arm64)

To download the latest release, visit: https://github.com/sadraiiali/maddy_chatmail/releases and pick the artifact matching your OS/architecture. Artifacts are packaged as tar.gz (Linux/macOS) or zip (Windows) and include a `maddy` binary and the default `maddy.conf`.

If you prefer to build locally, see the "Building from source" tutorial in the docs (it also documents how to use the releases and how to embed version information): docs/tutorials/building-from-source.md

## Configuration Differences from Standard Maddy

This chatmail-optimized version includes:

1. **Simplified Configuration**: Pre-configured for chatmail use cases
2. **Chatmail Endpoint**: Built-in HTTP/HTTPS endpoints for account creation
3. **Encryption Enforcement**: Automatic blocking of unencrypted outbound messages
4. **Account Management**: Streamlined user creation and cleanup processes
5. **Delta Chat Integration**: Native QR code generation and account provisioning

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Web Interface │    │   SMTP/IMAP      │    │   Delta Chat    │
│   (QR Codes)    │◄──►│   Mail Server    │◄──►│   Clients       │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌──────────────────┐
                    │   SQLite Storage │
                    │   (Accounts &    │
                    │    Messages)     │
                    └──────────────────┘
```

## Contributing

This project maintains compatibility with the upstream Maddy project while adding chatmail-specific optimizations. Contributions should:

1. Maintain backward compatibility with standard Maddy configurations
2. Follow the chatmail specification and best practices
3. Include tests for new chatmail-specific features
4. Update documentation for any user-facing changes

## Upstream Compatibility

This fork periodically syncs with the upstream Maddy project to incorporate security updates and improvements. Chatmail-specific features are implemented as optional modules that don't interfere with standard Maddy functionality.

## License

This project inherits the GPL-3.0 license from the upstream Maddy Mail Server project.

## Links

- **Live Demo**: [inja.bid](https://inja.bid)
- **Upstream Project**: [Maddy Mail Server](https://github.com/foxcpp/maddy)
- **Delta Chat**: [https://delta.chat](https://delta.chat)
- **Chatmail Specification**: [Delta Chat Chatmail Docs](https://github.com/deltachat/chatmail)
- **Documentation**: [Setup Guide](docs/chatmail-setup.md)

---

*For traditional email server needs, consider using the upstream [Maddy Mail Server](https://github.com/foxcpp/maddy) project.*
