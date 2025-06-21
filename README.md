# JWTK - JWT Toolkit

A comprehensive command-line JWT (JSON Web Token) toolkit that provides decoding, validation, and generation capabilities. JWTK serves as a local alternative to jwt.io with additional features for developers working with JWT tokens.

## Features:
 - Colorized JWT Parsing - Beautiful syntax highlighting for JWT components
 - Token Decoding - Parse and display JWT header, payload, and signature
 - Signature Validation - Verify JWT signatures with HS56 and RS256 algorithms
 - Token Generation - Create new JWT tokens with custom claims
 - Intercative TUI - Terminal User Interface for easy token manipulation
 - File Support - Load secrets and keys from files
 - Expiration Checking - Automatic detection of expired tokens
 - RSA Key Pairs Generation - Create new RSA key pairs in files

---

# Installation

## From AUR Repository

```bash
yay -S jwtk
```

## Build from Source

```bash
# clone source code
git clone https://github.com/Hanashiko/jwtk.git
cd jwtk
# install dependencies and build the binary
go mod tidy && go build -o jwtk
# install globally
sudo mv jwtk /usr/local/bin
```

---

# Usage

## Command Line Interface

### Decode JWT Token

```bash
jwtk decode <token>
```

#### Options: 
 - `-r, --raw`: Show raw JSON output without colors
 - `-s, --secret`: Secret key for signature validation
 - `-k, --keyfile`: Path to key file for signature validation

#### Example:
```bash
jwtk decode eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3NDg5NDczMTcsImlhdCI6MTc0ODk0NzMwNywibmFtZSI6IkpvaG4ifQ.-zBoiK5zu7QCBs-KlX0-DSd8h7ITI2ix0p0HEx6cpDQ

jwtk decode --raw <token>

jwtk decode --secret "your-256-bit-secret" <token>

jwtk decode --keyfile public.pem <token>

jwtk decode
```

### Validate JWT Token

```bash
jwtk validate [token]
```

#### Options:
 - `-s, --secret`: Secret key for validation (for HS256)
 - `-k, --keyfile`: Path to key file for validation (for RS256)

#### Example:
```bash
jwtk validate --secret "your-256-bit-secret" <token>

jwtk validate --keyfile public.pem <token>

jwtk validate
```

### Generate JWT Token

```bash
jwtk generate
```

#### Options:
 - `-a, --algorithm`: Signing algorithm (HS256, RS256) (defalt "HS256")
 - `-s, --secret`: Secret key for HS256
 - `-k, --keyfile`: Path to private key file for RS256
 - `--subject`: Subject claim (sub)
 - `--issuer`: Issuer claim (iss)
 - `--audience`: Audience claim (aud)
 - `--name`: Name claim
 - `--admin`: Admin claim (true/false)
 - `--type`: Token type (access/refresh/etc)
 - `--csrf`: CSRF token value
 - `--fresh`: Fresh token flag (true/false)
 - `--jti`: JWT ID (unique identifier)
 - `--key`: Arbitary key claim (can be used to embed key ID or custom value)
 - `-e, --expires`: Expiration time in seconds from now
 - `-n, --nbf`: Not Before (seconds from now)

#### Example:
```bash
jwtk generate --algorithm HS256 --secret "your-256-bit-secret" --subject "user123" --expires 3600

jwtk generate --algorithm RS256 --keyfile private.pem --issuer "myapp" --audience "api.example.com" --key "12345"

jwtk generate --algorithm HS256 --secret "your-256-bit-secret" --subject "1234567890" --name "John Doe" --admin true --expires 604800

jwtk generate
```

### Generate RSA Key Pair

```bash
jwtk genkeys
```

#### Options:
 - `-o, --outdir`: Output directory for the key pair (default ".")

#### Example:
```bash
jwtk genkeys --outdir ~/keys

jwtk genkeys
```

## Intercative TUI Mode

```bash
jwtk tui
```
This launches an interactive menu-driven interface for all JWTK operations
