# FerroHSM PKCS#11 User Guide

This guide provides instructions on how to use the FerroHSM PKCS#11 interface with various applications and tools.

## Getting Started

### Prerequisites

Before using the PKCS#11 interface, ensure you have:

1. FerroHSM installed and configured
2. The PKCS#11 shared library (`libhsm_pkcs11.so` on Linux, `libhsm_pkcs11.dylib` on macOS)
3. A compatible PKCS#11 application or tool

### Installation

1. Build the PKCS#11 module:
   ```bash
   cargo build -p hsm-pkcs11 --release
   ```

2. Locate the shared library in the target directory:
   ```bash
   find target -name "libhsm_pkcs11.*" -type f
   ```

3. Copy the shared library to a suitable location:
   ```bash
   cp target/release/libhsm_pkcs11.so /usr/local/lib/
   ```

## Configuration

### Environment Variables

The following environment variables can be used to configure the PKCS#11 module:

- `FERRoHSM_CONFIG`: Path to the FerroHSM configuration file
- `FERRoHSM_PKCS11_LOG_LEVEL`: Log level (error, warn, info, debug, trace)
- `SOFTHSM2_CONF`: Path to SoftHSM configuration file (if using SoftHSM)

### Configuration File

Create a configuration file for FerroHSM if one doesn't exist:

```yaml
# ferrohsm.yaml
server:
  host: 127.0.0.1
  port: 8080
  tls:
    enabled: false

storage:
  type: sqlite
  path: /var/lib/ferrohsm/keys.db

logging:
  level: info
  format: json

authentication:
  jwt_secret: "your-jwt-secret-here"
  token_expiry: 3600

audit:
  enabled: true
  path: /var/log/ferrohsm/audit.log
```

## Using with OpenSSL

### Command Line

To use FerroHSM with OpenSSL command line tools:

```bash
# Load the PKCS#11 engine
openssl engine -t dynamic -pre SO_PATH:/usr/local/lib/libhsm_pkcs11.so -pre ID:pkcs11 -pre LOAD

# Generate a key
openssl req -engine pkcs11 -new -keyform engine -key "label=mykey" -out cert.csr

# Sign data
openssl dgst -engine pkcs11 -keyform engine -sign "label=mykey" -out signature.bin data.txt
```

### Configuration File

Create an OpenSSL configuration file to make PKCS#11 easier to use:

```ini
# openssl.conf
openssl_conf = openssl_init

[openssl_init]
engines = engine_section

[engine_section]
pkcs11 = pkcs11_section

[pkcs11_section]
engine_id = pkcs11
dynamic_path = /usr/local/lib/libhsm_pkcs11.so
MODULE_PATH = /usr/local/lib/libhsm_pkcs11.so
init = 0
```

Then use it with:

```bash
OPENSSL_CONF=./openssl.conf openssl engine pkcs11 -t
```

## Using with SSH

### Client Configuration

Add the following to your SSH configuration (`~/.ssh/config`):

```
Host *
    PKCS11Provider /usr/local/lib/libhsm_pkcs11.so
```

### Agent Configuration

To use with ssh-agent:

```bash
# Start ssh-agent
eval $(ssh-agent)

# Add PKCS#11 provider
ssh-add -s /usr/local/lib/libhsm_pkcs11.so
```

### Key Generation

Generate a key that can be used with SSH:

```bash
# This would typically be done through the FerroHSM CLI or API
# and then the public key extracted for SSH use
```

## Using with Web Browsers

### Firefox

1. Open Firefox and navigate to `about:config`
2. Search for `security.pkcs11-modules`
3. Click "Add" and enter the path to the PKCS#11 library
4. Restart Firefox

### Chrome/Chromium

Chrome/Chromium uses the system's NSS database. Configure NSS to use the PKCS#11 module:

```bash
# Add the module to NSS
modutil -add "FerroHSM" -libfile /usr/local/lib/libhsm_pkcs11.so -dbdir sql:$HOME/.pki/nssdb

# List modules to verify
modutil -list -dbdir sql:$HOME/.pki/nssdb
```

## Using with Programming Languages

### Python

Using the `python-pkcs11` library:

```python
import pkcs11

# Load the library
lib = pkcs11.lib('/usr/local/lib/libhsm_pkcs11.so')

# Get available tokens
tokens = lib.get_tokens()

# Open a session with the first token
token = next(tokens)
session = token.open()

# Generate a key
key = session.generate_key(pkcs11.KeyType.AES, 256)

# Encrypt data
iv = session.generate_random(128)
ciphertext = key.encrypt(b'Hello, World!', mechanism_param=iv)

# Decrypt data
plaintext = key.decrypt(ciphertext, mechanism_param=iv)

# Close the session
session.close()
```

### Go

Using the `github.com/miekg/pkcs11` library:

```go
package main

import (
    "fmt"
    "github.com/miekg/pkcs11"
)

func main() {
    // Load the library
    ctx := pkcs11.New("/usr/local/lib/libhsm_pkcs11.so")
    defer ctx.Destroy()
    
    // Initialize the library
    err := ctx.Initialize()
    if err != nil {
        panic(err)
    }
    defer ctx.Finalize()
    
    // Get slot list
    slots, err := ctx.GetSlotList(true)
    if err != nil {
        panic(err)
    }
    
    if len(slots) == 0 {
        panic("No slots available")
    }
    
    // Open session
    session, err := ctx.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION)
    if err != nil {
        panic(err)
    }
    defer ctx.CloseSession(session)
    
    // Login (if required)
    err = ctx.Login(session, pkcs11.CKU_USER, "1234")
    if err != nil {
        panic(err)
    }
    defer ctx.Logout(session)
    
    // Generate random data
    randomData, err := ctx.GenerateRandom(session, 16)
    if err != nil {
        panic(err)
    }
    
    fmt.Printf("Random data: %x\n", randomData)
}
```

### Java

Using the SunPKCS11 provider:

```java
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;

public class PKCS11Example {
    public static void main(String[] args) throws Exception {
        // Configure the PKCS#11 provider
        String config = "--name=FerroHSM\nlibrary=/usr/local/lib/libhsm_pkcs11.so\n";
        
        Provider p = new sun.security.pkcs11.SunPKCS11(new java.io.ByteArrayInputStream(config.getBytes()));
        Security.addProvider(p);
        
        // Load the keystore
        KeyStore ks = KeyStore.getInstance("PKCS11", "SunPKCS11-FerroHSM");
        ks.load(null, "1234".toCharArray());
        
        // List aliases
        java.util.Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            System.out.println("Alias: " + alias);
        }
    }
}
```

## Key Management

### Generating Keys

Keys can be generated using the FerroHSM CLI or through PKCS#11 applications:

```bash
# Using FerroHSM CLI
ferrohsm-cli key generate --algorithm AES-256-GCM --label mykey

# Using pkcs11-tool
pkcs11-tool --module /usr/local/lib/libhsm_pkcs11.so --keypairgen --key-type rsa:2048 --label mykey
```

### Listing Keys

To list available keys:

```bash
# Using pkcs11-tool
pkcs11-tool --module /usr/local/lib/libhsm_pkcs11.so --list-objects
```

### Exporting Public Keys

To export public keys for use with other applications:

```bash
# Using pkcs11-tool
pkcs11-tool --module /usr/local/lib/libhsm_pkcs11.so --read-object --type pubkey --label mykey -o pubkey.der
```

## Cryptographic Operations

### Signing Data

```bash
# Using pkcs11-tool
echo "Hello, World!" | pkcs11-tool --module /usr/local/lib/libhsm_pkcs11.so --sign --label mykey -o signature.bin
```

### Verifying Signatures

```bash
# Using pkcs11-tool
echo "Hello, World!" | pkcs11-tool --module /usr/local/lib/libhsm_pkcs11.so --verify --signature signature.bin --label mykey
```

### Encrypting Data

```bash
# Using pkcs11-tool (for supported mechanisms)
pkcs11-tool --module /usr/local/lib/libhsm_pkcs11.so --encrypt --label mykey -i plaintext.txt -o ciphertext.bin
```

### Decrypting Data

```bash
# Using pkcs11-tool (for supported mechanisms)
pkcs11-tool --module /usr/local/lib/libhsm_pkcs11.so --decrypt --label mykey -i ciphertext.bin -o decrypted.txt
```

## Troubleshooting

### Common Issues

1. **Library not found**: Ensure the PKCS#11 library is in the correct location and has proper permissions.

2. **Slot not found**: Verify that FerroHSM is running and properly configured.

3. **Authentication failed**: Check that the PIN is correct and the user has proper permissions.

4. **Mechanism not supported**: Not all cryptographic mechanisms may be implemented yet.

### Logging

Enable debug logging to troubleshoot issues:

```bash
export FERRoHSM_PKCS11_LOG_LEVEL=debug
```

### Testing

Use `pkcs11-tool` to test basic functionality:

```bash
# Test if the module loads
pkcs11-tool --module /usr/local/lib/libhsm_pkcs11.so --list-slots

# Test token info
pkcs11-tool --module /usr/local/lib/libhsm_pkcs11.so --show-info

# Test random number generation
pkcs11-tool --module /usr/local/lib/libhsm_pkcs11.so --generate-random 16 | hexdump -C
```

## Security Considerations

### Key Storage

- Keys are stored securely within FerroHSM with tamper-evident protection
- Private keys never leave the HSM in plaintext form
- Key material is protected in memory with secure allocation

### Access Control

- Role-based access control limits who can perform operations
- Authentication is required for sensitive operations
- Audit logging tracks all cryptographic operations

### Network Security

- When used in networked mode, TLS encryption protects communications
- Mutual TLS authentication can be enabled for additional security
- Rate limiting prevents abuse of cryptographic services

## Performance

### Caching

The PKCS#11 module implements caching for frequently accessed objects to improve performance.

### Concurrency

Multiple sessions can be opened concurrently to improve throughput for multi-threaded applications.

### Resource Management

Properly close sessions and log out when finished to free up resources:

```c
// Always close sessions
C_CloseSession(hSession);

// Always log out when done
C_Logout(hSession);
```

## Advanced Configuration

### Multiple Tokens

Configure multiple tokens for redundancy or separation of duties:

```yaml
# ferrohsm.yaml
tokens:
  - name: primary
    storage:
      type: sqlite
      path: /var/lib/ferrohsm/primary.db
  - name: backup
    storage:
      type: sqlite
      path: /var/lib/ferrohsm/backup.db
```

### Hardware Integration

For production use, integrate with hardware security modules:

```yaml
# ferrohsm.yaml
hardware:
  type: softhsm
  config: /etc/softhsm/softhsm2.conf
```

## Support

For issues with the PKCS#11 interface, please check:

1. The FerroHSM documentation
2. The PKCS#11 specification
3. The GitHub issues page for FerroHSM
4. Community forums and mailing lists

## Contributing

Contributions to improve the PKCS#11 interface are welcome. Please follow the standard contribution guidelines for the FerroHSM project.