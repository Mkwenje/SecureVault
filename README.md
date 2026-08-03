<a id="top"></a>

<div align="center">

# 🔐 SecureVault

**A Java desktop application for multi-factor authenticated file encryption**

SecureVault protects sensitive local files using **AES-256-GCM**, **RSA-OAEP**, **PBKDF2**, **TOTP**, and **MongoDB Atlas**.

**Project status:** Functional academic prototype  
**Programme:** BSc (Hons) in Computing — Cybersecurity  
**Institution:** National College of Ireland

</div>

<!--
Add a screenshot at docs/images/securevault-dashboard.png, then uncomment the line below.

![SecureVault dashboard](docs/images/securevault-dashboard.png)
-->

> [!IMPORTANT]
> SecureVault is an academic cybersecurity prototype. Do not use it as a production security product without additional hardening, automated testing, dependency review, and independent security assessment.

<a id="contents"></a>

## Contents

> Select any item below to jump directly to the beginning of that section.

- [Overview](#overview)
- [Features](#features)
- [How SecureVault Works](#how-securevault-works)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Prerequisites](#prerequisites)
- [MongoDB Atlas Setup](#mongodb-atlas-setup)
- [Configure the Application](#configure-the-application)
- [Run SecureVault](#run-securevault)
- [Using the Application](#using-the-application)
- [MongoDB Data Model](#mongodb-data-model)
- [Project Structure](#project-structure)
- [Security Scope and Limitations](#security-scope-and-limitations)
- [Troubleshooting](#troubleshooting)
- [Author](#author)

<a id="overview"></a>

## Overview

SecureVault is a Java Swing desktop application that protects sensitive local files with multi-factor authentication and hybrid cryptography.

The application uses:

| Security area | Implementation |
|---|---|
| Password storage | PBKDF2WithHmacSHA512 |
| Multi-factor authentication | RFC 6238-compatible TOTP |
| File encryption | AES-256-GCM |
| AES key protection | RSA-2048 OAEP with SHA-256 |
| Database | MongoDB Atlas |
| Desktop interface | Java Swing |
| Build system | Maven |

Encrypted file contents remain on the user's computer. MongoDB Atlas stores user-account information, RSA key material, file paths, timestamps, and the RSA-wrapped AES key required to decrypt each file.


[↑ Back to contents](#contents)

<a id="features"></a>

## Features

- Secure user registration with a unique username
- Password hashing with a random salt and 100,000 PBKDF2 iterations
- TOTP multi-factor authentication using a generated QR code
- Show/hide password controls on registration, login, and password reset
- TOTP-protected forgotten-password reset
- AES-256-GCM encryption with a fresh AES key and IV for every file
- RSA-2048 OAEP wrapping of each AES key
- User-specific encrypted-file records stored in MongoDB Atlas
- Local encrypted file output using the `.sv` extension
- AES-GCM integrity verification during decryption
- Optional deletion of the original file after confirmation
- MongoDB connection validation at startup
- Automatic creation of required MongoDB indexes


[↑ Back to contents](#contents)

<a id="how-securevault-works"></a>

## How SecureVault Works

### Registration and authentication

1. The user creates an account with a unique username and password.
2. SecureVault generates:
   - a random password salt;
   - a PBKDF2 password hash;
   - a TOTP secret; and
   - an RSA public/private key pair.
3. The application displays a QR code.
4. The user scans the QR code with an RFC 6238-compatible authenticator application.
5. Future logins require:
   - the username;
   - the account password; and
   - the current six-digit TOTP code.

Compatible authenticator applications include SafeAuth, Google Authenticator, Microsoft Authenticator, and Authy.

### File encryption

1. SecureVault generates a new AES-256 key.
2. The file is encrypted locally with AES-GCM.
3. AES-GCM uses:
   - a random 12-byte IV; and
   - a 128-bit authentication tag.
4. The AES key is wrapped using the authenticated user's RSA public key.
5. The encrypted file is saved to the location chosen by the user.
6. MongoDB stores the file record and wrapped AES key.

### File decryption

1. The user selects a file record from the dashboard.
2. SecureVault loads the wrapped AES key from MongoDB.
3. The user's RSA private key unwraps the AES key.
4. AES-GCM verifies the encrypted file's integrity.
5. The plaintext is restored to the output location chosen by the user.


[↑ Back to contents](#contents)

<a id="architecture"></a>

## Architecture

```mermaid
flowchart LR
    U[User] --> UI[Java Swing Interface]

    UI --> AUTH[Authentication Service]
    AUTH --> PBKDF2[PBKDF2 Password Hashing]
    AUTH --> TOTP[TOTP Verification]

    UI --> CRYPTO[Cryptography Service]
    CRYPTO --> AES[AES-256-GCM]
    CRYPTO --> RSA[RSA-OAEP Key Wrapping]

    AUTH --> DB[(MongoDB Atlas)]
    CRYPTO --> DB
    CRYPTO --> FS[(Local File System)]

    DB --> USERS[users]
    DB --> RECORDS[file_records]
    FS --> FILES[Encrypted .sv Files]
```

MongoDB stores structured application data. The encrypted file contents remain on the local file system.


[↑ Back to contents](#contents)

<a id="quick-start"></a>

## Quick Start

1. Install Java 21 or later.
2. Install Apache Maven.
3. Create a MongoDB Atlas cluster.
4. Create a MongoDB database user.
5. Add the client IP address to the Atlas Network Access list.
6. Configure `MONGODB_URI` or the `mongodb.uri` JVM property.
7. Build and run the project.
8. Register an account and scan the generated TOTP QR code.
9. Log in with the username, password, and current TOTP code.


[↑ Back to contents](#contents)

<a id="prerequisites"></a>

## Prerequisites

| Requirement | Recommended version or status |
|---|---|
| Java Development Kit | Java 21 or newer |
| Apache Maven | Current stable version |
| MongoDB Atlas | Active account and cluster |
| Authenticator application | RFC 6238-compatible TOTP app |
| Internet connection | Required while using the application |
| Apache NetBeans | Optional; used during development |

Verify Java and Maven:

```bash
java -version
mvn -version
```

The project is compiled for Java 21 through `maven.compiler.release` in `pom.xml`.


[↑ Back to contents](#contents)

<a id="mongodb-atlas-setup"></a>

## MongoDB Atlas Setup

### 1. Create a cluster

Create or select a MongoDB Atlas project and deploy a cluster.

### 2. Create a database user

Open **Database Access** and create a database user for SecureVault.

> [!NOTE]
> The MongoDB database user is separate from the email address and password used to sign in to the MongoDB Atlas website.

Grant the user read/write access to the SecureVault database.

The default database name is:

```text
securevault
```

For least privilege, grant `readWrite` access to the `securevault` database instead of assigning a broad administrative role.

### 3. Allow the client IP address

Open **Network Access** and add the public IP address of the computer that will run SecureVault.

> [!WARNING]
> Avoid allowing all addresses with `0.0.0.0/0` unless this is a temporary test environment and you understand the risk.

### 4. Copy the Java connection string

Obtain the MongoDB connection string for a Java application.

It normally follows this format:

```text
mongodb+srv://<database-user>:<database-password>@<cluster-host>/?appName=<application-name>
```

Replace every placeholder with the real MongoDB Atlas database-user and cluster details.

If the password contains reserved URI characters, percent-encode them.

Examples:

| Character | Encoded value |
|---|---|
| `@` | `%40` |
| `#` | `%23` |
| `%` | `%25` |
| `/` | `%2F` |
| `:` | `%3A` |
| `?` | `%3F` |


[↑ Back to contents](#contents)

<a id="configure-the-application"></a>

## Configure the Application

SecureVault does not require the MongoDB URI to be stored in the Java source code.

Configure it with either:

- a JVM property; or
- an operating-system environment variable.

### Option A: NetBeans VM options

1. Open the extracted SecureVault folder as a Maven project.
2. Right-click the project.
3. Select **Properties**.
4. Open **Run**.
5. Enter the following in **VM Options** on one line:

```text
-Dmongodb.uri=mongodb+srv://<database-user>:<database-password>@<cluster-host>/?appName=SecureVault -Dmongodb.database=securevault
```

6. Select **OK**.

> [!CAUTION]
> Do not include XML tags such as `<exec.vmArgs>` in the NetBeans VM Options box.

### Option B: Environment variables

#### Windows PowerShell — current session

```powershell
$env:MONGODB_URI="mongodb+srv://<database-user>:<database-password>@<cluster-host>/?appName=SecureVault"
$env:MONGODB_DATABASE="securevault"
```

#### Windows Command Prompt — current session

```bat
set MONGODB_URI=mongodb+srv://<database-user>:<database-password>@<cluster-host>/?appName=SecureVault
set MONGODB_DATABASE=securevault
```

#### Windows — persistent variables

```powershell
setx MONGODB_URI "mongodb+srv://<database-user>:<database-password>@<cluster-host>/?appName=SecureVault"
setx MONGODB_DATABASE "securevault"
```

Restart NetBeans or open a new terminal after using `setx`.

#### macOS or Linux

```bash
export MONGODB_URI='mongodb+srv://<database-user>:<database-password>@<cluster-host>/?appName=SecureVault'
export MONGODB_DATABASE='securevault'
```

The database-name setting is optional. SecureVault uses `securevault` when no custom name is supplied.

### Configuration lookup order

SecureVault checks the MongoDB URI in this order:

1. JVM property: `mongodb.uri`
2. Environment variable: `MONGODB_URI`

SecureVault checks the database name in this order:

1. JVM property: `mongodb.database`
2. Environment variable: `MONGODB_DATABASE`
3. Default value: `securevault`


[↑ Back to contents](#contents)

<a id="run-securevault"></a>

## Run SecureVault

### NetBeans

1. Open the project folder containing `pom.xml`.
2. Confirm that the MongoDB URI is configured.
3. Select **Clean and Build**.
4. Select **Run Project**.

The main class is:

```text
ie.ncirl.securevault.ui.App
```

On startup, the application:

1. connects to MongoDB Atlas;
2. sends a ping command;
3. creates the required indexes; and
4. opens the login window.

If MongoDB cannot be reached, SecureVault displays an error and does not open the login screen.

### Command line

Open a terminal in the folder containing `pom.xml`.

Set `MONGODB_URI` in the same terminal session, then run:

```bash
mvn clean compile
```

```bash
mvn org.codehaus.mojo:exec-maven-plugin:3.5.1:java \
  -Dexec.mainClass=ie.ncirl.securevault.ui.App
```

On Windows Command Prompt, use the command on one line:

```bat
mvn org.codehaus.mojo:exec-maven-plugin:3.5.1:java -Dexec.mainClass=ie.ncirl.securevault.ui.App
```


[↑ Back to contents](#contents)

<a id="using-the-application"></a>

## Using the Application

### Register an account

1. Open SecureVault.
2. Select **Register**.
3. Enter a unique username.
4. Enter a password containing at least eight characters.
5. Use **Show password** only when required.
6. Select **Create Account**.
7. Scan the displayed QR code with a TOTP authenticator.
8. Store the manual TOTP secret securely.
9. Select **Done** and return to the login screen.

The application may create a QR image in the working directory using a name similar to:

```text
qrcode_<username>.png
```

> [!WARNING]
> Delete the QR image securely after configuring the authenticator. Anyone who obtains the QR image or manual TOTP secret may be able to generate valid authentication codes.

### Log in

Enter:

- the registered username;
- the account password; and
- the current six-digit TOTP code.

Select **Login**.

A TOTP code is normally valid for 30 seconds. SecureVault allows a small clock-drift window, but the computer and phone clocks should remain synchronised.

### Encrypt a file

1. Log in to the dashboard.
2. Select **Encrypt File**.
3. Choose the plaintext file.
4. Choose where to save the encrypted output.
5. Confirm the suggested `.sv` filename or select another filename.
6. Wait for the success message.

Optional:

1. Select **Delete original after encryption** before starting.
2. Confirm deletion when SecureVault asks.

> [!CAUTION]
> Normal operating-system deletion is not guaranteed secure erasure. Verify the encrypted file and maintain reliable backups before deleting important plaintext data.

### View encrypted-file records

The dashboard displays:

- the MongoDB record ID;
- the original file path; and
- the encrypted file path.

Select **Refresh** to reload records from MongoDB Atlas.

### Decrypt a file

1. Select a record in the dashboard table.
2. Select **Decrypt Selected**.
3. Choose the output location and filename.
4. SecureVault retrieves and unwraps the AES key.
5. SecureVault decrypts the file locally.
6. Choose whether to open the restored file.

> [!NOTE]
> The MongoDB record stores the encrypted file's current path. If the `.sv` file is moved, renamed, or deleted, the application may no longer be able to locate it. The current version does not provide a relink function.

### Reset a forgotten password

1. Select **Forgot Password?** on the login screen.
2. Enter the registered username.
3. Enter the current six-digit TOTP code.
4. Enter and confirm a new password containing at least eight characters.
5. Ensure the new password differs from the current password.
6. Select **Reset Password**.

The reset process changes only the password hash and salt. It preserves the existing TOTP secret and RSA key pair so files encrypted before the reset remain decryptable.

> [!IMPORTANT]
> A user who loses both the password and access to the TOTP secret cannot use the current recovery flow.

### Log out

Select **Logout** on the dashboard. SecureVault returns to the login window.


[↑ Back to contents](#contents)

<a id="mongodb-data-model"></a>

## MongoDB Data Model

SecureVault creates two collections.

### `users`

Typical fields:

| Field | Purpose |
|---|---|
| `_id` | MongoDB user identifier |
| `username` | Unique application username |
| `passwordHash` | PBKDF2 password hash |
| `salt` | Random password salt |
| `totpSecret` | TOTP authentication secret |
| `publicKey` | RSA public key |
| `privateKey` | RSA private key |
| `createdAt` | Account creation time |
| `passwordChangedAt` | Password reset time, when applicable |

### `file_records`

Typical fields:

| Field | Purpose |
|---|---|
| `_id` | MongoDB file-record identifier |
| `userId` | Owner of the file record |
| `originalPath` | Original plaintext path |
| `encryptedPath` | Local `.sv` file path |
| `wrappedKey` | RSA-wrapped AES key |
| `dateEncrypted` | Encryption timestamp |

### Indexes

SecureVault creates the following indexes at startup:

| Index | Purpose |
|---|---|
| `uq_users_username` | Unique ascending index on `users.username` |
| `ix_file_records_user_date` | Compound index on `file_records.userId` and descending `dateEncrypted` |


[↑ Back to contents](#contents)

<a id="project-structure"></a>

## Project Structure

```text
SecureVault/
├── pom.xml
├── README.md
├── MONGODB_SETUP.md
├── PASSWORD_FEATURES.md
└── src/
    └── main/
        └── java/
            └── ie/
                └── ncirl/
                    └── securevault/
                        ├── auth/
                        │   ├── AuthService.java
                        │   ├── QrCodeUtil.java
                        │   └── TotpUtil.java
                        ├── crypto/
                        │   ├── AesGcmCrypto.java
                        │   ├── KeyWrapUtil.java
                        │   ├── PasswordHasher.java
                        │   └── RsaKeyUtil.java
                        ├── db/
                        │   ├── MongoConnection.java
                        │   └── MongoFileRecordDao.java
                        ├── model/
                        │   ├── FileRecord.java
                        │   └── User.java
                        ├── securevault/
                        │   └── SecureVault.java
                        └── ui/
                            ├── App.java
                            ├── LoginFrame.java
                            ├── PasswordVisibility.java
                            ├── QrSetupDialog.java
                            ├── RegisterFrame.java
                            ├── ResetPasswordDialog.java
                            └── VaultDashboardFrame.java
```


[↑ Back to contents](#contents)

<a id="security-scope-and-limitations"></a>

## Security Scope and Limitations

SecureVault provides meaningful protection for encrypted files at rest, but it is important to understand the security boundary of this prototype.

### Security guidance

- Never commit the MongoDB URI, database password, QR image, or TOTP secret to GitHub.
- Rotate a MongoDB password immediately if it appears in source code, screenshots, logs, terminal output, or commit history.
- Use a MongoDB Atlas database user with only the permissions required by the application.
- Keep the authenticator device and TOTP secret secure.
- Maintain backups of important encrypted files.
- Protect decrypted output because it is ordinary plaintext.

### Current limitations

- The encrypted local file and matching MongoDB record are both required for normal decryption.
- MongoDB does not back up the encrypted file contents.
- The optional original-file deletion uses normal deletion, not certified secure erasure.
- The current implementation stores the RSA key pair in the MongoDB user document.
- A production implementation should protect private keys with an operating-system keystore, TPM, hardware security module, or dedicated key-management service.
- The application reads complete files into memory during encryption and decryption, so very large files may require substantial RAM.
- SecureVault does not claim to protect data on a computer that is already fully compromised by privileged malware.
- Additional automated testing, dependency review, penetration testing, and deployment hardening are required before production use.


[↑ Back to contents](#contents)

<a id="troubleshooting"></a>

## Troubleshooting

<details>
<summary><strong>MongoDB connection string is not configured</strong></summary>

Set `MONGODB_URI` or add `-Dmongodb.uri=...` to the JVM options.

Restart NetBeans if the environment variable was created after NetBeans was opened.

</details>

<details>
<summary><strong>MongoDB authentication failed</strong></summary>

Check that:

- the username is the Atlas database user, not the Atlas website email;
- the password is correct;
- reserved password characters are percent-encoded;
- the connection string points to the correct cluster; and
- the database user has sufficient permissions.

</details>

<details>
<summary><strong>Connection timeout or server-selection error</strong></summary>

Check that:

- the current public IP address is active in Atlas Network Access;
- the MongoDB cluster is running;
- the internet connection is available; and
- the local network or DNS service permits MongoDB SRV connections.

</details>

<details>
<summary><strong>Login fails with the correct password</strong></summary>

Confirm that:

- the current six-digit TOTP code was entered;
- the phone and computer clocks are synchronised;
- the correct authenticator account is selected; and
- the account exists in the configured MongoDB database.

</details>

<details>
<summary><strong>The QR code is not displayed</strong></summary>

SecureVault writes a QR image to the application's working directory.

Confirm that:

- the working directory is writable;
- the QR image has not been blocked;
- the QR file still exists while the setup dialog is open; and
- the application has permission to create image files.

</details>

<details>
<summary><strong>The username is already registered</strong></summary>

The `users.username` field has a unique index.

Choose another username or use the existing account.

</details>

<details>
<summary><strong>Decryption fails</strong></summary>

Confirm that:

- the selected `.sv` file still exists at the dashboard path;
- the file was not renamed or moved;
- the encrypted file has not been modified or corrupted;
- the correct user is logged in; and
- the MongoDB file record and wrapped AES key still exist.

AES-GCM intentionally rejects modified ciphertext instead of generating an untrusted plaintext file.

</details>

<details>
<summary><strong>Java compilation fails</strong></summary>

Use Java 21 or newer and confirm that Maven is using the correct JDK:

```bash
mvn -version
```

</details>


[↑ Back to contents](#contents)

<a id="author"></a>

## Author

**Tadiwa Mkwenje**  
BSc (Hons) in Computing — Cybersecurity  
National College of Ireland  
Student number: `x21360276`
