SecureVault

SecureVault is a Java desktop application for protecting sensitive local files with multi-factor authentication and hybrid cryptography. It uses:

PBKDF2WithHmacSHA512 for password hashing

TOTP for six-digit authenticator codes

AES-256-GCM for file confidentiality and integrity

RSA-OAEP for protecting each file's AES key

MongoDB Atlas for user accounts and encrypted-file metadata

Java Swing for the desktop interface

The encrypted file content remains on the user's computer. MongoDB stores the user account, RSA key material, file paths, and the RSA-wrapped AES key required to decrypt each file.

Project status: Functional academic prototype developed for a final-year BSc (Hons) in Computing, Cybersecurity project.

Contents

Features

How SecureVault works

Prerequisites

MongoDB Atlas setup

Configure the application

Run SecureVault

Using the application

MongoDB data model

Project structure

Security guidance and limitations

Troubleshooting

Features

Secure user registration with a unique username

Password hashing with a random salt and 100,000 PBKDF2 iterations

TOTP multi-factor authentication using a QR code

Show/hide password controls on registration, login, and password reset

TOTP-protected forgotten-password reset

AES-256-GCM file encryption with a fresh key and IV for each file

RSA-2048 OAEP wrapping of each AES key

User-specific encrypted-file records stored in MongoDB Atlas

Local encrypted file output using the .sv extension

File decryption with AES-GCM integrity verification

Optional deletion of the original file after confirmation

MongoDB connection validation and automatic index creation at startup

How SecureVault works

Registration and authentication

A user creates an account with a username and password.

SecureVault generates:

a random password salt;

a PBKDF2 password hash;

a TOTP secret; and

an RSA public/private key pair.

The application displays a QR code that can be scanned by an RFC 6238-compatible authenticator app, such as SafeAuth, Google Authenticator, Microsoft Authenticator, or Authy.

Future logins require the username, password, and current six-digit TOTP code.

File encryption

SecureVault generates a new AES-256 key.

The file is encrypted locally using AES-GCM with a random 12-byte IV and a 128-bit authentication tag.

The AES key is wrapped using the authenticated user's RSA public key and RSA-OAEP with SHA-256.

The encrypted file is written to the location chosen by the user.

MongoDB stores the file record and wrapped AES key.

File decryption

The user selects an encrypted-file record from the dashboard.

SecureVault loads the wrapped AES key from MongoDB.

The user's RSA private key unwraps the AES key.

AES-GCM verifies the encrypted file and restores the plaintext to the chosen output location.

Prerequisites

Install or prepare the following:

Java Development Kit 21 or newer

Apache Maven

MongoDB Atlas account and cluster

A TOTP authenticator application (Authenticator App- SafeAuth, can download it in the Google Play Store)

Internet access while using the application, because authentication and file records are stored in MongoDB Atlas

Optional: Apache NetBeans, which was used to develop the project

Verify Java and Maven from a terminal:

java -version
mvn -version

The project is compiled for Java 21 through maven.compiler.release in pom.xml.

MongoDB Atlas setup

1. Create a cluster

Create or select a MongoDB Atlas project and deploy a cluster.

2. Create a database user

Create an Atlas database user for the application. This is separate from the email/password used to sign in to the Atlas website.

Grant the user read/write access to the database that SecureVault will use. The default database name is:

securevault

For a least-privilege configuration, grant readWrite on the securevault database rather than a broad administrative role.

3. Allow the client IP address

Open Atlas Network Access and add the public IP address of the computer that will run SecureVault.

Avoid allowing all addresses (0.0.0.0/0) unless this is a temporary test environment and you understand the risk.

4. Copy the Java connection string

Obtain the MongoDB connection string for a Java application. It normally has this form:

mongodb+srv://<database-user>:<database-password>@<cluster-host>/?appName=<application-name>

Replace all placeholders with the real Atlas database-user details.

If the database password contains reserved URI characters such as @, #, %, /, :, or ?, percent-encode those characters in the connection string.

Configure the application

SecureVault deliberately does not require the MongoDB URI to be stored in Java source code. Configure it through either a JVM property or an operating-system environment variable.

Option A: NetBeans VM options

Open the extracted SecureVault folder as a Maven project.

Right-click the project and select Properties.

Open Run.

In VM Options, enter the following on one line:

-Dmongodb.uri=mongodb+srv://<database-user>:<database-password>@<cluster-host>/?appName=<application-name> -Dmongodb.database=securevault

Select OK.

Do not include XML tags such as <exec.vmArgs> in the VM Options box.

Option B: Environment variables

Windows PowerShell — current session

$env:MONGODB_URI="mongodb+srv://<database-user>:<database-password>@<cluster-host>/?appName=<application-name>"
$env:MONGODB_DATABASE="securevault"

Windows — persistent variables

setx MONGODB_URI "mongodb+srv://<database-user>:<database-password>@<cluster-host>/?appName=<application-name>"
setx MONGODB_DATABASE "securevault"

Restart NetBeans or open a new terminal after using setx.

macOS or Linux

export MONGODB_URI='mongodb+srv://<database-user>:<database-password>@<cluster-host>/?appName=<application-name>'
export MONGODB_DATABASE='securevault'

The database-name setting is optional. SecureVault uses securevault when no custom name is supplied.

Configuration lookup order

SecureVault reads configuration in this order:

JVM property mongodb.uri

Environment variable MONGODB_URI

For the database name:

JVM property mongodb.database

Environment variable MONGODB_DATABASE

Default value securevault

Run SecureVault

NetBeans

Open the project folder containing pom.xml.

Confirm that the MongoDB URI is configured.

Select Clean and Build.

Select Run Project.

The main class is:

ie.ncirl.securevault.ui.App

On startup, the application:

connects to MongoDB;

sends a ping command;

creates the required indexes; and

opens the login window.

If the MongoDB connection cannot be established, the application displays an error and does not open the login screen.

Command line

From the folder containing pom.xml:

mvn clean compile
mvn org.codehaus.mojo:exec-maven-plugin:3.5.1:java -Dexec.mainClass=ie.ncirl.securevault.ui.App

Make sure MONGODB_URI is set in the same terminal session before running the second command.

Using the application

1. Register an account

Open SecureVault.

Select Register.

Enter a unique username.

Enter a password containing at least 8 characters.

Use Show password only when required and make sure no one can observe the screen.

Select Create Account.

Scan the displayed QR code with a TOTP authenticator application.

Keep the displayed manual TOTP secret in a secure location in case the QR code cannot be scanned.

Select Done, then return to the login screen.

The application also creates a local QR image named:

qrcode_<username>.png

Delete this file securely after the authenticator has been configured. Anyone who obtains the QR image or manual secret may be able to generate valid TOTP codes.

2. Log in

Enter:

the registered username;

the account password; and

the current six-digit TOTP code.

Select Login. A TOTP code is normally valid for a 30-second period. SecureVault allows a small clock-drift window, but the computer and phone clocks should still be synchronised.

3. Encrypt a file

Log in to the dashboard.

Select Encrypt File.

Choose the plaintext file.

Choose where to save the encrypted output.

The suggested filename is the original name followed by .sv.

Wait for the success message.

Optional: select Delete original after encryption before starting encryption. SecureVault will ask for confirmation before deleting the original file.

Normal operating-system deletion is not guaranteed secure erasure. Keep reliable backups and verify the encrypted file before deleting important data.

4. View encrypted-file records

The dashboard table displays:

MongoDB record ID;

original file path; and

encrypted file path.

Select Refresh to reload records from MongoDB.

5. Decrypt a file

Select a record in the dashboard table.

Select Decrypt Selected.

Choose the output location and filename.

SecureVault retrieves and unwraps the AES key.

The file is decrypted locally.

Choose whether to open the restored file.

Do not move, rename, or delete the .sv file without also understanding that the MongoDB record stores its current path. If the encrypted file is moved, the stored path will no longer point to it and the current application has no relink function.

6. Reset a forgotten password

Select Forgot Password? on the login screen.

Enter the username.

Enter the current six-digit TOTP code.

Enter and confirm a new password of at least 8 characters.

The new password must be different from the current password.

Select Reset Password.

The password reset changes only the password hash and salt. It keeps the existing TOTP secret and RSA key pair so that files encrypted before the reset remain decryptable.

A user who loses both the password and access to the TOTP secret cannot use this recovery flow.

7. Log out

Select Logout on the dashboard. SecureVault returns to the login window.

MongoDB data model

SecureVault creates two collections.

users

Typical fields:

_id
username
passwordHash
salt
totpSecret
publicKey
privateKey
createdAt
passwordChangedAt   (added after a password reset)

file_records

Typical fields:

_id
userId
originalPath
encryptedPath
wrappedKey
dateEncrypted

Indexes

The application creates these indexes at startup:

uq_users_username — unique ascending index on users.username

ix_file_records_user_date — compound index on file_records.userId and descending dateEncrypted

Project structure

SecureVault/
├── pom.xml
├── README.md
├── MONGODB_SETUP.md
├── PASSWORD_FEATURES.md
└── src/
    └── main/
        └── java/
            └── ie/ncirl/securevault/
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

Security guidance and limitations

SecureVault provides meaningful file-at-rest protection, but it is important to understand the security boundary of this prototype.

Never commit the MongoDB URI, database password, QR image, or TOTP secret to GitHub.

Rotate a MongoDB password immediately if it has been exposed in source code, screenshots, logs, or commit history.

Use an Atlas database user with only the permissions required by the application.

The encrypted file and its matching MongoDB record are both required for normal decryption.

Encrypted file content is stored locally and is not backed up by MongoDB.

Decrypted output is ordinary plaintext and must be protected by the user and operating system.

The optional original-file deletion uses normal file deletion, not certified secure erasure.

The current implementation stores the RSA key pair in the MongoDB user document. A production system should protect private keys with an operating-system keystore, TPM, hardware security module, or dedicated key-management service.

The application reads a complete file into memory during encryption and decryption. Very large files may require substantial RAM.

SecureVault does not claim to protect data on a computer that is already fully compromised by privileged malware.

This repository is an academic prototype and should undergo additional hardening, automated testing, dependency review, and security assessment before production use.

Troubleshooting

MongoDB connection string is not configured

Set MONGODB_URI or add -Dmongodb.uri=... to the JVM options. Restart the IDE if an environment variable was created after NetBeans was opened.

Authentication failed

Check that:

the username is the Atlas database user, not the Atlas website email;

the password is correct;

reserved password characters are percent-encoded;

the connection string points to the correct cluster; and

the database user has sufficient permissions.

Connection timeout or server-selection error

Check that:

the current public IP address is active in Atlas Network Access;

the cluster is running;

the internet connection is available; and

the local network or DNS service allows MongoDB SRV connections.

Login fails with a correct password

Confirm that:

the current six-digit TOTP code was entered;

the phone and computer clocks are synchronised;

the correct authenticator account is being used; and

the account exists in the configured MongoDB database.

QR code is not displayed

SecureVault writes qrcode_<username>.png to the application's working directory. Confirm that the directory is writable and that the file has not been blocked or removed before the QR setup dialog opens.

That username is already registered

The users.username field has a unique index. Choose a different username or use the existing account.

Decryption fails

Confirm that:

the selected .sv file still exists at the path displayed in the dashboard;

the file was not renamed or moved;

the encrypted file has not been modified or corrupted;

the correct user account is logged in; and

the MongoDB file record and wrapped key still exist.

AES-GCM intentionally rejects modified ciphertext instead of generating an untrusted plaintext file.

Java compilation error

Use JDK 21 or newer and confirm that Maven is using the correct JDK:

mvn -version

Author

Tadiwa MkwenjeBSc (Hons) in Computing — CybersecurityNational College of IrelandStudent number: x21360276
