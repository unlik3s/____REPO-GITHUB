################################################################################################################################################
## Author : Jeremy GARCIA
## Version : 1.0
################################################################################################################################################

Prerequisistes :
- Activate extended log files by adding cryptolog capabilities in IIS :
-- Activate_Crypt_TLS_v1.0.ps1

- Get client workstation and user using old versions of TLS (1.0 and 1.1) :
-- Analyse_Crypt_TLS_v1.0.ps1
-- Example : 
    Get the last 24 hours logs and export CSV and HTML result in C:\scripts\Results (No email sent) with 5 Powershell jobs maximum
    .\Analyse_crypto_v1.0.ps1 -HTTPCipher $true -SMTPCipher $false -AgeLog "-24" -jobsNumber 5 -Output "c:\Scripts\Results"