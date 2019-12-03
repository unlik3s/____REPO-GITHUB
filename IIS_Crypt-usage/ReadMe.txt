################################################################################################################################################
## Author : Jeremy GARCIA
## Version : 1.0
## Description: Analyse crypto used by clients parsing IIS log and/or SMTP LOG
## Prerequisites: Extended log must be enabled in IIS for detection of HTTPS cipher and log parser installed 
## https://www.microsoft.com/security/blog/2017/09/07/new-iis-functionality-to-help-identify-weak-tls-usage/
## Usage : Example 1 : .\Analyse_crypto_v1.0.ps1 -HTTPCipher $true -SMTPCipher $false -AgeLog "-24" -jobsNumber 5 -Output "c:\Scripts\Results"
################################################################################################################################################