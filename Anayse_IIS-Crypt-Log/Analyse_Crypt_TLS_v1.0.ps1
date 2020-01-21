###################################################################################
## Version : 1.0
## Description: Analyse crypto used by clients parsing IIS logs WSVC1
## Prerequisites: 
## 1) HTTPS : Extended log must be enabled in IIS for detection of HTTPS cipher
## Usage : 
## 1) Example 1 : Analyse_Crypt_TLS_v1.0.ps1 -HTTPCipher $true -AgeLog "-24" -jobsNumber 5
## Author : Jeremy GARCIA
###################################################################################

param (
    [Parameter(Mandatory=$true)] [Bool]$HTTPCipher=$true,
    [Parameter(Mandatory=$true)] [string]$AgeLog=-24, #Specify age of IIS age to search in hours
    [Parameter(Mandatory=$true)] [string]$jobsNumber=5, #Specify max jobs to used
    [string] $Output="C:\SCRIPTS\Analyse-crypto\Results"
    )
## Variables
$servers = "SERVER1","SERVER2","SERVER3"
$UniqueValue = "OriginalIP"  #Specify value to sort unique object in the final report. Example : X-Forward-For

#Css style
$css = @"
<style>
h1, h5, th { text-align: center; font-family: Segoe UI; }
table { margin: auto; font-family: Segoe UI; box-shadow: 10px 10px 5px #888; border: thin ridge grey; }
th { background: #19EAB3; color: #fff; max-width: 400px; padding: 5px 10px; }
td { font-size: 11px; padding: 5px 20px; color: #000; }
tr { background: #b8d1f3; }
tr:nth-child(even) { background: #daf4ec; }
tr:nth-child(odd) { background: #bcb8f3; }
</style>
"@

##Options
Clear-Host
Write-Host "**********************************************************************************************************"
write-host "Analyse IIS Default Web Site (Front-end) | SMTP Procol logs"
#Prerequisites
Write-Host "---Prerequisites---" -ForegroundColor Magenta
 if(!(Test-Path -Path $Output)){Write-host "Try to create result folder : " -NoNewline;try{New-Item -ItemType directory -Path $Output | Out-Null;if(test-path -path $Output){Write-Host "OK" -ForegroundColor Green}}catch{Write-host "KO" -ForegroundColor Red}}else{Write-host "Try to create result folder : " -NoNewline;Write-Host "OK (result folder already created)" -ForegroundColor Green}
 if (!(Get-PSSnapin |Where-Object {$_.Name -like "*Exchange*"})){Write-Host "Try to load Exchange Snapin : " -NoNewline;try{Add-PSSnapin -Name *Exchange* -ErrorAction Stop 2>&1 | Out-Null; if(Get-PSSnapin |?{$_.Name -like "*Exchange*"}){Write-Host "OK" -ForegroundColor Green}}catch{Write-host "KO (error : $_)" -ForegroundColor Red}}else{Write-Host "Try to load Exchange Snapin : " -NoNewline;Write-Host "Exchange snapin already loaded" -ForegroundColor Green}
 if(!(Test-Path -Path "C:\Program Files (x86)\Log Parser 2.2\LogParser.exe")){Write-host "LogParser installed : " -NoNewline;Write-host "KO (please install logparser before continue...)" -ForegroundColor Red;exit}else{Write-host "LogParser installed : " -NoNewline;Write-host "OK" -ForegroundColor Green}
 $dateoftheday = Get-Date -Format "MM/dd/yyyy hh:mm:ss"
$daytosearch = (Get-Date).AddHours($AgeLog)
Write-Host "---Options---" -ForegroundColor Magenta
Write-Host "#Option Period : " -NoNewLine;Write-Host "From $daytosearch to $dateoftheday" -ForegroundColor Yellow
$srvprint = $servers -join ","
Write-Host "#Option Servers : " -NoNewline;Write-Host "$srvprint" -ForegroundColor Yellow
Write-Host "#Option Output : " -NoNewline;Write-Host "$Output" -ForegroundColor Yellow
if ($HTTPCipher){Write-Host "#Option HTTPCipher : "-NoNewLine;Write-host "ON" -ForegroundColor Green}else{Write-Host "#Option HTTPCipher : " -NoNewLine;Write-Host "OFF" -ForegroundColor Red}
if ($SMTPcipher){Write-Host "#Option SMTPCipher : " -NoNewLine;Write-Host "ON" -ForegroundColor Green}else{Write-Host "#Option SMTPCipher : " -NoNewLine;Write-Host "OFF" -ForegroundColor Red}
Write-Host "**********************************************************************************************************"

#HTTPCipher Code
if ($HTTPCipher){
Write-Host "[INFO] Start HTTPS analyse" -ForegroundColor DarkCyan
$sources = @()
$source = @()
foreach ($server in $servers){
   if ((Test-Connection $server -Count 1 -Quiet) -eq $true){
        $logUNCFile = "\\$server\c$\inetpub\logs\LogFiles\W3SVC1"
        try {$source += (Get-ChildItem $logUNCFile -ErrorAction Stop | Where-Object {$_.LastWriteTime -gt ((get-date).AddHours($AgeLog))}) }
        catch {Write-Host "[WARNING] Unable to use Get-ChilItem command from $server"  -ForegroundColor DarkYellow}
        $sources += $source.FullName | ForEach-Object {"'"+$_+"'"}
    }
    else{Write-Host "[WARNING] Unable to connect to $server"  -ForegroundColor DarkYellow}
}
$srcSize = ($source | Measure-Object -Sum Length).Sum / 1GB
Write-Host "[INFO] IIS logs files count: " -ForegroundColor DarkCyan -NoNewline;Write-Host "$($sources.count)" -ForegroundColor Yellow
Write-Host "[INFO] IIS logs size: " -ForegroundColor DarkCyan -NoNewline;Write-Host "$srcSize GB" -ForegroundColor Yellow
$sources = $sources -join ", "

#Log Parser request HTTP not equal to TLS 1.2 (400)
$SQLQueryHTTP = @"
SELECT date, time, s-computername, cs-username, c-ip, cs(User-Agent) as UserAgent,OriginalIP, cs-uri-stem, crypt-cipher, crypt-hash, crypt-keyexchange, crypt-protocol
INTO $Output\IIS-Logs.csv
FROM $sources
WHERE crypt-protocol <> 400 AND cs-username NOT LIKE '%HealthMailbox%' AND cs-uri-stem NOT LIKE '%HealthMailbox%' AND cs-uri-stem NOT LIKE '%powershell%' AND cs(User-Agent) NOT LIKE '%KEMP%'
"@

Write-Host "[INFO] IIS logs export..." -ForegroundColor DarkCyan
&"C:\Program Files (x86)\Log Parser 2.2\LogParser.exe" $SQLQueryHTTP -i:W3C -dQuotes ON


Write-Host "[INFO] split the CSV in multiple files"  -ForegroundColor DarkCyan
$i = 0
$ALLCSV = @()
Get-Content $Output\IIS-Logs.csv -ReadCount 50000 | ForEach-Object{
    $i++
    $_ | Out-File $Output\IIS-Logs_$i.csv
    $AllCsv += "$Output\IIS-Logs_$i.csv"
    Write-Host "[INFO] ** IIS-Log_$i.csv created" -ForegroundColor DarkCyan
}
#Delete the first line to avoid duplicate entries
$file = "$Output\IIS-Logs_1.csv"; (Get-Content $file | Select-Object -Skip 1) | Set-Content $file

$ALLCSV | ForEach-Object {
$tempcontent = Get-Content $_
Set-content $_ -value "date,time,s-computername,cs-username,c-ip,UserAgent,X-Forward-For,cs-uri-stem,crypt-cipher,crypt-hash,crypt-keyexchange,crypt-protocol",$tempcontent
Write-Host "[INFO] ** Adding header to $_" -ForegroundColor DarkCyan
}

#BEGIN WITH JOBS HERE
Write-Host "[INFO] Remove existing jobs before continue..." -ForegroundColor DarkCyan
Get-Job | Remove-Job
Write-Host "[INFO] Max $jobsNumber jobs in background to translate cipher code..." -ForegroundColor DarkCyan
foreach ($csv in $ALLCSV){
    $ScriptBlock = {
    function Get-StatusFromValue{
        Param($SV)
        switch($SV)
        {
        "400" { "TLS 1.2" }
        "100" { "TLS 1.1" } #Unsecured
        "40" { "TLS 1.0" } #Unsecured
        "10" { "SSLv3" } #Unsecured
        "660e" { "AES128" }
        "660.000000" { "AES128" } #Convert 660e after logparser in 660.000000
        "6610" { "AES256" }
        "6801" { "RC4" } #Unsecured
        "6603" { "3DES" } #Unsecured
        "8004" { "SHA1" } #Unsecured
        "800c" { "SHA256" }
        "800d" { "SHA384" }
        "800e" { "SHA512" }
        "ae06" { "ECDH_EPHEM" }
        "TLS protocol SP_PROT-TLS1_0_CLIENT" { "SEND_TLS 1.0" } #Unsecured
        "TLS protocol SP_PROT-TLS1_1_CLIENT" { "SEND_TLS 1.1" } #Unsecured
        "TLS protocol SP_PROT-TLS1_2_CLIENT" { "SEND_TLS 1.2" }
        "TLS protocol SP_PROT_TLS1_0_SERVER" { "RECEIVE_TLS 1.0" } #Unsecured
        "TLS protocol SP_PROT_TLS1_1_SERVER" { "RECEIVE_TLS 1.1" } #Unsecured
        "TLS protocol SP_PROT_TLS1_2_SERVER" { "RECEIVE_TLS 1.2" }
        Default { "Unknown" }
        }
        }
        $CsvToImport = Import-Csv -Path $args[0] 
        $CsvToImport | Select-Object date, time, s-computername, cs-username, c-ip, UserAgent, X-Forward-For, cs-uri-stem,`
        @{LABEL="crypt-cipher"; EXPRESSION={Get-StatusFromValue $_.'crypt-cipher'}},`
        @{LABEL="crypt-hash"; EXPRESSION={Get-StatusFromValue $_.'crypt-hash'}},`
        @{LABEL="crypt-keyexchange"; EXPRESSION={Get-StatusFromValue $_.'crypt-keyexchange'}},`
        @{LABEL="crypt-protocol"; EXPRESSION={Get-StatusFromValue $_.'crypt-protocol'}} | Export-Csv -NoTypeInformation -Encoding UTF8 -Path "$($args[1])\IIS-Logs-Converted.csv" -Append 
    }
    #Throttling powershell jobs
    if (((get-Job) | Where-Object {$_.State -eq "Running"}).count -gt ($jobsNumber - 1)){
        do {Write-Host "[WARNING] Throttling to $jobsNumber simultaneous jobs..." -ForegroundColor DarkYellow
        Start-Sleep 1}
        until (((get-Job) | Where-Object {$_.State -eq "Running"}).count -lt ($jobsNumber + 1))
        Write-Host "[INFO] Start job for $csv" -ForegroundColor DarkCyan
        Start-Job -ScriptBlock $ScriptBlock -ArgumentList $csv,$Output
    }else{
        Write-Host "[INFO] Start job for $csv" -ForegroundColor DarkCyan
        Start-Job -ScriptBlock $ScriptBlock -ArgumentList $csv,$Output
    }
}

$jobs = Get-Job
if (($jobs | Where-Object {$_.State -eq "Running"}).count -gt 0) {
      Do {
         Write-Host "[INFO] Jobs are still running... Next check in 10 secondes" -ForegroundColor DarkYellow
         Start-Sleep 10
      }
      Until (($jobs | Where-Object {$_.State -eq "Completed"}).count -eq $jobs.count)
   }else{
         Write-Host "[INFO] All jobs are already in state Completed" -ForegroundColor DarkGreen
        }      
    Write-Host "[INFO] All jobs are in completed state" -ForegroundColor Green
   #foreach ($j in $jobs) {Receive-Job $j.id}

#END JOBS
Write-Host "[INFO] Get Only unique value by $UniqueValue"  -ForegroundColor DarkCyan
$dataToAnalyse = Import-Csv "$Output\IIS-Logs-Converted.csv"
$dataToAnalyse = $dataToAnalyse | Sort-Object -Unique -Property $UniqueValue #X-Forward-For - OriginalIP
$dataToAnalyse | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $Output\IIS-Logs-Final-Result.csv #| Format-Table
$dataToAnalyse | ConvertTo-Html -Head $css -Body "<h1>HTTPS Exchange IIS Report Cipher</h1>`n<h5>Generated on $(Get-Date)</h5>" | Out-File "$Output\IIS-WeakProtocol-Result-HTML.html"

Write-Host "[INFO] HTTPS Analyse finished" -ForegroundColor Green
}