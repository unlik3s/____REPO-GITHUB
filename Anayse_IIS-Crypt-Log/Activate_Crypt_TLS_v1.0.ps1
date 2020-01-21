##
# Script to add logging to IIS log files :
# 1) 1 Standard header in Default & Back End : ComputerName
# 2) 5 Extended header in Default Web Site : X-Forward-For, crypt-protocol, crypt-cipher, crypt-hash, crypt-keyexchange
##

##Add Exchange Snappin
Add-PSSnapin *exchange*

#List of servers to apply
$E15 = "VM-CLOUD-EXC-01" #(Get-ExchangeServer | Where-Object {$_.AdminDisplayVersion -like "*15.1*"}).Name

#Init array
$FinalResult = @()
$Result = @()

#Script to execute
$ScriptBlock = {
    try {
        #Add ComputerName
        Write-Host "Ajout du champs cs-computername dans Default Web Site & Exchange Back End on $env:COMPUTERNAME" -ForegroundColor Yellow
        $DefaultWebSiteLog = Get-WebConfiguration -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/site[@name='Default Web Site']/logFile" | Select-Object -ExpandProperty logExtFileFlags
        $DefaultWebSiteLog += ",ComputerName"
        $ExchangeBackEndLog = Get-WebConfiguration -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/site[@name='Exchange Back End']/logFile" | Select-Object -ExpandProperty logExtFileFlags
        $ExchangeBackEndLog += ",ComputerName"
        Set-WebConfigurationProperty -Filter "system.applicationHost/sites/site[@name='Default Web Site']/logFile" -Name LogExtFileFlags -Value $DefaultWebSiteLog -ErrorAction continue -Verbose
        Set-WebConfigurationProperty -Filter "system.applicationHost/sites/site[@name='Exchange Back End']/logFile" -Name LogExtFileFlags -Value $ExchangeBackEndLog -ErrorAction continue -Verbose
    }
    catch {
        Write-Host ">>>> Error catch to add ComputerName header in IIS log files - Review Error and retry <<<<" -ForegroundColor Red
        $Error[0]
    }
    #Extended IIS logs files
   try {
    Write-Host "Ajout des champs crypt log on $env:COMPUTERNAME" -ForegroundColor Yellow
    #Ajout crypt-protocol
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/site[@name='Default Web Site']/logFile/customFields" -name "." -value @{logFieldName='crypt-protocol';sourceName='CRYPT_PROTOCOL';sourceType='ServerVariable'} -ErrorAction continue -Verbose
    #Ajout crypt-cipher
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/site[@name='Default Web Site']/logFile/customFields" -name "." -value @{logFieldName='crypt-cipher';sourceName='CRYPT_CIPHER_ALG_ID';sourceType='ServerVariable'} -ErrorAction continue -Verbose
    #Ajout crypt-hash
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/site[@name='Default Web Site']/logFile/customFields" -name "." -value @{logFieldName='crypt-hash';sourceName='CRYPT_HASH_ALG_ID';sourceType='ServerVariable'} -ErrorAction continue -Verbose
    #Ajout crypt-keyexchange
    Add-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/site[@name='Default Web Site']/logFile/customFields" -name "." -value @{logFieldName='crypt-keyexchange';sourceName='CRYPT_KEYEXCHANGE_ALG_ID';sourceType='ServerVariable'} -ErrorAction continue -Verbose
   }
   catch {
        Write-Host ">>>> Error catch to add IIS Extended log files - Review error and retry<<<<" -ForegroundColor Red
        $Error[0]
   }
}
$Result = Invoke-Command -ComputerName $E15 -ScriptBlock $ScriptBlock 4>&1
$Result

#Check if configuration is well applied to all servers

$ScriptBlockCheck = {
    
    $computerNameHeader = Get-WebConfiguration -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/site[@name='Default Web Site']/logFile" | Select-Object -ExpandProperty logExtFileFlags
    if ($computerNameHeader -match "ComputerName"){
        $cptStatus = "OK"
    } else {
        $cptStatus = "NOK"
    }

    $ExtendedLogHeader = (Get-WebConfiguration -pspath 'MACHINE/WEBROOT/APPHOST'  -filter "system.applicationHost/sites/site[@name='Default Web Site']/logFile/customFields").Collection.logFieldName
    if ($ExtendedLogHeader -contains "crypt-protocol" -and $ExtendedLogHeader -contains "crypt-cipher" -and $ExtendedLogHeader -contains "crypt-hash" -and $ExtendedLogHeader -contains "crypt-keyexchange"){
        $extStatus = "OK"
    } else {
        $extStatus = "NOK"
    }

    #Result in array
    $obj = New-Object PSObject
    $obj | Add-Member NoteProperty ServerName $env:COMPUTERNAME
    $obj | Add-Member NoteProperty Check_AddComputerName $cptStatus
    $obj | Add-Member NoteProperty Check_AddIISExtendedLog $extStatus
    Write-Output $obj
    }

$FinalResult = Invoke-Command -ComputerName $E15 -ScriptBlock $ScriptBlockCheck 4>&1
$FinalResult | Format-Table
#$FinalResult | Export-Csv "C:\Temp\Export-IISLogConf.csv" -Encoding UTF8 -NoTypeInformation