module Fetters.Registry.Provider

    open Microsoft.Win32
    open Fetters.Lists
    open Fetters.DotNet.Common
    open Fetters.DomainTypes


    //// Local Administrator Password Solution Enum ////
    let getLAPSSettings () : FettersRegistryRecord =
        //Test to see if LAPS is present/configured, and if so, pull some data
        //Will return a None since we test if the key is even present first
        let rKey = extractRegistryKey <| getRegistryKeyHKLM "Software\\Policies\\Microsoft Services\\AdmPwd"
        
        {lapsAdminAccountName = getRegistryValue "AdminAccountName" rKey
         lapsPasswordComplexity = getRegistryValue "PasswordComplexity" rKey
         lapsPasswordLength = getRegistryValue "PasswordLength" rKey
         lapsPasswdProtection = getRegistryValue "PwdExpirationProtectionEnabled" rKey
        } |> FettersRegistryRecord.LapsSettings
        

    //// Windows Automatic Logon Enum ////
    let getAutoLogonSettings () : FettersRegistryRecord =
        //Test to see if any autologon settings exist on the system.
        //Will return a Some even if the contents are None, since this key is
        //a default Windows key.
        let rKey = extractRegistryKey <| getRegistryKeyHKLM "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
        
        {defaultDomainName = getRegistryValue "DefaultDomainName" rKey
         defaultUserName = getRegistryValue "DefaultUserName" rKey
         defaultPassword = getRegistryValue "DefaultPassword" rKey
         altDefaultDomainName = getRegistryValue "AltDefaultDomainName" rKey
         altDefaultUserName = getRegistryValue "AltDefaultUserName" rKey
         altDefaultPassword = getRegistryValue "AltDefaultPassword" rKey
         } |> FettersRegistryRecord.AutoLogonSettings


    //// AutoRun Enum ////
    let getAutoRunValues () : FettersRegistryRecord list = 
        autorunLocations
        |> Array.map(fun s -> retrieveNamesByIntegrity HKEY_USER HKEY_CURRENT_USER s)
        |> Array.concat
        |> Array.map(fun tu -> 
            let rKey, pArray = tu
            pArray |> Array.map(fun p -> {location = rKey.Name; value = getRegistryValue p rKey }))
        |> Array.concat
        |> Array.toList
        |> List.map FettersRegistryRecord.AutorunSetting
 

    //// Sysmon Config Enum
    let listSysmonconfig () : FettersRegistryRecord =
        //Test to see if any Sysmon config is present on the system.
        //Will return a None if the relevant key is absent
        let rKey = extractRegistryKey <| getRegistryKeyHKLM "SYSTEM\\CurrentControlSet\\Services\\SysmonDrv\\Parameters" 
            
        {hashingAlgorithm = getRegistryValue "HashingAlgorithm" rKey
         options = getRegistryValue "Options" rKey
         rules = getRegistryValue "Rules" rKey
         } |> FettersRegistryRecord.SysmonConfig
        

    //// RDP Saved Connection Enum ////
    let private getRDPSavedConnectionsNames ()  : (RegHive * string * string [])[] =
        retrieveSubKeysByIntegrity "Software\\Microsoft\\Terminal Server Client\\Servers"
        
    
    let private getRDPSavedConnection (hive:RegHive) (path: string) (p: string) : RDPSavedConnection =
        let rKey = getRegistryKey hive (path + "\\" + p) |> extractRegistryKey
        {host = p; usernameHint = getRegistryValue "UsernameHint" rKey}
            

    let getRDPSavedConnections () : FettersRegistryRecord list =
        //Retrieves RDP connection info from the registry.
        getRDPSavedConnectionsNames ()
        |> Array.map(fun tuple ->
            let hive, path, pArray = tuple
            pArray
            |> Array.map(fun p -> getRDPSavedConnection hive path p))
            |> Array.concat
            |> Array.toList
            |> List.map FettersRegistryRecord.RDPSavedConnection


    //// MRU Commands Enum ////         
    let private getRecentRuncommandsNames () : (RegistryKey * string [])[] =  
        retrieveNamesByIntegrity HKEY_USER HKEY_CURRENT_USER "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU"
        
  
    let private getRecentRuncommand (rKey: RegistryKey) (p: string) : RecentCommand =
        {recentCommand = getRegistryValue p rKey}
  
 
    let getRecentCommands () : FettersRegistryRecord list =
        getRecentRuncommandsNames () 
        |> Array.map(fun tuple -> 
            let rKey, pArray = tuple
            pArray 
            |> Array.filter(fun f -> not(f = "MRUList")) 
            |> Array.map(fun p -> getRecentRuncommand rKey p ))
        |> Array.concat
        |> Array.toList
        |> List.map FettersRegistryRecord.RecentCommand

        
    //// UAC Policy Enum ////
    let getUACSystemPolicies () : FettersRegistryRecord =
        let uacKey = extractRegistryKey <| getRegistryKeyHKLM "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
        let consentPromptBehavior = getRegistryValue "ConsentPromptBehaviorAdmin" uacKey
        let enableLUA = getRegistryValue "EnableLUA" uacKey 
        let localAccounttokenFilterPolicy = getRegistryValue "LocalAccounttokenFilterPolicy" uacKey
        let filterAdministratorToken = getRegistryValue "FilterAdministratorToken" uacKey
                
        {consentPromptBehavior = consentPromptBehavior
         enableLUA = enableLUA
         localAccountTokenFilterPolicy = localAccounttokenFilterPolicy
         filterAdministratorToken = filterAdministratorToken
         } |> FettersRegistryRecord.UACPolicies


    //// PowerShell Environment Enum ////
    let getPShellEnv () : FettersRegistryRecord =
        let rKey2 = extractRegistryKey <| getRegistryKeyHKLM "SOFTWARE\\Microsoft\\PowerShell\\1\\PowerShellEngine" 
        let pshellver2 = getRegistryValue "PowerShellVersion" rKey2
        let rKey5 = extractRegistryKey <| getRegistryKeyHKLM "SOFTWARE\\Microsoft\\PowerShell\\3\\PowerShellEngine" 
        let pshellver5 = getRegistryValue "PowerShellVersion" rKey5
        let pshellTLog = 
            collectLowIntegrityNames HKEY_LOCAL_MACHINE "SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription"
            |> Array.map(fun (rKey, pArray) -> 
                pArray
                |> Array.map(fun p -> getRegistryValue p rKey))
                |> Array.concat
                |> Array.toList
        let pshellMLog = 
            collectLowIntegrityNames HKEY_LOCAL_MACHINE "SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging"
            |> Array.map(fun (rKey, pArray) -> 
                pArray
                |> Array.map(fun p -> getRegistryValue p rKey))
                |> Array.concat
                |> Array.toList
        let pshellSLog = 
            collectLowIntegrityNames HKEY_LOCAL_MACHINE "SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging"
            |> Array.map(fun (rKey, pArray) -> 
                pArray
                |> Array.map(fun p -> getRegistryValue p rKey))
                |> Array.concat
                |> Array.toList

        {poshVersion2 = pshellver2
         poshVersion5 = pshellver5
         poshTLog = pshellTLog
         poshMLog = pshellMLog
         poshSLog = pshellSLog
         } |> FettersRegistryRecord.PowerShellEnv


    //// System/User Proxy Settings Enum ////
    let getSystemInternetSettings () : FettersRegistryRecord =
        let rKey = extractRegistryKey <| getRegistryKeyHKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"  
        
        {proxyServer = getRegistryValue "ProxyServer" rKey
         proxyOverride = getRegistryValue "ProxyOverride" rKey
         proxyEnable = getRegistryValue "ProxyEnable" rKey
        } |> FettersRegistryRecord.InternetSettings
    

    let getUserInternetSettings () : FettersRegistryRecord =
        let rKey = extractRegistryKey <| getRegistryKeyHKCU "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" 
            
        {proxyServer = getRegistryValue "ProxyServer" rKey
         proxyOverride = getRegistryValue "ProxyOverride" rKey
         proxyEnable = getRegistryValue "ProxyEnable" rKey
        } |> FettersRegistryRecord.InternetSettings


    //// LSA Status Enum ////
    let getLSASettings () : FettersRegistryRecord  =
        let rKey = extractRegistryKey <| getRegistryKeyHKLM "SYSTEM\\CurrentControlSet\\Control\\Lsa" 
        let lsaResults = 
            lsaNames
            |> Array.map(fun n -> getRegistryValue n rKey)
        
        {lsaPid = lsaResults.[0]
         notificationPkgs = lsaResults.[1]
         authorizationPkgs = lsaResults.[2]
         prodType = lsaResults.[3]
         limitBlankPwd = lsaResults.[4]
         secureboot = lsaResults.[5]
         disdomcreds = lsaResults.[6]
         everyoneAnon = lsaResults.[7]
         forceGuest = lsaResults.[8]
         restrictAnon = lsaResults.[9]
         restrictSAM = lsaResults.[10]
         samConnAccnt = lsaResults.[11]
         } |> FettersRegistryRecord.LSASettings


    //// Windows Audit Settings Enum ////
    let getAuditSettings () : FettersRegistryRecord = 
        //I couldn't find any sort of decent list of posible Audit values, so
        //I'm checking for just the one I found.
        let rKey = extractRegistryKey <| getRegistryKeyHKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit"
            
        {processauditing = getRegistryValue "ProcessCreationIncludeCmdLine_Enabled" rKey} |> FettersRegistryRecord.AuditSettings


    //// Windows Event Forwarding Enum ////
    let getWEFSettings () : FettersRegistryRecord = 
        //Just bulk grabbing crap. Huge potential list of results.
        let names = 
            collectLowIntegrityNames HKEY_LOCAL_MACHINE "Software\\Policies\\Microsoft\\Windows\\EventLog\\EventForwarding\\SubscriptionManager"
        let results = 
            names
            |> Array.map(fun tu ->
                let rKey, pArray = tu
                pArray
                |> Array.map(fun p -> getRegistryValue p rKey))
            |> Array.concat
            |> Array.toList
        {policies = results} |> FettersRegistryRecord.WEFSettings


    //// PuTTY Session Enumeration ////
    let private getPuttySessionKeys () : (RegHive * string * string)[] = 
        let subKeysT = retrieveSubKeysByIntegrity "Software\\SimonTatham\\PuTTY\\Sessions"
        subKeysT
        |> Array.map(fun tu -> 
            let hive, path, pArray = tu 
            pArray |> Array.map(fun p -> hive, path, p))
        |> Array.concat

    
    let private getPuttySessionValue (hive:RegHive, path: string, name:string ) : PuttySSHSession = 
        let key = getRegistryKey hive (path + "\\" + name) |> extractRegistryKey
        let results = puttySessionNames |> Array.map(fun p -> getRegistryValue p key)
        {hostname = results.[0]; username = results.[1]; publicKeyFile = results.[2]; portForwardings = results.[3]; connectionSharing = results.[4]}
         
    
    let getPuttySessions () : FettersRegistryRecord list = 
        getPuttySessionKeys () 
        |> Array.map getPuttySessionValue 
        |> Array.toList 
        |> List.map FettersRegistryRecord.PuttySSHSession


    //// PuTTY Hostkey Enum ////
    let private getPuttyHostPublickeyNames () : (RegistryKey * string)[] =
        let names = retrieveNamesByIntegrity HKEY_USER HKEY_CURRENT_USER "Software\\SimonTatham\\PuTTY\\SshHostKeys"
        names
        |> Array.map(fun tu -> 
            let key, pArray = tu
            pArray |> Array.map(fun p ->  key, p))
        |> Array.concat
        
    
    let private getPuttyHostPublickeyValue (rKey: RegistryKey, name: string) : PuttyHostPublicKeys =
        let result = getRegistryValue name rKey
        {recentHostKeys = result}


    let getPuttyHostkeys () : FettersRegistryRecord list = 
        getPuttyHostPublickeyNames () 
        |> Array.map getPuttyHostPublickeyValue 
        |> Array.toList
        |> List.map FettersRegistryRecord.PuttyHostPublicKeys


    let private getInternetExplorerHistoryNames() : (RegistryKey * string [])[] =
        //I don't care about when the URL was accessed really. Skipping the
        //Datetime computation
        retrieveNamesByIntegrity HKEY_USER HKEY_CURRENT_USER "SOFTWARE\\Microsoft\\Internet Explorer\\TypedURLs"
        

    let private getInternetExplorerHistoryValues (rKey: RegistryKey) (name: string ) : HistoryIE =
        {path = rKey.Name; url = getRegistryValue name rKey}


    let getInternetExplorerHistory () : FettersRegistryRecord list = 
        getInternetExplorerHistoryNames () 
        |> Array.map(fun tu ->  
            let rKey, p = tu 
            p |> Array.map (getInternetExplorerHistoryValues rKey))
        |> Array.concat
        |> Array.toList
        |> List.map FettersRegistryRecord.HistoryIE