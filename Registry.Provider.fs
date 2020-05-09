module Fetters.Registry.Provider

    open Fetters.Lists
    open Fetters.dotNet.Common
    open Fetters.DomainTypes

    
    let getLAPSSettings () 
        : LapsSettings =
        //Test to see if LAPS is present/configured, and if so, pull some data
        //Will return a None since we test if the key is even present first
        let rKey = 
            match getRegistryKeyHKLM "Software\\Policies\\Microsoft Services\\AdmPwd" with
            |Some rKey -> rKey
            |None -> getThrowawayKey
        {lapsAdminAccountName = getRegistryValue "AdminAccountName" rKey
         lapsPasswordComplexity = getRegistryValue "PasswordComplexity" rKey
         lapsPasswordLength = getRegistryValue "PasswordLength" rKey
         lapsPasswdProtection = getRegistryValue "PwdExpirationProtectionEnabled" rKey
        }
        

    let getAutoLogonSettings ()
        : AutoLogonSettings =
        //Test to see if any autologon settings exist on the system.
        //Will return a Some even if the contents are None, since this key is
        //a default Windows key.
        let rKey =     
            match getRegistryKeyHKLM "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" with
            |Some rKey -> rKey
            |None -> getThrowawayKey
        {defaultDomainName = getRegistryValue "DefaultDomainName" rKey
         defaultUserName = getRegistryValue "DefaultUserName" rKey
         defaultPassword = getRegistryValue "DefaultPassword" rKey
         altDefaultDomainName = getRegistryValue "AltDefaultDomainName" rKey
         altDefaultUserName = getRegistryValue "AltDefaultUserName" rKey
         altDefaultPassword = getRegistryValue "AltDefaultPassword" rKey
         }


    let listSysmonconfig ()
        : SysmonConfig =
        //Test to see if any Sysmon config is present on the system.
        //Will return a None if the relevant key is absent
        let rKey = 
            match getRegistryKeyHKLM "SYSTEM\\CurrentControlSet\\Services\\SysmonDrv\\Parameters" with
            |Some rKey -> rKey
            |None -> getThrowawayKey
        {hashingAlgorithm = getRegistryValue "HashingAlgorithm" rKey
         options = getRegistryValue "Options" rKey
         rules = getRegistryValue "Rules" rKey
         }
        

    let getRDPSavedConnections ()
        : RDPSavedConnection [] =
        //Performs differently if running high or low integrity.
                    
        let rArray = 
            match isHighIntegrity with
            |true -> collectHighIntegritySubKeysHKU "Software\\Microsoft\\Terminal Server Client\\Servers"
            |false -> collectLowIntegritySubKeysHKCU "Software\\Microsoft\\Terminal Server Client\\Servers"
        
        let uArray = 
            rArray 
            |> Array.map(fun tu ->
                let hive, path, pArray = tu
                pArray 
                |> Array.map(fun p ->
                    match getRegistryKey hive (path + "\\" + p) with
                    |Some rKey -> {host = p; usernameHint = getRegistryValue "UsernameHint" rKey}
                    |None -> {host = ""; usernameHint = None}
                    ))
                
        match uArray.Length with
        |x when x > 0 -> uArray |> Array.reduce Array.append
        |_ -> [||]
            
        
    
    let getRecentRuncommands ()
     : RecentCommand [] =
    // MRU for all users if high integrity, current user otherwise
        let rArray = 
            match isHighIntegrity with
            |true -> collectHighIntegrityNames HKEY_USER "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU"
            |false -> collectLowIntegrityNames HKEY_CURRENT_USER "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU"
        
        let uArray =
            rArray
            |> Array.map(fun tu ->
                let rKey, pArray = tu
                pArray
                |> Array.filter(fun f -> not(f = "MRUList")) //We don't care
                |> Array.map(fun p -> {recentCommand = getRegistryValue p rKey}))
                    
        match uArray.Length with
        |x when x > 0 -> uArray |> Array.reduce Array.append
        |_ -> [||]


    let getUACSystemPolicies ()
        : UACPolicies =
        let uacKey = 
           match getRegistryKeyHKLM "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"  with
           |Some rKey -> rKey
           |None -> getThrowawayKey
        
        let consentPromptBehavior = getRegistryValue "ConsentPromptBehaviorAdmin" uacKey
        let enableLUA = getRegistryValue "EnableLUA" uacKey 
        let localAccounttokenFilterPolicy = getRegistryValue "LocalAccounttokenFilterPolicy" uacKey
        let filterAdministratorToken = getRegistryValue "FilterAdministratorToken" uacKey
                
        {consentPromptBehavior = consentPromptBehavior
         enableLUA = enableLUA
         localAccountTokenFilterPolicy = localAccounttokenFilterPolicy
         filterAdministratorToken = filterAdministratorToken
         }


    let getPShellEnv () 
        : PowerShellEnv =
        let pshellver2 = 
            match getRegistryKeyHKLM "SOFTWARE\\Microsoft\\PowerShell\\1\\PowerShellEngine"  with
            |Some rKey -> getRegistryValue "PowerShellVersion" rKey
            |None -> None
        let pshellver5 = 
            match getRegistryKeyHKLM "SOFTWARE\\Microsoft\\PowerShell\\3\\PowerShellEngine"  with
            |Some rKey -> getRegistryValue "PowerShellVersion" rKey
            |None -> None
        
        let pshellTLog = 
            collectLowIntegrityNames HKEY_LOCAL_MACHINE "SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription"
            |> Array.map(fun (rKey, pArray) -> 
                pArray
                |> Array.map(fun p -> getRegistryValue p rKey))
                |> Array.reduce Array.append
        let pshellMLog = 
            collectLowIntegrityNames HKEY_LOCAL_MACHINE "SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging"
            |> Array.map(fun (rKey, pArray) -> 
                pArray
                |> Array.map(fun p -> getRegistryValue p rKey))
                |> Array.reduce Array.append
        let pshellSLog = 
            collectLowIntegrityNames HKEY_LOCAL_MACHINE "SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging"
            |> Array.map(fun (rKey, pArray) -> 
                pArray
                |> Array.map(fun p -> getRegistryValue p rKey))
                |> Array.reduce Array.append

        {
         poshVersion2 = pshellver2
         poshVersion5 = pshellver5
         poshTLog = pshellTLog
         poshMLog = pshellMLog
         poshSLog = pshellSLog
         }


    let getInternetSettings ()
        : InternetSettings [] =
        //The InternetSettings key is a standard Windows key, so I feel safe
        //just yanking the value from the option.
        let sSettings = 
            let rKey = getRegistryKeyHKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" |> Option.get
            let proxyServer = getRegistryValue "ProxyServer" rKey
            let proxyOverride = getRegistryValue "ProxyOverride" rKey
            let proxyEnable = getRegistryValue "ProxyEnable" rKey
            {proxyServer = proxyServer; proxyOverride = proxyOverride; proxyEnable = proxyEnable}
        let uSettings = 
            let rKey = getRegistryKeyHKCU "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" |> Option.get
            let proxyServer = getRegistryValue "ProxyServer" rKey
            let proxyOverride = getRegistryValue "ProxyOverride" rKey
            let proxyEnable = getRegistryValue "ProxyEnable" rKey
            {proxyServer = proxyServer; proxyOverride = proxyOverride; proxyEnable = proxyEnable}
        [|sSettings;uSettings|]


    let getLSASettings ()
        : LSASettings =
        //LSA registry key is a standard Windows key, so I feel safe just
        //yanking the value from the option
         
        let rKey = getRegistryKeyHKLM "SYSTEM\\CurrentControlSet\\Control\\Lsa" |> Option.get
        let lsaResults = 
            lsaNames
            |> Array.map(fun n -> 
                getRegistryValue n rKey)
        
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
         }


    let getAuditSettings () : AuditSettings = 
        //This registry key is a standard Windows key, so I feel safe just
        //yanking the value from the option. I couldn't find any sort of
        //decent list of posible Audit values, so I'm checking for just the
        //one I found.
        let rKey = 
            getRegistryKeyHKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit"
            |> Option.get
        {processauditing = getRegistryValue "ProcessCreationIncludeCmdLine_Enabled" rKey}


    let getWEFSettings () : WEFSettings = 
        //Just bulk grabbing crap. Huge potential list of results.
        let names = 
            collectLowIntegrityNames HKEY_LOCAL_MACHINE "Software\\Policies\\Microsoft\\Windows\\EventLog\\EventForwarding\\SubscriptionManager"
        let results = 
            names
            |> Array.map(fun tu ->
                let rKey, pArray = tu
                pArray
                |> Array.map(fun p -> getRegistryValue p rKey))
            |> Array.reduce Array.append
        {policies = results}


    let getPuttySessions () : PuttySSHSession [] = 
        let subkeys = 
            match isHighIntegrity with
            |true -> collectHighIntegritySubKeysHKU "Software\\SimonTatham\\PuTTY\\Sessions"
            |false -> collectLowIntegritySubKeysHKCU "Software\\SimonTatham\\PuTTY\\Sessions"

        subkeys
        |> Array.map(fun tu ->
            let hive, path, pArray = tu
            let rKeyO = getRegistryKey hive path
            let rKey =     
                match rKeyO with
                |Some rKey -> rKey
                |None -> getThrowawayKey
            puttySessionNames
            |> Array.map(fun psn -> getRegistryValue psn rKey))
            |> Array.map(fun x -> 
                {hostname = x.[0]; username = x.[1]; publicKeyFile = x.[2]; portForwardings = x.[3]; connectionSharing = x.[4]})
    

    let getPuttyHostPublicKeys () : PuttyHostPublicKeys [] =
        let names = 
            match isHighIntegrity with
            |true -> collectHighIntegrityNames HKEY_USER "Software\\SimonTatham\\PuTTY\\SshHostKeys"
            |false -> collectLowIntegrityNames HKEY_CURRENT_USER "Software\\SimonTatham\\PuTTY\\SshHostKeys"
        
        names
        |> Array.map(fun tu ->
            let rKey, pArray = tu
            pArray
            |> Array.map(fun p -> getRegistryValue p rKey))
        |> Array.map(fun x -> {recentHostKeys = x} )

            