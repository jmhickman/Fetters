module Fetters.Registry.Provider

    open Fetters.dotNet.Common
    open Fetters.DomainTypes

    
    let getLAPSSettings () 
        : LapsSettings option =
        //Test to see if LAPS is present/configured, and if so, pull some data
        //Will return a None since we test if the key is even present first
        match getRegistryKeyHKLM "Software\\Policies\\Microsoft Services\\AdmPwd" with
        |Some rKey -> 
            match getRegistryValue "AdmPwdEnabled" rKey with
            |Some rVal -> //Yes, we don't use this value.
                let result = {
                    lapsAdminAccountName = getRegistryValue "AdminAccountName" rKey
                    lapsPasswordComplexity = getRegistryValue "PasswordComplexity" rKey
                    lapsPasswordLength = getRegistryValue "PasswordLength" rKey
                    lapsPasswdProtection = getRegistryValue "PwdExpirationProtectionEnabled" rKey
                    }
                result |> Some
            |None -> None
        |None -> None

    
    let getAutoLogonSettings ()
        : AutoLogonSettings option =
        //Test to see if any autologon settings exist on the system.
        //Will return a Some even if the contents are None, since this key is
        //a default Windows key.
        match getRegistryKeyHKLM "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" with
        |Some rKey ->
            let result = {
                defaultDomainName = getRegistryValue "DefaultDomainName" rKey
                defaultUserName = getRegistryValue "DefaultUserName" rKey
                defaultPassword = getRegistryValue "DefaultPassword" rKey
                altDefaultDomainName = getRegistryValue "AltDefaultDomainName" rKey
                altDefaultUserName = getRegistryValue "AltDefaultUserName" rKey
                altDefaultPassword = getRegistryValue "AltDefaultPassword" rKey
                }
            result |> Some
        |None -> None


    let listSysmonconfig ()
        : SysmonConfig option =
        //Test to see if any Sysmon config is present on the system.
        //Will return a None if the relevant key is absent
        match getRegistryKeyHKLM "SYSTEM\\CurrentControlSet\\Services\\SysmonDrv\\Parameters" with
        |Some rKey ->
            let result = {
                hashingAlgorithm = getRegistryValue "HashingAlgorithm" rKey
                options = getRegistryValue "Options" rKey
                rules = getRegistryValue "Rules" rKey
                }
            result |> Some
        |None -> None


    let getRDPSavedConnections ()
        : RDPSavedConnection [] =
        //Performs differently if running high or low integrity.
        let collectHighIntegrity () =
            getRegistrySubKeyNamesHKU ""
            |> Array.filter(fun x ->  x.StartsWith("S-1-5") && not (x.Contains("_Classes")))
            |> Array.map(fun x -> 
                let path = sprintf "%s\\Software\\Microsoft\\Terminal Server Client\\Servers" x
                (HKEY_USER, path, getRegistrySubKeyNamesHKU path))
            |> Array.filter(fun f -> 
                let _, _, fs = f
                not ( fs |> Array.isEmpty))
         
        let collectLowIntegrity () =
            match getRegistrySubKeyNamesHKCU "Software\\Microsoft\\Terminal Server Client\\Servers" with
            | x when x.Length > 0 -> [|(HKEY_CURRENT_USER, "Software\\Microsoft\\Terminal Server client\\Servers", x)|]
            | _ -> [|(HKEY_CURRENT_USER, "Software\\Microsoft\\Terminal Server Client\\Servers", [||])|]
            
        let rArray = 
            match isHighIntegrity with
            |true -> collectHighIntegrity ()
            |false -> collectLowIntegrity ()
        
        let unflattened = 
            rArray 
            |> Array.map(fun tu ->
                let hive, path, pArray = tu
                pArray 
                |> Array.map(fun p ->
                    match getRegistryKey hive (path + "\\" + p) with
                    |Some rKey -> {host = p; usernameHint = getRegistryValue "UsernameHint" rKey}
                    |None -> {host = ""; usernameHint = None}
                    ))
                
        match unflattened.Length with
        |x when x > 0 -> unflattened |> Array.reduce Array.append
        |_ -> [||]
            
        
        
        