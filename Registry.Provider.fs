module Fetters.Registry.Provider

    open Fetters.dotNet.Common
    open Fetters.DomainTypes

    let getLAPSSettings () 
        : LapsSettings option =
        //Test to see if LAPS is present/configured, and if so, pull some data
        //Unfortunate extra 
        
        match getRegistryValueHKLM "Software\\Policies\\Microsoft Services\\AdmPwd" with
        |Some rKey -> 
            match getRegistryValue "AdmPwdEnabled" rKey with
            |Some rVal -> 
                let result = 
                    {lapsAdminAccountName = getRegistryValue "AdminAccountName" rKey
                     lapsPasswordComplexity = getRegistryValue "PasswordComplexity" rKey
                     lapsPasswordLength = getRegistryValue "PasswordLength" rKey
                     lapsPasswdProtection = getRegistryValue "PwdExpirationProtectionEnabled" rKey
                    }
                result |> Some
            |None -> None
        |None -> None