module Fetters.Registry.Provider

    open Fetters.dotNet.Common
    open Fetters.DomainTypes

    let getLAPSSettings () 
        : LapsSettings option =
        //Test to see if LAPS is present/configured, and if so, pull some data
        //Unfortunate extra 
        let rKeyT = 
            match getRegistryValueHKLM "Software\\Policies\\Microsoft Services\\AdmPwd" with
            |Some rKey -> (rKey, rKey |> Some)
            |None -> (getThrowawayKey, None)
        let lKey, rKey = rKeyT
        let lapsEnabled =
            match rKey with
            |Some key -> getRegistryValue "AdmPwdEnabled" key
            |None -> None
        match lapsEnabled with
        |Some v -> //Yes, we don't actually care about the Result here.
            let result = 
                {lapsAdminAccountName = getRegistryValue "AdminAccountName" lKey
                 lapsPasswordComplexity = getRegistryValue "PasswordComplexity" lKey
                 lapsPasswordLength = getRegistryValue "PasswordLength" lKey
                 lapsPasswdProtection = getRegistryValue "PwdExpirationProtectionEnabled" lKey
                }
            result |> Some
        |None -> None