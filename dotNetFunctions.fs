﻿module Fetters.dotNet.Common

    open System
    open System.Net.NetworkInformation
    open System.Security.Principal
    open Microsoft.Win32

    open Fetters.DomainTypes
    
    ///////////////////
    //Process Integrity
    ///////////////////

    let getCurrentRole 
        (role: WindowsBuiltInRole) 
        : bool = 
    // Ask Windows about the role of the user who owns the Fetters process.
    // This is linked to the privileges on the token, not necessarily the literal groups
    // the user is in. An administrative user will still come back False if their token
    // is not elevated, so be aware of the difference.

        WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(role)

    //Partial application for testing if the process is high integrity
    let isHighIntegrity = getCurrentRole WindowsBuiltInRole.Administrator

    //////////
    //Registry
    //////////
    
    let getRegistryKey (hive: RegHive) (path: string) : RegistryKey option =
        //Because Windows, invalid Registry Keys return null instead of an 
        //error. So I have to do this awkward stuff because 'Some null' is,
        //hilariously, valid.
        match hive with
        |HKEY_LOCAL_MACHINE -> 
            let rKey = Registry.LocalMachine.OpenSubKey(path)
            rKey |> Option.ofObj
        |HKEY_USER -> 
            let rKey = Registry.Users.OpenSubKey(path)
            rKey |> Option.ofObj
        |HKEY_CURRENT_USER -> 
            let rKey = Registry.CurrentUser.OpenSubKey(path)
            rKey |> Option.ofObj
            

    let getRegistryKeyHKCU = getRegistryKey HKEY_CURRENT_USER
    let getRegistryKeyHKU = getRegistryKey HKEY_USER
    let getRegistryKeyHKLM = getRegistryKey HKEY_LOCAL_MACHINE
    
    let getThrowawayKeyOption = getRegistryKeyHKCU "Software"
    let getThrowawayKey = Registry.CurrentUser.OpenSubKey("Software")

    
    let getRegistrySubKeyNames (hive: RegHive) (path: string) : string []  =
        match hive with
        |HKEY_LOCAL_MACHINE -> 
            let rKey = Registry.LocalMachine.OpenSubKey(path)
            if rKey = null then [||] 
            else  
                rKey.GetSubKeyNames()
                |> Array.filter(fun x -> not(x = null))
        |HKEY_USER -> 
            let rKey = Registry.Users.OpenSubKey(path)
            if rKey = null then [||] 
            else    
               rKey.GetSubKeyNames()
               |> Array.filter(fun x -> not(x = null))
        |HKEY_CURRENT_USER ->
            let rKey = Registry.CurrentUser.OpenSubKey(path)
            if rKey = null then [||] 
            else    
                rKey.GetSubKeyNames()
                |> Array.filter(fun x -> not(x = null))

    let getRegistrySubKeyNamesHKCU = getRegistrySubKeyNames HKEY_CURRENT_USER
    let getRegistrySubKeyNamesHKU = getRegistrySubKeyNames HKEY_USER
    let getRegistrySubKeyNamesHKLM = getRegistrySubKeyNames HKEY_LOCAL_MACHINE
    
    
    let getRegistryValue 
        (name: string) (key: RegistryKey) : RegistryResult option =
        //This doesn't take an RegistryKey option because I don't want to reach
        //this function with Nones. There's no point.
        let extractType 
            (rKind : RegistryValueKind)
            (rObj: obj)
            : RegistryValueType =
            match rKind with
            |RegistryValueKind.DWord -> unbox<int32> rObj |> DWord
            |RegistryValueKind.QWord -> unbox<int64> rObj |> QWord
            |RegistryValueKind.Binary -> unbox<byte[]> rObj |> Binary
            |RegistryValueKind.String -> unbox<string> rObj |> String
            |RegistryValueKind.ExpandString -> unbox<string> rObj |> ExpandString
            |RegistryValueKind.MultiString -> unbox<string[]> rObj |> MultiString
            |_ -> "Unknown type" |> String
       
        let rObj = key.GetValue(name, "Name does not exist")
        let rKind = try key.GetValueKind(name) |> Some with _ -> None
        match rKind with
        |Some rKind -> {name = name; value = extractType rKind rObj} |> Some
        |None -> None
    
    
    let extractRegistryKey (rKeyO: RegistryKey option) : RegistryKey =
        match rKeyO with
        |Some rKey -> rKey
        |None -> getThrowawayKey
 
    //// Gather Sub Keys ////
    let collectHighIntegritySubKeysHKU (path: string) =
        getRegistrySubKeyNamesHKU ""
        |> Array.filter(fun x ->  x.StartsWith("S-1-5") && not (x.Contains("_Classes")))
        |> Array.map(fun sidPath -> 
            let fpath = sprintf "%s\\%s" sidPath path 
            (HKEY_USER, fpath, getRegistrySubKeyNamesHKU fpath))
        |> Array.filter(fun f -> 
            let _, _, fs = f
            not (fs |> Array.isEmpty))

 
    let collectLowIntegritySubKeys (path: string) =
        match getRegistrySubKeyNamesHKCU path with
        | xa when xa.Length > 0 -> [|(HKEY_CURRENT_USER, path, xa)|]
        | _ -> [|(HKEY_CURRENT_USER, path, [||])|]
        
    //// Gather Key Names ////
    let collectHighIntegrityNames (hive: RegHive) (path: string) : (RegistryKey * string [])[] =
        getRegistrySubKeyNames hive ""
        |> Array.filter(fun x ->  x.StartsWith("S-1-5") && not (x.Contains("_Classes")))
        |> Array.map(fun sidPath -> 
            let rKey = getRegistryKeyHKU (sidPath + "\\" + path) |> extractRegistryKey
            (rKey, rKey.GetValueNames()))
        |> Array.filter(fun f -> 
            not ( snd f |> Array.isEmpty))


    let collectLowIntegrityNames (hive: RegHive) (path: string) : (RegistryKey * string [])[] =
        let rKey = getRegistryKey hive path |> extractRegistryKey
        [|rKey, rKey.GetValueNames()|]
        
    
    let retrieveSubKeysByIntegrity (path: string) : (RegHive * string * string[])[] =
        match isHighIntegrity with
        |true -> collectHighIntegritySubKeysHKU path
        |false -> collectLowIntegritySubKeys path


    let retrieveNamesByIntegrity 
        (hiveHigh: RegHive)
        (hiveLow: RegHive)
        (path: string) 
        : (RegistryKey * string[])[] =
        match isHighIntegrity with
        |true -> collectHighIntegrityNames hiveHigh path
        |false -> collectLowIntegrityNames hiveLow path
