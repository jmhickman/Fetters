module Fetters.dotNet.Common

    open System
    open System.Net.NetworkInformation
    open System.Security.Principal
    open Microsoft.Win32

    open Fetters.DomainTypes

    let getCurrentRole 
        (role: WindowsBuiltInRole) 
        : bool = 
    // Ask Windows about the role of the user who owns the Fetters process.
    // This is linked to the privileges on the token, not necessarily the literal groups
    // the user is in. An administrative user will still come back False if their token
    // is not elevated, so be aware of the difference.

        let currentUser = WindowsPrincipal(WindowsIdentity.GetCurrent())
        currentUser.IsInRole(role)

    
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
            if rKey  = null then None else rKey |> Some
        |HKEY_USER -> 
            let rKey = Registry.Users.OpenSubKey(path)
            if rKey  = null then None else rKey |> Some
        |HKEY_CURRENT_USER -> 
            let rKey = Registry.CurrentUser.OpenSubKey(path)
            if rKey  = null then None else rKey |> Some

    let getRegistryValueHKCU = getRegistryKey HKEY_CURRENT_USER
    let getRegistryValueHKU = getRegistryKey HKEY_USER
    let getRegistryValueHKLM = getRegistryKey HKEY_LOCAL_MACHINE
    let getThrowawayKey = Registry.CurrentUser.OpenSubKey("Software")

    let getRegistryValue (name: string) (key: RegistryKey) : RegistryResult option =
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