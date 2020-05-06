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
        match hive with
        |HKEY_LOCAL_MACHINE -> try Registry.LocalMachine.OpenSubKey(path) |> Some with _ -> None
        |HKEY_USER -> try Registry.Users.OpenSubKey(path) |> Some with _ -> None
        |HKEY_CURRENT_USER -> try Registry.CurrentUser.OpenSubKey(path) |> Some with _ -> None


    let getRegistryValueHKCU = getRegistryKey HKEY_CURRENT_USER
    let getRegistryValueHKU = getRegistryKey HKEY_USER
    let getRegistryValueHKLM = getRegistryKey HKEY_LOCAL_MACHINE


    let getRegistryValue (name: string) (key: RegistryKey) : RegistryValueType =
                
        let extracttype 
            (rType : RegistryValueKind)
            (rObj: obj)
            : RegistryValueType =
            match rType with
            |RegistryValueKind.DWord -> unbox<int32> rObj |> DWord
            |RegistryValueKind.QWord -> unbox<int64> rObj |> QWord
            |RegistryValueKind.Binary -> unbox<byte[]> rObj |> Binary
            |RegistryValueKind.String -> unbox<string> rObj |> String
            |RegistryValueKind.ExpandString -> unbox<string> rObj |> ExpandString
            |RegistryValueKind.MultiString -> unbox<string[]> rObj |> MultiString
            |_ -> "Unknown type" |> String
       
        let rObj = key.GetValue(name, "Name does not exist")
        let rType = try key.GetValueKind(name) |> Some with _ -> None

        match rType with
        |Some x -> extracttype x rObj
        |None -> "Name does not exist" |> String