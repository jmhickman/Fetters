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

    //////////
    //Registry
    //////////

    let getRegistryValue (hive: string) (path: string, name: string) : RegistryResult =

        let blank = {name=""
                     value = "" |> String}
        blank


    let getRegistryValueHKCU = getRegistryValue "HKEY_CURRENT_USER"
    let getRegistryValueHKU = getRegistryValue "HKEY_USER"
    let getRegistryValueHKLM = getRegistryValue "HKEY_LOCAL_MACHINE"