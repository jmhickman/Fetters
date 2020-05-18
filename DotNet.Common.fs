﻿module Fetters.DotNet.Common

    open System
    open System.Diagnostics.Eventing.Reader
    open System.IO
    open System.Text
    open System.Text.RegularExpressions
    open System.Net.NetworkInformation
    open System.Security
    open Microsoft.Win32

    open Fetters.DomainTypes
    open Fetters.Lists
    
    ////////////////////////////////////
    //Common Process Integrity Functions
    ////////////////////////////////////

    let getCurrentRole 
        (role: Principal.WindowsBuiltInRole) 
        : bool = 
    // Ask Windows about the role of the user who owns the Fetters process.
    // This is linked to the privileges on the token, not necessarily the literal groups
    // the user is in. An administrative user will still come back False if their token
    // is not elevated, so be aware of the difference.

        Principal.WindowsPrincipal(Principal.WindowsIdentity.GetCurrent()).IsInRole(role)

    //Partial application for testing if the process is high integrity
    let isHighIntegrity = getCurrentRole Principal.WindowsBuiltInRole.Administrator

    ///////////////////////////
    //Common Registry Functions
    ///////////////////////////
    
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

    ///////////////////////
    //Common File Functions
    ///////////////////////

    //// Fetters Init Code ////
    let buildSystemDriveRoot () : string = 
        //Instead of computing the system root over and over, build it once
        //and be done with it.
        sprintf "%s\\" <| Environment.GetEnvironmentVariable("SystemDrive")
    
    
    let buildLocalUserFolders (sysroot: string) = //: string list =
        //Instead of computing the list of local user directories we have
        //access to over and over, build the list once and be done with it.
        let userRoot = sysroot + "Users\\"
        Directory.GetDirectories(userRoot) |> Array.except(filterUserFolders)

    let createWeekTimeWindow () : DateTime =
        //Some functions want a time window over which they retrieve data.
        DateTime.Now.AddDays(-7.0) //why is this forced to be a float when its an int in Seatbelt?

    //// File IO helpers ////
    let prependPath (path: string) (pathArray: string array) : string array =
        pathArray |> Array.map(fun f -> path + "\\" + f)

    
    let listChildDirectories (path: string) : string array = 
        Directory.GetDirectories(path)


    let fileExistsAtLocation (path: string) : bool =
        File.Exists(path)

    
    let dirExistsAtLocation (path: string) : bool =
        Directory.Exists(path)


    let openFileReader (path: string) : FileStream =
        //utilize with 'use' keyword so that it closes once it leaves scope
        File.OpenRead(path)


    let openStreamReader (path: string) : StreamReader option =
        //utilize with 'use' keyword so that it closes once it leaves scope
        try 
            let fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite) 
            new StreamReader(fs) |> Some    
        with _ -> None

    
    let nullStream () = 
        //When I have to give back a StreamReader but want it to do nothing
        let dummy = new MemoryStream(1)
        dummy.WriteByte(9uy)
        new StreamReader(dummy)

    let yieldLineSequence (path: string) : string seq =
        seq{ use sr = 
                match openStreamReader path with
                |Some sr -> sr
                |None -> nullStream ()
        
             while not sr.EndOfStream do 
             yield sr.ReadLine()}

    
    let yieldWholeFile (path: string) : string =
        use sr = 
            match openStreamReader path with
            |Some sr -> sr
            |None -> nullStream ()
        sr.ReadToEnd()
    

    let fileExistsInArray (fileArray: string array) (file: string) : bool =
        fileArray |> Array.contains file
    
    
    let keepFilesInArrayFromSource (fileSet: string array) (fileSource: string array) =
        fileSet |> Array.filter (fileExistsInArray fileSource)
    

    let createMatchRegex regstring : Regex =
        new Regex(regstring)


    let matchStringRegex (reg: Regex) matchstring = 
        let m = reg.Match(matchstring)
        match m.Success with
        |true -> m.Groups.[0].ToString().Trim()
        |false -> ""
        
        

    let createByteArray (bstring: string) : byte array =
        UTF8Encoding.ASCII.GetBytes(bstring)

    
    let createb64String bArray : string =
        Convert.ToBase64String(bArray)


    let encodeEntireFileB64 (path: string) : string = 
        yieldWholeFile path |> createByteArray |> createb64String


    (*let checkUserSIDInACL (sidList: Principal.IdentityReference list) (userSID: Principal.IdentityReference)  =
        //Is an individual SID in the list of SIDs from the ACL on the filesystem object
        sidList |> List.contains userSID


    let checkUserSIDsInACL 
        (userSIDList: Principal.IdentityReference list) 
        (aclSIDList: Principal.IdentityReference list) =
        //Checks each SID on the user's token to see if it exists in the ACL on the filesystem object
        userSIDList |> List.filter (checkUserSIDInACL aclSIDList)*)