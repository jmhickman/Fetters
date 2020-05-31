module Fetters.DotNet.Common

    open System
    open System.Collections
    open System.Diagnostics
    open System.Diagnostics.Eventing.Reader
    open System.IO
    open System.Reflection
    open System.Runtime.InteropServices
    open System.Text
    open System.Text.RegularExpressions
    open System.Security.Principal
    open Microsoft.Win32

    open Fetters.DomainTypes
    open Fetters.Lists
    
    ///////////////////////
    //Common Misc Functions    
    ///////////////////////

    let createStopWatch () =
        new Stopwatch()


    let startWatch (stopwatch: Stopwatch) =
        stopwatch.Start()

    
    let stopWatch (stopwatch: Stopwatch) =
        stopwatch.Stop()


    let getExecutiontime (stopwatch: Stopwatch) = 
        stopwatch.ElapsedMilliseconds


    let gPrinter (g: Glyph) text =
        match g with
        |Asterisk -> "[*] " + text
        |Plus ->  "[+] " + text
        |Minus ->  "[-] " + text
        |At ->  "[@] " + text
        |Bang ->  "[!] " + text
        |Octothorpe -> "[#] " + text
    
    
    let setCColor col text = 
        Console.ForegroundColor <- col
        printfn "%s" text
        Console.ResetColor()

    
    let cPrinter col text = 
        match col with
        |Red -> setCColor ConsoleColor.Red text
        |Yellow  -> setCColor ConsoleColor.Yellow text
        |Green -> setCColor ConsoleColor.Green text
        |Blue -> setCColor ConsoleColor.Blue text


    let centerPrint (text:string) =
        let halfpad = (Console.WindowWidth - text.Length ) / 2
        sprintf "%*s%s%-*s" halfpad "" text halfpad ""


    let leftQuarPrint text = 
        let quarW = Console.WindowWidth / 4
        sprintf "%*s" quarW text


    let rightQuarPrint text = 
        let quarW = Console.WindowWidth / 4
        sprintf "%-*s" quarW text


    let leftTenthPrint text = 
        let tenW = Console.WindowWidth / 10
        sprintf "%*s" tenW text


    let rightTenthPrint text = 
        let tenW = Console.WindowWidth / 10
        sprintf "%-*s" tenW text


    let splitPrint (text1:string, text2:string) = 
        let spacer = Console.WindowWidth - (text1.Length + text2.Length)
        printfn "%s%*s%s" text1 spacer "" text2



    /////////////////////////////////////
    //Common Windows User/Group functions
    /////////////////////////////////////

    let getCurrentRole (role: WindowsBuiltInRole) : bool = 
    // Ask Windows about the role of the user who owns the Fetters process.
    // This is linked to the privileges on the token, not necessarily the literal groups
    // the user is in. An administrative user will still come back False if their token
    // is not elevated, so be aware of the difference.

        WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(role)
        

    //Convenience alias for testing if the process is high integrity
    let isHighIntegrity () = getCurrentRole WindowsBuiltInRole.Administrator

    
    let getCurrentUsersGroups () =
        //Retrieve group SIDs and sort them
        let grps = WindowsIdentity.GetCurrent().Groups
        [for g in grps do yield g.Value, g.Translate(typeof<NTAccount>)|> string] 
        |> List.sortBy(fun g -> (fst g).Length)


    let isLocalAdmin () = 
        //I don't trust the PInvoke version of this to work properly or give
        //sensible output. This alternative is native .Net and in my testing
        //did the business.
        //let sid = getTokenGroupSIDs () 
        let sid = [for c in WindowsPrincipal(WindowsIdentity.GetCurrent()).Claims do yield c]
        sid |> List.map(fun s -> s.Value) |> List.contains("S-1-5-32-544")

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
    
    //// Get Registry values ////
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
    let private collectHighIntegritySubKeysHKU (path: string) =
        getRegistrySubKeyNamesHKU ""
        |> Array.filter(fun x ->  x.StartsWith("S-1-5") && not (x.Contains("_Classes")))
        |> Array.map(fun sidPath -> 
            let fpath = sprintf "%s\\%s" sidPath path 
            (HKEY_USER, fpath, getRegistrySubKeyNamesHKU fpath))
        |> Array.filter(fun f -> 
            let _, _, fs = f
            not (fs |> Array.isEmpty))

 
    let private collectLowIntegritySubKeys (path: string) =
        match getRegistrySubKeyNamesHKCU path with
        | xa when xa.Length > 0 -> [|(HKEY_CURRENT_USER, path, xa)|]
        | _ -> [|(HKEY_CURRENT_USER, path, [||])|]
        
    
    //// Gather Registry Names ////
    let private collectHighIntegrityNames (hive: RegHive) (path: string) : (RegistryKey * string [])[] =
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
        match isHighIntegrity () with
        |true -> collectHighIntegritySubKeysHKU path
        |false -> collectLowIntegritySubKeys path


    let retrieveNamesByIntegrity 
        (hiveHigh: RegHive)
        (hiveLow: RegHive)
        (path: string) 
        : (RegistryKey * string[])[] =
        match isHighIntegrity () with
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
    
    
    let getLocalUserFolders (sysroot: string) : string array =
        //Instead of computing the list of local user directories we have
        //access to over and over, build the list once and be done with it.
        let userRoot = sysroot + "Users\\"
        Directory.GetDirectories(userRoot) |> Array.except(filterUserFolders)

    
    let createNowTime () : DateTime =
        DateTime.Now
    
    
    let createWeekTimeWindow () : DateTime =
        //Some functions want a time window over which they retrieve data.
        DateTime.Now.AddDays(-7.0) //why is this forced to be a float when its an int in Seatbelt?


    //// File IO helpers ////
    let listChildFiles (path: string) : string array =
        Directory.GetFiles(path)

    
    let listChildDirectories (path: string) : string array = 
        Directory.GetDirectories(path)


    let fileExistsAtLocation (path: string) : bool =
        File.Exists(path)

    
    let dirExistsAtLocation (path: string) : bool =
        Directory.Exists(path)

    
    let getFileVersionInfo path : string =
        try
            (FileVersionInfo.GetVersionInfo path).CompanyName
        with
        | _ -> ""

    let getDotNetAssembly path : bool =
        try 
            AssemblyName.GetAssemblyName path |> ignore
            true
        with 
        | :? System.BadImageFormatException -> true
        | _ -> false


    //let isQuotedPath path : ServiceBinaryPath =
        

    let openFileReader (path: string) : FileStream =
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
    

    let getByteSection startb endb path =
        let filestream = openFileReader path
        filestream.Seek(startb, SeekOrigin.Begin) |> ignore
        let b = Array.zeroCreate endb
        filestream.Read(b, 0, endb) |> ignore
        filestream.Dispose()
        b

    //// Regex Helpers ////
    let createMatchRegex regstring : Regex =
        new Regex(regstring)


    let matchStringRegex (reg: Regex) matchstring = 
        let m = reg.Match(matchstring)
        match m.Success with
        |true -> m.Groups.[0].ToString().Trim()
        |false -> ""
        
    
    let matchWMIServiceString path =
        let m = Regex.Match(path, @"^\W*([a-z]:\\.+?(\.exe|\.dll|\.sys))\W*", RegexOptions.IgnoreCase)
        match m.Success with
        |true -> m.Groups.[1].ToString()
        |false -> "false"

    //// Base64 Helpers ////
    let createByteArray (bstring: string) : byte array =
        UTF8Encoding.ASCII.GetBytes(bstring)

    
    let createb64String bArray : string =
        Convert.ToBase64String(bArray)


    let encodeEntireFileB64 (path: string) : string = 
        yieldWholeFile path |> createByteArray |> createb64String

    ////////////////////////////
    //Common Event Log Functions  
    ////////////////////////////

    let createEventQuery (log: string) (query: string) =
        let ev = new EventLogQuery(log, PathType.LogName, query)
        ev.ReverseDirection = true |> ignore
        ev

    
    let eventFilter x =
        filteredEventAccounts |> List.contains(x)

    
    let createEventLogReader (q: EventLogQuery) = 
        new EventLogReader(q)


    let extractEventLogs (e: EventLogReader) =
        let ev _ = e.ReadEvent()
        Seq.initInfinite ev 
        |> Seq.takeWhile (fun r -> not(r = null)) 
        |> Seq.filter(fun f -> not(eventFilter <| f.Properties.[5].Value.ToString()))
        |> Seq.map(fun r -> 
            r.TimeCreated.ToString(), [for p in r.Properties do yield p.Value |> string])
        
    ///////////////////////////
    //Common Firewall Functions
    ///////////////////////////

    let createFirewallObj () : obj =
        let x = Type.GetTypeFromCLSID("E2B3C97F-6AE1-41AC-817A-F6F92166D7DD" |> Guid)
        Activator.CreateInstance x


    let closeCOMHandle (x: obj) =
        Marshal.ReleaseComObject x

    
    let getFProfileProperty (fObj: obj) = 
        fObj.GetType().InvokeMember("CurrentProfileTypes", BindingFlags.GetProperty, null, fObj, null)


    let getFRuleProperty (fObj: obj) =
        fObj.GetType().InvokeMember("Rules", BindingFlags.GetProperty, null, fObj, null)


    let getFRuleEnumerator (fObj: obj) = 
        fObj, (fObj.GetType().InvokeMember("GetEnumerator", BindingFlags.InvokeMethod, null, fObj, null)) :?> IEnumerator
    
    
    let extractFirewallRules (fObj: obj, rEnum: IEnumerator) =
        let readit _ = rEnum.Current
        let rules =    
            Seq.initInfinite readit
            |> Seq.takeWhile (fun i -> rEnum.MoveNext())
            |> Seq.filter (fun f -> not(f = null) && (f.GetType().InvokeMember("Enabled", BindingFlags.GetProperty, null, f, null).ToString() = "True"))
            |> Seq.toList
        closeCOMHandle fObj |> ignore
        rules


    let getRawRules () = 
        createFirewallObj () |> getFRuleProperty |> getFRuleEnumerator |> extractFirewallRules

    
    let denyOnlyFilter (l: obj list) = 
        l |> List.filter(fun f -> (f.GetType().InvokeMember("Action", BindingFlags.GetProperty, null, f, null).ToString() = "0"))
    
    
    let allowFilter (l: obj list) =
        l |> List.filter(fun f -> (f.GetType().InvokeMember("Action", BindingFlags.GetProperty, null, f, null).ToString() = "1"))

    
    let getFirewallAttr (fObj : obj) (attrName: string) =
        fObj.GetType().InvokeMember(attrName, BindingFlags.GetProperty, null, fObj, null) |> string

    
    
    
        

        