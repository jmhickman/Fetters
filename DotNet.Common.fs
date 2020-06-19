//Licensed to the Apache Software Foundation (ASF) under one
//or more contributor license agreements.  See the NOTICE file
//distributed with this work for additional information
//regarding copyright ownership.  The ASF licenses this file
//to you under the Apache License, Version 2.0 (the
//"License"); you may not use this file except in compliance
//with the License.  You may obtain a copy of the License at

//  http://www.apache.org/licenses/LICENSE-2.0

//Unless required by applicable law or agreed to in writing,
//software distributed under the License is distributed on an
//"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
//KIND, either express or implied.  See the License for the
//specific language governing permissions and limitations
//under the License.

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
        sprintf "\n%*s%s%-*s" halfpad "" text halfpad ""

    
    let centerPrintN (text:string) =
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
        let spacer = Console.WindowWidth - (text1.Length + text2.Length) - 1
        printfn "%s%*s%s" text1 spacer "" text2

    
    let printKerbTickets tickets =
        tickets
        |> List.iter(fun ticket ->
            match ticket with
            |KerberosQueryTicket t -> 
                printfn "\n=== Ticket ==="
                printfn "Kerberos Realm: %s" t.realm
                printfn "Server: %s" t.serverName
                printfn "Lifespan: %A - %A" t.startTime t.endTime
                printfn "Renewal: %A" t.renewTime
                printfn "Encryption type: %s" t.encryptionType
                printfn "Ticket flags %A" t.ticketFlags
            |KerberosRetrieveTicket t ->
                printfn "\n=== TGT ==="
                printfn "Service: %s/%s.%s" t.serviceName t.client t.domain
                printfn "Target Domain: %s" t.targetDomain
                printfn "alternate domain: %s" t.altTargetDomain
                printfn "Sessionkey type: %s" t.sessionKeyType
                printfn "Key: %s" t.base64SessionKey
                printfn "Key Expiry: %A" t.keyExpiry
                printfn "Lifespan: %A - %A" t.startTime t.endTime
                printfn "Renewal: %A" t.renewTime
                printfn "Blobsz: %i" t.encodedSize
                printfn "Ticket: %s" t.base64EncodedTicket)
            
    
    let regValuePrint regV =
        match regV with
        |String s -> sprintf "%s" s
        |ExpandString s -> sprintf "%s" s
        |MultiString ss -> 
            Array.fold(fun s -> sprintf "%s ") "" ss
        |Binary b -> Convert.ToBase64String(b)
        |DWord i -> sprintf "%i" i
        |QWord i -> sprintf "%i" i


    let printCredentialRecord record =
        match record with
        |AWSCredential r ->
            sprintf "Original Path: %s" r.path |> cPrinter Blue
            printfn "Base64 File: %s\n"r.encodedFile
        |GoogleCredential r ->
            sprintf "Original Path: %s" r.path |> cPrinter Blue
            printfn "Base64 File: %s\n" r.encodedFile
        |AzureCredential r -> 
            sprintf "Original Path: %s" r.path |> cPrinter Blue
            printfn "Base64 File: %s\n" r.encodedFile
        |DPAPIMasterKey r -> 
            sprintf "Original SID: %s" r.userSID |> cPrinter Blue
            printfn "Base64 File: %s\n" r.encodedBlob
        |DPAPICredFile r ->
            sprintf "Original Path: %s" r.path |> cPrinter Blue
            printfn "Description: %s" r.description
            printfn "Base64 File: %s\n" r.encodedBlob
            

    let printFRecord record =
        match record with
        |Credential r -> printCredentialRecord r
        |FirefoxInfo r ->
            r.history 
            |> List.iter(fun rr ->
                sprintf "User path: %s" rr.path |> cPrinter Blue
                rr.url |> List.iter (printfn "%s"))
        |ChromeInfo r ->
            sprintf "User path: %s" r.history.path |> cPrinter Blue
            r.history.url
            |> List.iter (printfn "%s")

    let printPRecord record = 
        match record with
        |ArpTableByInd r ->
            let idx, remote = r.indexaddresses
            //sprintf "Index of interface: %i"  idx |> gPrinter Asterisk |> cPrinter Blue
            printfn "ARP entry %A::%s" (fst remote) (snd remote)
        |DomainSession r ->
            "=== Session Information ===" |> centerPrint |> cPrinter Blue
            if r.kerberosTGTcontents.Length > 0 then "=== TGT CONTENTS CAPTURED ===" |> gPrinter Plus |> cPrinter Green else ()
            printfn "Session User: %s\%s" r.domain r.username
            printfn "SID: %A" r.userSID
            printfn "UPN: %s" r.userPrincipalName
            printfn "Logon Server: %s\%s" r.logonServerDnsDomain r.logonServer
            printfn "Logon type: %s" r.logonType
            printfn "Logon time: %A" r.loginTime
            printfn "LogonID: %i\n" r.logonID
            printKerbTickets r.kerberosCachedTickets
            printKerbTickets r.kerberosTGTcontents
        |RdpSession r ->
            printfn "Remote Host: %s" r.hostName
            printfn "Remote IP: %A" r.remoteAddress
            printfn "Username: %s" r.username
            printfn "Session ID: %i" r.sessionID
            printfn "Session name: %s:%s\n" r.sessionName r.state
        |TCPConnection r ->
            sprintf "%s" r.connectionState |> gPrinter Plus |> cPrinter Blue
            r.service |> Option.defaultValue("Unknown_service") |> printf "%s@"
            sprintf "%A:%i <--> %A:%i  PID: %i" r.localAddress r.localport r.remoteAddress r.remoteport r.pid|> printfn "%s\n"
        |UDPListener r -> 
            r.service |> Option.defaultValue("Unknown_service") |> printf "%s@"
            sprintf "%A:%i" r.localAddress r.localport |> printfn "%s"
            printfn "PID %i\n" r.pid
        |TokenPrivileges r ->
            r.privileges |> List.iter (printfn "%s")
            printfn ""
        |VaultRecord r ->
            printfn "Name: %s" r.name
            printfn "Last modified: %A" r.lastModified
            r.resource |> Option.defaultValue("No resouce") |> printfn "%s"
            r.identity |> Option.defaultValue("No identity") |> printfn "%s"
            r.credential |> Option.defaultValue("No credential") |> printfn "%s"
            r.packageSid |> Option.defaultValue("No SID\n") |> printfn "%s"


    let unwrapRegistryResult (result: RegistryResult option) =
        result |> Option.map(fun o -> (sprintf "%s" o.name), regValuePrint o.value)

    let printRRecord record = 
        match record with
        |AuditSettings r ->
            unwrapRegistryResult r.processauditing |> Option.iter(fun p -> printfn "%s\n%s" (fst p) (snd p))
            printfn ""
        |AutoLogonSettings r ->
            unwrapRegistryResult r.defaultDomainName |> Option.iter (fun p -> printfn "Domain: %s" <| snd p)
            unwrapRegistryResult r.defaultUserName |> Option.iter(fun p -> printfn "Username: %s" <| snd p)
            unwrapRegistryResult r.defaultPassword |> Option.iter(fun p -> printfn "Password: %s" <| snd p)
            unwrapRegistryResult r.altDefaultDomainName |> Option.iter (fun p -> printfn "AltDomain: %s" <| snd p)
            unwrapRegistryResult r.altDefaultUserName |> Option.iter(fun p -> printfn "AltUsername: %s" <| snd p)
            unwrapRegistryResult r.altDefaultPassword |> Option.iter(fun p -> printfn "AltPassword: %s" <| snd p)
            printfn ""
        |AutorunSetting r ->
            printfn "%s" r.location
            unwrapRegistryResult r.value |> Option.iter(fun p -> printfn "Name: %s\nValue: %s" (fst p)(snd p))
            printfn ""
        |HistoryIE r ->
            printfn "Original path: %s" r.path
            unwrapRegistryResult r.url |> Option.iter(fun p -> printfn "URL: %s" <| snd p)
            printfn ""
        |InternetSettings r ->
            unwrapRegistryResult r.proxyServer |> Option.iter(fun p -> printfn "Proxy Server: %s" <| snd p)
            unwrapRegistryResult r.proxyEnable |> Option.iter(fun p -> printfn "Proxy Enabled: %s" <| snd p)
            unwrapRegistryResult r.proxyOverride |> Option.iter(fun p -> printfn "Proxy Override: %s" <| snd p)
            printfn ""
        |LapsSettings r ->
            unwrapRegistryResult r.lapsAdminAccountName |> Option.iter(fun p -> printfn "LAPS Admin account: %s" <| snd p)
            unwrapRegistryResult r.lapsPasswordLength |> Option.iter(fun p -> printfn "Password length: %s" <| snd p)
            unwrapRegistryResult r.lapsPasswordComplexity |> Option.iter(fun p -> printfn "Pass Complexity: %s" <| snd p)
            unwrapRegistryResult r.lapsPasswdProtection |> Option.iter(fun p -> printfn "Pass Protection: %s" <| snd p)
            printfn ""
        |LSASettings r ->
            unwrapRegistryResult r.lsaPid |> Option.iter(fun p -> printfn "LSA Pid: %s" <| snd p)
            unwrapRegistryResult r.prodType |> Option.iter(fun p -> printfn "Product type: %s" <| snd p)
            unwrapRegistryResult r.authorizationPkgs |> Option.iter(fun p -> printfn "Auth packages: %s" <| snd p)
            unwrapRegistryResult r.disdomcreds |> Option.iter(fun p -> printfn "Disable Domain creds: %s" <| snd p)
            unwrapRegistryResult r.everyoneAnon |> Option.iter(fun p -> printfn "Everyone Anonymous: %s" <| snd p)
            unwrapRegistryResult r.forceGuest |> Option.iter(fun p -> printfn "Force Guest: %s" <| snd p)
            unwrapRegistryResult r.limitBlankPwd |> Option.iter(fun p -> printfn "Limit Blank Passwords: %s" <| snd p)
            unwrapRegistryResult r.notificationPkgs |> Option.iter(fun p -> printfn "Notification packages: %s" <| snd p)
            unwrapRegistryResult r.restrictAnon |> Option.iter(fun p -> printfn "Restrict Anonymous Accounts: %s" <| snd p)
            unwrapRegistryResult r.restrictSAM |> Option.iter(fun p -> printfn "Restrict to SAM: %s" <| snd p)
            unwrapRegistryResult r.samConnAccnt |> Option.iter(fun p -> printfn "SAM Connected Accounts Exist: %s" <| snd p)
            unwrapRegistryResult r.secureboot |> Option.iter(fun p -> printfn "Secure Boot: %s" <| snd p)
        |PuttyHostPublicKeys r ->
            unwrapRegistryResult r.recentHostKeys |> Option.iter(fun p -> printfn "Host key: %s" <| snd p)
        |PuttySSHSession r ->
            unwrapRegistryResult r.username |> Option.iter(fun p -> printfn "Username: %s" <| snd p)
            unwrapRegistryResult r.hostname |> Option.iter(fun p -> printfn "Hostname: %s" <| snd p)
            unwrapRegistryResult r.portForwardings |> Option.iter(fun p -> printfn "Port Forwarding: %s" <| snd p)
            unwrapRegistryResult r.connectionSharing |> Option.iter(fun p -> printfn "Connection Sharing: %s" <| snd p)
            unwrapRegistryResult r.publicKeyFile |> Option.iter(fun p -> printfn "Public Key File: %s" <| snd p)
        |PowerShellEnv r ->
            unwrapRegistryResult r.poshVersion2 |> Option.iter(fun p -> printfn "PowerShell2: %s" <| snd p)
            unwrapRegistryResult r.poshVersion5 |> Option.iter(fun p -> printfn "PowerShell2+: %s" <| snd p)
            r.poshSLog 
            |> List.iter(fun x -> 
                unwrapRegistryResult x 
                |> Option.iter (fun p -> 
                printfn "%s: %s" (fst p) (snd p)))
            r.poshTLog 
            |> List.iter(fun x -> 
                unwrapRegistryResult x 
                |> Option.iter (fun p -> 
                    printfn "%s: %s" (fst p) (snd p)))
            r.poshMLog 
            |> List.iter(fun x -> 
                unwrapRegistryResult x 
                |> Option.iter (fun p -> 
                printfn "%s: %s" (fst p) (snd p)))
            printfn ""
        |RDPSavedConnection r ->
            printfn "Remotehost: %s" r.host
            unwrapRegistryResult r.usernameHint |> Option.iter(fun p -> printfn "Username Hint: %s" <| snd p)
            printfn ""
        |RecentCommand r ->
            unwrapRegistryResult r.recentCommand |> Option.iter(fun p -> printfn "Recent Command: %s" <| snd p)
            printfn ""
        |SysmonConfig r ->
            unwrapRegistryResult r.rules |> Option.iter(fun p -> printfn "Rules: %s" <| snd p)
            unwrapRegistryResult r.hashingAlgorithm |> Option.iter(fun p -> printfn "Hashing algorithm: %s" <| snd p)
            unwrapRegistryResult r.options |> Option.iter(fun p -> printfn "Options: %s" <| snd p)
            printfn ""
        |UACPolicies r ->
            unwrapRegistryResult r.consentPromptBehavior |> Option.iter(fun p -> printfn "Consent Prompt Behavior: %s" <| snd p)
            unwrapRegistryResult r.enableLUA |> Option.iter(fun p -> printfn "Enable LUA: %s" <| snd p)
            unwrapRegistryResult r.filterAdministratorToken |> Option.iter(fun p -> printfn "Local Account Token Filter Policy: %s" <| snd p)
            unwrapRegistryResult r.localAccountTokenFilterPolicy |> Option.iter(fun p -> printfn "Filter Administrator Token: %s" <| snd p)
            printfn ""
        |WEFSettings r ->
            r.policies |> List.iter(fun x -> unwrapRegistryResult x |> Option.iter(fun p -> printfn "Name: %s\nValue: %s" (fst p) (snd p )))
            printfn ""


    let printSRecord record = 
        match record with
        |EnvironmentVar r ->
            sprintf "Key: %s" r.environmentKey |> printfn "%s"
            sprintf "Value: %s" r.environmentVal |> printfn "%s\n"
        |Event4624 r ->
            printfn "Subject User: %s\%s" r.subjectDomainname r.subjectUsername
            printfn "User SID: %s" r.subjectSID
            printfn "LogonID: %s" r.subjectLogonId
            printfn "Target User: %s\%s" r.targetDomainname r.targetUsername
            printfn "Target SID: %s" r.targetUserSID
            printfn "Remote IP: %s" r.ipAddress
            printfn "Logon Type: %s" r.logonType
            printfn "Local Process: %s" r.processName
        |Event4648 r ->
            printfn "Subject User: %s\%s" r.subjectDomainname r.subjectUsername
            printfn "User SID: %s" r.subjectSID
            printfn "LogonID: %s" r.subjectLogonId
            printfn "Target User: %s\\%s\%s" r.targetDomainname r.targetServername r.targetUsername
            printfn "Remote IP: %s" r.ipAddress
            printfn "Local Process: %s" r.processName
            printfn "Time: %s" r.timeStamp
        |Firewall r ->
            sprintf "Firewall Profile: %s" r.profile |> cPrinter Blue
            r.rules 
            |> List.iter(fun f -> 
                printfn "Rule Name: %s" f.name
                printfn "Rule Description: %s" f.description
                printfn "Protocol number: %s" f.protocol
                printfn "Binary Name: %s" f.applicationName
                printfn "Binding addresses: %s" f.localAddresses
                printfn "Binding ports: %s" f.localPorts
                printfn "Remote addresses: %s" f.remoteAddresses
                printfn "Remote ports: %s" f.remotePorts
                printfn "Direction: %s" f.direction
                printfn "Applied to profiles: %s\n" f.profiles)
        |Network r -> ()
        |PC r ->
            sprintf "Hostname: %s" r.hostname |> printfn "%s"
            sprintf "Processor Core count: %i" r.processorCount |> printfn "%s"
        |WindowsDetails r ->
            printfn "User: %s" r.currentSession.username
            printfn "Current Working Directory: %s" r.currentSession.cwd
            match r.currentSession.isHighIntegrity, r.currentSession.isLocalAdmin with
            |true, _ -> sprintf "Process is high integrity!" |> gPrinter Bang |> cPrinter Red
            |false, true -> sprintf "Low-integrity process, but user is local administrator" |> gPrinter Plus |> cPrinter Green
            |false, false -> sprintf "Low integrity process, user lacks administrative privileges" |> gPrinter Minus |> cPrinter Green
            printfn "System architecture: %s" r.arch
            match r.buildBranch with
            |Some v -> 
                printf "%s: " v.name
                regValuePrint v.value |> printfn "%s"
            |None -> printfn "No build retrieved"
            match r.currentBuild with
            |Some v -> 
                printf "%s: " v.name
                regValuePrint v.value |> printfn "%s"
            |None -> printfn "No build retrieved"
            match r.productName with
            |Some v -> 
                printf "%s: " v.name
                regValuePrint v.value |> printfn "%s"
            |None -> printfn "No productname retrieved"
            match r.releaseId with
            |Some v -> 
                printf "%s: " v.name
                regValuePrint v.value |> printfn "%s"
            |None -> printfn "No release ID retrieved"


    let printWRecord record = 
        match record with
        |AV r ->
            printfn "Engine: %s" r.engine
            printfn "Product Executable: %s" r.productExe
            printfn "Reporting executable: %s\n" r.reportingExe
        |Disk r ->
            printfn "Name: %s" r.name
            printfn "Size(GB): %i" <| (r.size |> uint64) / 1073741274UL
            printfn "filesystem: %s\n" r.filesystem
        |Group r ->
            printfn "SID + Name: %s\%s" r.sid r.name
            printfn "Members:"
            match r.members with
            |x when x.Length > 0  -> x |> List.iter (printfn "%s")
            |_ -> printf "No members"
            printfn ""
        |MappedDrive r ->
            printfn "Share name: %s" r.localName
            printfn "Connected account name: %s" r.userName
            printfn "State: %s" r.connectionState
            printfn "Persistent: %s" r.persistent
            printfn "Remote Path: %s" r.remotePath
            printfn "Remote Name: %s\n" r.remoteName
        |Service r ->
            printfn "Service Name: %s" r.serviceName
            printfn "Display Name: %s" r.serviceDisplayname
            printfn "Company: %s" r.serviceCompany
            printfn "Description: %s" r.serviceDescription
            printfn "Binary path: %s" r.serviceBinpath
            printfn "Startup-type: %s" r.serviceStarttype
            printfn "Running: %s" r.serviceRunning
            printfn "DotNet binary: %b\n" r.serviceIsdotnet
        |NetworkShare r ->
            printfn "Name: %s" r.shareName
            printfn "Description: %s" r.shareDesc
            printfn "Path: %s\n" r.sharePath
        |Patch r ->
            printfn "Description: %s" r.description
            printfn "KB: %s" r.hotfixId
            printfn "Install date: %s\n" r.installedOn
        |Process r ->
            printfn "PID\Process name: %s\%s" r.pid r.processName
            printfn "Binary path: %s" r.processBinpath
            printfn "Process arguments: %s" r.processInvocation
            printfn "Owner: %s\n" r.processOwner
        |User r ->
            printfn "UPN: %s\%s" r.domain r.name
            printfn "User SID: %s" r.sid
            r.groups |> List.iter(fun rr -> printfn "SID: %s Name: %s" (fst rr) (snd rr))
            printfn ""
        

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
        let sids = [for c in WindowsPrincipal(WindowsIdentity.GetCurrent()).Claims do yield c]
        sids |> List.map(fun s -> s.Value) |> List.contains("S-1-5-32-544")

    ///////////////////////////
    //Common Registry Functions
    ///////////////////////////
    
    let getRegistryKey hive path : RegistryKey option =
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

    
    let getRegistrySubKeyNames hive path : string []  =
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
        name (key: RegistryKey) : RegistryResult option =
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
    let private collectHighIntegritySubKeysHKU path =
        getRegistrySubKeyNamesHKU ""
        |> Array.filter(fun x ->  x.StartsWith("S-1-5") && not (x.Contains("_Classes")))
        |> Array.map(fun sidPath -> 
            let fpath = sprintf "%s\\%s" sidPath path 
            (HKEY_USER, fpath, getRegistrySubKeyNamesHKU fpath))
        |> Array.filter(fun f -> 
            let _, _, fs = f
            not (fs |> Array.isEmpty))

 
    let private collectLowIntegritySubKeys path =
        match getRegistrySubKeyNamesHKCU path with
        | xa when xa.Length > 0 -> [|(HKEY_CURRENT_USER, path, xa)|]
        | _ -> [|(HKEY_CURRENT_USER, path, [||])|]
        
    
    //// Gather Registry Names ////
    let private collectHighIntegrityNames hive path : (RegistryKey * string array) array =
        getRegistrySubKeyNames hive ""
        |> Array.filter(fun x ->  x.StartsWith("S-1-5") && not (x.Contains("_Classes")))
        |> Array.map(fun sidPath -> 
            let rKey = getRegistryKeyHKU (sidPath + "\\" + path) |> extractRegistryKey
            (rKey, rKey.GetValueNames()))
        |> Array.filter(fun f -> 
            not ( snd f |> Array.isEmpty))


    let collectLowIntegrityNames hive path : (RegistryKey * string array) array  =
        let rKey = getRegistryKey hive path |> extractRegistryKey
        [|rKey, rKey.GetValueNames()|]
        
        
    let retrieveSubKeysByIntegrity path : (RegHive * string * string array) array =
        match isHighIntegrity () with
        |true -> collectHighIntegritySubKeysHKU path
        |false -> collectLowIntegritySubKeys path


    let retrieveNamesByIntegrity hiveHigh hiveLow path : (RegistryKey * string[])[] =
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
    
    
    let getLocalUserFolders sysroot : string array =
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
    let listChildFiles path : string array =
        Directory.GetFiles(path)

    
    let listChildDirectories path : string array = 
        Directory.GetDirectories(path)


    let fileExistsAtLocation path : bool =
        File.Exists(path)

    
    let dirExistsAtLocation path : bool =
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


    let openFileReader path : FileStream =
        File.OpenRead(path)


    let openStreamReader path : StreamReader option =
        //utilize with 'use' keyword so that it closes once it leaves scope
        try 
            let fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite) 
            new StreamReader(fs) |> Some    
        with _ -> None

    
    let nullStream () = 
        //When I have to give back a StreamReader but want it to do nothing
        let dummy = new MemoryStream(1)
        new StreamReader(dummy)

    
    let yieldLineSequence path : string seq =
        seq{use sr = 
               match openStreamReader path with
               |Some sr -> sr
               |None -> nullStream ()
        
            while not sr.EndOfStream do 
            yield sr.ReadLine()
            }

    
    let yieldWholeFile path : string =
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


    let encodeEntireFileB64 path : string = 
        yieldWholeFile path |> createByteArray |> createb64String

    ////////////////////////////
    //Common Event Log Functions  
    ////////////////////////////

    let createEventQuery log query =
        let ev = new EventLogQuery(log, PathType.LogName, query)
        ev.ReverseDirection = true |> ignore
        ev

    
    let eventFilter account =
        filteredEventAccounts |> List.contains(account)

    
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