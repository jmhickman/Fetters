
open System

open Fetters.Lists
open Fetters.DomainTypes 
open Fetters.PInvoke.Provider
open Fetters.WMI.Provider
open Fetters.DotNet.Common
open Fetters.DotNet.Provider
open Fetters.Registry.Provider

//////
//Init
//////

let initialSetup () =
    let s = buildSystemDriveRoot ()
    let l = getLocalUserFolders s
    let lAdm = isLocalAdmin ()
    let hi = isHighIntegrity ()
    let now = createNowTime ()
    let wWeek = createWeekTimeWindow ()

    {sysRoot = s; luserFolders = l; localAdmin = lAdm; highIntegrity = hi; now = now; windowWeek = wWeek}

let recordPrinter record =
    match record with
    |FettersFilesystemRecord r-> printFRecord r
    |FettersPInvokeRecord r -> printPRecord r
    |FettersRegistryRecord r -> printRRecord r
    |FettersSpecialRecord r -> printSRecord r
    |WmiRecord r -> printWRecord r

let (|FunctionName|_|) (functionname: string) = 
    if functionNames |> List.contains (functionname.ToLower()) then Some (functionname.ToLower()) else None

let rec createArgumentRecord args (initArgs:ProgramArguments ) : ProgramArguments =
    match args with
    | [] -> initArgs
    | "getprocessinformation"::tail -> 
        let uArgs = {initArgs with functionGroup = ["getprocessinformation"]; terseHelp = false}
        uArgs
    | "-hh"::tail ->
        let uArgs = {initArgs with fullHelp = true; terseHelp = false}
        createArgumentRecord tail uArgs 
    |FunctionName x::tail -> 
        let uArgs = {initArgs with functionGroup = x::initArgs.functionGroup; terseHelp = false}
        createArgumentRecord tail uArgs
    |"all"::tail ->
        let uArgs = {initArgs with functionGroup = systemGroup @ userGroup @ extraGroup; terseHelp = false}
        uArgs
    |"extra"::tail ->
        let uArgs = {initArgs with functionGroup = extraGroup; terseHelp = false}
        uArgs
    |"system"::tail ->
        let uArgs = {initArgs with functionGroup = systemGroup; terseHelp = false}
        uArgs
    |"user"::tail ->
        let uArgs = {initArgs with functionGroup = userGroup ; terseHelp = false}
        uArgs
    | x::tail ->
        sprintf "Unknown command '%s'" x |> cPrinter Red
        createArgumentRecord tail initArgs


let printTerseHelp () =
    "FETTERS" |> centerPrint |> cPrinter Yellow
    "release: beta 2" |> centerPrint |> cPrinter Yellow
    printfn "\n\n"
    "fetters [group]" |> leftTenthPrint |> cPrinter Yellow
    "fetters [<functionname1>..<functionnameN>]" |> leftTenthPrint |> cPrinter Yellow
    printfn "\n"
    "Options:" |> leftTenthPrint |> cPrinter Green
    "-hh              Shows verbose help for each enumeration function" |> cPrinter Blue
    "system           Runs enumerations targeting the system" |> cPrinter Blue
    "user             Runs enumerations targeting individual users" |> cPrinter Blue
    "extra            Checks that are long running, require elevation or unreliable" |> cPrinter Blue
    "all              Runs system and user checks together" |> cPrinter Blue
    "<functionname>   List of individual checks, not case sensitive" |> cPrinter Blue
    printfn ""
    "getprocessinformation   Long check that excludes others, dumps processes and owners" |> gPrinter Asterisk |> cPrinter Blue


let printFullHelp () =
    "FETTERS" |> centerPrint |> cPrinter Yellow
    "release: beta" |> centerPrint |> cPrinter Yellow
    printfn "\n\n"
    "Full help" |> leftTenthPrint |> cPrinter Green
    "Function names are not case-sensitive" |> gPrinter Bang |> cPrinter Red
    "Checks that benefit from high integrity processes automatically do so." |> gPrinter Bang |> cPrinter Red
    printfn "\n"
    "'system' checks:" |> gPrinter Asterisk |> cPrinter Green
    ("getbasicinfo", "Lists Windows information, plus process integrity info") |> splitPrint
    ("querywmi-mappeddrive", "Lists drives that are mapped to remote shares") |> splitPrint
    ("querywmi-networkshare", "Lists items shared to the local network on the host") |> splitPrint
    ("querywmi-av", "Lists Antivirus products registered to Windows") |> splitPrint
    ("querywmi-process", "Lists all processes on the system.") |> splitPrint // tighten up wording
    ("querywmi-service", "Lists Windows services aside from svchost/conhost processes") |> splitPrint
    ("querywmi-disk", "Lists local disk information") |> splitPrint
    ("querywmi-group", "Lists all local groups on the system") |> splitPrint
    ("querywmi-user", "Lists all local user accounts and group memberships") |> splitPrint
    ("gettokenprivinformation", "Lists the system privileges claimed by current process") |> splitPrint
    ("getlocalgroupmembership", "Lists supplied group members; Default 'Administrators'") |> splitPrint
    ("getlocalarptables", "Lists local ARP entries that are *dynamic*") |> splitPrint
    ("enumeratetcpconnections", "Lists all TCP connections") |> splitPrint
    ("enumerateudpconnections", "Lists UDP listening processes") |> splitPrint
    ("getfirewallrules-deny", "Lists firewall DENY rules") |> splitPrint
    ("getfirewallrules-allow", "Lists firewall ALLOW rules") |> splitPrint
    ("getuacsystempolicies", "Displays system UAC behavior and configuration") |> splitPrint
    ("getpshellenv", "Lists the current PowerShell environment and logging settings") |> splitPrint
    ("getauditsettings", "Lists the current system auditing settings (Registry)") |> splitPrint
    ("getwefsettings", "Lists any Windows Event Forwarding settings") |> splitPrint
    ("getlsasettings", "Lists Local Security Authority settings (Registry)") |> splitPrint
    ("getsystemenvvariables", "Lists system-wide environment variables") |> splitPrint
    ("getuserenvvariables", "Lists current user's environment variables") |> splitPrint
    ("getsysteminternetsettings", "Lists system-wide proxy settings") |> splitPrint
    ("getuserinternetsettings", "Lists current user's proxy settings") |> splitPrint
    ("getlapssettings", "Lists the LAPS configuration if present") |> splitPrint
    ("enumeraterdpsessions", "Lists any active inbound RDP sessions") |> splitPrint
    ("getautologonsettings", "Lists Windows automatic logons, if present") |> splitPrint
    ("getautorunvalues", "Lists autorun registry values") |> splitPrint
    ("listsysmonconfig", "Queries Sysmon regkeys if present and elevated") |> splitPrint
    printfn ""
    "'user' checks:" |> gPrinter Asterisk |> cPrinter Green
    ("triagefirefox", "Dumps Firefox history information") |> splitPrint
    ("triagechrome", "Dumps Chrome history and bookmarks") |> splitPrint
    ("getdpapimasterkeys", "Dumps all accessible DPAPI blobs in base64 form") |> splitPrint
    ("getcredfiles", "Dumps all accessible credential blobs in base64 form") |> splitPrint
    ("detectrdcmanfile", "Prints path if a Remote Desktop Manager conn file is found") |> splitPrint
    ("getgooglecloudcreds", "Dumps Google Cloud cred files if found") |> splitPrint
    ("getgooglecloudcredsl", "Dumps Google Cloud cred files if found, legacy location") |> splitPrint
    ("getgoogleaccesstokens", "Dumps Google Cloud access tokens if found") |> splitPrint
    ("getazuretokens", "Dumps Azure API tokens if found") |> splitPrint
    ("getauzreprofile", "Dumps Azure profile contents if found") |> splitPrint
    ("getawscreds", "Dumps AWS retained credentials if found") |> splitPrint
    ("getrdpsavedconnections", "Lists RDP hostname items from registry") |> splitPrint
    ("getrecentcommands", "Lists Run menu saved commands") |> splitPrint
    ("getputtysessions", "Lists PuTTY session information from registry") |> splitPrint
    ("getputtyhostkeys", "Lists public keys from remembered hosts") |> splitPrint
    ("getinternetexplorerhistory", "Lists IE history items") |> splitPrint
    ("enumerateuservaults", "Dumps all accessible Windows Vault contents") |> splitPrint
    ("enumeratedomainsessions", "Dumps Session and Kerberos TGT/Cached ticket data") |> splitPrint
    printfn ""
    "'extra' checks" |> gPrinter Asterisk |> cPrinter Green 
    ("geteventlog4624", "ELEVATED Only 7 day Event 4624 information from Security Log") |> splitPrint
    ("geteventlog4624", "ELEVATED Only 7 day Event 4648 information from Security Log") |> splitPrint
    ("gettokengroupsids", "Lists SIDs the current process claims. (Unreliable)") |> splitPrint
    ("getprocessinformation", "Lists processes and their owners. Very Slow") |> splitPrint
    ("querywmi-patches", "Lists all installed Windows patches") |> splitPrint


let matchFunctionAndRun (uFolders: string array) highBool now week (func: string)  =
    match func with
    |"getbasicinfo" -> 
        "===== Basic PC Information =====" |> centerPrint |> cPrinter Yellow
        let w, p = getBasicInfo ()
        printSRecord p
        printSRecord w
    |"islocaladmin" -> isLocalAdmin () |> printfn "%A"
    |"ishighintegrity" -> isHighIntegrity () |> printfn "%A"
    |"gettokengroupsids" -> getTokenGroupSIDs () |> printfn "%A"
    |"gettokenprivinformation" -> getTokenPrivInformation () |> printfn "%A"
    |"getuacsystempolicies" -> getUACSystemPolicies () |> printfn "%A"
    |"getpshellenv" -> getPShellEnv () |> printfn "%A"
    |"getauditsettings" -> getAuditSettings |> printfn "%A"
    |"getwefsettings" -> getWEFSettings |> printfn "%A"
    |"getlsasettings" -> getLSASettings () |> printfn "%A"
    |"getsystemenvvariables" -> 
        "===== System Environment Variables =====" |> centerPrint |> cPrinter Yellow
        getSystemEnvVariables () |> List.iter printSRecord
    |"getuserenvvariables" -> 
        "===== User's Environment Variables ====" |> centerPrint |> cPrinter Yellow
        getUserEnvVariables () |> List.iter printSRecord
    
    |"getsysteminternetsettings" -> getSystemInternetSettings () |> printfn "%A"
    |"getuserinternetsettings" -> getUserInternetSettings () |> printfn "%A"
    |"getlapssettings" -> getLAPSSettings () |> printfn "%A"
    |"getlocalgroupmembership" -> getLocalGroupMembership "Administrators" |> printfn "%A"
    |"enumeraterdpsessions" -> enumerateRdpSessions () |> printfn "%A"
    
    |"getfirewallrules-deny" -> getFirewallRules true |> printSRecord
    |"getfirewallrules-allow" -> getFirewallRules false |> printSRecord
    |"getautologonsettings" -> getAutoLogonSettings () |> printfn "%A"
    |"getautorunvalues" -> getAutoRunValues () |> printfn "%A"
    |"getlocalarptables" -> getLocalArpTables () |> printfn "%A"
    |"enumeratetcpconnections" -> enumerateTCPConnections () |> printfn "%A"
    |"enumerateudpconnections" -> enumerateUDPConnections () |> printfn "%A"
    |"listsysmonconfig" -> listSysmonconfig () |> printfn "%A"
    |"triagefirefox" -> 
        "===== Triage Firefox ====="|> centerPrint |> cPrinter Yellow
        uFolders |> Array.map triageFirefox |> Array.iter printFRecord
    |"triagechrome" -> 
        "===== Triage Chrome =====" |> centerPrint |> cPrinter Yellow
        uFolders |> Array.map triageChrome |> Array.iter printFRecord
    |"getdpapimasterkeys" -> 
        "===== DPAPI Master Keys =====" |> centerPrint |> cPrinter Yellow
        uFolders |> getDPAPIMasterKeys |> List.iter printFRecord
    |"getcredfiles" -> 
        "===== DPAPI Credential Files =====" |> centerPrint |> cPrinter Yellow
        uFolders |> getDPAPICredFiles |> List.iter printFRecord
    |"detectrdcmanfile" -> 
        "===== Remote Desktop Connection Manager Files =====" |> centerPrint |> cPrinter Yellow
        uFolders |> detectRDCManFile |> List.map (gPrinter Plus) |> List.iter (cPrinter Blue)
    |"getgooglecloudcreds"  -> uFolders |> getGoogleCloudCreds  |> List.iter printFRecord
    |"getgooglecloudcredsl" -> uFolders |> getGoogleCloudCredsL |> List.iter printFRecord
    |"getgoogleaccesstokens" -> uFolders |> getGoogleAccessTokens |> List.iter printFRecord
    |"getazuretokens" -> uFolders |> getAzureTokens |> List.iter printFRecord
    |"getazureprofile" -> uFolders |> getAzureProfile |> List.iter printFRecord
    |"getawscreds" -> uFolders |> getAWSCreds |> List.iter printFRecord
    |"getrdpsavedconnections" -> getRDPSavedConnections () |> printfn "%A"
    |"getrecentcommands" -> getRecentCommands () |> printfn "%A"
    |"getputtysessions" -> getPuttySessions () |> printfn "%A"
    |"getputtyhostkeys" -> getPuttyHostkeys () |> printfn "%A"
    |"getinternetexplorerhistory" -> getInternetExplorerHistory () |> printfn "%A"
    |"enumerateuservaults" -> enumerateUserVaults () |> printfn "%A"
    |"enumeratedomainsessions" -> enumerateDomainSessions () |> printfn "%A"
    |"geteventlog4624" -> 
        "===== Event Log 4624  =====" |> centerPrint |> cPrinter Yellow
        match highBool with
        |true -> getEventLog4624 week now |> List.iter printSRecord
        |false -> "Lack privileges to access Security log!" |> gPrinter Bang |> cPrinter Red
    |"geteventlog4648" -> 
        "===== Event Log 4648 =====" |> centerPrint |> cPrinter Yellow
        match highBool with
        |true -> getEventLog4648 week now |> List.iter printSRecord
        |false -> "Lack privileges to access Security log!" |> gPrinter Bang |> cPrinter Red
    |"querywmi-av" -> 
        "===== Anti-virus Enumeration (WMI) =====" |> centerPrint |> cPrinter Yellow
        queryWMI SAV |> List.iter printWRecord
    |"querywmi-disk" -> 
        "===== Windows Disks (WMI) =====" |> centerPrint |> cPrinter Yellow
        queryWMI SDisk |> List.iter printWRecord
    |"querywmi-group" -> 
        "===== Local Groups =====" |> centerPrint |> cPrinter Yellow
        queryWMI SGroup |> List.iter printWRecord
    |"querywmi-mappeddrive" -> 
        "===== Mapped Drives =====" |> centerPrint |> cPrinter Yellow
        queryWMI SMappedDrive |> List.iter printWRecord
    |"querywmi-networkshare" -> 
        "===== Network Shares =====" |> centerPrint |> cPrinter Yellow
        queryWMI SNetworkShare |> List.iter printWRecord
    |"querywmi-user" -> 
        "===== Current User Enumeration (WMI) =====" |> centerPrint |> cPrinter Yellow
        queryWMI SUser |> List.iter printWRecord
    |"querywmi-process" -> 
        "===== Windows Processes (WMI) =====" |> centerPrint |> cPrinter Yellow
        queryWMI SProcess |> List.iter printWRecord
    |"querywmi-service" -> 
        "===== Installed Services (WMI) =====" |> centerPrint |> cPrinter Yellow
        queryWMI SService |> List.iter printWRecord
    |"querywmi-patches" -> 
        "===== Installed Patches (WMI) =====" |> centerPrint |> cPrinter Yellow
        queryWMI SPatches |> List.iter printWRecord
    |_ -> printf ""





[<EntryPoint>]
let main sysargs =
    let w = createStopWatch ()
    w |> startWatch
    let init = initialSetup ()
    let initArgs = {terseHelp = true; fullHelp = false; functionGroup = []}
    let args = sysargs |> Array.toList
    let actualArgs = createArgumentRecord args initArgs
    //if actualArgs.terseHelp = true then printTerseHelp () else ()
    match actualArgs.terseHelp with
    |true -> 
        printTerseHelp ()
        System.Environment.Exit 0
    |false -> ()

    match actualArgs.fullHelp with
    |true ->
        printFullHelp ()
        System.Environment.Exit 0
    |false -> ()
    
    match actualArgs.functionGroup.[0] = "getprocessinformation" with
    |true -> 
        getProcessInformation () |> List.iter printWRecord
        System.Environment.Exit 0
    |false -> ()
    
    
    actualArgs.functionGroup
    |> List.iter (matchFunctionAndRun init.luserFolders init.highIntegrity init.now init.windowWeek)
    
    w |> stopWatch
    sprintf "Elapsed Time: %i" <| w.ElapsedMilliseconds |> gPrinter Bang |> cPrinter Red
    0

