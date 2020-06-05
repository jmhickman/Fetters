
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


let (|FunctionName|_|) (functionname: string) = 
    if functionNames |> List.contains (functionname.ToLower()) then Some (functionname.ToLower()) else None


let rec createArgumentRecord args (initArgs:ProgramArguments) : ProgramArguments =
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
    "Fetters: Windows System Enumeration" |> centerPrint |> cPrinter Yellow
    "A port of Seatbelt in F#" |> centerPrint |> cPrinter Yellow
    "Release 2" |> centerPrint |> cPrinter Yellow
    printfn "\n\n"
    "fetters [groupname]" |> leftTenthPrint |> cPrinter Yellow
    "fetters [<functionname1>..<functionnameN>]" |> leftTenthPrint |> cPrinter Yellow
    printfn "\n"
    "Options:" |> leftTenthPrint |> cPrinter Green
    "-hh              Shows verbose help for each enumeration function" |> cPrinter Blue
    "system           Runs enumerations targeting the system" |> cPrinter Blue
    "user             Runs enumerations targeting individual users" |> cPrinter Blue
    "extra            Long running/very verbose checks that require elevation" |> cPrinter Blue
    "all              Runs system and user checks together" |> cPrinter Blue
    "<functionname>   Individual checks, not case sensitive. May be grouped" |> cPrinter Blue
    "                 together in any number or order. Some can be very    " |> cPrinter Blue
    "                 verbose!" |> cPrinter Blue
    printfn ""
    "getprocessinformation   Excludes other checks, dumps processes and owners" |> gPrinter Asterisk |> cPrinter Blue
    "                        SLOW!" |> gPrinter Asterisk |> cPrinter Blue


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
    ("querywmi-patches", "Lists all installed Windows patches") |> splitPrint


let matchFunctionAndRun (uFolders: string array) highBool now week (func: string) : unit  =
    match func with
    |"getbasicinfo" ->
        printfn ""
        "===== Basic PC Information =====" |> centerPrint |> cPrinter Yellow
        let w, p = getBasicInfo ()
        printSRecord p
        printSRecord w
    |"islocaladmin" -> isLocalAdmin () |> printfn "%A"
    |"ishighintegrity" -> isHighIntegrity () |> printfn "%A"
    |"gettokengroupsids" -> getTokenGroupSIDs () |> printfn "%A" // special case
    |"gettokenprivinformation" -> 
        printfn ""
        "===== Token Privileges =====" |> centerPrint |> cPrinter Yellow
        getTokenPrivInformation () |> printPRecord
    |"getuacsystempolicies" -> 
        printfn ""
        "===== UAC Policies =====" |> centerPrint |> cPrinter Yellow
        getUACSystemPolicies () |> printRRecord
    |"getpshellenv" -> 
        printfn ""
        "===== PowerShell Environment Information and Logging =====" |> centerPrint |> cPrinter Yellow
        getPShellEnv () |> printRRecord
    |"getauditsettings" -> 
        printfn ""
        "===== Windows Audit Settings (if set) =====" |> centerPrint |> cPrinter Yellow
        getAuditSettings () |> printRRecord
    |"getwefsettings" -> 
        printfn ""
        "===== Windows Event Forwarding Settings (if set) =====" |> centerPrint |> cPrinter Yellow
        getWEFSettings () |> printRRecord
    |"getlsasettings" -> 
        printfn ""
        "===== LSA Settings =====" |> centerPrint |> cPrinter Yellow
        getLSASettings () |> printRRecord
    |"getsystemenvvariables" -> 
        printfn ""
        "===== System Environment Variables =====" |> centerPrint |> cPrinter Yellow
        getSystemEnvVariables () |> List.iter printSRecord
    |"getuserenvvariables" -> 
        printfn ""
        "===== User's Environment Variables ====" |> centerPrint |> cPrinter Yellow
        getUserEnvVariables () |> List.iter printSRecord
    |"getsysteminternetsettings" -> 
        printfn ""
        "===== System Proxy Settings =====" |> centerPrint |> cPrinter Yellow
        getSystemInternetSettings () |> printRRecord
    |"getuserinternetsettings" -> 
        printfn ""
        "===== User Proxy Settings =====" |> centerPrint |> cPrinter Yellow
        getUserInternetSettings () |> printRRecord
    |"getlapssettings" -> 
        printfn ""
        "===== LAPS Settings (if present) =====" |> centerPrint |> cPrinter Yellow
        getLAPSSettings () |> printRRecord
    |"getlocalgroupmembership" -> getLocalGroupMembership "Administrators" |> printfn "%A" //special
    |"enumeraterdpsessions" -> 
        printfn ""
        "===== RDP Sessions =====" |> centerPrint |> cPrinter Yellow
        enumerateRdpSessions () |> List.iter printPRecord
    |"getfirewallrules-deny" -> 
        printfn ""
        "===== Firewall Rules DENY ONLY =====" |> centerPrint |> cPrinter Yellow
        getFirewallRules true |> printSRecord
    |"getfirewallrules-allow" -> 
        printfn ""
        "===== Firewall Rules ALLOW ONLY =====" |> centerPrint |> cPrinter Yellow
        getFirewallRules false |> printSRecord
    |"getautologonsettings" -> 
        printfn ""
        "===== Autologon Settings (if present) =====" |> centerPrint |> cPrinter Yellow
        getAutoLogonSettings () |> printRRecord
    |"getautorunvalues" -> 
        printfn ""
        "===== Autoruns =====" |> centerPrint |> cPrinter Yellow
        getAutoRunValues () |> List.iter printRRecord
    |"getlocalarptables" -> 
        printfn ""
        "===== ARP entries =====" |> centerPrint |> cPrinter Yellow
        getLocalArpTables () |> List.iter printPRecord
    |"enumeratetcpconnections" -> 
        printfn ""
        "===== TCP Connections =====" |> centerPrint |> cPrinter Yellow
        enumerateTCPConnections () |> List.iter printPRecord
    |"enumerateudpconnections" -> 
        printfn ""
        "===== UDP Listeners =====" |> centerPrint |> cPrinter Yellow
        enumerateUDPConnections () |> List.iter printPRecord
    |"listsysmonconfig" -> 
        printfn ""
        "===== Sysmon Config (if present) =====" |> centerPrint |> cPrinter Yellow
        listSysmonconfig () |> printRRecord
    |"triagefirefox" -> 
        printfn ""
        "===== Triage Firefox ====="|> centerPrint |> cPrinter Yellow
        uFolders |> Array.map triageFirefox |> Array.iter printFRecord
    |"triagechrome" -> 
        printfn ""
        "===== Triage Chrome =====" |> centerPrint |> cPrinter Yellow
        uFolders |> Array.map triageChrome |> Array.iter printFRecord
    |"getdpapimasterkeys" -> 
        printfn ""
        "===== DPAPI Master Keys =====" |> centerPrint |> cPrinter Yellow
        uFolders |> getDPAPIMasterKeys |> List.iter printFRecord
    |"getcredfiles" -> 
        printfn ""
        "===== DPAPI Credential Files =====" |> centerPrint |> cPrinter Yellow
        uFolders |> getDPAPICredFiles |> List.iter printFRecord
    |"detectrdcmanfile" -> 
        printfn ""
        "===== Remote Desktop Connection Manager Files =====" |> centerPrint |> cPrinter Yellow
        uFolders |> detectRDCManFile |> List.map (gPrinter Plus) |> List.iter (cPrinter Blue)
    |"getgooglecloudcreds"  -> 
        printfn ""
        "===== Google Cloud Creds (if any) =====" |> centerPrint |> cPrinter Yellow
        uFolders |> getGoogleCloudCreds  |> List.iter printFRecord
    |"getgooglecloudcredsl" -> 
        printfn ""
        "===== Google Cloud Creds Legacy Location (if any) ====="|> centerPrint |> cPrinter Yellow
        uFolders |> getGoogleCloudCredsL |> List.iter printFRecord
    |"getgoogleaccesstokens" -> 
        printfn ""
        "===== Google Access Tokens (if any) ====="|> centerPrint |> cPrinter Yellow
        uFolders |> getGoogleAccessTokens |> List.iter printFRecord
    |"getazuretokens" -> 
        printfn ""
        "===== Azure Tokens (if any) ====="|> centerPrint |> cPrinter Yellow
        uFolders |> getAzureTokens |> List.iter printFRecord
    |"getazureprofile" -> 
        printfn ""
        "===== Azure Profiles (if any) ====="|> centerPrint |> cPrinter Yellow
        uFolders |> getAzureProfile |> List.iter printFRecord
    |"getawscreds" ->
        printfn ""
        "===== AWS credentials (if any) ====="|> centerPrint |> cPrinter Yellow
        uFolders |> getAWSCreds |> List.iter printFRecord
    |"getrdpsavedconnections" -> 
        printfn ""
        "===== RDP Saved Connection info =====" |> centerPrint |> cPrinter Yellow
        getRDPSavedConnections () |> List.iter printRRecord 
    |"getrecentcommands" -> 
        printfn ""
        "===== Recent Commands =====" |> centerPrint |> cPrinter Yellow
        getRecentCommands () |> List.iter printRRecord
    |"getputtysessions" -> 
        printfn ""
        "===== PuTTY Session info =====" |> centerPrint |> cPrinter Yellow
        getPuttySessions () |> List.iter printRRecord
    |"getputtyhostkeys" -> 
        printfn ""
        "===== PuTTY Host Public Keys =====" |> centerPrint |> cPrinter Yellow
        getPuttyHostkeys () |>  List.iter printRRecord
    |"getinternetexplorerhistory" -> 
        printfn ""
        "===== IE History (Reg) =====" |> centerPrint |> cPrinter Yellow
        getInternetExplorerHistory () |> List.iter printRRecord
    |"enumerateuservaults" -> 
        printfn ""
        "===== Windows Vault Contents =====" |> centerPrint |> cPrinter Yellow
        enumerateUserVaults () |> List.iter printPRecord
    |"enumeratedomainsessions" -> enumerateDomainSessions () |> List.iter printPRecord 
    |"geteventlog4624" -> 
        printfn ""
        "===== Event Log 4624  =====" |> centerPrint |> cPrinter Yellow
        match highBool with
        |true -> getEventLog4624 week now |> List.iter printSRecord
        |false -> "Lack privileges to access Security log!" |> gPrinter Bang |> cPrinter Red
    |"geteventlog4648" -> 
        printfn ""
        "===== Event Log 4648 =====" |> centerPrint |> cPrinter Yellow
        match highBool with
        |true -> getEventLog4648 week now |> List.iter printSRecord
        |false -> "Lack privileges to access Security log!"  |> gPrinter Bang |> cPrinter Red
    |"querywmi-av" -> 
        printfn ""
        "===== Anti-virus Enumeration (WMI) =====" |> centerPrint |> cPrinter Yellow
        queryWMI SAV |> List.iter printWRecord
    |"querywmi-disk" -> 
        printfn ""
        "===== Windows Disks (WMI) =====" |> centerPrint |> cPrinter Yellow
        queryWMI SDisk |> List.iter printWRecord
    |"querywmi-group" -> 
        printfn ""
        "===== Local Groups =====" |> centerPrint |> cPrinter Yellow
        queryWMI SGroup |> List.iter printWRecord
    |"querywmi-mappeddrive" -> 
        printfn ""
        "===== Mapped Drives =====" |> centerPrint |> cPrinter Yellow
        queryWMI SMappedDrive |> List.iter printWRecord
    |"querywmi-networkshare" -> 
        printfn ""
        "===== Network Shares =====" |> centerPrint |> cPrinter Yellow
        queryWMI SNetworkShare |> List.iter printWRecord
    |"querywmi-user" -> 
        printfn ""
        "===== Current User Enumeration (WMI) =====" |> centerPrint |> cPrinter Yellow
        queryWMI SUser |> List.iter printWRecord
    |"querywmi-process" -> 
        printfn ""
        "===== Windows Processes (WMI) =====" |> centerPrint |> cPrinter Yellow
        queryWMI SProcess |> List.iter printWRecord
    |"querywmi-service" -> 
        printfn ""
        "===== Installed Services (WMI) =====" |> centerPrint |> cPrinter Yellow
        queryWMI SService |> List.iter printWRecord
    |"querywmi-patches" -> 
        printfn ""
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
    |> List.rev
    |> List.iter(matchFunctionAndRun init.luserFolders init.highIntegrity init.now init.windowWeek)
    
    w |> stopWatch
    sprintf "Elapsed Time: %i" <| w.ElapsedMilliseconds |> gPrinter Bang |> cPrinter Red
    0

