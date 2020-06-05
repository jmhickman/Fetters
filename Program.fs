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
    "Fetters: Windows System Enumeration" |> centerPrintN |> printfn "%s"
    "A port of Seatbelt in F# under Apache Public License v2" |> centerPrintN |> printfn "%s"
    "Release 2" |> centerPrintN |> printfn "%s"
    printfn "\n\n"
    "fetters [groupname]" |> leftTenthPrint |> printfn "%s"
    "fetters [<functionname1>..<functionnameN>]" |> leftTenthPrint |> printfn "%s"
    printfn "\n"
    "Options:" |> leftTenthPrint |> cPrinter Green
    "-hh              Shows verbose help for each enumeration function" |> printfn "%s"
    "system           Runs enumerations targeting the system" |> printfn "%s"
    "user             Runs enumerations targeting individual users" |> printfn "%s"
    "extra            Long running/very verbose checks that require elevation" |> printfn "%s"
    "all              Runs system and user checks together" |> printfn "%s"
    "<functionname>   Individual checks, not case sensitive. May be grouped" |> printfn "%s"
    "                 together in any number or order. Some can be very    " |> printfn "%s"
    "                 verbose!" |> printfn "%s"
    printfn ""
    "getprocessinformation   Excludes other checks, dumps processes and owners" |> gPrinter Asterisk |> printfn "%s"
    "                            SLOW!" |> printfn "%s"


let printFullHelp () =
    "Fetters: Windows System Enumeration" |> centerPrintN |> printfn "%s"
    "A port of Seatbelt in F#" |> centerPrintN |> printfn "%s"
    "Release 2" |> centerPrintN |> printfn "%s"
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
        "===== Basic PC Information =====" |> centerPrint |> printfn "%s"
        let w, p = getBasicInfo ()
        printSRecord p
        printSRecord w
    |"islocaladmin" -> isLocalAdmin () |> printfn "%A"
    |"ishighintegrity" -> isHighIntegrity () |> printfn "%A"
    |"gettokengroupsids" -> getTokenGroupSIDs () |> printfn "%A" // special case
    |"gettokenprivinformation" -> 
        printfn ""
        "===== Token Privileges =====" |> centerPrint |> printfn "%s"
        getTokenPrivInformation () |> printPRecord
    |"getuacsystempolicies" -> 
        printfn ""
        "===== UAC Policies =====" |> centerPrint |> printfn "%s"
        getUACSystemPolicies () |> printRRecord
    |"getpshellenv" -> 
        printfn ""
        "===== PowerShell Environment Information and Logging =====" |> centerPrint |> printfn "%s"
        getPShellEnv () |> printRRecord
    |"getauditsettings" -> 
        printfn ""
        "===== Windows Audit Settings (if set) =====" |> centerPrint |> printfn "%s"
        getAuditSettings () |> printRRecord
    |"getwefsettings" -> 
        printfn ""
        "===== Windows Event Forwarding Settings (if set) =====" |> centerPrint |> printfn "%s"
        getWEFSettings () |> printRRecord
    |"getlsasettings" -> 
        printfn ""
        "===== LSA Settings =====" |> centerPrint |> printfn "%s"
        getLSASettings () |> printRRecord
    |"getsystemenvvariables" -> 
        printfn ""
        "===== System Environment Variables =====" |> centerPrint |> printfn "%s"
        getSystemEnvVariables () |> List.iter printSRecord
    |"getuserenvvariables" -> 
        printfn ""
        "===== User's Environment Variables ====" |> centerPrint |> printfn "%s"
        getUserEnvVariables () |> List.iter printSRecord
    |"getsysteminternetsettings" -> 
        printfn ""
        "===== System Proxy Settings =====" |> centerPrint |> printfn "%s"
        getSystemInternetSettings () |> printRRecord
    |"getuserinternetsettings" -> 
        printfn ""
        "===== User Proxy Settings =====" |> centerPrint |> printfn "%s"
        getUserInternetSettings () |> printRRecord
    |"getlapssettings" -> 
        printfn ""
        "===== LAPS Settings (if present) =====" |> centerPrint |> printfn "%s"
        getLAPSSettings () |> printRRecord
    |"getlocalgroupmembership" -> getLocalGroupMembership "Administrators" |> printfn "%A" //special
    |"enumeraterdpsessions" -> 
        printfn ""
        "===== RDP Sessions =====" |> centerPrint |> printfn "%s"
        enumerateRdpSessions () |> List.iter printPRecord
    |"getfirewallrules-deny" -> 
        printfn ""
        "===== Firewall Rules DENY ONLY =====" |> centerPrint |> printfn "%s"
        getFirewallRules true |> printSRecord
    |"getfirewallrules-allow" -> 
        printfn ""
        "===== Firewall Rules ALLOW ONLY =====" |> centerPrint |> printfn "%s"
        getFirewallRules false |> printSRecord
    |"getautologonsettings" -> 
        printfn ""
        "===== Autologon Settings (if present) =====" |> centerPrint |> printfn "%s"
        getAutoLogonSettings () |> printRRecord
    |"getautorunvalues" -> 
        printfn ""
        "===== Autoruns =====" |> centerPrint |> printfn "%s"
        getAutoRunValues () |> List.iter printRRecord
    |"getlocalarptables" -> 
        printfn ""
        "===== ARP entries =====" |> centerPrint |> printfn "%s"
        getLocalArpTables () |> List.iter printPRecord
    |"enumeratetcpconnections" -> 
        printfn ""
        "===== TCP Connections =====" |> centerPrint |> printfn "%s"
        enumerateTCPConnections () |> List.iter printPRecord
    |"enumerateudpconnections" -> 
        printfn ""
        "===== UDP Listeners =====" |> centerPrint |> printfn "%s"
        enumerateUDPConnections () |> List.iter printPRecord
    |"listsysmonconfig" -> 
        printfn ""
        "===== Sysmon Config (if present) =====" |> centerPrint |> printfn "%s"
        listSysmonconfig () |> printRRecord
    |"triagefirefox" -> 
        printfn ""
        "===== Triage Firefox ====="|> centerPrint |> printfn "%s"
        uFolders |> Array.map triageFirefox |> Array.iter printFRecord
    |"triagechrome" -> 
        printfn ""
        "===== Triage Chrome =====" |> centerPrint |> printfn "%s"
        uFolders |> Array.map triageChrome |> Array.iter printFRecord
    |"getdpapimasterkeys" -> 
        printfn ""
        "===== DPAPI Master Keys =====" |> centerPrint |> printfn "%s"
        uFolders |> getDPAPIMasterKeys |> List.iter printFRecord
    |"getcredfiles" -> 
        printfn ""
        "===== DPAPI Credential Files =====" |> centerPrint |> printfn "%s"
        uFolders |> getDPAPICredFiles |> List.iter printFRecord
    |"detectrdcmanfile" -> 
        printfn ""
        "===== Remote Desktop Connection Manager Files =====" |> centerPrint |> printfn "%s"
        uFolders |> detectRDCManFile |> List.map (gPrinter Plus) |> List.iter (cPrinter Green)
    |"getgooglecloudcreds"  -> 
        printfn ""
        "===== Google Cloud Creds (if any) =====" |> centerPrint |> printfn "%s"
        uFolders |> getGoogleCloudCreds  |> List.iter printFRecord
    |"getgooglecloudcredsl" -> 
        printfn ""
        "===== Google Cloud Creds Legacy Location (if any) ====="|> centerPrint |> printfn "%s"
        uFolders |> getGoogleCloudCredsL |> List.iter printFRecord
    |"getgoogleaccesstokens" -> 
        printfn ""
        "===== Google Access Tokens (if any) ====="|> centerPrint |> printfn "%s"
        uFolders |> getGoogleAccessTokens |> List.iter printFRecord
    |"getazuretokens" -> 
        printfn ""
        "===== Azure Tokens (if any) ====="|> centerPrint |> printfn "%s"
        uFolders |> getAzureTokens |> List.iter printFRecord
    |"getazureprofile" -> 
        printfn ""
        "===== Azure Profiles (if any) ====="|> centerPrint |> printfn "%s"
        uFolders |> getAzureProfile |> List.iter printFRecord
    |"getawscreds" ->
        printfn ""
        "===== AWS credentials (if any) ====="|> centerPrint |> printfn "%s"
        uFolders |> getAWSCreds |> List.iter printFRecord
    |"getrdpsavedconnections" -> 
        printfn ""
        "===== RDP Saved Connection info =====" |> centerPrint |> printfn "%s"
        getRDPSavedConnections () |> List.iter printRRecord 
    |"getrecentcommands" -> 
        printfn ""
        "===== Recent Commands =====" |> centerPrint |> printfn "%s"
        getRecentCommands () |> List.iter printRRecord
    |"getputtysessions" -> 
        printfn ""
        "===== PuTTY Session info =====" |> centerPrint |> printfn "%s"
        getPuttySessions () |> List.iter printRRecord
    |"getputtyhostkeys" -> 
        printfn ""
        "===== PuTTY Host Public Keys =====" |> centerPrint |> printfn "%s"
        getPuttyHostkeys () |>  List.iter printRRecord
    |"getinternetexplorerhistory" -> 
        printfn ""
        "===== IE History (Reg) =====" |> centerPrint |> printfn "%s"
        getInternetExplorerHistory () |> List.iter printRRecord
    |"enumerateuservaults" -> 
        printfn ""
        "===== Windows Vault Contents =====" |> centerPrint |> printfn "%s"
        enumerateUserVaults () |> List.iter printPRecord
    |"enumeratedomainsessions" -> enumerateDomainSessions () |> List.iter printPRecord 
    |"geteventlog4624" -> 
        printfn ""
        "===== Event Log 4624  =====" |> centerPrint |> printfn "%s"
        match highBool with
        |true -> getEventLog4624 week now |> List.iter printSRecord
        |false -> "Lack privileges to access Security log!" |> gPrinter Bang |> cPrinter Red
    |"geteventlog4648" -> 
        printfn ""
        "===== Event Log 4648 =====" |> centerPrint |> printfn "%s"
        match highBool with
        |true -> getEventLog4648 week now |> List.iter printSRecord
        |false -> "Lack privileges to access Security log!"  |> gPrinter Bang |> cPrinter Red
    |"querywmi-av" -> 
        printfn ""
        "===== Anti-virus Enumeration (WMI) =====" |> centerPrint |> printfn "%s"
        queryWMI SAV |> List.iter printWRecord
    |"querywmi-disk" -> 
        printfn ""
        "===== Windows Disks (WMI) =====" |> centerPrint |> printfn "%s"
        queryWMI SDisk |> List.iter printWRecord
    |"querywmi-group" -> 
        printfn ""
        "===== Local Groups =====" |> centerPrint |> printfn "%s"
        queryWMI SGroup |> List.iter printWRecord
    |"querywmi-mappeddrive" -> 
        printfn ""
        "===== Mapped Drives =====" |> centerPrint |> printfn "%s"
        queryWMI SMappedDrive |> List.iter printWRecord
    |"querywmi-networkshare" -> 
        printfn ""
        "===== Network Shares =====" |> centerPrint |> printfn "%s"
        queryWMI SNetworkShare |> List.iter printWRecord
    |"querywmi-user" -> 
        printfn ""
        "===== Current User Enumeration (WMI) =====" |> centerPrint |> printfn "%s"
        queryWMI SUser |> List.iter printWRecord
    |"querywmi-process" -> 
        printfn ""
        "===== Windows Processes (WMI) =====" |> centerPrint |> printfn "%s"
        queryWMI SProcess |> List.iter printWRecord
    |"querywmi-service" -> 
        printfn ""
        "===== Installed Services (WMI) =====" |> centerPrint |> printfn "%s"
        queryWMI SService |> List.iter printWRecord
    |"querywmi-patches" -> 
        printfn ""
        "===== Installed Patches (WMI) =====" |> centerPrint |> printfn "%s"
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