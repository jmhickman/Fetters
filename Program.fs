
open System

open Fetters.DomainTypes 
open Fetters.PInvoke.Provider
open Fetters.WMI.Provider
open Fetters.DotNet.Common
open Fetters.DotNet.Provider
open Fetters.Registry.Provider

//// Start your engines ////
let w = createStopWatch()
startWatch w

let sysroot = buildSystemDriveRoot ()
let userfolders = buildLocalUserFolders sysroot
let nowtime = createNowTime ()
let weekago = createWeekTimeWindow ()

// Testing/rework harness

"================================Basic Info======================================" |> cPrinter Red
sprintf "%A" <| getBasicInfo () |> cPrinter Green

"===WMI QUERIES: DISK, GROUPS, OS DETAILS, USERS, MAPPED DISKS, NETWORK SHARES===" |> cPrinter Yellow
"=====================ANTIVIRUS, INSTALLED PATCHES===============================" |> cPrinter Yellow
//queryWMI SDisk |> List.iter(printfn "%A") // something makes win7 unhappy
//queryWMI SGroup |> List.iter(printfn "%A") //compatible as-is
//queryWMI SUser |> List.iter(printfn "%A") // compatible as-is
//queryWMI SMappedDrive |> List.iter(printfn "%A") //compatible as-is
//queryWMI SNetworkShare |> List.iter (printfn "%A") //compatible as-is
//queryWMI SAV |> List.iter (printfn "%A") //no result, but didn't explode either
//queryWMI SService |> List.iter (printfn "%A")
//queryWMI SPatches |> List.iter(fun x -> printfn "%A" x) //
//queryWMI SProcess 
//|> List.filter(fun f -> 
//    match f with
//    |Process x -> not(x.processBinpath.Contains "System32" || x.processBinpath.Contains "system32" || x.processBinpath.Length = 0)
//    |_ -> true )
//|> List.iter (printfn "%A")

"====================LAPS SETTINGS========================" |> cPrinter Blue
//let laps = getLAPSSettings ()
//printfn "%A\n" laps

"===================AUTOLOGON SETTINGS====================" |> cPrinter Green
//let autologon = getAutoLogonSettings ()
//printfn "%A\n" autologon


//printfn "===================AUTORUN SETTINGS====================="
//let autorun = getAutoRunValues ()
//printfn "%A\n" autorun

//printfn "================RDP CONNECTION USERNAMES================="
//let rdpsaved =  getRDPSavedConnections ()
//printfn "%A\n" rdpsaved

//printfn "===============RECENT RUN COMMANDS (Win+R)==============="
//let recents = getRecentCommands ()
//printfn "%A\n" recents

//printfn "================UAC SYSTEM CONFIGURATION================="
//let uac = getUACSystemPolicies ()
//printfn "%A\n" uac

//printfn "=================POWERSHELL ENVIRONMENT=================="
//let psh = getPShellEnv ()
//printfn "%A\n" psh

//printfn "================SYSTEM INTERNET SETTINGS================="
//let iss = getSystemInternetSettings ()
//printfn "%A\n" iss

//printfn "================USER INTERNET SETTINGS==================="
//let uss = getUserInternetSettings ()
//printfn "%A\n" uss

//printfn "===================LSA REGISTRY DUMP====================="
//let lsa = getLSASettings ()
//printfn "%A\n" lsa

//printfn "================SYSTEM AUDITING SETTINGS================="
//let audit = getAuditSettings ()
//printfn "%A\n" audit

//printfn "============WINDOWS EVENT FORWARDING SETTINGS============"
//let wef = getWEFSettings ()
//printfn "%A\n" wef

//printfn "=======PUTTY SAVED HOST KEYS AND SESSION SETTINGS========"
//printfn "%A" <| getPuttyHostPublickeyCollection ()
//printfn "%A" <| getPuttySessionCollection ()

//printfn "==================NATIVE PLATFORM INVOKE================="
//printfn "============DOMAIN SESSIONS AND KERBEROS TICKETS========="
//printfn "%A" <| enumerateDomainSessions ()
//printfn "===============WINDOWS VAULT CONTENTS===================="
//printfn "%A" <| enumerateAllVaults ()
//printfn "====================TCP CONNECTIONS======================"
//printfn "%A" <| enumerateTCPConnections ()
//printfn "====================UDP CONNECTIONS======================"
//printfn "%A" <| enumerateUDPConnections ()
//printfn "====================LOCAL ARP TABLES====================="
//printfn "%A" <| getLocalArpTables ()
//printfn "==============USER PROCESS TOKEN PRIVILEGES=============="
//printfn "%A" <| getTokenPrivInformation ()
//let ie = getInternetExplorerHistory ()
//printfn "%A" ie


//userfolders |> Array.iter (printfn "%s")
//userfolders |> Array.map triageChrome |> Array.iter (printfn "%A")

//let ff = userfolders |> Array.map(fun u -> getFirefoxProfiles u) |> Array.concat |> Array.map(fun u -> extractFirefoxHistory u)
//printfn "%A" ff


//getEventLog4624 weekago nowtime |> List.iter (printfn "%A")
//getEventLog4648 weekago nowtime |> List.iter (printfn "%A")
//let rfrec = createFirewallRecord false
//printfn "%A" rfrec
let frec = createFirewallRecord true
//printfn "%A" frec

//getCurrentUsersGroups () |> List.iter (printfn "%A")

//getDPAPIMasterKeys userfolders |> List.iter (printfn "%A")
//getCredFiles userfolders |> List.iter (printfn "%A")

//getGoogleCloudCreds userfolders |> List.iter (printfn "%A")
//getGoogleCloudCredsL userfolders |> List.iter (printfn "%A")
//getGoogleAccessTokens userfolders |> List.iter (printfn "%A")
//getAzureProfile userfolders |> List.iter (printfn "%A")
//getAzureTokens userfolders |> List.iter (printfn "%A")
//getAWSCreds userfolders |> List.iter (printfn "%A")

stopWatch w
sprintf "Elapsed time in ms: %i" <| getExecutiontime w |> gPrinter Asterisk |> cPrinter Green

let nolines = yieldLineSequence "C:\\doesntexist"
printfn "%A" nolines