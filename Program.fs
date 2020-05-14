open System
open System.Management

open Fetters.DomainTypes 
open Fetters.NI.Providers
open Fetters.WMI.Providers
open Fetters.dotNet.Common
open Fetters.Registry.Provider


// Testing/rework harness
printfn "===WMI QUERIES: DISK, GROUPS, OS DETAILS, USERS, MAPPED DISKS, NETWORK SHARES==="
printfn "=====================ANTIVIRUS, INSTALLED PATCHES==============================="
queryWMI SDisk |> List.iter(fun x -> printfn "%A" x) // something makes win7 unhappy
queryWMI SGroup |> List.iter(fun x -> printfn "%A" x) //compatible as-is
queryWMI SOSDetails |> List.iter(fun x -> printfn "%A" x) //compatible as-is
queryWMI SUser |> List.iter(fun x -> printfn "%A" x) // compatible as-is
queryWMI SMappedDrive |> List.iter(fun x -> printfn "%A" x) //compatible as-is
queryWMI SNetworkShare |> List.iter(fun x -> printfn "%A" x) //compatible as-is
queryWMI SAV |> List.iter(fun x -> printfn "%A" x) //no result, but didn't explode either
queryWMI SPatches |> List.iter(fun x -> printfn "%A" x) //

printfn "====================LAPS SETTINGS========================"
let laps = getLAPSSettings ()
printfn "%A\n" laps

printfn "===================AUTOLOGON SETTINGS===================="
let autologon = getAutoLogonSettings ()
printfn "%A\n" autologon

printfn "================RDP CONNECTION USERNAMES================="
let results =  getRDPSavedConnections ()
printfn "%A\n" results

printfn "===============RECENT RUN COMMANDS (Win+R)==============="
let recents = getRecentCommands ()
printfn "%A\n" recents

printfn "================UAC SYSTEM CONFIGURATION================="
let uac = getUACSystemPolicies ()
printfn "%A\n" uac

printfn "=================POWERSHELL ENVIRONMENT=================="
let psh = getPShellEnv ()
printfn "%A\n" psh

printfn "================SYSTEM INTERNET SETTINGS================="
let iss = getSystemInternetSettings ()
printfn "%A\n" iss

printfn "================USER INTERNET SETTINGS==================="
let uss = getUserInternetSettings ()
printfn "%A\n" uss

printfn "===================LSA REGISTRY DUMP====================="
let lsa = getLSASettings ()
printfn "%A\n" lsa

printfn "================SYSTEM AUDITING SETTINGS================="
let audit = getAuditSettings ()
printfn "%A\n" audit

printfn "============WINDOWS EVENT FORWARDING SETTINGS============"
let wef = getWEFSettings ()
printfn "%A\n" wef

printfn "=======PUTTY SAVED HOST KEYS AND SESSION SETTINGS========"
printfn "%A" <| getPuttyHostPublickeyCollection ()
printfn "%A" <| getPuttySessionCollection ()

printfn "==================NATIVE PLATFORM INVOKE================="
printfn "============DOMAIN SESSIONS AND KERBEROS TICKETS========="
printfn "%A" <| enumerateDomainSessions ()
printfn "===============WINDOWS VAULT CONTENTS===================="
printfn "%A" <| enumerateAllVaults ()
printfn "====================TCP CONNECTIONS======================"
printfn "%A" <| enumerateTCPConnections ()
printfn "====================UDP CONNECTIONS======================"
printfn "%A" <| enumerateUDPConnections ()
printfn "====================LOCAL ARP TABLES====================="
printfn "%A" <| getLocalArpTables ()
printfn "==============USER PROCESS TOKEN PRIVILEGES=============="
printfn "%A" <| getTokenPrivInformation ()