﻿open System
open System.Security
open System.Management


open Fetters.DomainTypes 
open Fetters.PInvoke.Provider
open Fetters.WMI.Provider
open Fetters.DotNet.Common
open Fetters.DotNet.Provider
open Fetters.Registry.Provider


let sysroot = buildSystemDriveRoot ()
let userfolders = buildLocalUserFolders sysroot
let nowtime = createNowTime ()
let weekago = createWeekTimeWindow ()

// Testing/rework harness
printfn "===WMI QUERIES: DISK, GROUPS, OS DETAILS, USERS, MAPPED DISKS, NETWORK SHARES==="
printfn "=====================ANTIVIRUS, INSTALLED PATCHES==============================="
//queryWMI SDisk |> List.iter(fun x -> printfn "%A" x) // something makes win7 unhappy
//queryWMI SGroup |> List.iter(fun x -> printfn "%A" x) //compatible as-is
//queryWMI SUser |> List.iter(fun x -> printfn "%A" x) // compatible as-is
//queryWMI SMappedDrive |> List.iter(fun x -> printfn "%A" x) //compatible as-is
//queryWMI SNetworkShare |> List.iter(fun x -> printfn "%A" x) //compatible as-is
//queryWMI SAV |> List.iter(fun x -> printfn "%A" x) //no result, but didn't explode either
let xx = queryWMI SService 
        |> List.filter(fun f -> 
        let ff =
            match f with 
            |WmiRecord.Service x -> x.serviceCompany
            |_ -> ""
        not(ff = "Microsoft Corporation"))
        //|> List.iter (printfn "%A")
printfn "%i" xx.Length
let xxx = queryWMI SService
printfn "%i" xxx.Length
//queryWMI SPatches |> List.iter(fun x -> printfn "%A" x) //
(*
printfn "====================LAPS SETTINGS========================"
let laps = getLAPSSettings ()
printfn "%A\n" laps

printfn "===================AUTOLOGON SETTINGS===================="
let autologon = getAutoLogonSettings ()
printfn "%A\n" autologon

printfn "===================AUTORUN SETTINGS====================="
let autorun = getAutoRunValues ()
printfn "%A\n" autorun

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
let ie = getInternetExplorerHistory ()
printfn "%A" ie*)


//userfolders |> Array.iter (printfn "%s")
//userfolders |> Array.map triageChrome |> Array.iter (printfn "%A")

//let ff = userfolders |> Array.map(fun u -> getFirefoxProfiles u) |> Array.concat |> Array.map(fun u -> extractFirefoxHistory u)
//printfn "%A" ff


//getEventLog4624 weekago nowtime |> List.iter (printfn "%A")
//getEventLog4648 weekago nowtime |> List.iter (printfn "%A")
//let rfrec = createFirewallRecord false
//printfn "%A" rfrec
//let frec = createFirewallRecord true
//printfn "%A" frec

//getCurrentUsersGroups () |> List.iter (printfn "%A")

//getDPAPIMasterKeys userfolders |> List.iter (printfn "%A")
//getCredFiles userfolders |> List.iter (printfn "%A")

//getGoogleCloudCreds userfolders |> ignore
//getGoogleCloudCredsL userfolders |> ignore
//getGoogleAccessTokens userfolders |> ignore
//getAzureProfile userfolders |> ignore
//getAzureTokens userfolders |> ignore
//getAWSCreds userfolders |> ignore

//printfn "%A" <| getBasicInfo () 

