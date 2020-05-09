open System
open System.Management

open Fetters.DomainTypes 
//open Fetters.NI.Providers
open Fetters.WMI.Providers
//open Fetters.dotNet.Common
open Fetters.Registry.Provider


// Testing/rework harness
//queryWMI SDisk |> List.iter(fun x -> printfn "%A" x) // something makes win7 unhappy
//queryWMI SGroup |> List.iter(fun x -> printfn "%A" x) //compatible as-is
//queryWMI SOSDetails |> List.iter(fun x -> printfn "%A" x) //compatible as-is
//queryWMI SUser |> List.iter(fun x -> printfn "%A" x) // compatible as-is
//queryWMI SMappedDrive |> List.iter(fun x -> printfn "%A" x) //compatible as-is
//queryWMI SNetworkShare |> List.iter(fun x -> printfn "%A" x) //compatible as-is
//queryWMI SAV |> List.iter(fun x -> printfn "%A" x) //no result, but didn't explode either
//queryWMI SPatches |> List.iter(fun x -> printfn "%A" x) //


let laps = getLAPSSettings ()
printfn "%A\n" laps

let autologon = getAutoLogonSettings ()
printfn "%A\n" autologon

let results =  getRDPSavedConnections ()
printfn "%A\n" results

let recents = getRecentRuncommands ()
printfn "%A\n" recents

let uac = getUACSystemPolicies ()
printfn "%A\n" uac

let psh = getPShellEnv ()
printfn "%A\n" psh

let iss = getInternetSettings ()
printfn "%A\n" iss

let lsa = getLSASettings ()
printfn "%A\n" lsa

let audit = getAuditSettings ()
printfn "%A\n" audit

let wef = getWEFSettings ()
printfn "%A\n" wef

let putty = getPuttySessions ()
printfn "%A\n" putty

let puttyh = getPuttyHostPublicKeys ()
printfn "%A\n" puttyh