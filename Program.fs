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

(*let bindit = 
    getRegistryValueHKCU "Software\Microsoft\BingASDS\BigAs" 
    |> Option.map(fun key -> getRegistryValue "HotKeyStae" key)
printfn "size of bindit: %b" bindit.IsNone
match bindit with
|Some x -> match x with | String y -> printfn "%s" y
|None -> ()*)

let laps = getLAPSSettings ()
printfn "laps not present: %b" laps.IsNone

let autologon = getAutoLogonSettings ()
printfn "Autologon not present: %b" autologon.IsNone
printfn "%A" autologon

let results =  getRDPSavedConnections ()
printfn "%A" results

let recents = getRecentRuncommands ()
printfn "%A" recents

let uac = getUACSystemPolicies ()
printfn "%A" uac

let psh = getPShellEnv ()
printfn "%A" psh

let iss = getInternetSettings ()
printfn "%A" iss

let lsa = getLSASettings ()
printfn "%A" lsa