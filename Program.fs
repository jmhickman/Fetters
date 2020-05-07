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
printfn "Boolean test: %b" laps.IsNone