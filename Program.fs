open System
//open System.Security.Principal

open Fetters.DomainTypes 
open Fetters.NI.Providers
open Fetters.WMI.Providers
open Fetters.dotNetFunctions


// Testing/rework harness
getTokenPrivInformation () |> List.iter(fun x -> printfn "privilege %s" x)
