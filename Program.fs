open System
open System.Security.Principal
open System.Runtime.InteropServices

open Fetters.DomainTypes 
open Fetters.NI.Providers
open Fetters.WMI.Providers
open Fetters.dotNetFunctions


// Testing/rework harness
printfn "%s" <| getSystem()
let results = enumerateDomainSessions ()
printfn "Number of LSA Sessions detected: %i" <| results.Length
revertToSelf () |> ignore

results
|> List.iter(fun result -> printfn "%s:::%i:::%i" result.username result.kerberosCachedTickets.Length result.kerberosTGTcontents.Length)
