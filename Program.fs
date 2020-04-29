open System
//open System.Security.Principal

open Fetters.DomainTypes 
open Fetters.NI.Providers
open Fetters.WMI.Providers
open Fetters.dotNetFunctions


// Testing/rework harness
getUdpTable () 
|> getUdpTableRows 
|> List.map(fun x ->  createUdpRecord x) 
|> List.iter(fun x -> let service = 
                        match x.service with
                        | Some x -> x
                        | None -> ""
                      printfn "%s:%i :: %i :: %s" (x.localAddress.ToString()) x.localport x.pid service)

getLocalArpTables () |> List.iter (fun x -> printfn "%A" x)
