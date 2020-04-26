open System
//open System.Security.Principal

open Fetters.DomainTypes 
open Fetters.NI.Providers
open Fetters.WMI.Providers
open Fetters.dotNetFunctions


// Testing/rework harness

getTcpTable () 
|> getTcpTableRows
|> List.map(fun x -> createTCPRecord x) 
|> List.iter(fun x -> printfn "=====Begin Record====="
                      printfn "address and port: %s:%i" x.localAddress x.localport
                      printfn "remote host and port: %s:%i" x.remoteAddress x.remoteport
                      printfn "connection state: %s" x.connectionState
                      printfn "PID: %i" x.pid
                      match x.service with
                      |Some xo -> printfn "Service name: %s" xo
                      |None -> ()
                      printfn "=====End Record=====\n"
                      )
