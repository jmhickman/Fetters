open System
//open System.Security.Principal

open Fetters.DomainTypes 
open Fetters.NI.Providers
open Fetters.WMI.Providers
open Fetters.dotNetFunctions


// Testing/rework harness
let results = enumerateDomainSessions ()
printfn "Number of LSA Sessions detected: %i" <| results.Length
revertToSelf () |> ignore

results
|> List.map(fun result -> printfn "======START SESSION DATA======"
                          printfn "Username: %s" result.username
                          printfn "domain: %s" result.domain
                          printfn "logonID: 0x%08x" result.logonID
                          printfn "userSID: %A" result.userSID
                          printfn "authenticationPackage: %s" result.authenticationPkg
                          printfn "logontype: %s" result.logonType
                          printfn "logintime: %A" result.loginTime
                          printfn "logon server: %s" result.logonServer
                          printfn "logon server Domain %s" result.logonServerDnsDomain
                          printfn "user principal name: %s" result.userPrincipalName
                          printfn "------END SESSION DATA------"
                          result.kerberosTGTcontents
                          |> List.iter(fun x -> match x with
                                                |KerberosRetrieveTicket xx -> 
                                                    printfn "======START TGT DUMP======"
                                                    printfn "client Name: %s" xx.client 
                                                    printfn "service name: %s" xx.serviceName
                                                    printfn "target: %s" xx.target
                                                    printfn "domain: %s" xx.domain
                                                    printfn "target domain: %s" xx.targetDomain
                                                    printfn "session key type: %s" xx.sessionKeyType
                                                    printfn "base64 session key: %s" xx.base64SessionKey
                                                    printfn "key expiry: %A" xx.keyExpiry
                                                    printfn "flags: %A" xx.flags
                                                    printfn "start: %A" xx.startTime
                                                    printfn "end: %A" xx.endTime
                                                    printfn "renew: %A" xx.renewTime
                                                    printfn "skew: %A" xx.skewTime
                                                    printfn "encoded size: %i" xx.encodedSize
                                                    printfn "ticket: %s" xx.base64EncodedTicket
                                                    printfn "------END TGT------" 
                                                |KerberosQueryTicket xx -> ()) |>ignore
                          result.kerberosCachedTickets
                          |> List.iter(fun x -> match x with 
                                                |KerberosQueryTicket xx -> 
                                                     printfn "======START CACHE DATA======"
                                                     printfn "servername: %s" xx.serverName
                                                     printfn "realm: %s" xx.realm
                                                     printfn "start: %A" xx.startTime
                                                     printfn "end: %A" xx.endTime
                                                     printfn "renew: %A" xx.renewTime
                                                     printfn "encryption type: %s" xx.encryptionType
                                                     printfn "flags %A" xx.ticketFlags
                                                     printfn "------END CACHE DATA------"
                                                 |KerberosRetrieveTicket xx -> ())) |> ignore
