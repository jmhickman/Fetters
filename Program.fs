open System
open System.Security.Principal
open System.Runtime.InteropServices

open Fetters.DomainTypes 
open Fetters.NI.Providers
open Fetters.WMI.Providers
open Fetters.dotNetFunctions

let signs = {
        user = User{name="";domain="";sid=""}
        disk = Disk{name="";size="";mountpoint=""}}
printfn "%s" <| getSystem()
let lsaHandle = registerLsaLogonProcess ()
revertToSelf () |> ignore
let count, ptr = enumerateLsaLogonSessions () 
let sessions = getLsaSessionData (count, ptr) 
let authpkg_ = sessions
                |> List.map(fun _x -> _x.loginID.lower, _x.loginID.upper)
                |> List.head


let LSAString = LSA_STRING_IN(length = uint16("kerberos".Length), maxLength = uint16("kerberos".Length + 1), buffer = "kerberos")

let authpkg = lookupLsaAuthenticationPackage lsaHandle LSAString

let _bogusLUID = LUID(lower = fst authpkg_, upper = snd authpkg_)
let kerbquery = 
    KERB_QUERY_TKT_CACHE_REQUEST(messageType = KERB_PROTOCOL_MESSAGE_TYPE.KerbQueryTicketCacheMessage, 
                                    logonID = _bogusLUID)

let intauth = authpkg |> fun (LsaAuthPackage authpkg) -> authpkg
let kerbresponse = getKerberosTicketResponse lsaHandle authpkg (kerbquery |> KERB_QUERY_TKT_CACHE_REQ)

match kerbresponse with
|KERB_QUERY_TKT_CACHE_RESP _res -> printfn "%A"_res.countOfTickets
|KERB_RETRIEVE_TKT_RESP _res -> printfn "%A "_res.ticket 
 

