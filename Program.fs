open System
open System.Security.Principal

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
let sessions = getLsaSessionData ptr count
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
let kerbresponse = callLsaAuthenticationPackage lsaHandle authpkg kerbquery
printfn "%i::%i" intauth kerbresponse.countOfTickets

