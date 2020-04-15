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
//let authpkg_ = sessions
//                |> List.map(fun _x -> _x.authenticationPackage)
//                |> List.head


let LSAString = LSA_STRING_IN(length = uint16("kerberos".Length), maxLength = uint16("kerberos".Length + 1), buffer = "kerberos")

let authpkg = lookupLsaAuthenticationPackage lsaHandle LSAString 
