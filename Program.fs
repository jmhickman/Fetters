open System
open System.Security.Principal

open Fetters.DomainTypes 
open Fetters.NI.Providers
open Fetters.WMI.Providers
open Fetters.dotNetFunctions

let signs = {
        user = User{name="";domain="";sid=""}
        disk = Disk{name="";size="";mountpoint=""}}
printf "%s" (getSystem())
