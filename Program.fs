open Fetters.DomainTypes 
open Fetters.NI.Providers
open Fetters.WMI.Providers
open System
open System.Security.Principal
open System.Security.Permissions
open System.Runtime.InteropServices

let signs = {
        user = User{name="";domain="";sid=""}
        disk = Disk{name="";size="";mountpoint=""}}

