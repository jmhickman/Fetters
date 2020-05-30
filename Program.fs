
open System

open Fetters.Lists
open Fetters.DomainTypes 
open Fetters.PInvoke.Provider
open Fetters.WMI.Provider
open Fetters.DotNet.Common
open Fetters.DotNet.Provider
open Fetters.Registry.Provider

//////
//Init
//////



let intitialSetup () =
    let s = buildSystemDriveRoot ()
    let l = buildLocalUserFolders s
    let lAdm = isLocalAdmin ()
    let hi = isHighIntegrity ()
    let now = createNowTime ()
    let wWeek = createWeekTimeWindow ()

    {sysRoot = s; luserFolders = l; localAdmin = lAdm; highIntegrity = hi; now = now; windowWeek = wWeek}

let (|FunctionName|_|) (functionname: string) = 
    if functionNames |> List.contains (functionname.ToLower()) then Some (functionname.ToLower()) else None

let rec createArgumentRecord args (initArgs:ProgramArguments ) : ProgramArguments =
    match args with
    | [] -> initArgs
    | "-v"::tail -> 
        let uArgs = {initArgs with verbose = true}
        createArgumentRecord tail uArgs
    | "-hh"::tail ->
        let uArgs = {initArgs with fullHelp = true; terseHelp = false}
        createArgumentRecord tail uArgs 
    |FunctionName x::tail -> 
        let uArgs = {initArgs with functionGroup = x::initArgs.functionGroup; terseHelp = false}
        createArgumentRecord tail uArgs
    | _::tail ->
        createArgumentRecord tail initArgs

[<EntryPointAttribute>]
let main cargs =
    "Hi, this is Fetters! There's no real help right now, so please leave a message" |> gPrinter Asterisk |> cPrinter Blue
    let initArgs = {verbose = false; terseHelp = true; fullHelp = false; functionGroup = []}
    let args = cargs |> Array.toList
    let actualArgs = createArgumentRecord args initArgs
    printfn "%A" actualArgs
    0

