﻿module Fetters.WMI.Provider
    
    open System
    open System.Management
    open Fetters.DomainTypes
    open Fetters.DotNet.Common

    let private localScope semaphore : string = 
        match semaphore with
        |SAV -> sprintf "\\\\%s\\root\\securitycenter2" <| Environment.GetEnvironmentVariable "COMPUTERNAME"
        |_ -> sprintf "\\\\%s\\root\\cimv2" <| Environment.GetEnvironmentVariable "COMPUTERNAME"


    let private initializeManagementScope path : ManagementScope = 
        let mpath = new ManagementPath(path)
        let mScope = new ManagementScope(mpath)
        mScope


    let private connectManagementScope (managementScope: ManagementScope) : unit option =
        try
            Some (managementScope.Connect())
        with
        | _ -> None


    let private createObjectQuery semaphore : ObjectQuery = 
        match semaphore with
        |SAV -> new ObjectQuery "SELECT * FROM AntiVirusProduct"
        |SDisk -> new ObjectQuery "SELECT * FROM Win32_LogicalDisk WHERE DriveType = 3"
        |SGroup -> new ObjectQuery "Select * from Win32_Group Where LocalAccount = True"
        |SMappedDrive -> new ObjectQuery "SELECT * FROM Win32_NetworkConnection WHERE LocalName IS NOT NULL"
        |SNetworkShare -> new ObjectQuery "SELECT * FROM Win32_Share WHERE NOT Name LIKE '%$'"
        |SPatches -> new ObjectQuery "SELECT * FROM win32_quickfixengineering"
        |SProcess -> ObjectQuery "SELECT * FROM Win32_Process WHERE NOT Name LIKE '%svchost%' AND NOT Name LIKE '%conhost%'"
        |SService -> new ObjectQuery "SELECT * FROM win32_service"
        |SUser -> new ObjectQuery "SELECT * FROM Win32_Account where SidType=1"


    let private createObjectSearcher (connectedScope: ManagementScope) objectQuery = 
        new ManagementObjectSearcher(connectedScope, objectQuery)
        
    
    let private generateRawWMIResult semaphore (mObjectSearcher: ManagementObjectSearcher) : WmiRawResult = 
        let filters = 
            match semaphore with
            |SAV -> ["DisplayName";"PathToSignedProductExe";"PathToSignedReportingExe"]
            |SDisk -> ["Name";"Size";"Filesystem"]
            |SGroup -> ["Name";"SID";]
            |SMappedDrive -> ["ConnectionState";"LocalName";"Persistent";"RemoteName";"RemotePath";"Status";"UserName"]
            |SNetworkShare -> ["Name";"Description";"Path"]
            |SPatches -> ["Description";"HotfixId";"InstalledOn"]
            |SProcess -> ["Name";"ProcessId";"ExecutablePath";"CommandLine"]
            |SService -> ["Name";"DisplayName";"Description";"State";"StartMode";"PathName"]
            |SUser -> ["Name";"Domain";"SID"]
        
        let wmiResults = mObjectSearcher.Get()
        {rawListofList = 
         [for result in wmiResults do
            [for filter in filters do
                if not(result.[filter] = null) then
                   yield (result.[filter]).ToString()
                else yield ""
            ]    
         ]}
        
        
    
    let private createRecord semaphore rawResult : WmiRecord list = 

        match semaphore with
        |SAV -> 
            rawResult.rawListofList
            |> List.map(fun rawList -> 
                let av = {
                    engine = rawList.[0]
                    productExe = rawList.[1]
                    reportingExe = rawList.[2]
                }
                av |> WmiRecord.AV) 
        |SDisk -> 
            rawResult.rawListofList
            |> List.map(fun rawList -> 
                let disk = {
                    name = rawList.[0]
                    size = rawList.[1]
                    filesystem = rawList.[2]
                }
                disk |> WmiRecord.Disk) 
        |SGroup -> 
            rawResult.rawListofList
            |> List.map(fun rawList ->
                let group = {
                    name = rawList.[0]
                    sid = rawList.[1]
                    members = [""]
                }
                group |> WmiRecord.Group)
        |SMappedDrive ->
            rawResult.rawListofList
            |> List.map(fun rawList ->
                let mappedDrive = {
                    connectionState = rawList.[0]
                    localName = rawList.[1]
                    persistent = rawList.[2]
                    remoteName = rawList.[3]
                    remotePath = rawList.[4]
                    status = rawList.[5]
                    userName = rawList.[6]
                }
                mappedDrive |> WmiRecord.MappedDrive)
        |SNetworkShare ->
            rawResult.rawListofList
            |> List.map(fun rawList ->
                let networkShare = {
                    shareName = rawList.[0]
                    shareDesc = rawList.[1]
                    sharePath = rawList.[2]
                    }
                networkShare |> WmiRecord.NetworkShare)
        |SPatches ->
            rawResult.rawListofList
            |> List.map(fun rawList ->
                let patch = {
                    description = rawList.[0]
                    hotfixId = rawList.[1]
                    installedOn = rawList.[2]
                    }
                patch |> WmiRecord.Patch)
        |SProcess ->
            rawResult.rawListofList
            |> List.map(fun rawList ->
                let processr = {
                    processName = rawList.[0]
                    pid = rawList.[1]
                    processBinpath = rawList.[2]
                    processInvocation = rawList.[3]
                    processOwner = ""
                    }
                processr |> WmiRecord.Process)
        |SService -> 
            rawResult.rawListofList
            |> List.map(fun rawList ->
                let service = {
                    serviceName = rawList.[0]
                    serviceDisplayname = rawList.[1]
                    serviceCompany = getFileVersionInfo (matchWMIServiceString rawList.[5])
                    serviceDescription = rawList.[2]
                    serviceRunning = rawList.[3]
                    serviceStarttype = rawList.[4]
                    serviceIsdotnet = getDotNetAssembly (matchWMIServiceString  rawList.[5])
                    serviceBinpath = matchWMIServiceString  rawList.[5]
                    }
                service |> WmiRecord.Service)
        |SUser -> 
            rawResult.rawListofList
            |> List.map(fun rawList ->
                let user = {
                    name = rawList.[0]
                    domain = rawList.[1]
                    sid = rawList.[2]
                    groups = getCurrentUsersGroups ()
                } 
                user |> WmiRecord.User)


    let queryWMI 
        (semaphore: WmiSemaphore)
        : WmiRecord list = 
        initializeManagementScope <| localScope semaphore 
        |> fun cs -> 
            match connectManagementScope cs with
            |Some xu -> 
                createObjectQuery semaphore 
                |> createObjectSearcher cs 
                |> generateRawWMIResult semaphore 
                |> createRecord semaphore
            |None -> []

    
    //Owner lookup is extremely expensive. Not hooked up for now
    let getProcessInformation () : WmiRecord list =
        let filters = ["Name";"ProcessID";"ExecutablePath";"CommandLine"]
        let c = initializeManagementScope (localScope SProcess)
        let q = createObjectQuery SProcess
        let s = createObjectSearcher c q
        let WmiResults = s.Get()
        [for r in WmiResults do 
            let mo = r :?> ManagementObject
            let objr = Array.zeroCreate 1
            mo.InvokeMethod("GetOwner", objr) |> ignore
            let powner = unbox<string> objr.[0]
            let rlist = 
                [for filter in filters do
                 if not(r.[filter] = null) then
                    let rl = (r.[filter]).ToString()
                    yield  rl
                 else yield ""
                ]
            yield powner, rlist       
        ]
        |> List.map(fun tu ->
            let po, rl = tu
            {processName = rl.[0]
             pid = rl.[1]
             processBinpath = rl.[2]
             processInvocation = rl.[3]
             processOwner = po} |> WmiRecord.Process
             )