module Fetters.WMI.Providers
    open System
    open System.Management
    open Fetters.DomainTypes

    let localScope 
        (semaphore: WmiSemaphore) 
        : string = 
        match semaphore with
        |SAV -> sprintf "\\\\%s\\root\\securitycenter2" <| Environment.GetEnvironmentVariable("COMPUTERNAME")
        |_ -> sprintf "\\\\%s\\root\\cimv2" <| Environment.GetEnvironmentVariable("COMPUTERNAME")


    let private initializeManagementScope 
        (path: string)
        : ManagementScope = 
        let mpath = new ManagementPath(path)
        let mScope = new ManagementScope(mpath)
        mScope


    let private connectManagementScope 
        (managementScope: ManagementScope) 
        : unit option =
        try
            Some (managementScope.Connect())
        with
        | _ -> None


    let private createObjectQuery
        (semaphore: WmiSemaphore)
        : ObjectQuery = 
        match semaphore with
        |SAV -> new ObjectQuery("SELECT * FROM AntiVirusProduct")
        |SDisk -> new ObjectQuery("SELECT * FROM Win32_LogicalDisk WHERE DriveType = 3")
        |SGroup -> new ObjectQuery("Select * from Win32_Group Where LocalAccount = True")
        |SMappedDrive -> new ObjectQuery("SELECT * FROM Win32_NetworkConnection WHERE LocalName IS NOT NULL")
        |SNetworkShare -> new ObjectQuery("SELECT * FROM Win32_Share WHERE NOT Name LIKE '%$'")
        |SOSDetails -> new ObjectQuery("SELECT * FROM Win32_OperatingSystem")
        |SPatches -> new ObjectQuery("SELECT * FROM win32_quickfixengineering")
        |SUser -> new ObjectQuery("SELECT * FROM Win32_Account where SidType=1")


    let private createObjectSearcher 
        (connectedScope: ManagementScope) 
        (objectQuery: ObjectQuery)
        : ManagementObjectSearcher = 
        new ManagementObjectSearcher(connectedScope, objectQuery)
        
    
    let private generateRawWMIResult
        (semaphore: WmiSemaphore)
        (mObjectSearcher: ManagementObjectSearcher)
        : WmiRawResult = 
        let filters = 
            match semaphore with
            |SAV -> ["DisplayName";"PathToSignedProductExe";"PathToSignedReportingExe"]
            |SDisk -> ["Name";"Size";"Filesystem"]
            |SGroup -> ["Name";"SID";]
            |SMappedDrive -> ["ConnectionState";"LocalName";"Persistent";"RemoteName";"RemotePath";"Status";"UserName"]
            |SNetworkShare -> ["Name";"Description";"Path"]
            |SPatches -> ["Description";"HotfixId";"InstalledOn"]
            |SOSDetails -> ["BuildNumber";"Name"]
            |SUser -> ["Name";"Domain";"SID"]
        
        let wmiResults = mObjectSearcher.Get()
        let result = {
            rawListofList = 
                [for result in wmiResults do
                    [for filter in filters do
                        yield (result.[filter]).ToString()
                    ]    
                ]
        }
        result
    
    
    let private createRecord 
        (semaphore: WmiSemaphore)
        (rawResult: WmiRawResult)         
        : WmiRecord list = 

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
                    mountpoint = rawList.[2]
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
                networkShare |> WmiRecord.Share)
        |SPatches ->
            rawResult.rawListofList
            |> List.map(fun rawList ->
                let patch = {
                    description = rawList.[0]
                    hotfixId = rawList.[1]
                    installedOn = rawList.[2]
                    }
                patch |> WmiRecord.Patch)
        |SOSDetails -> 
            rawResult.rawListofList
            |> List.map(fun rawList ->
                let os = {
                    winVer = rawList.[0]
                    build = rawList.[1]
                    runtimeVer = ""
                    runtimeType= ""
                }
                os |> WmiRecord.OS)
        |SUser -> 
            rawResult.rawListofList
            |> List.map(fun rawList ->
                let user = {
                    name = rawList.[0]
                    domain = rawList.[1]
                    sid = rawList.[2]
                } 
                user |> WmiRecord.User)


    let queryWMI 
        (semaphore: WmiSemaphore)
        : WmiRecord list = 
        initializeManagementScope <| localScope semaphore 
        |> fun cs -> match connectManagementScope cs with
                     |Some xu -> createObjectQuery semaphore 
                                 |> createObjectSearcher cs 
                                 |> generateRawWMIResult semaphore 
                                 |> createRecord semaphore
                     |None -> []