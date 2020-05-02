module Fetters.WMI.Providers
    open System
    open System.Management
    open Fetters.DomainTypes

    let localScope = 
        sprintf "\\\\%s\\root\cimv2" <| Environment.GetEnvironmentVariable("COMPUTERNAME")

        /////////////////////////////////
    // WMI Management Object Creation
    /////////////////////////////////
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
        |SDisk -> new ObjectQuery("SELECT * FROM Win32_LogicalDisk")
        |SGroup -> new ObjectQuery("Select * from Win32_Group Where LocalAccount = True")
        |SOS -> new ObjectQuery("SELECT * FROM Win32_OperatingSystem")
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
            |SDisk -> ["Name";"Size";"Filesystem"]
            |SGroup -> ["Name";"SID";]
            |SOS -> ["BuildNumber";"Name"]
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
        |SDisk -> rawResult.rawListofList
                  |> List.map(fun rawList -> 
                      let disk = {
                          name = rawList.[0]
                          size = rawList.[1]
                          mountpoint = rawList.[2]
                      }
                      disk |> WmiRecord.Disk) 
        |SGroup -> rawResult.rawListofList
                   |> List.map(fun rawList ->
                        let group = {
                            name = rawList.[0]
                            sid = rawList.[1]
                            members = [""]
                        }
                        group |> WmiRecord.Group)
        |SOS -> rawResult.rawListofList
                |> List.map(fun rawList ->
                     let os = {
                         winVer = rawList.[0]
                         build = rawList.[1]
                         runtimeVer = ""
                         runtimeType= ""
                        }
                     os |> WmiRecord.OS)
        |SUser -> rawResult.rawListofList
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
        initializeManagementScope localScope 
        |> fun cs -> match connectManagementScope cs with
                     |Some xu -> createObjectQuery semaphore |> createObjectSearcher cs |> generateRawWMIResult semaphore |> createRecord semaphore
                     |None -> []