module Fetters.WMI.Providers
    open System
    open System.Management
    open Fetters.DomainTypes

    let localScope = String.Format
                        ("\\\\{0}\\root\cimv2",  
                        Environment.GetEnvironmentVariable("COMPUTERNAME"))

    let connectionError = 
        ["Error: Scope didn't connect. Check credentials or WMI path"]

    let wmiUserQuery = 
        {wmiSqlQuery = "SELECT * FROM Win32_Account where SidType=1"; 
        wmiFilterList = ["Name";"Domain";"SID"]}
    
    let wmiOsQuery = 
        {wmiSqlQuery = "SELECT * FROM Win32_OperatingSystem";
        wmiFilterList = ["BuildNumber";"Name"]}

    let wmiDiskQuery = 
        {wmiSqlQuery = "SELECT * FROM Win32_LogicalDisk";
        wmiFilterList = ["Name";"Size";"Filesystem"]}

    let wmiGroupQuery = 
        {wmiSqlQuery = "Select * from Win32_Group  Where LocalAccount = True"
         wmiFilterList = ["Name";"SID";]}

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

    let private createObjectQuery query = new ObjectQuery(query)

    let private createObjectSearcher 
        (objectQuery: ObjectQuery)
        (connectedScope: ManagementScope) 
        : ManagementObjectSearcher = 
        
        new ManagementObjectSearcher(connectedScope, objectQuery)
        
    // Get the results of the WMI query, and then convert to a useful output
    // Since the wmiResults are in a strange not-collection, I have to either
    // do this, or convert to a list with a yield anyway if I want to use
    // nested List.map. 
    let private generateWmiResultsList 
            (mObjectSearcher: ManagementObjectSearcher) 
            (wmiQueryFilters: string list) 
            : string list list= 
        let wmiResults = mObjectSearcher.Get()
         
        [for _r in wmiResults do
            [for _f in wmiQueryFilters do
                 yield (_r.[_f]).ToString()
            ]    
        ]
         
    let private getWmiSearchResults 
        (wmiSingleQuery: WmiSingleQuery) 
        : string list list=
        let path = wmiSingleQuery.wmiPath
        let {wmiSqlQuery= query; wmiFilterList= filters} = wmiSingleQuery.wmiQuery
        let mScope = initializeManagementScope path
        let oQuery = createObjectQuery query

        // We only initialize the ObjectSearcher if the scope object connected
        match connectManagementScope mScope with
        | Some () -> createObjectSearcher oQuery mScope
                     |> fun x -> generateWmiResultsList x filters
        | None -> [connectionError]

    let private createRecord 
        (rawObject: string list list) 
        (outputRecordType: WmiRecord) 
        : WmiRecord list = 
        match outputRecordType with
        | User x -> rawObject 
                    |> List.map(fun _l -> 
                                User {name = _l.[0]; domain = _l.[1]; sid = _l.[2]})
        | Disk x -> rawObject 
                    |> List.map(fun _l -> 
                                Disk {name = _l.[0]; size = _l.[1]; mountpoint = _l.[2]})

    let queryWMI = getWmiSearchResults >> createRecord
    // change outputRecordType to the planned semaphore instead of overloading the WmiRecord type.
    // the signature should look like semaphore -> WmiRecord lsit
