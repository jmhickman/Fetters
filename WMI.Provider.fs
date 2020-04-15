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
    let private createManagementPath path = new ManagementPath(path)

    let private createManagementScope (managementPath: ManagementPath) = 
        new ManagementScope(managementPath)

    let private initializeManagementScope path = 
        createManagementPath path |> createManagementScope

    let private createObjectQuery query = new ObjectQuery(query)

    let private createObjectSearcher objectQuery connectedScope = 
        new ManagementObjectSearcher(query = objectQuery, 
                                    scope = connectedScope)

    // Must connect the scope, which can fail
    let private connectManagementScope (managementScope: ManagementScope) =
        try
          Some (managementScope.Connect())
        with
        | _ -> None

    // Finally, create the ManagementObjectSearcher
    let private initializeObjectSearcher query 
            (connectedScope: ManagementScope) = 
        createObjectQuery query 
        |> fun _objq -> createObjectSearcher _objq connectedScope
    
    // Get the results of the WMI query, and then convert to a useful output
    // Since the wmiResults are in a strange not-collection, I have to either
    // do this, or convert to a list with a yield anyway if I want to use
    // nested List.map. 
    let private generateWmiResultsList 
            (mObjectSearcher: ManagementObjectSearcher) 
            (wmiQueryFilters: string list) = 
        let wmiResults = mObjectSearcher.Get()
        let _results = 
            [   for _r in wmiResults do
                    [
                    for _f in wmiQueryFilters do
                         yield (_r.[_f]).ToString()
                    ]    
            ]
        _results
         
    let getWmiSearchResults (wmiSingleQuery: WmiSingleQuery) =
        let _path = wmiSingleQuery.wmiPath
        let {wmiSqlQuery= _query; wmiFilterList= _filter} = 
            wmiSingleQuery.wmiQuery
        let initScope = initializeManagementScope _path
        let connectedScope = connectManagementScope initScope
        // We only initialize the ObjectSearcher if the scope object connected
        match (connectedScope) with
        | Some () -> initializeObjectSearcher _query initScope
                     |> fun x -> generateWmiResultsList x _filter
        | None -> [connectionError]

    let createRecord 
            (rawObject: (string list) list) 
            (outputRecordType: WmiRecord) : WmiRecord list = 
        match outputRecordType with
        | User x -> rawObject 
                    |> List.map(fun _l -> 
                    User {name = _l.[0]; domain = _l.[1]; sid = _l.[2]})
        | Disk x -> rawObject 
                    |> List.map(fun _l -> 
                    Disk {name = _l.[0]; size = _l.[1]; mountpoint = _l.[2]})

        
