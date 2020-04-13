module Fetters.WMI.Providers
    open System.Management
    
    let setManagementPath scope = 
        new ManagementPath(scope)

    let setManagementScope (path: ManagementPath) = 
        new ManagementScope(path)

    let connectManagementScope (managementScope: ManagementScope) =
        managementScope.Connect()
        managementScope.IsConnected

    let createObjectQuery query = 
        new ObjectQuery(query)

    let createObjectSearcher (objectQuery: ObjectQuery) = 
        new ManagementObjectSearcher(objectQuery)



