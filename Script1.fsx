open System
#r @"c:\Users\jon_h\source\repos\Fetters\bin\Debug\netcoreapp3.1\System.Management.dll"

let disk_query_list = [
    "Name";
    "Size";
    "Description";
    "SystemName";
    "VolumeName";
    "DeviceID"
    ]
let disk_query = "SELECT * FROM Win32_LogicalDisk"

/////////////////////////////
// Generic WMI query function
/////////////////////////////

let wmi_query query_string query_list = 
    let mgmnt_path = new System.Management.ManagementPath("\\\\Nino\\root\cimv2")

    let mgmnt_scope = new System.Management.ManagementScope(mgmnt_path)
    mgmnt_scope.Connect()

    let obj_search = new System.Management.ObjectQuery(query_string)

    let obj_searcher = new System.Management.ManagementObjectSearcher(mgmnt_scope, obj_search)

    let obj_collect = obj_searcher.Get()

    for query_item in obj_collect do
        query_list |> List.iter (fun q -> printf "Checking %s: %A - " q query_item.[q])
    printfn ""

// Call the generic with both args
printfn "Calling generically"
wmi_query disk_query disk_query_list

// Let's be smarter and use partial application
let wmi_disk_query = wmi_query disk_query disk_query_list

// We've now made a less generic query that preloads the proper arguments
printfn "Calling using partial application"

wmi_disk_query
