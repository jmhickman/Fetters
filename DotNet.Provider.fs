module Fetters.DotNet.Provider

    open System
    open System.Net
    open System.Text
    open Fetters.Lists
    open Fetters.DomainTypes
    open Fetters.DotNet.Common
    

    let getBasicInfo () =
        let currentUser = 
            {username = Environment.UserName
             cwd = Environment.CurrentDirectory
             isHighIntegrity = isHighIntegrity ()
             isLocalAdmin = isLocalAdmin ()
            }
        
        let rKey = getRegistryKey HKEY_LOCAL_MACHINE "Software\\Microsoft\\Windows NT\\CurrentVersion" |> Option.get
        let windowsDetails = 
            {productName = getRegistryValue "ProductName" rKey
             releaseId = getRegistryValue "ReleaseId" rKey
             currentBuild = getRegistryValue "CurrentBuild" rKey
             arch = Environment.GetEnvironmentVariable "PROCESSOR_ARCHITECTURE"
             buildBranch = getRegistryValue "BuildBranch" rKey
             currentSession = currentUser
            }
        let pc = {hostname = (NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().DomainName + "\\" + Dns.GetHostName())
                  processorCount = Environment.ProcessorCount}
        windowsDetails, pc
    
    
    let extractChromeHistory (path: string) : ChromeHistory =
        let cPath = path + "\\" + "AppData\\Local\\Google\\Chrome\\User Data\\Default\\History"
        match fileExistsAtLocation cPath with
        |true ->
            let rgx = createMatchRegex @"(http|ftp|https|file)://([\w_-]+(?:(?:\.[\w_-]+)+))([\w.,@?^=%&:/~+#-]*[\w@?^=%&/~+#-]\s)?"
            let res = yieldLineSequence cPath  |> Seq.map (matchStringRegex rgx) |> Seq.toList |> List.filter(fun l -> not(l = ""))
            {path = path; url = res}

        |false -> {path = ""; url = []}


    let extractChromeBookmarks (path: string) : ChromeBookmark list =
        let cPath = path + "\\" + "AppData\\Local\\Google\\Chrome\\User Data\\Default\\Bookmarks"
        match fileExistsAtLocation cPath with
        |true -> let bookmarks = ChromeBookmarkJ.Parse(yieldWholeFile cPath)
                 bookmarks.Roots.BookmarkBar.Children 
                 |> Array.map(fun b -> {name = b.Name; url = b.Url})
                 |> Array.toList
        |false -> []


    let triageChrome (path: string) : ChromeInfo =
        let b = extractChromeBookmarks path
        let h = extractChromeHistory path
        {bookmarks = b; history = h}
        
    
    let getFirefoxProfiles (path: string) =
        let cPath = path + "\\" + "AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\"
        match dirExistsAtLocation cPath with
        |true -> let dirs = listChildDirectories cPath
                 dirs 
                 |> Array.map (fun d -> d + "\\places.sqlite")
                 |> Array.filter(fun d -> fileExistsAtLocation d)
        |false -> [||]


    let extractFirefoxHistory (path: string) : FirefoxHistory =
        match fileExistsAtLocation path with //Leaving the check because whatever
        |true ->
            printfn "True path"
            let rgx = createMatchRegex @"(http|ftp|https|file)://([\w_-]+(?:(?:\.[\w_-]+)+))([\w.,@?^=%&:/~+#-]*[\w@?^=%&/~+#-]\s)?"
            let res = yieldLineSequence path  |> Seq.map (matchStringRegex rgx) |> Seq.toList |> List.filter(fun l -> not(l = ""))
            {path = path; url = res}

        |false -> {path = ""; url = []}


    let getEventLog4624 (week: DateTime) (now: DateTime) : Event4624 list =
        let query = 
            sprintf "*[System/EventID=4624] and *[System[TimeCreated[@SystemTime >= '%s']]] and *[System[TimeCreated[@SystemTime <= '%s']]]" 
                (week.ToUniversalTime().ToString("o")) 
                (now.ToUniversalTime().ToString("o"))
        
        createEventQuery "Security" query 
        |> createEventLogReader
        |> extractEventLogs
        |> Seq.map(fun ev -> 
            let tstamp, e = ev
            {eventId = 4624us 
             timeStamp = tstamp
             subjectSID = e.[0]  
             subjectUsername = e.[1] 
             subjectDomainname = e.[2] 
             subjectLogonId = e.[3] 
             targetUserSID = e.[4] 
             targetUsername = e.[5] 
             targetDomainname = e.[6] 
             logonType = e.[8] 
             workstationName = e.[11]
             processName = e.[17]
             ipAddress = e.[18] 
             })
        |> Seq.toList
        
    let getEventLog4648 (week: DateTime) (now: DateTime) : Event4648 list = 
        let query = 
            sprintf "*[System/EventID=4648] and *[System[TimeCreated[@SystemTime >= '%s']]] and *[System[TimeCreated[@SystemTime <= '%s']]]" 
                (week.ToUniversalTime().ToString("o")) 
                (now.ToUniversalTime().ToString("o"))
        
        createEventQuery "Security" query 
        |> createEventLogReader 
        |> extractEventLogs
        |> Seq.map(fun ev -> 
            let tstamp, e = ev
            {eventId = 4648us 
             timeStamp = tstamp
             subjectSID = e.[0]  
             subjectUsername = e.[1] 
             subjectDomainname = e.[2] 
             subjectLogonId = e.[3] 
             targetUsername = e.[5] 
             targetDomainname = e.[6] 
             targetServername = e.[7]
             processName = e.[10]
             ipAddress = e.[11] 
            })
        |> Seq.toList


    let getFirewallRules (onlyDeny: bool) : FirewallRule list  =
        let rawRules = getRawRules ()
        
        let filteredRules = 
            match onlyDeny with
            |true -> denyOnlyFilter rawRules
            |false -> allowFilter rawRules
        
        filteredRules
        |> List.map(fun fR -> 
            let pList = 
                firewallPropertyNames
                |> List.map(fun pN -> 
                    getFirewallAttr fR pN)
            {name = pList.[0]
             description = pList.[1]
             protocol = pList.[2]
             applicationName = pList.[3]
             localAddresses = pList.[4]
             localPorts = pList.[5]
             remoteAddresses = pList.[6]
             remotePorts = pList.[7]
             direction = pList.[8]
             profiles = pList.[9]
            })


    let createFirewallRecord denyOnly : Firewall = 
        match denyOnly with
        |true -> {profile = createFirewallObj() |> getFProfileProperty |> string
                  rules = getFirewallRules true}
        |false -> {profile = createFirewallObj() |> getFProfileProperty |> string
                   rules = getFirewallRules false}


    let getDPAPIMasterKeys userFolders : DPAPIMasterKey list =
        userFolders
        |> Array.map(fun u -> u + "\\" + "AppData\\Roaming\\Microsoft\\Protect\\")
        |> Array.filter dirExistsAtLocation
        |> Array.map listChildDirectories
        |> Array.concat
        |> Array.map listChildFiles
        |> Array.concat
        |> Array.filter(fun f -> 
            let r = f.Split '\\'
            not(r |> Array.last = "Preferred"))
        |> Array.map(fun d ->
            let token = d.Split('\\')
            let sid = token.[token.Length-2]
            {userSID = sid; encodedBlob = encodeEntireFileB64 d})
        |> Array.toList

        
    let getCredFiles userFolders : DPAPICredFile list =
        userFolders
        |> Array.map(fun u -> u + "\\" + "AppData\\Local\\Microsoft\\Credentials\\")
        |> Array.filter dirExistsAtLocation
        |> Array.map listChildFiles
        |> Array.concat
        |> Array.map(fun p -> 
            let mguid = new Guid(getByteSection 36L 16 p)
            let strlen = BitConverter.ToInt32((getByteSection 56L 4 p), 0)
            let credtype = Encoding.Unicode.GetString(getByteSection 60L (strlen - 6) p)
            {path = p; description = credtype; encodedBlob = encodeEntireFileB64 p })
        |> Array.toList


    let detectRDCManFile userFolders : string list =
        userFolders
        |> Array.map(fun u -> u + "\\" + "AppData\\Local\\Microsoft\\Remote Desktop Connection Manager\\RDCMan.settings")
        |> Array.filter fileExistsAtLocation
        |> Array.map (sprintf "Remote Desktop Manager connection file exists at %s")
        |> Array.toList


    let getGoogleCloudCreds userFolders : GoogleCredential list =
        userFolders
        |> Array.map(fun u -> u + "\\" + "AppData\\Roaming\\gcloud\\credentials.db")
        |> Array.filter fileExistsAtLocation
        |> Array.map(fun f -> 
            {GoogleCredential.path = f; encodedFile = encodeEntireFileB64 f})
        |> Array.toList


    let getGoogleCloudCredsL userFolders : GoogleCredential list =
        userFolders
        |> Array.map(fun u -> u + "\\" + "AppData\\Roaming\\gcloud\\legacy_credentials.db")
        |> Array.filter fileExistsAtLocation
        |> Array.map(fun f -> 
            {GoogleCredential.path = f; encodedFile = encodeEntireFileB64 f})
        |> Array.toList
    
    
    let getGoogleAccessTokens userFolders : GoogleCredential list =
        userFolders
        |> Array.map(fun u -> u + "\\" + "AppData\\Roaming\\gcloud\\access_tokens.db")
        |> Array.filter fileExistsAtLocation
        |> Array.map(fun f -> 
            {GoogleCredential.path = f; encodedFile = encodeEntireFileB64 f})
        |> Array.toList

    
    let getAzureTokens userFolders : AzureCredential list =
        userFolders
        |> Array.map(fun u -> u + "\\" + ".azure\\accessTokens.json")
        |> Array.filter fileExistsAtLocation
        |> Array.map(fun f -> 
            {AzureCredential.path = f; encodedFile = encodeEntireFileB64 f})
        |> Array.toList


    let getAzureProfile userFolders : AzureCredential list =
        userFolders
        |> Array.map(fun u -> u + "\\" + ".azure\\azureProfile.json")
        |> Array.filter fileExistsAtLocation
        |> Array.map(fun f -> 
            {AzureCredential.path = f; encodedFile = encodeEntireFileB64 f})
        |> Array.toList


    let getAWSCreds userFolders : AWSCredential list =
        userFolders
        |> Array.map(fun u -> u + "\\" + ".aws\\credentials")
        |> Array.filter fileExistsAtLocation
        |> Array.map(fun f -> 
            {AWSCredential.path = f; encodedFile = encodeEntireFileB64 f})
        |> Array.toList