//Licensed to the Apache Software Foundation (ASF) under one
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

module Fetters.DomainTypes

    open FSharp.Data
    open System
    open System.Net
    open System.Security

    //////////////////
    //Elementary Types
    //////////////////

    type RegistryValueType = 
         |String of string
         |ExpandString of string
         |Binary of byte array
         |MultiString of string array
         |DWord of int32
         |QWord of int64

     type RegistryResult = {
         name : string
         value : RegistryValueType
         }

    type ChromeBookmarkJ = JsonProvider<".\SampleBookmarks">

    ///////////////
    //PInvoke Types
    ///////////////
    
    type LsaProcessHandle = LsaProcessHandle of IntPtr
    
    type LsaAuthPackage = LsaAuthPackage of int
    
    type LUIDPtr = LUIDPtr of IntPtr
    
    type VaultGuid = VaultGuid of IntPtr
    
    type VaultPtr = VaultPtr of IntPtr
    
    type VaultItemPtr = VaultItemPtr of IntPtr
    
    type VaultHandle = VaultHandle of IntPtr
    
    type ArpTableByInd = {
           indexaddresses : (int32 * (IPAddress * string))
           }

    //type ArpTable = {
    //    localaddress : IPAddress
    //    addresses : (IPAddress * string) list
    //    }

    [<Flags>]
    type KERB_TICKET_FLAGS =
        |reserved = 2147483648u
        |forwardable = 0x40000000u
        |forwarded = 0x20000000u
        |proxiable = 0x10000000u
        |proxy = 0x08000000u
        |may_postdate = 0x04000000u
        |postdated = 0x02000000u
        |invalid = 0x01000000u
        |renewable = 0x00800000u
        |initial = 0x00400000u
        |pre_authent = 0x00200000u
        |hw_authent = 0x00100000u
        |ok_as_delegate = 0x00040000u
        |name_canonicalize = 0x00010000u
        |enc_pa_rep = 0x00010000u
        |reserved1 = 0x00000001u

    type KerberosRetrieveTicket = {
        serviceName : string
        target : string
        client : string
        domain : string
        targetDomain : string
        altTargetDomain : string
        sessionKeyType : string
        base64SessionKey : string
        keyExpiry : DateTime
        flags : KERB_TICKET_FLAGS
        startTime : DateTime
        endTime : DateTime
        renewTime : DateTime
        skewTime : DateTime
        encodedSize : int32
        base64EncodedTicket : string
        }

    type KerberosQueryTicket = {
        serverName : string
        realm : string
        startTime : DateTime
        endTime : DateTime
        renewTime : DateTime
        encryptionType : string
        ticketFlags: KERB_TICKET_FLAGS
        }
    
    type KerberosTicket =
        |KerberosRetrieveTicket of KerberosRetrieveTicket
        |KerberosQueryTicket of KerberosQueryTicket
    
    type DomainSession = {
        username : string
        domain : string
        logonID : uint32
        userSID : Principal.SecurityIdentifier
        authenticationPkg : string
        logonType : string
        loginTime : DateTime
        logonServer : string
        logonServerDnsDomain : string
        userPrincipalName : string
        kerberosCachedTickets : KerberosTicket list
        kerberosTGTcontents : KerberosTicket list
        }

    type RdpSession = {
        state : string
        sessionID : int
        sessionName : string
        hostName : string
        username : string
        remoteAddress : Net.IPAddress
        }

    type TCPConnection = {
        localAddress : IPAddress
        remoteAddress : IPAddress
        localport : uint16
        remoteport : uint16
        connectionState : string
        pid : uint32
        service : string option
        }

    type TokenPrivileges = {
         privileges : string list
        }

    type UDPListener = {
        localAddress : IPAddress
        localport : uint16
        pid : uint32
        service : string option
        }
    
    type VaultRecord = {
        name : string
        resource : string option
        identity : string option
        packageSid : string option
        credential : string option
        lastModified : DateTime
        }

    type FettersPInvokeRecord = 
        |ArpTableByInd of ArpTableByInd
        |DomainSession of DomainSession
        |RdpSession of RdpSession
        |TCPConnection of TCPConnection
        |TokenPrivileges of TokenPrivileges
        |UDPListener of UDPListener
        |VaultRecord of VaultRecord

    ////////////////
    //Registry Types
    ////////////////

    type AuditSettings = {
        processauditing : RegistryResult option
        }

    type AutoLogonSettings = {
        defaultDomainName : RegistryResult option
        defaultUserName : RegistryResult option
        defaultPassword : RegistryResult option
        altDefaultDomainName : RegistryResult option
        altDefaultUserName : RegistryResult option
        altDefaultPassword : RegistryResult option
        }

    type AutorunSetting = {
        location : string
        value : RegistryResult option
        }
    
    type HistoryIE = {
        path : string
        url : RegistryResult option
        }

    type InternetSettings = {
        proxyServer : RegistryResult option
        proxyOverride : RegistryResult option
        proxyEnable : RegistryResult option
        }

    type LapsSettings = {
        lapsAdminAccountName : RegistryResult option
        lapsPasswordComplexity : RegistryResult option
        lapsPasswordLength : RegistryResult option
        lapsPasswdProtection : RegistryResult option
        }
  
    type LSASettings = {
        lsaPid : RegistryResult option
        notificationPkgs : RegistryResult option
        authorizationPkgs : RegistryResult option
        prodType : RegistryResult option
        limitBlankPwd : RegistryResult option
        secureboot : RegistryResult option
        disdomcreds : RegistryResult option
        everyoneAnon : RegistryResult option
        forceGuest: RegistryResult option
        restrictAnon : RegistryResult option
        restrictSAM : RegistryResult option
        samConnAccnt : RegistryResult option
        }

    type PuttySSHSession = {
        hostname : RegistryResult option
        username : RegistryResult option
        publicKeyFile : RegistryResult option
        portForwardings : RegistryResult option
        connectionSharing : RegistryResult option
        }

    type PuttyHostPublicKeys = {
        recentHostKeys : RegistryResult option
        }

    type PowerShellEnv = {
        poshVersion2 : RegistryResult option 
        poshVersion5 : RegistryResult option 
        poshTLog : RegistryResult option list
        poshMLog : RegistryResult option list
        poshSLog : RegistryResult option list
        }

    type RDPSavedConnection = {
        host : string
        usernameHint : RegistryResult option
        }

    type RecentCommand = {
        recentCommand : RegistryResult option
        }
    type SysmonConfig = {
        hashingAlgorithm : RegistryResult option
        options : RegistryResult option
        rules : RegistryResult option
        }
    
    type UACPolicies = {
        //Will need to do some logic with these values to print restiction
        //information at export.
        consentPromptBehavior : RegistryResult option
        enableLUA : RegistryResult option
        localAccountTokenFilterPolicy : RegistryResult option
        filterAdministratorToken : RegistryResult option
        }

    type WEFSettings = {
          //Potentially huge keyspace makes anything more specific untenable
          policies : RegistryResult option list
          }

    type FettersRegistryRecord =
        |AuditSettings of AuditSettings
        |AutoLogonSettings of AutoLogonSettings
        |AutorunSetting of AutorunSetting
        |HistoryIE of HistoryIE
        |InternetSettings of InternetSettings
        |LapsSettings of LapsSettings
        |LSASettings of LSASettings
        |PuttyHostPublicKeys of PuttyHostPublicKeys
        |PuttySSHSession of PuttySSHSession
        |PowerShellEnv of PowerShellEnv
        |RDPSavedConnection of RDPSavedConnection
        |RecentCommand of RecentCommand
        |SysmonConfig of SysmonConfig
        |UACPolicies of UACPolicies
        |WEFSettings of WEFSettings
    
    //////////////////////////////
    //Filesystem Enumeration Types
    //////////////////////////////

    type AWSCredential = {
        path : string
        encodedFile : string
        }

    type AzureCredential = {
        path : string
        encodedFile : string
        }
    
    type ChromeBookmark = {
        name : string
        url : string
        }
    
    type ChromeHistory = {
        path : string
        url : string list //comes from filesystem, not registry
        }

    type ChromeInfo = {
        bookmarks : ChromeBookmark list
        history : ChromeHistory
        }

    type DPAPIMasterKey = {
          userSID : string 
          encodedBlob : string 
          }

    type DPAPICredFile = {
          path : string
          description : string
          encodedBlob : string
          }

    type FirefoxHistory = {
        path : string
        url : string list
        }

    type FirefoxInfo = {
        history : FirefoxHistory list
        }
    
    type GoogleCredential = {
        path : string 
        encodedFile : string 
        }

    type Credential = 
        |AWSCredential of AWSCredential
        |AzureCredential of AzureCredential
        |DPAPIMasterKey of DPAPIMasterKey
        |DPAPICredFile of DPAPICredFile
        |GoogleCredential of GoogleCredential

    type FettersFilesystemRecord = 
        |Credential of Credential
        |FirefoxInfo of FirefoxInfo
        |ChromeInfo of ChromeInfo

    ///////////////
    //Special Types
    ///////////////

    type CurrentSession = {
        username : string 
        cwd : string
        isHighIntegrity : bool
        isLocalAdmin : bool
        }
    
    type EnvironmentVar = {
        environmentKey : string
        environmentVal : string
        }

    type Event4624 = {
        eventId : uint16
        timeStamp : string
        subjectSID : string
        subjectUsername : string
        subjectDomainname : string
        subjectLogonId : string
        targetUserSID : string
        targetUsername : string
        targetDomainname : string
        logonType : string
        workstationName : string
        processName : string
        ipAddress : string
        }

    type Event4648 = {
        eventId : uint16
        timeStamp : string
        subjectSID : string
        subjectUsername : string
        subjectDomainname : string
        subjectLogonId: string
        targetUsername : string
        targetDomainname : string
        targetServername : string
        processName : string
        ipAddress : string
        }

    type FirewallRule = {
        name : string
        description: string
        protocol : string
        applicationName: string
        localAddresses : string
        localPorts : string
        remoteAddresses : string
        remotePorts : string
        direction : string
        profiles : string
        }
    
    type Firewall = {
        profile : string
        rules : FirewallRule list
        }

    type Interface = {
        adapterIndex : uint16
        adapterAddr : IPAddress
        adapterMAC : string
        gatewayAddr : IPAddress
        dnsServers : IPAddress list
        dhcpServers : IPAddress list
        //arpTable : ArpTable Later
        }

    type Network = {
        interfaces : Interface list
        }

    type PC = {
        hostname : string
        processorCount : int
        }

    type ServiceBinaryPath = 
          |Unquoted_Path
          |Quoted_Path

    type WindowsDetails = {
        productName: RegistryResult option
        releaseId : RegistryResult option 
        currentBuild: RegistryResult option
        arch : string
        buildBranch : RegistryResult option
        currentSession : CurrentSession
        }

    type FettersSpecialRecord = 
        |EnvironmentVar of EnvironmentVar
        |Event4624 of Event4624
        |Event4648 of Event4648
        |Firewall of Firewall     
        |Network of Network
        |PC of PC
        |WindowsDetails of WindowsDetails

    ///////////
    //WMI Types
    ///////////

    type AntiVirus = {
        engine : string
        productExe : string
        reportingExe : string
        }

    type Disk = {
        name : string
        size: string
        filesystem : string
        }
    
    type InterestingProcess = {
         reason : string
         description : string}

    type LocalGroup = {
        name : string
        sid : string
        members : string list
        }
    
    type MappedDrive = {
        connectionState : string
        localName : string
        persistent : string
        remoteName : string
        remotePath : string
        userName : string
        }
    
    type Patch = {
        description : string
        hotfixId : string
        installedOn : string}
    
    type Process = {
        processName : string 
        pid : string
        processBinpath : string 
        processInvocation : string 
        processOwner : string
         //InterestingProcess : InterestingProcess option
        }

    type Service = {
        serviceName : string 
        serviceDisplayname : string 
        serviceCompany : string 
        serviceDescription : string 
        serviceRunning : string 
        serviceStarttype : string 
        serviceIsdotnet : bool 
        serviceBinpath : string
        }
    
    type Share = {
        shareName : string 
        shareDesc : string 
        sharePath : string 
        }

    type User = { 
        name : string
        domain : string
        sid: string
        groups : (string * string) list
        }

    //type LogonSession = {
    //    name : string
    //    logonId : string
    //    logonType : string
    //    authPkg : string
    //    }

    type WmiQueryType = {
        wmiSqlQuery: string
        wmiFilterList: string list
        }

    type WmiRawResult = {
        rawListofList : string list list
        }

    type WmiSemaphore = 
        |SAV
        |SDisk
        |SGroup
        |SMappedDrive
        |SNetworkShare
        |SPatches
        |SProcess
        |SService
        |SUser
        //|SLogonSession
    
    type WmiRecord = 
        |AV of AntiVirus
        |Disk of Disk
        |Group of LocalGroup
        |MappedDrive of MappedDrive
        |Service of Service
        |NetworkShare of Share
        |Patch of Patch
        |Process of Process
        |User of User
        //|LogonSession of LogonSession


    ///////////////
    //Program Types
    ///////////////

    type RegHive = 
        |HKEY_LOCAL_MACHINE
        |HKEY_CURRENT_USER
        |HKEY_USER

    type CColor =
        |Red
        |Yellow
        |Green
        |Blue
    
    type Glyph = 
        |Asterisk
        |Plus
        |Minus
        |At
        |Bang
        |Octothorpe

    type initRecord = {
        sysRoot : string
        luserFolders : string array
        localAdmin : bool
        highIntegrity : bool
        now : DateTime
        windowWeek : DateTime
        }

    type ProgramArguments = {
        terseHelp : bool
        fullHelp : bool
        functionGroup : string list
        }

    type FettersRecords = 
        |FettersFilesystemRecord of FettersFilesystemRecord
        |FettersPInvokeRecord of FettersPInvokeRecord
        |FettersRegistryRecord of FettersRegistryRecord
        |FettersSpecialRecord of FettersSpecialRecord
        |WmiRecord of WmiRecord
        