// Domain Types

module Fetters.DomainTypes

    open Microsoft.Win32
    open System

    // File types
    type InterestingFile = {
        reason : string
        location : string
    }

    type Recent_File = {
        location : string
    }

    // Credential types
    type AWSCredential = {
        username : string
        password : string
    }

    type AzureCredential = {
        username : string
        password : string
    }

    type DPAPIBlob = {
        username : string 
        password : string 
    }

    type GoogleCredential = {
        username : string 
        password : string 
    }

    type NetworkCredential = {
        username : string 
        password : string 
    }

    type SSHCredential = {
        username : string
        key : string option
        password : string option
    }

    ///////////////
    // System Types
    ///////////////
    type Disk = {
        name : string
        size: string
        mountpoint : string
    }

    type Firewall = {
        name : string
        rules : string list
    }

    type Network = {
        // Try to find an IPAddress type
        ifaces : string list
        routes : string list
        dns : string list
        dhcp : string list
    }

    type PC = {
        hostname : string
        is_vm : bool 
    }

    type Session = {
        token : string 
        logon_type : string 
    }

    type WindowsDetails = {
        winVer : string 
        runtimeVer: string 
        runtimeType : string //function output
        build : string 
    }

    type System = {
        disks : Disk list
        firewall : Firewall
        networks : Network list
        pc : PC
        sessions : Session list
        winDetails : WindowsDetails
    }
    //////////////////////
    // System Secret Types
    //////////////////////

    type Credential = 
        |AWSCredential
        |AzureCredential
        |DPAPIBlob
        |GoogleCredential
        |NetworkCredential
        |SSHCredential

    type File = 
        | Interesting_File
        | Recent_File 

    type SystemSecrets = {
        creds : Credential list
        files : File list
        ieDump : string list
        mruCommands : string list
        rdpConnections : string list
        vaultSecrets : string list
    }

    /////////////////////////////////
    // System Static Attributes Types
    /////////////////////////////////

    type AutorunKey = AutorunKey of RegistryKey

    type EnvironmentVar = {
        environmentKey : string
        environmentVal : string 
    }

    type LocalGroup = {
        name : string
        members : string list
    }

    type LSASettings = {
        lsaPid : uint16
        notificationPkgs : string list
        authorizationPkgs : string list 
        prodType : uint8
        limitBlankPwd : bool
        secureboot : bool 
        disdomcreds : bool 
        everyoneAnon : bool 
        forceGuest: bool 
        restrictAnon : bool 
        restrictSAM : bool 
        samConnAccnt : bool 
    }

    type PowerShellEnv = {
        poshVersion : string 
        poshTLog : string 
        poshMLog : string 
        poshSLog : string 
    }

    type ServiceBinaryPath = 
        |Unquoted_Path
        |Quoted_Path

    type Service = {
        serviceName : string 
        serviceDisplayname : string 
        serviceCompany : string 
        serviceDescription : string 
        serviceRunning : string 
        serviceStarttype : string 
        serviceIsdotnet : string 
        serviceBinpath : ServiceBinaryPath
    }

    type Share = {
        shareName : string 
        shareDesc : string 
        sharePath : string 
    }

    type User = 
        {name : string
         domain : string
         sid: string}
                

    type SystemStaticAttributes = {
        autoruns : AutorunKey list
        environmentVars : EnvironmentVar list
        localGroupsAndMembers : LocalGroup list
        lsaSettings : LSASettings
        missingCriticalPatches : string list //function output
        patches : string list
        poshenv : PowerShellEnv
        services : Service list
        shares : Share list
        uaclevel : string
        users : User list
        userFolders : string list
        wefEn : bool 
    }

    ////////////////////////////
    // System dynamic Attributes
    ////////////////////////////

    type KerberosRetrieveTicket = {
        serviceName : string
        target : string
        client : string
        domain : string
        targetDomain : string
        altTargetDomain : string
        sessionKeyType : string
        base64SessionKey : string
        keyExpiry : string
        flags : string //probably wrong
        startTime : uint64
        endTime : uint64
        renewTime : uint64
        skewTime : uint64
        encodedSize : uint32
        base64EncodedTicket : string
        }

    type KerberosQueryTicket = {
        serverName : string
        realm : string
        startTime : uint64
        endTime : uint64
        renewTime : uint64
        encryptionType : string
        ticketContents : KerberosRetrieveTicket
        }

    type DomainSession = {
        domain : string
        logonID : uint32
        userSID : string // probably wrong
        authenticationPkg : string
        logonType : string
        logonTime : uint32
        logonServer : string
        logonServerDnsDomain : string
        userPrincipalName : string
        kerberosTickets : KerberosQueryTicket list}

    type Event = {
        eventId : uint32 
        eventDesc : string 
    }

    type Process = {
        processName : string 
        pid : uint16 
        processBinpath : string 
        processInvocation : string 
        processIntegrity : string 
        dotnetProcess : string 
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
        localAddress : string
        remoteAddress : string
        connectionState : string
        pid : uint16
        service : string option
        processName : string
    }

    type UDPConnection = {
        localAddress : string
        pid : uint16
        service : string option
        processName : string
    }

    type SystemDynamicAttributes = {
        domainSessions : DomainSession list
        events : Event list
        interestingProcesses : string list // filtered from Process list
        processes : Process list
        rdpSessions : RdpSession list
        tcpConnections : TCPConnection list
        udpTraffic : UDPConnection list
    }

    type FullOutput = {
        loot : SystemSecrets
        sys : System
        sysStatic : SystemStaticAttributes
        sysSnapshot : SystemDynamicAttributes
    }
    /////////////////////////
    // WMI Query Module types
    /////////////////////////

    type WmiQueryType = {
        wmiSqlQuery: string
        wmiFilterList: string list
        }

    type WmiSingleQuery = {
        wmiPath: string
        wmiQuery: WmiQueryType 
        }

    type WmiRecord = 
        | User of User 
        | Disk of Disk
        

    type outputRecordType = 
        {user: WmiRecord
         disk: WmiRecord
        }

    ////////////////////
    // Native Call Types
    ////////////////////

    // the handles for the Kerberos enum are difficult to track because of the enormous
    // code structure differences between Seatbelt and Fetters. To help keep the handles
    // and pointers and such straight, I'm going to make them Types.

    type LsaProcessHandle = LsaProcessHandle of IntPtr

    type LsaAuthPackage = LsaAuthPackage of int

    type LUIDPtr = LUIDPtr of IntPtr
