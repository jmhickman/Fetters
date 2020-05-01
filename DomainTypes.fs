// Domain Types

module Fetters.DomainTypes

    open Microsoft.Win32
    open System
    open System.Net
    open System.Security

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
        mountpoint : string}

    type Firewall = {
        name : string
        rules : string list}

    type ArpTableByInd = {
        indexaddresses : (int32 * (IPAddress * string))}

    type ArpTable = {
        addresses : (IPAddress * string) list}

    type Interface = {
        adapterIndex : uint16
        adapterAddr : IPAddress
        adapterMAC : string
        gatewayAddr : IPAddress
        dnsServers : IPAddress list
        dhcpServers : IPAddress list
        arpTable : ArpTable}

    type Network = {
        interfaces : Interface list}

    type PC = {
        hostname : string
        is_vm : bool}

    type Session = {
        token : string 
        logon_type : string}

    type WindowsDetails = {
        winVer : string 
        runtimeVer: string 
        runtimeType : string //function output
        build : string}

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

    type VaultRecord = {
        name : string
        resource : string option
        identity : string option
        packageSid : string option
        credential : string option
        lastModified : DateTime
        }

    type SystemSecrets = {
        creds : Credential list
        files : File list
        ieDump : string list
        mruCommands : string list
        rdpConnections : string list
        vaultSecrets : VaultRecord list
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
        kerberosTGTcontents : KerberosTicket list}

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
        localAddress : IPAddress
        remoteAddress : IPAddress
        localport : uint16
        remoteport : uint16
        connectionState : string
        pid : uint32
        service : string option}

    type TokenPrivileges = {
         privileges : string list}

    type UDPListener = {
        localAddress : IPAddress
        localport : uint16
        pid : uint32
        service : string option}

    type SystemDynamicAttributes = {
        domainSessions : DomainSession list
        events : Event list
        interestingProcesses : string list // filtered from Process list
        processes : Process list
        rdpSessions : RdpSession list
        tcpConnections : TCPConnection list
        udpTraffic : UDPListener list
        userTokenPrivileges : TokenPrivileges}

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

    //The handles and pointers for the Kerberos enumeration are difficult to track 
    //because of the enormous code structure differences between Seatbelt and Fetters. 
    //To help keep the handles and pointers straight, make them Types.

    type LsaProcessHandle = LsaProcessHandle of IntPtr

    type LsaAuthPackage = LsaAuthPackage of int

    type LUIDPtr = LUIDPtr of IntPtr

    type VaultGuid = VaultGuid of IntPtr

    type VaultPtr = VaultPtr of IntPtr

    type VaultItemPtr = VaultItemPtr of IntPtr

    type VaultHandle = VaultHandle of IntPtr
    
