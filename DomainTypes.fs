module Fetters.DomainTypes

    open Microsoft.Win32
    open System
    open System.Net
    open System.Security

    //////////////////
    //Elementary types
    //////////////////

    //// File Types ////
    type InterestingFile = {
        reason : string
        location : string
        }

    type Recent_File = {
        location : string
        }

    //// Registry Types ////
    type RegistryValueType = 
         |String of string
         |ExpandString of string
         |Binary of byte array
         |DWord of int32
         |MultiString of string array
         |QWord of int64

     type RegistryResult = {
         name : string
         value : RegistryValueType
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

    type ArpTableByInd = {
        indexaddresses : (int32 * (IPAddress * string))
        }

    type ArpTable = {
        addresses : (IPAddress * string) list
        }

    type Interface = {
        adapterIndex : uint16
        adapterAddr : IPAddress
        adapterMAC : string
        gatewayAddr : IPAddress
        dnsServers : IPAddress list
        dhcpServers : IPAddress list
        arpTable : ArpTable
        }

    type Network = {
        interfaces : Interface list
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

    //// Credential types ////
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

    type Credential = 
        |AWSCredential
        |AzureCredential
        |DPAPIBlob
        |GoogleCredential
        |NetworkCredential

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
        //files : File list
        ieDump : string list
        mruCommands : string list
        rdpConnections : string list
        vaultSecrets : VaultRecord list
        }

    /////////////////////////////////
    // System Static Attributes Types
    /////////////////////////////////

    type AuditSettings = {
        processauditing : RegistryResult option}

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
    
    type AntiVirus = {
        engine : string
        productExe : string
        reportingExe : string
        }
    
    type EnvironmentVar = {
        environmentKey : string
        environmentVal : string 
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

    type LocalGroup = {
        name : string
        sid : string
        members : string list
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

    type MappedDrive = {
        connectionState : string
        localName : string
        persistent : string
        remoteName : string
        remotePath : string
        status : string
        userName : string
        }
    
    type Patch = {
        description : string
        hotfixId : string
        installedOn : string}
    
    type PowerShellEnv = {
        poshVersion2 : RegistryResult option 
        poshVersion5 : RegistryResult option 
        poshTLog : RegistryResult option []
        poshMLog : RegistryResult option []
        poshSLog : RegistryResult option []
        }

    type RDPSavedConnection = {
        host : string
        usernameHint : RegistryResult option
        }

    type RecentCommand = {
        recentCommand : RegistryResult option
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
    type User = { 
         name : string
         domain : string
         sid: string
         }
 
    type WEFSettings = {
        //Potentially huge keyspace makes anything more specific untenable
        policies : RegistryResult option []
        }

    type SystemStaticAttributes = {
        //autoruns : 
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
        kerberosTGTcontents : KerberosTicket list
        }

    type Event = {
        eventId : uint32 
        eventDesc : string 
        }

    type InterestingProcess = {
        reason : string
        description : string}

    type Process = {
        processName : string 
        pid : uint16 
        processBinpath : string 
        processInvocation : string 
        processIntegrity : string 
        dotnetProcess : string
        InterestingProcess : InterestingProcess option
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

    type SystemDynamicAttributes = {
        domainSessions : DomainSession list
        events : Event list
        interestingProcesses : string list // filtered from Process list
        processes : Process list
        rdpSessions : RdpSession list
        tcpConnections : TCPConnection list
        udpTraffic : UDPListener list
        userTokenPrivileges : TokenPrivileges
        }

    
    /////////////////////////
    // WMI Query Module Types
    /////////////////////////

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
        |SOSDetails
        |SUser
    
    type Null = Null of string

    type WmiRecord = 
        |AV of AntiVirus
        |Disk of Disk
        |Group of LocalGroup
        |MappedDrive of MappedDrive
        |Share of Share
        |OS of WindowsDetails
        |Patch of Patch
        |User of User
        |Null of Null
        

    (*type outputRecordType = 
        {user: WmiRecord
         disk: WmiRecord
        }*)

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
    
    ///////////////
    // dotNet Types
    ///////////////

    //These are for the dotNet.Common and Registry.Provider functions

    type RegHive = 
        |HKEY_LOCAL_MACHINE
        |HKEY_CURRENT_USER
        |HKEY_USER
