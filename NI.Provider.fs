﻿module Fetters.NI.Providers

    open System
    open System.Diagnostics
    open System.Runtime.InteropServices
    open System.Security.Principal

    open Fetters.dotNetFunctions
    open Fetters.DomainTypes

    /////////////////////////////
    // DU "enums" for native code
    /////////////////////////////

    //KERB Enum

    [<Struct>]
    [<Flags>]
    // Unverified
    type KERB_CACHE_OPTIONS =
        |KERB_RETRIEVE_TICKET_DEFAULT = 0x0UL
        |KERB_RETRIEVE_TICKET_DONT_USE_CACHE = 0x1UL
        |KERB_RETRIEVE_TICKET_USE_CACHE_ONLY = 0x2UL
        |KERB_RETRIEVE_TICKET_USE_CREDHANDLE = 0x4UL
        |KERB_RETRIEVE_TICKET_AS_KERB_CRED = 0x8UL
        |KERB_RETRIEVE_TICKET_WITH_SEC_CRED = 0x10UL
        |KERB_RETRIEVE_TICKET_CACHE_TICKET = 0x20UL
        |KERB_RETRIEVE_TICKET_MAX_LIFETIME = 0x40UL

    [<Struct>]
    type KERB_ENCRYPTION_TYPE =
        |reserved0 = 0
        |des_cbc_crc = 1
        |des_cbc_md4 = 2
        |des_cbc_md5 = 3
        |reserved1 = 4
        |des3_cbc_md5 = 5
        |reserved2 = 6
        |des3_cbc_sha1 = 7
        |dsaWithSHA1_CmsOID = 9
        |md5WithRSAEncryption_CmsOID = 10
        |sha1WithRSAEncryption_CmsOID = 11
        |rc2CBC_EnvOID = 12
        |rsaEncryption_EnvOID = 13
        |rsaES_OAEP_ENV_OID = 14
        |des_ede3_cbc_Env_OID = 15
        |des3_cbc_sha1_kd = 16
        |aes128_cts_hmac_sha1_96 = 17
        |aes256_cts_hmac_sha1_96 = 18
        |aes128_cts_hmac_sha256_128 = 19
        |aes256_cts_hmac_sha384_192 = 20
        |rc4_hmac = 23
        |rc4_hmac_exp = 24
        |camellia128_cts_cmac = 25
        |camellia256_cts_cmac = 26
        |subkey_keymaterial = 65

    [<Struct>]
    type KERB_PROTOCOL_MESSAGE_TYPE = 
        |KerbDebugRequestMessage = 0u
        |KerbQueryTicketCacheMessage = 1u
        |KerbChangeMachinePasswordMessage = 2u
        |KerbVerifyPacMessage = 3u
        |KerbRetrieveTicketMessage = 4u
        |KerbUpdateAddressesMessage = 5u
        |KerbPurgeTicketCacheMessage = 6u
        |KerbChangePasswordMessage = 7u
        |KerbRetrieveEncodedTicketMessage = 8u
        |KerbDecryptDataMessage = 9u
        |KerbAddBindingCacheEntryMessage = 10u
        |KerbSetPasswordMessage = 11u
        |KerbSetPasswordExMessage = 12u
        |KerbVerifyCredentialsMessage = 13u
        |KerbQueryTicketCacheExMessage = 14u
        |KerbPurgeTicketCacheExMessage = 15u
        |KerbRefreshSmartcardCredentialsMessage = 16u
        |KerbAddExtraCredentialsMessage = 17u
        |KerbQuerySupplementalCredentialsMessage = 18u
        |KerbTransferCredentialsMessage = 19u
        |KerbQueryTicketCacheEx2Message = 20u
        |KerbSubmitTicketMessage = 21u
        |KerbAddExtraCredentialsExMessage = 22u
        |KerbQueryKdcProxyCacheMessage = 23u
        |KerbPurgeKdcProxyCacheMessage = 24u
        |KerbQueryTicketCacheEx3Message = 25u
        |KerbCleanupMachinePkinitCredsMessage = 26u
        |KerbAddBindingCacheEntryExMessage = 27u
        |KerbQueryBindingCacheMessage = 28u
        |KerbPurgeBindingCacheMessage = 29u
        |KerbQueryDomainExtendedPoliciesMessage = 30u
        |KerbQueryS4U2ProxyCacheMessage = 31u
    
    [<Struct>]
    //unverified
    type SECURITY_LOGON_TYPE =
        |UndefinedLogonType
        |Interactive
        |Network
        |Batch
        |Service
        |Proxy
        |Unlock
        |NetworkCleartext
        |NewCredentials
        |RemoteInteractive
        |CachedInteractive
        |CachedRemoteInteractive
        |CachedUnlock  

    //RDP Enum
    
    [<Struct>]
    type WTS_CONNECTED_CLASS =
        |Active
        |Connected
        |ConnectQuery
        |Shadow
        |Disconnected
        |Idle
        |Listen
        |Reset
        |Down
        |Init

    [<Struct>]
    // Controls what query we make
    type WTS_INFO_CLASS =
        |WTSClientAddress = 14

    // Vault section
    
    [<Struct>]
    type VAULT_ELEMENT_TYPE = 
        |Undefined = -1
        |Boolean = 0
        |Short = 1
        |UnsignedShort = 2
        |Int = 3
        |UnsignedInt = 4
        |Double = 5
        |Guid = 6
        |String = 7
        |ByteArray = 8
        |TimeStamp = 9
        |ProtectedArray = 10
        |Attribute = 11
        |Sid = 12
        |Last = 13

    [<Struct>]
    type VAULT_SCHEMA_ELEMENT_ID =
        |Illegal = 0
        |Resource = 1
        |Identity = 2
        |Authenticator = 3
        |Tag = 4
        |PackageSid = 5
        |AppStart = 100
        |AppEnd = 10000

    //////////////////////////////
    // Structs for the native code
    //////////////////////////////

    // LSA Section

    [<Struct>]
    [<StructLayout(LayoutKind.Sequential)>]
    type LSA_STRING_IN =
        val mutable length : uint16
        val mutable maxLength : uint16
        val mutable buffer : string

    [<Struct>]
    [<StructLayout(LayoutKind.Sequential)>]
    type LSA_STRING_OUT =
        val mutable length : uint16
        val mutable maxLength : uint16
        val mutable buffer : IntPtr

    [<Struct>]
    [<StructLayout(LayoutKind.Sequential)>]
    type LUID = 
        val mutable lower: uint32
        val mutable upper: int 

    [<Struct>]
    [<StructLayout(LayoutKind.Sequential)>]
    // Unverfied: Folks list some weird self-reference thing in the signatures
    // but the docs say these two pointers only, so this is what I'm 
    // rolling with.
    type SECURITY_HANDLE = 
        val mutable lower: IntPtr
        val mutable upper: IntPtr

    // KERB section

    [<Struct>]
    [<StructLayout(LayoutKind.Sequential)>]
    type KERB_CRYPTO_KEY = 
        val mutable keyType : int32
        val mutable length : int32
        val mutable value : IntPtr

    [<Struct>]
    [<StructLayout(LayoutKind.Sequential)>]
    type KERB_EXTERNAL_NAME =
        val mutable nameType : int16
        val mutable nameCount : uint16
        val mutable names : LSA_STRING_OUT

    [<Struct>]
    [<StructLayout(LayoutKind.Sequential)>]
    type KERB_EXTERNAL_TICKET = 
        val mutable ServiceName : IntPtr
        val mutable TargetName : IntPtr
        val mutable ClientName : IntPtr 
        val mutable DomainName : LSA_STRING_OUT 
        val mutable TargetDomainName : LSA_STRING_OUT 
        val mutable AltTargetDomainName : LSA_STRING_OUT 
        val mutable SessionKey : KERB_CRYPTO_KEY 
        val mutable TicketFlags : uint32 
        val mutable Flags : uint32 
        val mutable KeyExpirationTime : int64 
        val mutable StartTime : int64 
        val mutable EndTime : int64 
        val mutable RenewUntil : int64 
        val mutable TimeSkew : int64 
        val mutable EncodedTicketSize : int32 
        val mutable EncodedTicket : IntPtr 

    [<Struct>]
    [<StructLayout(LayoutKind.Sequential)>]
    type KERB_TICKET_CACHE_INFO = 
        val mutable serverName : LSA_STRING_OUT
        val mutable realmName : LSA_STRING_OUT
        val mutable startTime : int64
        val mutable endTime : int64
        val mutable renewTime : int64
        val mutable encryptionType : int32
        val mutable ticketFlags : uint32

    [<Struct>]
    [<StructLayout(LayoutKind.Sequential)>]
    type KERB_QUERY_TKT_CACHE_REQUEST =
        val mutable messageType : KERB_PROTOCOL_MESSAGE_TYPE
        val mutable logonID : LUID

    [<Struct>]
    [<StructLayout(LayoutKind.Sequential)>]
    type KERB_QUERY_TKT_CACHE_RESPONSE = 
        val mutable messageType : KERB_PROTOCOL_MESSAGE_TYPE
        val mutable countOfTickets : int
        val mutable startOfTickets : IntPtr // A bodge

    [<Struct>]
    [<StructLayout(LayoutKind.Sequential)>]
    type KERB_RETRIEVE_TKT_REQUEST =
        val mutable messageType : KERB_PROTOCOL_MESSAGE_TYPE
        val mutable logonID : LUID
        val mutable targetName : LSA_STRING_IN
        val mutable ticketFlags : uint64
        val mutable cacheOptions : KERB_CACHE_OPTIONS
        val mutable encryptionType : int64
        val mutable credentialsHandle : SECURITY_HANDLE

    [<Struct>]
    [<StructLayout(LayoutKind.Sequential)>]
    type KERB_RETRIEVE_TKT_RESPONSE =
        val mutable ticket : KERB_EXTERNAL_TICKET

    [<Struct>]
    [<StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)>]
    type LOCAL_GROUP_MEMBER_INFO2 = 
         val mutable lgrmi2_sid : IntPtr
         val mutable lgrmi2_sidusage : int
         val mutable lgrmi2_domainandname : string
    
    [<Struct>]
    [<StructLayout(LayoutKind.Sequential)>]
    type SECURITY_LOGON_SESSION_DATA =
        val mutable size : uint32
        val mutable loginID : LUID
        val mutable username : LSA_STRING_OUT
        val mutable loginDomain : LSA_STRING_OUT
        val mutable authenticationPackage : LSA_STRING_OUT
        val mutable logonType : SECURITY_LOGON_TYPE
        val mutable session : uint32
        val mutable pSID : IntPtr
        val mutable loginTime : uint64
        val mutable logonServer : LSA_STRING_OUT
        val mutable dnsDomainName : LSA_STRING_OUT
        val mutable upn : LSA_STRING_OUT

    // RDP section

    [<Struct>]
    [<StructLayout(LayoutKind.Sequential)>]
    type WTS_SESSION_INFO_1 = 
        val mutable ExecEnvId : int32
        val mutable State : WTS_CONNECTED_CLASS
        val mutable SessionID : int32
        val mutable pSessionName : string
        val mutable pHostName : string
        val mutable pUserName : string
        val mutable pDomainName : string
        val mutable pFarmName : string

    [<Struct>]
    [<StructLayout(LayoutKind.Sequential)>]
    type WTS_CLIENT_ADDRESS = 
        val mutable addressFamily : uint32
        [<MarshalAs(UnmanagedType.ByValArray, SizeConst = 20)>]
        val mutable addressRaw : byte[]
    
    type KerberosRequest = 
        |KERB_QUERY_TKT_CACHE_REQ of KERB_QUERY_TKT_CACHE_REQUEST
        |KERB_RETRIEVE_TKT_REQ of KERB_RETRIEVE_TKT_REQUEST

    type KerberosResponse = 
        |KERB_QUERY_TKT_CACHE_RESP of KERB_QUERY_TKT_CACHE_RESPONSE
        |KERB_RETRIEVE_TKT_RESP of KERB_RETRIEVE_TKT_RESPONSE

    type KerberosTicketStruct = 
        |KERB_EXTERNAL_TKT of KERB_EXTERNAL_TICKET
        |KERB_TKT_CACHE_INFO of KERB_TICKET_CACHE_INFO

    [<Struct>]
    [<StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)>]
    type VAULT_ITEM_WIN8 = 
        val mutable SchemaId : Guid
        val mutable pszCredentialFriendlyName :IntPtr
        val mutable pResourceElement : IntPtr
        val mutable pIdentityElement : IntPtr
        val mutable pAuthenticatorElement : IntPtr
        val mutable pPackageSid : IntPtr
        val mutable LastModified : uint64
        val mutable dwFlags : uint32
        val mutable dwPropertiesCount : uint32
        val mutable pPropertyElements : IntPtr 

    [<Struct>]
    [<StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)>]
    type VAULT_ITEM_WIN7 = 
        val mutable SchemaId : Guid
        val mutable pszCredentialFriendlyName :IntPtr
        val mutable pResourceElement : IntPtr
        val mutable pIdentityElement : IntPtr
        val mutable pAuthenticatorElement : IntPtr
        val mutable LastModified : uint64
        val mutable dwFlags : uint32
        val mutable dwPropertiesCount : uint32
        val mutable pPropertyElements : IntPtr 
    [<Struct>]
    [<StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)>]
    type VAULT_ITEM_ELEMENT =
       [<FieldOffset(0)>]
       val mutable SchemaElementId : VAULT_SCHEMA_ELEMENT_ID
       [<FieldOffset(8)>]
       val mutable Type : VAULT_ELEMENT_TYPE

    type VaultItem = 
        |WIN8VAULT of VAULT_ITEM_WIN8
        |WIN7VAULT of VAULT_ITEM_WIN7

    //////////////////////
    // Import Declarations
    //////////////////////

    //advapi32
    
    [<DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)>]
    extern bool LogonUser(string lpszUsername,
                         string lpszDomain,
                         string lpszPassword, 
                         int dwLogonType, 
                         int dwLogonProvider, 
                         [<Out>] IntPtr& phToken)

    [<DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)>]
    extern bool OpenProcessToken(IntPtr processHandle, 
                                uint32 desiredAccess, 
                                [<Out>] IntPtr& tokenHandle)

    [<DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)>]
    extern bool DuplicateToken(IntPtr existingTokenHandle, 
                              int impersonationLevel, 
                              [<Out>] IntPtr& duplicatTokenHandle)

    [<DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)>]
    extern bool ImpersonateLoggedOnUser(IntPtr tokenHandle)

    [<DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)>]
    extern bool RevertToSelf()

    //kernel32
    
    [<DllImport("kernel32.dll")>]
    extern bool CloseHandle(IntPtr handle)

    //NetApi32

    [<DllImport("Netapi32.dll")>]
    extern int NetApiBufferFree(IntPtr bufptr)
    
       
    [<DllImport("netapi32.dll", CharSet = CharSet.Unicode)>]
    extern int NetLocalGroupGetMembers(string serverName, 
                                      string localGroupName, 
                                      int level, // 2
                                      [<Out>] IntPtr& bufptr,
                                      int prefmaxlen, // -1
                                      [<Out>] int& entriesRead,
                                      [<Out>] int& totalEntries,
                                      [<Out>] IntPtr resumeHandle)

    //secur32
    
    [<DllImport("secur32.dll", SetLastError = true)>]
    //unverified
    extern int LsaConnectUntrusted([<Out>] IntPtr& lsaHandle)

    [<DllImport("secur32.dll", SetLastError = true)>]
    extern int LsaRegisterLogonProcess(LSA_STRING_IN& logonProcessName, 
                                      [<Out>] IntPtr& lsaHandle, 
                                      [<Out>] uint64& securityMode)

    [<DllImport("secur32.dll", SetLastError = true)>]
    extern int LsaDeregisterLogonProcess([<In>] IntPtr lsaHandle)

    [<DllImport("secur32.dll", SetLastError = true)>]
    extern int LsaLookupAuthenticationPackage(IntPtr lsaHandle, 
                                             LSA_STRING_IN packageName, 
                                             [<Out>] int& authenticationPackage)

    [<DllImport("secur32.dll", EntryPoint = "LsaCallAuthenticationPackage", SetLastError = true)>]
    extern int LsaCallAuthenticationPackage_CACHE(IntPtr lsaHandle, 
                                                 int authenticationPackage, 
                                                 KERB_QUERY_TKT_CACHE_REQUEST protocolSubmitBuffer, 
                                                 int submitBufferLength, 
                                                 [<Out>] IntPtr& protocolReturnBuffer, 
                                                 [<Out>] int& returnBufferLength, 
                                                 [<Out>] int protocolStatus)

    [<DllImport("secur32.dll", EntryPoint = "LsaCallAuthenticationPackage", SetLastError = true)>]
    extern int LsaCallAuthenticationPackage_RET(IntPtr lsaHandle, 
                                               int authenticationPackage, 
                                               KERB_RETRIEVE_TKT_REQUEST protocolSubmitBuffer, 
                                               int submitBufferLength, 
                                               [<Out>] IntPtr& protocolReturnBuffer, 
                                               [<Out>] int& returnBufferLength, 
                                               [<Out>] int protocolStatus)
                                            
    [<DllImport("secur32.dll", SetLastError = true)>]
    extern uint32 LsaFreeReturnBuffer(IntPtr& buffer)

    [<DllImport("secur32.dll", SetLastError = true)>]
    extern uint32 LsaEnumerateLogonSessions([<Out>] uint64& logonSessionCount, [<Out>] IntPtr& logonSessionList)

    [<DllImport("secur32.dll", SetLastError = true)>]
    extern uint32 LsaGetLogonSessionData(IntPtr luid, [<Out>] IntPtr& ppLogonSessionData )

    [<DllImport("wtsapi32.dll", SetLastError = true)>]
    extern int WTSEnumerateSessionsEx(IntPtr hServer,
                                     int& pLevel,
                                     int Filter,
                                     [<Out>] IntPtr& ppSessionInfo,
                                     [<Out>] int& pCount)
                                        

    [<DllImport("wtsapi32.dll", SetLastError = true)>]
    extern IntPtr WTSOpenServer(string pServerName)

    [<DllImport("Wtsapi32.dll", SetLastError = true)>]
    extern bool WTSQuerySessionInformation(IntPtr& hServer,
                                          int sessionId,
                                          WTS_INFO_CLASS wtsClientAddress,
                                          [<Out>] IntPtr& ppBuffer,
                                          [<Out>] int& pBytesReturned)

    ////////////////////////
    // Native function calls
    ////////////////////////

    let marshalLSAString
        (sourceStruct: LSA_STRING_OUT)
        : string =
        match sourceStruct with
        | x when not(x.buffer = IntPtr.Zero) && 
                 not(x.length = 0us) -> let unmanagedString = Marshal.PtrToStringAuto(sourceStruct.buffer, (int(sourceStruct.maxLength /2us))).Trim()
                                        unmanagedString
        |_ -> ""

    //////////////////////////
    // RDP Session Enumeration
    //////////////////////////
    
    let private populateRdpSessionStructs 
        (ppSessionBaseAddr: IntPtr)
        (count: int) 
        : WTS_SESSION_INFO_1[] =
        // Helper function to pull unmanaged info into managed code 
        let mutable ppSBA = ppSessionBaseAddr
        //let enumSessions = Array.create count (WTS_SESSION_INFO_1())
        [|0..(count - 1)|] 
        |> Array.map(fun c -> let wtsSessionInfo = Marshal.PtrToStructure<WTS_SESSION_INFO_1>(ppSBA)
                              ppSBA <- IntPtr.Add(ppSBA, Marshal.SizeOf<WTS_SESSION_INFO_1>())
                              wtsSessionInfo)

    let private rdpSessionGetAddress 
        (ppBuffer: IntPtr) 
        : System.Net.IPAddress = 
        // Helper function for extracting IP address strings from the 
        // WTS_CLIENT_ADDRESS struct
        let addr = Marshal.PtrToStructure<WTS_CLIENT_ADDRESS>(ppBuffer)
        System.Net.IPAddress(addr.addressRaw.[2..5])
        
    let private rdpSessionReverseLookup 
        (sessionID: int) =
        // Helper function to do a reverse IP lookup on a given Session ID
        let mutable server = WTSOpenServer("localhost")
        let mutable ppBuffer = IntPtr.Zero
        let mutable pBytesReturned = 0

        let revLookup = 
            WTSQuerySessionInformation(&server, 
                                       sessionID,
                                       WTS_INFO_CLASS.WTSClientAddress, 
                                       &ppBuffer, 
                                       &pBytesReturned)
        
        match revLookup with
        | true -> rdpSessionGetAddress ppBuffer 
        | false -> System.Net.IPAddress.None

    let enumerateRdpSessions () =
        // Returns a RdpSession record list option of local sessions meeting the filter,
        // namely that they contain the name "RDP" in the session. We don't want
        // non-Rdp sessions in this output.
        let server = WTSOpenServer("localhost")
        let mutable ppSessionInfo = IntPtr.Zero
        let mutable count = 0
        let mutable level = 1

        let returnValue = 
            WTSEnumerateSessionsEx(server, &level, 0, &ppSessionInfo, &count)

        let allEnumeratedSessions = 
            match returnValue with
            | x when x > 0 -> populateRdpSessionStructs ppSessionInfo count
            | _ -> [||]

        let enumList = 
            allEnumeratedSessions 
            |> Array.filter(fun f -> f.pSessionName.StartsWith("RDP"))
            |> Array.map(fun sess -> {state = sess.State.ToString(); 
                                       sessionID = sess.SessionID;
                                       sessionName = sess.pSessionName;
                                       hostName = sess.pHostName;
                                       username = sess.pUserName;
                                       remoteAddress = (rdpSessionReverseLookup sess.SessionID)})
            |> Array.toList

        match enumList with
        | x when x.Length > 0 -> Some enumList
        | _ -> None

    //////////////////////////
    // Local Group Enumeration
    //////////////////////////

    let populateGroupMemberStruct 
        (bufferPtr: IntPtr) 
        (entriesRead: int) =
        // Helper function for populating the LOCAL_GROUP_MEMBER structs
        // I feel like this should actualy use mutability, because it's not necessarily
        // clear that the `memberStructs` thta gets passed back is a copy?
        let mutable bPtr = bufferPtr
        
        [|0..(entriesRead - 1)|] 
        |> Array.map(fun c -> 
                     let mstruct = Marshal.PtrToStructure<LOCAL_GROUP_MEMBER_INFO2>(bPtr)
                     bPtr <- IntPtr.Add(bPtr, Marshal.SizeOf<LOCAL_GROUP_MEMBER_INFO2>())
                     mstruct)
        

    let getLocalGroupMembership 
        (groupName: string) =
        // Enumerates the members of a local group. Will emit a None on empty 
        // groups or if there was a non-0 return code.
        let mutable bufPtr = IntPtr.Zero
        let mutable rHandle = IntPtr.Zero
        let mutable entRead = 0
        let mutable totEntries = 0

        let returnValue = 
            NetLocalGroupGetMembers("", groupName, 2, &bufPtr, -1, &entRead, &totEntries, rHandle)
        
        // kinda awkward, but we don't deal with errors at this point.
        let members = 
            match returnValue with
            | 0 -> populateGroupMemberStruct bufPtr entRead
            | _ -> Array.create 0 (LOCAL_GROUP_MEMBER_INFO2())
        
        NetApiBufferFree(bufPtr) |> ignore
        
        let groupMemberList = 
            members
            |> Array.filter(fun gmember -> not (gmember.lgrmi2_sid = IntPtr.Zero))
            |> Array.map(fun gmember -> gmember.lgrmi2_domainandname) 
            |> Array.toList 
        // None means there was an error in the NLGGM call, or the group doesn't exist. 
        match groupMemberList with
        | x when groupMemberList.Length > 0 -> Some groupMemberList
        | _ -> None

    ////////////////
    // Impersonation
    ////////////////

    let private impersonateSystem () = 
        // finds, opens and duplicates a SYSTEM process, performs the impersonation, then drops
        // the handles. Blows up dramatically if user isn't in the Administrator role.
        // This should probably return a Result< >, but I don't understand how to do those yet.
        let mutable procHandle = IntPtr.Zero
        let mutable dupToken = IntPtr.Zero
        
        let sysProcess = 
            Process.GetProcessesByName("winlogon")
            |> Array.head
        let result = 
            match (OpenProcessToken(sysProcess.Handle, 0x0002u, &procHandle) &&
                   DuplicateToken(procHandle, 2, &dupToken) &&
                   ImpersonateLoggedOnUser(dupToken)) with
            |true -> sprintf "Impersonating %s" <| WindowsIdentity.GetCurrent().Name
            |false -> sprintf "Failed to impersonate SYSTEM, error: %i" 
                              <| Marshal.GetLastWin32Error()

        CloseHandle(dupToken) |> ignore
        CloseHandle(procHandle) |> ignore
        result
        
    let revertToSelf () = 
        match RevertToSelf() with
        |true -> true
        |false -> false

    let getSystem () = 
        // Impersonate the NTAUTHORITY\SYSTEM user for the purposes of high integrity actions.
        match (getCurrentRole WindowsBuiltInRole.Administrator) with
        | true -> impersonateSystem ()
        | false -> sprintf "Current role cannot escalate privileges"
        
    /////////////////////////////
    // LSA Methods (for Kerberos)
    /////////////////////////////

    let private registerLsaLogonProcess () : LsaProcessHandle =
        // We use the LsaProcessHandle later in the important call to LsaCallAuthenticationPackage
        let mutable lsaProcessHandle = IntPtr.Zero
        let mutable securityMode = 0UL
        let registeredProcessName = "SomethingCustom"

        let mutable configString = 
            LSA_STRING_IN(length = uint16(registeredProcessName.Length), 
                          maxLength = uint16(registeredProcessName.Length + 1), 
                          buffer = registeredProcessName)

        LsaRegisterLogonProcess(&configString, &lsaProcessHandle, &securityMode) |> ignore
        lsaProcessHandle |> LsaProcessHandle

    let private deregisterLsaLogonProcess (lsaHandle: LsaProcessHandle) =
        let mutable (LsaProcessHandle lHandle) = lsaHandle
        LsaDeregisterLogonProcess(lHandle) |> ignore

    let private untrustedLsaConnection () : LsaProcessHandle =
        let mutable lsaHandle = IntPtr.Zero
        LsaConnectUntrusted(&lsaHandle) |> ignore
        lsaHandle |> LsaProcessHandle

    let private closeLsaHandle (handle: LsaProcessHandle) = 
        let mutable (LsaProcessHandle _handle) = handle
        LsaFreeReturnBuffer(&_handle) |> ignore


    let closeLsaH (ptr) =
        let mutable ptr = ptr
        LsaFreeReturnBuffer(&ptr) |> ignore

    let private enumerateLsaLogonSessions () : (uint64 * LUIDPtr) =
        // Doesn't use the LsaProcessHandle, but requires SYSTEM token or equal privs
        let mutable countOfLUIDs = 0UL
        let mutable luidPtr = IntPtr.Zero

        let ntstatus = LsaEnumerateLogonSessions(&countOfLUIDs, &luidPtr)
        printfn "%i" ntstatus
        (countOfLUIDs, luidPtr |> LUIDPtr)

    let private getLsaSessionData 
        (count: uint64, luidPtr: LUIDPtr)
        : SECURITY_LOGON_SESSION_DATA list =
        // Returns a filtered list of SECURITY_LOGON_SESSION_DATA structs. Seatbelt only processed
        // results with a pSID, so that's what we're doing. I don't know what the Some/None on this
        // should be, so I'm leaving it out for now.
        let mutable sessionDataPtr = IntPtr.Zero
        let mutable (LUIDPtr _luidPtr) = luidPtr
        let sessionData = 
            [|1..int(count)|]
            |> Array.map(fun x -> 
                         LsaGetLogonSessionData(_luidPtr, &sessionDataPtr) |> ignore
                         let sessionData = Marshal.PtrToStructure<SECURITY_LOGON_SESSION_DATA>(sessionDataPtr)
                         _luidPtr <- IntPtr.Add(_luidPtr, Marshal.SizeOf<LUID>())
                         closeLsaH sessionDataPtr
                         sessionData)
             |> Array.filter(fun _s -> not(_s.pSID = IntPtr.Zero)) // We only want results where there is a pSID
             |> Array.toList
        
        closeLsaHandle (_luidPtr |> LsaProcessHandle)
        sessionData
    let private fetchLsaSessions = enumerateLsaLogonSessions >> getLsaSessionData

    let private lookupLsaAuthenticationPackage 
        (lsaHandle: LsaProcessHandle) 
        (lsaKerberosString: LSA_STRING_IN) 
        : LsaAuthPackage = 
        // This call is around to generate authpkgs for the later call to LsaCallAuthenticationPackage
        // which is where the magic happens, I suppose. Leveraging types again to help keep the 
        // handles and pointer types straight.
        let mutable (LsaProcessHandle lsaHandle) = lsaHandle
        let mutable authPkg = 0
                
        LsaLookupAuthenticationPackage(lsaHandle, lsaKerberosString, &authPkg) |> ignore
        authPkg |> LsaAuthPackage

    let private getKerberosTicketResponse
        (lsaHandle: LsaProcessHandle) 
        (aPkg: LsaAuthPackage)
        (kerbReq: KerberosRequest)
        : (IntPtr * KerberosResponse) option = 
        // Returns a KERB response, depending on the type of KERB request submitted
        let mutable ticketPtr = IntPtr.Zero
        let mutable returnBufferLength = 0
        let mutable protocolStatus = 0

        let mutable (LsaProcessHandle lsaHandle) = lsaHandle
        let mutable (LsaAuthPackage aPkg) = aPkg
        
        match kerbReq with
        |KERB_QUERY_TKT_CACHE_REQ kReq -> 
            let mutable _kReq = kReq
            LsaCallAuthenticationPackage_CACHE(lsaHandle, 
                                               aPkg, 
                                               _kReq, 
                                               Marshal.SizeOf(_kReq),
                                               &ticketPtr,
                                               &returnBufferLength,
                                               protocolStatus) |> ignore
            match returnBufferLength with
            |x when x > 0 -> let kR = Marshal.PtrToStructure<KERB_QUERY_TKT_CACHE_RESPONSE>(ticketPtr)
                             match kR.countOfTickets with
                             | x when x > 0 -> Some (ticketPtr, kR |> KERB_QUERY_TKT_CACHE_RESP)
                             | _ -> None
            | _ -> None

        |KERB_RETRIEVE_TKT_REQ kReq -> 
            let mutable _kReq = kReq
            LsaCallAuthenticationPackage_RET(lsaHandle, 
                                             aPkg, 
                                             _kReq, 
                                             Marshal.SizeOf(_kReq),
                                             &ticketPtr,
                                             &returnBufferLength,
                                             protocolStatus) |> ignore
            match returnBufferLength with
            | x when x > 0 -> Some (ticketPtr, Marshal.PtrToStructure<KERB_RETRIEVE_TKT_RESPONSE>(ticketPtr) 
                              |> KERB_RETRIEVE_TKT_RESP)
            | _ -> None
                                        
    let private extractKerberosReponseTickets
        (ticketPtr: IntPtr, kResponse: KerberosResponse)
        : KerberosTicketStruct list =
        // Takes in either type of response struct, and outputs a list we can work with
        match kResponse with
        |KERB_QUERY_TKT_CACHE_RESP ticket -> 
            [0..(ticket.countOfTickets - 1)] 
            |> List.map(fun count -> 
                        Marshal.PtrToStructure<KERB_TICKET_CACHE_INFO>(IntPtr.Add(ticketPtr, (8+ (count * 64)))) 
                        |> KERB_TKT_CACHE_INFO)
        |KERB_RETRIEVE_TKT_RESP x -> 
                        [Marshal.PtrToStructure<KERB_EXTERNAL_TICKET>(ticketPtr) |> KERB_EXTERNAL_TKT] 

    let private createKerberosQueryTicket
        (ticket: KERB_TICKET_CACHE_INFO)
        : KerberosQueryTicket =
        let flags = Microsoft.FSharp.Core.LanguagePrimitives.EnumOfValue<uint32, Fetters.DomainTypes.KERB_TICKET_FLAGS>(ticket.ticketFlags)
        let kerbTicket = {serverName = marshalLSAString ticket.serverName
                          realm = marshalLSAString ticket.realmName
                          startTime = DateTime.FromFileTime(ticket.startTime)
                          endTime = DateTime.FromFileTime(ticket.endTime)
                          renewTime = DateTime.FromFileTime(ticket.renewTime)
                          encryptionType = KERB_ENCRYPTION_TYPE.GetName(typeof<KERB_ENCRYPTION_TYPE>, ticket.encryptionType)
                          ticketFlags = flags}
        kerbTicket

    let private createKerberosRetrieveTicket
        (ticket: KERB_EXTERNAL_TICKET)
        : KerberosRetrieveTicket =
        
        let serviceTkt = Marshal.PtrToStructure<KERB_EXTERNAL_NAME>(ticket.ServiceName)
        //let targetTkt = Marshal.PtrToStructure<KERB_EXTERNAL_NAME>(ticket.TargetName) caused NullReference Exceptions on 2012 box.
        let clientTkt = Marshal.PtrToStructure<KERB_EXTERNAL_NAME>(ticket.ClientName)
        let serviceName = marshalLSAString serviceTkt.names
        let targetName = ""//marshalLSAString targetTkt.names
        let clientName = marshalLSAString clientTkt.names

        let flags = Microsoft.FSharp.Core.LanguagePrimitives.EnumOfValue<uint32, KERB_TICKET_FLAGS>(ticket.Flags)
        // Have to create some b64Strings here before packing the record
        let rawSessionKey = Array.create (ticket.SessionKey.length) 0uy
        Marshal.Copy(ticket.SessionKey.value, rawSessionKey, 0, ticket.SessionKey.length)
        let b64SessionKey = Convert.ToBase64String(rawSessionKey)

        let rawEncodedTicket = Array.create (ticket.EncodedTicketSize) 0uy
        Marshal.Copy(ticket.EncodedTicket, rawEncodedTicket, 0, ticket.EncodedTicketSize)
        let b64Ticket = Convert.ToBase64String(rawEncodedTicket)

        let kerbTicket = {serviceName = serviceName
                          target = targetName
                          client = clientName
                          domain = marshalLSAString ticket.DomainName
                          targetDomain = marshalLSAString ticket.TargetDomainName
                          altTargetDomain = marshalLSAString ticket.AltTargetDomainName
                          sessionKeyType = KERB_ENCRYPTION_TYPE.GetName(typeof<KERB_ENCRYPTION_TYPE>, ticket.SessionKey.keyType)
                          base64SessionKey = b64SessionKey
                          keyExpiry = DateTime.FromFileTime(ticket.KeyExpirationTime)
                          flags = flags
                          startTime = DateTime.FromFileTime(ticket.KeyExpirationTime)
                          endTime = DateTime.FromFileTime(ticket.EndTime)
                          renewTime = DateTime.FromFileTime(ticket.RenewUntil)
                          skewTime = DateTime.FromFileTime(ticket.TimeSkew)
                          encodedSize = ticket.EncodedTicketSize
                          base64EncodedTicket = b64Ticket}
        kerbTicket
        
    let private createDomainSessionRecord 
        (sess: SECURITY_LOGON_SESSION_DATA, 
         kQRecords: KerberosTicket list, 
         kRRecords: KerberosTicket list)
        : DomainSession =
        let SID = 
             match getCurrentRole WindowsBuiltInRole.Administrator with
             |true -> SecurityIdentifier(sess.pSID)
             |false -> SecurityIdentifier("S-1-1-0")
                     

        let dsession = {username = marshalLSAString sess.username
                        domain = marshalLSAString sess.loginDomain
                        logonID = sess.loginID.lower
                        userSID = SID
                        authenticationPkg = marshalLSAString sess.authenticationPackage
                        logonType = sess.logonType.ToString()
                        loginTime = DateTime.FromFileTime(int64(sess.loginTime))
                        logonServer = marshalLSAString sess.logonServer
                        logonServerDnsDomain = marshalLSAString sess.dnsDomainName
                        userPrincipalName = marshalLSAString sess.upn
                        kerberosCachedTickets = kQRecords
                        kerberosTGTcontents = kRRecords}
        dsession

    let private createKerberosRecordList
        (ticketList: KerberosTicketStruct list)
        : KerberosTicket list =
        // Returns a list of Ticket records.
        ticketList 
        |> List.map(fun ticket ->   
                    match ticket with
                    |KERB_EXTERNAL_TKT tkt -> 
                        createKerberosRetrieveTicket tkt |> KerberosRetrieveTicket
                    |KERB_TKT_CACHE_INFO tkt -> 
                        createKerberosQueryTicket tkt |> KerberosQueryTicket)

    let enumerateDomainSessions ()
        : DomainSession list =
        // Emits a DomainSession for each enumerated session, containing KerberosTickets as well
        // as other metadata.
        let LSAStringQuery = 
            LSA_STRING_IN(length = uint16("kerberos".Length), 
                          maxLength = uint16("kerberos".Length + 1), 
                          buffer = "kerberos")
        
        // Handle error cases. How best to do it...?
        
        let tTuple = 
            match getCurrentRole WindowsBuiltInRole.Administrator with
            |true -> printfn "%s" <| getSystem()
                     let lsaHandle = registerLsaLogonProcess ()
                     let lsaAuthPackage = lookupLsaAuthenticationPackage lsaHandle LSAStringQuery
                     let sessionList = fetchLsaSessions ()
                     let luidList = 
                         sessionList
                         |> List.map(fun session -> session.loginID.lower, session.loginID.upper)
                     sessionList, luidList, lsaAuthPackage, lsaHandle

            |false -> let lsaHandle = untrustedLsaConnection ()
                      let lsaAuthPackage = lookupLsaAuthenticationPackage lsaHandle LSAStringQuery
                      let sessionList = [SECURITY_LOGON_SESSION_DATA()]
                      let luidList = [0u,0]
                      sessionList, luidList, lsaAuthPackage, lsaHandle
        
        let sessionList, luidList, lsaAuthPackage, lsaHandle =
            match tTuple with
            |w, x, y, z -> w, x, y, z
        
        let domainSessionRecord =
            (sessionList, luidList)
            ||>List.map2(fun sess luid -> 
                          let _luid = LUID(lower= fst luid, upper = snd luid)
                          (sess, 
                           KERB_QUERY_TKT_CACHE_REQUEST
                            (messageType = KERB_PROTOCOL_MESSAGE_TYPE.KerbQueryTicketCacheMessage,
                             logonID = _luid ) |> KERB_QUERY_TKT_CACHE_REQ,
                           KERB_RETRIEVE_TKT_REQUEST
                            (messageType = KERB_PROTOCOL_MESSAGE_TYPE.KerbRetrieveTicketMessage,
                             logonID = _luid) |> KERB_RETRIEVE_TKT_REQ) )

            |>List.map(fun sessiontuple -> 
                        match sessiontuple with
                        |sess, kCReq,kRReq -> 
                            let kCacheResp = getKerberosTicketResponse lsaHandle lsaAuthPackage kCReq
                            let kRetResp = getKerberosTicketResponse lsaHandle lsaAuthPackage kRReq
                            (sess, kCacheResp, kRetResp))

            |>List.map(fun sessiontuple -> 
                       match sessiontuple with
                       |sess, Some kCReq, Some kRetReq -> 
                            let KQTickStruct = extractKerberosReponseTickets kCReq
                            let KRTickStruct = extractKerberosReponseTickets kRetReq
                            (sess,KQTickStruct,KRTickStruct)
                       |sess, Some kCReq, None -> 
                            let KQTickStruct = extractKerberosReponseTickets kCReq
                            (sess,KQTickStruct,[])
                       |sess, None, Some toss -> (sess, [], []) //Should never end up here
                       |sess, None, None -> (sess, [], []))

            |>List.map(fun sessiontuple ->  
                       match sessiontuple with
                       |sess, kQTickStruct, kExtStruct -> 
                            let kQRecords = createKerberosRecordList kQTickStruct
                            let kRRecords = createKerberosRecordList kExtStruct
                            (sess,kQRecords,kRRecords))
            
            |>List.map createDomainSessionRecord

        //Cleanup and then pass out result
        deregisterLsaLogonProcess lsaHandle
        closeLsaHandle lsaHandle
        domainSessionRecord
    
    //Credential Vault

    let enumerateVaults : (uint32 * IntPtr) = ()

    let openVault 
        (count: uint32, vaultPtr: VaultPtr) 
        : VaultHandle list = ()

    let enumerateVaultItems 
        (vaultHandle: VaultHandle) 
        : (uint32 * VaultItemPtr) = ()

    let getVaultItem 
        (count: uint32, vaultItemPtr: VaultItemPtr) 
        : VaultItem list = ()

    let createVaultRecord 
        (vaultItem: VaultItem) 
        : VaultRecord = ()
