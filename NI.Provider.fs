module Fetters.NI.Providers

    open System
    open System.Diagnostics
    open System.Runtime.InteropServices
    open System.Security.Principal

    open Fetters.dotNetFunctions
    open Fetters.DomainTypes

    /////////////////////////////
    // DU "enums" for native code
    /////////////////////////////

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

    //////////////////////////////
    // Structs for the native code
    //////////////////////////////

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
        val mutable logonType : uint32
        val mutable session : uint32
        val mutable pSID : IntPtr
        val mutable loginTime : uint64
        val mutable logonServer : LSA_STRING_OUT
        val mutable dnsDomainName : LSA_STRING_OUT
        val mutable upn : LSA_STRING_OUT

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


    //////////////////////
    // Import Declarations
    //////////////////////

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

    [<DllImport("kernel32.dll")>]
    extern bool CloseHandle(IntPtr handle)

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
    extern uint32 LsaFreeReturnBuffer(IntPtr buffer)

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

    ////////////////////////////////
    // RDP Session Enumeration Calls
    ////////////////////////////////
    
    let private populateRdpSessionStructs ppSessionBaseAddr count =
        // Helper function to pull unmanaged info into managed code 
        let mutable _ppSBA = ppSessionBaseAddr
        let enumSessions = Array.create count (WTS_SESSION_INFO_1())
        enumSessions 
        |> Array.map(fun _s -> let _s = Marshal.PtrToStructure<WTS_SESSION_INFO_1>(_ppSBA)
                               _ppSBA <- IntPtr.Add(_ppSBA, Marshal.SizeOf<WTS_SESSION_INFO_1>())
                               _s)


    let private rdpSessionGetAddress ppBuffer = 
        // Helper function for extracting IP address strings from the 
        // WTS_CLIENT_ADDRESS struct
        let _a = Marshal.PtrToStructure<WTS_CLIENT_ADDRESS>(ppBuffer)
        System.Net.IPAddress(_a.addressRaw.[2..5])
        
    let private rdpSessionReverseLookup sessionID =
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
            |> Array.filter(fun _f -> _f.pSessionName.StartsWith("RDP"))
            |> Array.map(fun _sess -> {state = _sess.State.ToString(); 
                                       sessionID = _sess.SessionID;
                                       sessionName = _sess.pSessionName;
                                       hostName = _sess.pHostName;
                                       username = _sess.pUserName;
                                       remoteAddress = (rdpSessionReverseLookup _sess.SessionID)})
            |> Array.toList

        match enumList with
        | x when x.Length > 0 -> Some enumList
        | _ -> None
        


    ////////////////////////////////
    // Local Group Enumeration Calls
    ////////////////////////////////

    let populateGroupMemberStruct 
        (bufferPtr: IntPtr) 
        (entriesRead: int) =
        // Helper function for populating the LOCAL_GROUP_MEMBER structs
        // I feel like this should actualy use mutability, because it's not necessarily
        // clear that the `memberStructs` thta gets passed back is a copy?
        let memberStructs = Array.create entriesRead (LOCAL_GROUP_MEMBER_INFO2())
        let mutable _b = bufferPtr
        
        memberStructs 
        |> Array.map(fun _m -> let _m = Marshal.PtrToStructure<LOCAL_GROUP_MEMBER_INFO2>(_b)
                               _b <- IntPtr.Add(_b, Marshal.SizeOf<LOCAL_GROUP_MEMBER_INFO2>())
                               _m)
        

    let getLocalGroupMembership (groupName: string) =
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
            |> Array.filter(fun _f -> not (_f.lgrmi2_sid = IntPtr.Zero))
            |> Array.map(fun _m -> _m.lgrmi2_domainandname) 
            |> Array.toList 
        // None means there was an error in the NLGGM call, or the group doesn't exist. 
        match groupMemberList with
        | x when groupMemberList.Length > 0 -> Some groupMemberList
        | _ -> None

    //////////////////////
    // Impersonation Calls 
    //////////////////////

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
        | true -> true
        | false -> false

    let getSystem () = 
        // Impersonate the NTAUTHORITY\SYSTEM user for the purposes of high integrity actions.
        match (getCurrentRole WindowsBuiltInRole.Administrator) with
        | true -> impersonateSystem ()
        | false -> sprintf "Current role cannot escalate privileges"
        
    /////////////////////////////
    // LSA Methods (for Kerberos)
    /////////////////////////////

    let registerLsaLogonProcess () : LsaProcessHandle =
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

    let deregisterLsaLogonProcess (lsaHandle: LsaProcessHandle) =
        let mutable (LsaProcessHandle lHandle) = lsaHandle
        printfn "Exitcode %i" <| LsaDeregisterLogonProcess(lHandle)

    let untrustedLsaConnection () : LsaProcessHandle =
        let mutable lsaHandle = IntPtr.Zero
        LsaConnectUntrusted(&lsaHandle) |> ignore
        lsaHandle |> LsaProcessHandle

    let closeLsaHandle (handle: LsaProcessHandle) = 
        let (LsaProcessHandle _handle) = handle
        LsaFreeReturnBuffer(_handle)

    let enumerateLsaLogonSessions () : (uint64 * LUIDPtr) =
        // As it says on the tin.
        let mutable countOfLUIDs = 0UL
        let mutable luidPtr = IntPtr.Zero

        let ntstatus = LsaEnumerateLogonSessions(&countOfLUIDs, &luidPtr)
        (countOfLUIDs, luidPtr |> LUIDPtr)

    let getLsaSessionData 
        (count: uint64, luidPtr: LUIDPtr)
        : SECURITY_LOGON_SESSION_DATA list =
        // Returns a filtered list of SECURITY_LOGON_SESSION_DATA structs. Seatbelt only processed
        // results with a pSID, so that's what we're doing. I don't know what the Some/None on this
        // should be, so I'm leaving it out for now.
        let mutable sessionDataPtr = IntPtr.Zero
        let mutable (LUIDPtr _luidPtr) = luidPtr

        [|0..int(count)- 1|]
        |> Array.map(fun x ->  LsaGetLogonSessionData(_luidPtr, &sessionDataPtr) |> ignore
                               let sessionData = Marshal.PtrToStructure<SECURITY_LOGON_SESSION_DATA>(sessionDataPtr)
                               sessionDataPtr <- IntPtr.Add(sessionDataPtr, Marshal.SizeOf<SECURITY_LOGON_SESSION_DATA>())
                               _luidPtr <- IntPtr.Add(_luidPtr, Marshal.SizeOf<LUID>())
                               sessionData)
        |> Array.filter(fun _s -> not(_s.pSID = IntPtr.Zero)) // We only want results where there is a pSID
        |> Array.toList

    let fetchLsaSessions = enumerateLsaLogonSessions >> getLsaSessionData

    let lookupLsaAuthenticationPackage 
        (lsaHandle: LsaProcessHandle) 
        (lsaKerberosString: LSA_STRING_IN) 
        : LsaAuthPackage = 
        // This call is around to generate authpkgs for the later call to LsaCallAuthenticationPackage
        // which is where the magic happens, I suppose. Leveraging types again to help keep the 
        // handles and pointer types straight.
        let mutable (LsaProcessHandle _lsaHandle) = lsaHandle
        let mutable _authPkg = 0
                
        LsaLookupAuthenticationPackage(_lsaHandle, lsaKerberosString, &_authPkg) |> ignore
        _authPkg |> LsaAuthPackage

    let getKerberosTicketResponse
        (lsaHandle: LsaProcessHandle) 
        (aPkg: LsaAuthPackage)
        (kerbReq: KerberosRequest)
        : (IntPtr * KerberosResponse) option = 
        // Returns a KERB response, depending on the type of KERB request
        // passed in.
        let mutable ticketPtr = IntPtr.Zero
        let mutable returnBufferLength = 0
        let mutable protocolStatus = 0
        // Unwrap types
        let mutable (LsaProcessHandle _lsaHandle) = lsaHandle
        let mutable (LsaAuthPackage _aPkg) = aPkg
        
        match kerbReq with
        |KERB_QUERY_TKT_CACHE_REQ req -> let mutable _req = req
                                         LsaCallAuthenticationPackage_CACHE(_lsaHandle, 
                                                                            _aPkg, 
                                                                            _req, 
                                                                            Marshal.SizeOf(_req),
                                                                            &ticketPtr,
                                                                            &returnBufferLength,
                                                                            protocolStatus) |> ignore
                                         match returnBufferLength with
                                         |x when x > 0 -> let kR = Marshal.PtrToStructure<KERB_QUERY_TKT_CACHE_RESPONSE>(ticketPtr)
                                                          match kR.countOfTickets with
                                                          | x when x > 0 -> Some (ticketPtr, kR 
                                                                            |> KERB_QUERY_TKT_CACHE_RESP)
                                                          | _ -> None
                                         | _ -> None
        |KERB_RETRIEVE_TKT_REQ req -> let mutable _req = req
                                      LsaCallAuthenticationPackage_RET(_lsaHandle, 
                                                                       _aPkg, 
                                                                       _req, 
                                                                       Marshal.SizeOf(_req),
                                                                       &ticketPtr,
                                                                       &returnBufferLength,
                                                                       protocolStatus) |> ignore
                                      match returnBufferLength with
                                      | x when x > 0 -> Some (ticketPtr, 
                                                              Marshal.PtrToStructure<KERB_RETRIEVE_TKT_RESPONSE>(ticketPtr) 
                                                        |> KERB_RETRIEVE_TKT_RESP)
                                      | _ -> None
                                        
    let extractKerberosReponseTickets
        (ticketPtr: IntPtr, kResponse: KerberosResponse)
        : KerberosTicketStruct list =
        // Takes in either type of response struct, and outputs a list we can work with
        let tktptr, kResp = ticketPtr, kResponse
        
        match kResp with
        |KERB_QUERY_TKT_CACHE_RESP ticket -> [0..(ticket.countOfTickets - 1)] 
                                             |> List.map(fun count -> Marshal.PtrToStructure<KERB_TICKET_CACHE_INFO>(IntPtr.Add(tktptr, (8+ (count * 64)))) 
                                                                   |> KERB_TKT_CACHE_INFO)
        //Only one TGT per session, so no count of tickets to iterate
        |KERB_RETRIEVE_TKT_RESP ticket -> [Marshal.PtrToStructure<KERB_EXTERNAL_TICKET>(tktptr) |> KERB_EXTERNAL_TKT] 

    let createKerberosQueryTicket
        (ticket: KERB_TICKET_CACHE_INFO)
        : KerberosQueryTicket =
        let flags = Microsoft.FSharp.Core.LanguagePrimitives.EnumOfValue<uint32, Fetters.DomainTypes.KERB_TICKET_FLAGS>(ticket.ticketFlags)
        let kerbTicket = {serverName = Marshal.PtrToStringAuto(ticket.serverName.buffer)
                          realm = Marshal.PtrToStringAuto(ticket.realmName.buffer)
                          startTime = DateTime.FromFileTime(ticket.startTime)
                          endTime = DateTime.FromFileTime(ticket.endTime)
                          renewTime = DateTime.FromFileTime(ticket.renewTime)
                          encryptionType = KERB_ENCRYPTION_TYPE.GetName(typeof<KERB_ENCRYPTION_TYPE>, ticket.encryptionType)
                          ticketFlags = flags }
        kerbTicket

    let createKerberosRetrieveTicket
        (ticket: KERB_EXTERNAL_TICKET)
        : KerberosRetrieveTicket =

        let flags = Microsoft.FSharp.Core.LanguagePrimitives.EnumOfValue<uint32, KERB_TICKET_FLAGS>(ticket.Flags)
        let rawSessionKey = Array.create (ticket.SessionKey.length) 0uy
        Marshal.Copy(ticket.SessionKey.value, rawSessionKey, 0, ticket.SessionKey.length)
        let b64SessionKey = Convert.ToBase64String(rawSessionKey)

        let rawEncodedTicket = Array.create (ticket.EncodedTicketSize) 0uy
        Marshal.Copy(ticket.EncodedTicket, rawEncodedTicket, 0, ticket.EncodedTicketSize)
        let b64Ticket = Convert.ToBase64String(rawEncodedTicket)

        let kerbTicket = {serviceName = Marshal.PtrToStringAuto(ticket.ServiceName)
                          target = Marshal.PtrToStringAuto(ticket.TargetName)
                          client = Marshal.PtrToStringAuto(ticket.ClientName)
                          domain = Marshal.PtrToStringAuto(ticket.DomainName.buffer)
                          targetDomain = Marshal.PtrToStringAuto(ticket.TargetDomainName.buffer)
                          altTargetDomain = Marshal.PtrToStringAuto(ticket.AltTargetDomainName.buffer)
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
        
    let createDomainSessionRecord 
        (sess: SECURITY_LOGON_SESSION_DATA, 
         kQRecords: KerberosTicket list, 
         kRRecords: KerberosTicket list)
        : DomainSession =
        let dsession = {username = Marshal.PtrToStringUni(sess.username.buffer)
                        domain = Marshal.PtrToStringAuto(sess.loginDomain.buffer)
                        logonID = sess.loginID.lower
                        userSID = "bogusValue" // We'll come back around to this
                        authenticationPkg = Marshal.PtrToStringAuto(sess.authenticationPackage.buffer)
                        logonType = sess.logonType.ToString()
                        loginTime = DateTime.FromFileTime(int64(sess.loginTime))
                        logonServer = Marshal.PtrToStringAuto(sess.logonServer.buffer)
                        logonServerDnsDomain = Marshal.PtrToStringAuto(sess.dnsDomainName.buffer)
                        userPrincipalName = Marshal.PtrToStringAuto(sess.upn.buffer)
                        kerberosCachedTickets = kQRecords
                        kerberosTGTcontents = kRRecords}
        dsession

    let createKerberosRecordList
        (ticketList: KerberosTicketStruct list)
        : KerberosTicket list =
        // Returns a list of Ticket records.
        ticketList 
        |> List.map(fun ticket ->   match ticket with
                                    |KERB_EXTERNAL_TKT tkt -> createKerberosRetrieveTicket tkt |> KerberosRetrieveTicket
                                    |KERB_TKT_CACHE_INFO tkt -> createKerberosQueryTicket tkt |> KerberosQueryTicket)

    let enumerateDomainSessions ()
        : DomainSession list =
        // Emits a DomainSession for each enumerated session, containing KerberosTickets as well
        // as other metadata.
        let LSAStringQuery = LSA_STRING_IN( length = uint16("kerberos".Length), 
                                            maxLength = uint16("kerberos".Length + 1), 
                                            buffer = "kerberos")
        let tTuple = 
            match getCurrentRole WindowsBuiltInRole.Administrator with
            |true -> getSystem() |> ignore
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
        
        //let lsaHandle = registerLsaLogonProcess ()
        //let lsaAuthPackage = lookupLsaAuthenticationPackage lsaHandle LSAStringQuery
        //let sessionList = fetchLsaSessions ()
        //let luidList = 
        //    sessionList
        //    |> List.map(fun session -> session.loginID.lower, session.loginID.upper)
        // With our sessions and LUIDs ready, create the queries to LSA, and process the tickets
        // and session into our eventual DomainSession record. The third case in the third
        // map is a dummy case to make the compiler happy. No stand-alone TGTs.
        let domainSessionRecord =
            (sessionList, luidList)
            ||> List.map2(fun sess luid -> let _luid = LUID(lower= fst luid, upper = snd luid)
                                           (sess, 
                                            KERB_QUERY_TKT_CACHE_REQUEST(messageType = KERB_PROTOCOL_MESSAGE_TYPE.KerbQueryTicketCacheMessage,
                                                                         logonID = _luid ) |> KERB_QUERY_TKT_CACHE_REQ,
                                            KERB_RETRIEVE_TKT_REQUEST(messageType = KERB_PROTOCOL_MESSAGE_TYPE.KerbRetrieveTicketMessage,
                                                                      logonID = _luid) |> KERB_RETRIEVE_TKT_REQ))
            |> List.map(fun sessiontuple -> match sessiontuple with
                                            |sess, kCReq,kRReq -> let kCacheResp = getKerberosTicketResponse lsaHandle lsaAuthPackage kCReq
                                                                  let kRetResp = getKerberosTicketResponse lsaHandle lsaAuthPackage kRReq
                                                                  (sess, kCacheResp,kRetResp))
            |>List.map(fun sessiontuple ->  match sessiontuple with
                                            |sess, Some kCReq, Some kRetReq -> let KQTickStruct = extractKerberosReponseTickets kCReq
                                                                               let KRTickStruct = extractKerberosReponseTickets kRetReq
                                                                               (sess,KQTickStruct,KRTickStruct)
                                            |sess, Some kCReq, None -> let KQTickStruct = extractKerberosReponseTickets kCReq
                                                                       (sess,KQTickStruct,[])
                                            |sess, None, Some toss -> (sess, [], [])
                                            |sess, None, None -> (sess, [], []))
            |>List.map(fun sessiontuple ->  match sessiontuple with
                                            |_, kQTickStruct, kExtStruct -> let kQRecords = createKerberosRecordList kQTickStruct
                                                                            let kRRecords = createKerberosRecordList kExtStruct
                                                                            match sessiontuple with
                                                                            |sess, _, _ -> (sess,kQRecords,kRRecords))
            |>List.map(fun sessiontuple -> createDomainSessionRecord sessiontuple)
        deregisterLsaLogonProcess lsaHandle
        closeLsaHandle lsaHandle |> ignore
        domainSessionRecord
        
                                                                        

