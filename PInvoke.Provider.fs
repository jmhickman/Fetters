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

module Fetters.PInvoke.Provider

    open System
    open System.Diagnostics
    open System.Net
    open System.Runtime.InteropServices
    open System.Security.Principal

    open Fetters.DotNet.Common
    open Fetters.DomainTypes

    ///////
    //Enums
    ///////

    //// Arp section ////

    type ArpEntryType =
        |Other = 1
        |Invalid = 2
        |Dynamic = 3
        |Static = 4


    //// KERB Enum ////

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

    //// RDP Enum Section ////
    
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
    type WTS_INFO_CLASS =
        |WTSClientAddress = 14

    //// TCP dump Section ////

    [<Struct>]
    type MIB_TCP_STATE = 
        |CLOSED = 1
        |LISTEN = 2
        |SYN_SENT = 3
        |SYN_RCVD = 4
        |ESTAB = 5
        |FIN_WAIT1 = 6
        |FIN_WAIT2 = 7
        |CLOSE_WAIT = 8
        |CLOSING = 9
        |LAST_ACK = 10
        |TIME_WAIT = 11
        |DELETE_TCB = 12
    
    [<Struct>]
    type SC_SERVICE_TAG_QUERY_TYPE =
        |ServiceNameFromTagInformation = 1
        |ServiceNamesReferencingModuleInformation = 2
        |ServiceNameTagMappingInformation = 3
    
    [<Struct>]
    type TCP_TABLE_CLASS =
        |TCP_TABLE_BASIC_LISTENER
        |TCP_TABLE_BASIC_CONNECTIONS
        |TCP_TABLE_BASIC_ALL
        |TCP_TABLE_OWNER_PID_LISTENER
        |TCP_TABLE_OWNER_PID_CONNECTIONS
        |TCP_TABLE_OWNER_PID_ALL
        |TCP_TABLE_OWNER_MODULE_LISTENER
        |TCP_TABLE_OWNER_MODULE_CONNECTIONS
        |TCP_TABLE_OWNER_MODULE_ALL
    
    //// Token Section ////
    [<Struct>]
    type TOKEN_INFORMATION_CLASS = 
        |TokenUser = 1u
        |TokenGroups = 2u
        |TokenPrivileges = 3u
        |TokenOwner = 4u
        |TokenPrimaryGroup = 5u
        |TokenDefaultDacl = 6u
        |TokenSource = 7u
        |TokenType = 8u
        |TokenImpersonationLevel = 9u
        |TokenStatistics = 10u
        |TokenRestrictedSids = 11u
        |TokenSessionId = 12u
        |TokenGroupsAndPrivileges = 13u
        |TokenSessionReference = 14u
        |TokenSandBoxInert = 15u
        |TokenAuditPolicy = 16u
        |TokenOrigin = 17u

    //// UDP Section ////

    [<Struct>]
    type UDP_TABLE_CLASS = 
        |UDP_TABLE_BASIC
        |UDP_TABLE_OWNER_PID
        |UDP_TABLE_OWNER_MODULE

    //// Vault section ////
    
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

    //////////////
    //Struct types
    //////////////

    
    //// Arp Section ////

    [<Struct>]
    [<StructLayout(LayoutKind.Sequential)>]
    type MIB_IPNETROW = 
        val mutable dwIndex : int32
        val mutable dwPhysAddrLen : int32
        val mutable mac0 : byte
        val mutable mac1 : byte
        val mutable mac2 : byte
        val mutable mac3 : byte
        val mutable mac4 : byte
        val mutable mac5 : byte
        val mutable mac6 : byte
        val mutable mac7 : byte
        val mutable dwAddr : int32
        val mutable dwType : int32

    [<Struct>]
    [<StructLayout(LayoutKind.Sequential)>]
    type MIB_IPNETTABLE = 
        val mutable numEntries : int32
        val mutable tablePtr : IntPtr
    

    //// LSA Section ////

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
    type SID_IDENTIFIER_AUTHORITY = 
        [<MarshalAs(UnmanagedType.ByValArray, SizeConst = 6)>]
        val mutable value: char []

    [<Struct>]
    [<StructLayout(LayoutKind.Sequential)>]
    type SID =
        val mutable revision : char
        val mutable subauthcount : char
        val mutable idauthority : SID_IDENTIFIER_AUTHORITY
        val mutable subauthority : uint32


    [<Struct>]
    [<StructLayout(LayoutKind.Sequential)>]
    // Unverfied: Folks list some weird self-reference thing in the signatures
    // but the docs say these two pointers only, so this is what I'm 
    // rolling with.
    type SECURITY_HANDLE = 
        val mutable lower: IntPtr
        val mutable upper: IntPtr

    //// KERB section ////

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

    type KerberosRequest = 
        |KERB_QUERY_TKT_CACHE_REQ of KERB_QUERY_TKT_CACHE_REQUEST
        |KERB_RETRIEVE_TKT_REQ of KERB_RETRIEVE_TKT_REQUEST

    type KerberosResponse = 
        |KERB_QUERY_TKT_CACHE_RESP of KERB_QUERY_TKT_CACHE_RESPONSE
        |KERB_RETRIEVE_TKT_RESP of KERB_RETRIEVE_TKT_RESPONSE

    type KerberosTicketStruct = 
        |KERB_EXTERNAL_TKT of KERB_EXTERNAL_TICKET
        |KERB_TKT_CACHE_INFO of KERB_TICKET_CACHE_INFO

    //// RDP section ////

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
    
    //// TCP Query Section ////
    
    [<Struct>]
    [<StructLayout(LayoutKind.Sequential)>]
    type MIB_TCPROW_OWNER_MODULE = 
         val State : MIB_TCP_STATE
         val LocalAddr : uint32
         val LocalPort1 : byte
         val LocalPort2 : byte
         val LocalPort3 : byte
         val LocalPort4 : byte
         val RemoteAddr : uint32
         val RemotePort1 : byte
         val RemotePort2 : byte
         val RemotePort3 : byte
         val RemotePort4 : byte
         val OwningPid : uint32 
         val CreateTimestamp : uint64
         val OwningModuleInfo0 : uint64
         val OwningModuleInfo1 : uint64
         val OwningModuleInfo2 : uint64
         val OwningModuleInfo3 : uint64
         val OwningModuleInfo4 : uint64
         val OwningModuleInfo5 : uint64
         val OwningModuleInfo6 : uint64
         val OwningModuleInfo7 : uint64
         val OwningModuleInfo8 : uint64
         val OwningModuleInfo9 : uint64
         val OwningModuleInfo10 : uint64
         val OwningModuleInfo11 : uint64
         val OwningModuleInfo12 : uint64
         val OwningModuleInfo13 : uint64
         val OwningModuleInfo14 : uint64
         val OwningModuleInfo15 : uint64
    
    [<Struct>]
    [<StructLayout(LayoutKind.Sequential)>]
    type MIB_TCPTABLE_OWNER_MODULE =
         val mutable numEntries : uint32
         val mutable table : MIB_TCPROW_OWNER_MODULE
    
    //// Token Section ////
    [<Struct>]
    [<StructLayout(LayoutKind.Sequential)>]
    type LUID_AND_ATTRIBUTES = 
        val mutable luid : LUID
        val mutable attributes : int32
    
    [<Struct>]
    [<StructLayout(LayoutKind.Sequential)>]
    type TOKEN_PRIVILEGES = 
        val mutable privilegeCount : uint32
        val mutable privilegeArray : IntPtr

    [<Struct>]
    [<StructLayout(LayoutKind.Sequential)>]
     type SID_AND_ATTRIBUTES =
        val mutable sid : IntPtr
        val mutable attributes : uint32
    
    [<Struct>]
    [<StructLayout(LayoutKind.Sequential)>]
    type TOKEN_GROUPS = 
        //Groups is a SID_AND_ATTRIBUTES struct array
        val mutable GroupCount : uint32
        val mutable Groups : IntPtr
    
    
    //// UDP Section ////

    [<Struct>]
    [<StructLayout(LayoutKind.Sequential)>]
    type MIB_UDPROW_OWNER_MODULE =
       val LocalAddr : uint32
       val LocalPort1 : byte
       val LocalPort2 : byte
       val LocalPort3 : byte
       val LocalPort4 : byte
       val OwningPid : uint32
       val CreateTimestamp : uint64
       val SpecificPortBind_Flags : uint32
       val OwningModuleInfo0 : uint64
       val OwningModuleInfo1 : uint64
       val OwningModuleInfo2 : uint64
       val OwningModuleInfo3 : uint64
       val OwningModuleInfo4 : uint64
       val OwningModuleInfo5 : uint64
       val OwningModuleInfo6 : uint64
       val OwningModuleInfo7 : uint64
       val OwningModuleInfo8 : uint64
       val OwningModuleInfo9 : uint64
       val OwningModuleInfo10 : uint64
       val OwningModuleInfo11 : uint64
       val OwningModuleInfo12 : uint64
       val OwningModuleInfo13 : uint64
       val OwningModuleInfo14 : uint64
       val OwningModuleInfo15 : uint64

    [<Struct>]
    [<StructLayout(LayoutKind.Sequential)>]
    type MIB_UDPTABLE_OWNER_MODULE =
        val numEntries : uint32
        val table : MIB_UDPROW_OWNER_MODULE


    [<Struct>]
    [<StructLayout(LayoutKind.Sequential)>]
    type SC_SERVICE_TAG_QUERY =
        val mutable processId : uint32
        val mutable serviceTag : uint32
        val mutable unknown : uint32
        val mutable buffer : IntPtr

    //// Vault Dump Section ////

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
        val mutable SchemaElementId : VAULT_SCHEMA_ELEMENT_ID
        val mutable Type : VAULT_ELEMENT_TYPE

    type VaultItem = 
        |WIN8VAULT of VAULT_ITEM_WIN8
        |WIN7VAULT of VAULT_ITEM_WIN7

    type VaultElementContent =
        |EleGUID of Guid
        |EleStr of string
        |EleSID of SecurityIdentifier

    /////////////////////
    //Import Declarations
    /////////////////////

    //// advapi32 ////
    
    [<DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)>]
    extern bool OpenProcessToken(
        IntPtr processHandle, 
        uint32 desiredAccess, 
        [<Out>] IntPtr& tokenHandle
        )

    [<DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)>]
    extern bool DuplicateToken(
        IntPtr existingTokenHandle, 
        int impersonationLevel, 
        [<Out>] IntPtr& duplicatTokenHandle
        )

    [<DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)>]
    extern bool GetTokenInformation(
        IntPtr TokenHandle, 
        TOKEN_INFORMATION_CLASS TokenInformationClass, 
        IntPtr TokenInformation, 
        [<Out>] int TokenInformationLength, 
        [<Out>] int32& ReturnLength
        )
    
    [<DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true)>]
    extern bool ConvertSidToStringSid(IntPtr pSID, IntPtr& ptrSid)
    
    [<DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Ansi)>]
    extern bool LookupPrivilegeName(
        string lpSystemName, 
        IntPtr lpLuid, 
        IntPtr lpName, 
        [<Out>] int32& cchName 
        )
    
    [<DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)>]
    extern bool ImpersonateLoggedOnUser(IntPtr tokenHandle)

    [<DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)>]
    extern bool RevertToSelf()

    [<DllImport("advapi32.dll", SetLastError = true)>]
    extern uint32 I_QueryTagInformation(
        IntPtr nothing, 
        SC_SERVICE_TAG_QUERY_TYPE Type, 
        [<In>] [<Out>] SC_SERVICE_TAG_QUERY& Query
        )

    //// iphlpapi ////
    
    [<DllImport("iphlpapi.dll", SetLastError = true)>]
    extern int FreeMibTable(IntPtr plpNetTable)

    [<DllImport("iphlpapi.dll", SetLastError = true)>]
    extern uint32 GetExtendedTcpTable(
        IntPtr pTcpTable, 
        uint32& dwOutBufLen, 
        bool sort, 
        int ipVersion, 
        TCP_TABLE_CLASS tblClass, 
        int reserved
        )

    [<DllImport("iphlpapi.dll", SetLastError = true)>]
    extern uint32 GetExtendedUdpTable(
        IntPtr pUdpTable, 
        uint32& dwOutBufLen, 
        bool sort, 
        int ipVersion, 
        UDP_TABLE_CLASS tblClass, 
        int reserved
        )

    [<DllImport("iphlpapi.dll", SetLastError = true)>]
    extern int GetIpNetTable(IntPtr pIpNetTable, int& pdwSize, bool bOrder)
    
    //// kernel32 ////
    
    [<DllImport("kernel32.dll")>]
    extern bool CloseHandle(IntPtr handle)

    
    //// NetApi32 ////

    [<DllImport("Netapi32.dll")>]
    extern int NetApiBufferFree(IntPtr bufptr)
    
       
    [<DllImport("netapi32.dll", CharSet = CharSet.Unicode)>]
    extern int NetLocalGroupGetMembers(
        string serverName, 
        string localGroupName, 
        int level,
        [<Out>] IntPtr& bufptr,
        int prefmaxlen, 
        [<Out>] int& entriesRead,
        [<Out>] int& totalEntries,
        [<Out>] IntPtr resumeHandle
        )

    //// secur32 ////
    
    [<DllImport("secur32.dll", SetLastError = true)>]
    extern int LsaConnectUntrusted([<Out>] IntPtr& lsaHandle)

    [<DllImport("secur32.dll", SetLastError = true)>]
    extern int LsaRegisterLogonProcess(
        LSA_STRING_IN& logonProcessName, 
        [<Out>] IntPtr& lsaHandle, 
        [<Out>] uint64& securityMode
        )

    [<DllImport("secur32.dll", SetLastError = true)>]
    extern int LsaDeregisterLogonProcess([<In>] IntPtr lsaHandle)

    [<DllImport("secur32.dll", SetLastError = true)>]
    extern int LsaLookupAuthenticationPackage(
        IntPtr lsaHandle, 
        LSA_STRING_IN packageName, 
        [<Out>] int& authenticationPackage
        )

    [<DllImport("secur32.dll", EntryPoint = "LsaCallAuthenticationPackage", SetLastError = true)>]
    extern int LsaCallAuthenticationPackage_CACHE(
        IntPtr lsaHandle, 
        int authenticationPackage, 
        KERB_QUERY_TKT_CACHE_REQUEST protocolSubmitBuffer, 
        int submitBufferLength, 
        [<Out>] IntPtr& protocolReturnBuffer, 
        [<Out>] int& returnBufferLength, 
        [<Out>] int protocolStatus
        )

    [<DllImport("secur32.dll", EntryPoint = "LsaCallAuthenticationPackage", SetLastError = true)>]
    extern int LsaCallAuthenticationPackage_RET(
        IntPtr lsaHandle, 
        int authenticationPackage, 
        KERB_RETRIEVE_TKT_REQUEST protocolSubmitBuffer, 
        int submitBufferLength, 
        [<Out>] IntPtr& protocolReturnBuffer, 
        [<Out>] int& returnBufferLength, 
        [<Out>] int protocolStatus
        )
                                            
    [<DllImport("secur32.dll", SetLastError = true)>]
    extern uint32 LsaFreeReturnBuffer(IntPtr& buffer)

    [<DllImport("secur32.dll", SetLastError = true)>]
    extern uint32 LsaEnumerateLogonSessions([<Out>] uint64& logonSessionCount, [<Out>] IntPtr& logonSessionList)

    [<DllImport("secur32.dll", SetLastError = true)>]
    extern uint32 LsaGetLogonSessionData(IntPtr luid, [<Out>] IntPtr& ppLogonSessionData )

    //// vaultcli ////

    [<DllImport("vaultcli.dll")>]
    extern int32 VaultOpenVault(
        Guid vaultGuid, 
        uint32 offset, 
        [<Out>] IntPtr& vaultHandle
        )

    [<DllImport("vaultcli.dll")>]
    extern int32 VaultCloseVault(IntPtr vaultHandle) //these two need to be integrated into the vault code!

    [<DllImport("vaultcli.dll")>]
    extern int32 VaultFree(IntPtr vaultHandle) // ^

    [<DllImport("vaultcli.dll")>]
    extern int32 VaultEnumerateVaults(
        int32 offset, 
        [<Out>] int32& vaultCount, 
        [<Out>] IntPtr& vaultGuid
        )

    [<DllImport("vaultcli.dll")>]
    extern int32 VaultEnumerateItems(
        IntPtr vaultHandle, 
        int32 chunkSize, 
        [<Out>] int32& vaultItemCount, 
        [<Out>] IntPtr& vaultItem
        )

    [<DllImport("vaultcli.dll", EntryPoint = "VaultGetItem")>]
    extern int32 VaultGetItem_WIN8(
        IntPtr vaultHandle, 
        Guid schemaId, 
        IntPtr pResourceElement, 
        IntPtr pIdentityElement, 
        IntPtr pPackageSid, 
        IntPtr zero, 
        int32 arg6, 
        [<Out>] IntPtr& passwordVaultPtr
        )

    [<DllImport("vaultcli.dll", EntryPoint = "VaultGetItem")>]
    extern int32 VaultGetItem_WIN7(
        IntPtr vaultHandle, 
        Guid schemaId, 
        IntPtr pResourceElement,
        IntPtr pIdentityElement, 
        IntPtr zero, 
        int32 arg5, 
        [<Out>] IntPtr& passwordVaultPtr
        )
            
    
    //// wtsapi32 ////

    [<DllImport("wtsapi32.dll", SetLastError = true)>]
    extern IntPtr WTSOpenServer(string pServerName)

    [<DllImport("Wtsapi32.dll", SetLastError = true)>]
    extern bool WTSQuerySessionInformation(
        IntPtr& hServer,
        int sessionId,
        WTS_INFO_CLASS wtsClientAddress,
        [<Out>] IntPtr& ppBuffer,
        [<Out>] int& pBytesReturned
        )
    
    [<DllImport("wtsapi32.dll", SetLastError = true)>]
    extern int WTSEnumerateSessionsEx(
        IntPtr hServer,
        int& pLevel,
        int Filter,
        [<Out>] IntPtr& ppSessionInfo,
        [<Out>] int& pCount)

    /////////////////////////
    //Native Function Helpers
    /////////////////////////

    //For extracting LSA_STRING_OUT 
    let marshalLSAStringS (sourceStruct: LSA_STRING_OUT) : string =
        match sourceStruct with
        | x when not(x.buffer = IntPtr.Zero) && not(x.length = 0us) -> 
            let unmanagedString = Marshal.PtrToStringAuto(sourceStruct.buffer, (int(sourceStruct.maxLength /2us) - 1))
            unmanagedString
        |_ -> ""

    let marshalLSAString (sourceStruct: LSA_STRING_OUT) : string =
        match sourceStruct with
        | x when not(x.buffer = IntPtr.Zero) && not(x.length = 0us) -> 
            let unmanagedString = Marshal.PtrToStringAuto(sourceStruct.buffer, (int(sourceStruct.maxLength /2us) ))
            unmanagedString
        |_ -> ""


    //For extracting strings at an offset from a Ptr. Used in the Vault enum code
    let marshalIndirectString offset ptr : string =
        let oPtr = IntPtr.Add(ptr, offset)
        let strPtr = Marshal.ReadIntPtr(oPtr)
        Marshal.PtrToStringAuto(strPtr)


    //Useful partial for vault code
    let marshalVaultString = marshalIndirectString 16

    
    ///////////////////////
    //Native function calls
    ///////////////////////

    /////////////////////////
    //RDP Session Enumeration
    /////////////////////////
    
    let private populateRdpSessionStructs ppSessionBaseAddr count : WTS_SESSION_INFO_1[] =
        let mutable ppSBA = ppSessionBaseAddr
        [|0..(count - 1)|] 
        |> Array.map(fun _ -> 
            let wtsSessionInfo = Marshal.PtrToStructure<WTS_SESSION_INFO_1>(ppSBA)
            ppSBA <- IntPtr.Add(ppSBA, Marshal.SizeOf<WTS_SESSION_INFO_1>())
            wtsSessionInfo)


    let private rdpSessionGetAddress ppBuffer : IPAddress = 
        // Helper function for extracting IP address strings from the 
        // WTS_CLIENT_ADDRESS struct
        let addr = Marshal.PtrToStructure<WTS_CLIENT_ADDRESS>(ppBuffer)
        System.Net.IPAddress(addr.addressRaw.[2..5])
        

    let private rdpSessionReverseLookup sessionID : IPAddress =
        //Helper function to do a reverse IP lookup on a given Session ID
        let mutable server = WTSOpenServer("localhost")
        let mutable ppBuffer = IntPtr.Zero
        let mutable pBytesReturned = 0

        let revLookup = 
            WTSQuerySessionInformation(
                &server, 
                sessionID,
                WTS_INFO_CLASS.WTSClientAddress, 
                &ppBuffer, 
                &pBytesReturned
            )
        
        match revLookup with
        | true -> rdpSessionGetAddress ppBuffer 
        | false -> System.Net.IPAddress.None


    let enumerateRdpSessions () : FettersPInvokeRecord list =
        // Returns a RdpSession record list of local sessions meeting the filter,
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

        allEnumeratedSessions 
        |> Array.filter(fun f -> f.pSessionName.StartsWith("RDP"))
        |> Array.map(fun sess -> 
            {state = sess.State.ToString(); 
            sessionID = sess.SessionID;
            sessionName = sess.pSessionName;
            hostName = sess.pHostName;
            username = sess.pUserName;
            remoteAddress = (rdpSessionReverseLookup sess.SessionID)
            })
        |> Array.toList
        |> List.map FettersPInvokeRecord.RdpSession
        
        
    /////////////////////////
    //Local Group Enumeration
    /////////////////////////

    let private populateGroupMemberStruct bufferPtr entriesRead : LOCAL_GROUP_MEMBER_INFO2 [] =
    // Helper function for populating the LOCAL_GROUP_MEMBER structs
        // I feel like this should actualy use mutability, because it's not necessarily
        // clear that the `memberStructs` thta gets passed back is a copy?
        let mutable bPtr = bufferPtr
        
        [|0..(entriesRead - 1)|] 
        |> Array.map(fun _ -> 
            let mstruct = Marshal.PtrToStructure<LOCAL_GROUP_MEMBER_INFO2>(bPtr)
            bPtr <- IntPtr.Add(bPtr, Marshal.SizeOf<LOCAL_GROUP_MEMBER_INFO2>())
            mstruct)
        

    let getLocalGroupMembership groupName : string list =
        //Enumerates the members of a local group. Will emit a None on empty 
        //groups or if there was a non-0 return code.
        let mutable bufPtr = IntPtr.Zero
        let mutable rHandle = IntPtr.Zero
        let mutable entRead = 0
        let mutable totEntries = 0

        let returnValue = 
            NetLocalGroupGetMembers("", groupName, 2, &bufPtr, -1, &entRead, &totEntries, rHandle)
        
        //Kinda awkward, but we don't deal with errors at this point.
        let members = 
            match returnValue with
            | 0 -> populateGroupMemberStruct bufPtr entRead
            | _ -> Array.zeroCreate 0 //(LOCAL_GROUP_MEMBER_INFO2())
        
        NetApiBufferFree(bufPtr) |> ignore
        
        members
        |> Array.filter(fun gmember -> not (gmember.lgrmi2_sid = IntPtr.Zero))
        |> Array.map(fun gmember -> gmember.lgrmi2_domainandname.Trim()) 
        |> Array.toList 
            

    ///////////////
    //Impersonation
    ///////////////

    let private impersonateSystem () = 
        //Finds, opens and duplicates a SYSTEM process, performs the 
        //impersonation, then closes the handles. Blows up dramatically if user 
        //isn't in the Administrator role. This should probably return a 
        //Result< >, but I don't understand how to do those yet.
        let mutable procHandle = IntPtr.Zero
        let mutable  dupToken = IntPtr.Zero
        
        let sysProcess = 
            Process.GetProcessesByName("winlogon")
            |> Array.head
        let impersonationResult = 
            match (OpenProcessToken(sysProcess.Handle, 0x0002u, &procHandle) &&
                   DuplicateToken(procHandle, 2, &dupToken) &&
                   ImpersonateLoggedOnUser(dupToken)) with
            |true -> sprintf "Impersonating %s" <| WindowsIdentity.GetCurrent().Name |> gPrinter Plus |> cPrinter Green
            |false -> sprintf "Failed to impersonate SYSTEM, error: %i" <| Marshal.GetLastWin32Error() |> gPrinter Bang |> cPrinter Red

        CloseHandle(dupToken) |> ignore
        CloseHandle(procHandle) |> ignore
        impersonationResult
        

    let private revertToSelf () = 
        match RevertToSelf() with
        |true -> 
            "Completed task, reverting to current user" |> gPrinter Plus |> cPrinter Green
            true
        |false -> 
            "Revert failed" |> gPrinter Bang |> cPrinter Red
            false

    let private getSystem () = 
        //Impersonate the NTAUTHORITY\SYSTEM user in order to access sensitive processes.
        match isHighIntegrity () with
        | true -> impersonateSystem ()
        | false -> sprintf "Current role cannot escalate privileges" |> gPrinter Minus |> cPrinter Red
        
    ////////////////////////////
    //LSA Methods (for Kerberos)
    ////////////////////////////

    let private registerLsaLogonProcess () : LsaProcessHandle =
        //We use the LsaProcessHandle later in the important call to LsaCallAuthenticationPackage
        let mutable lsaProcessHandle = IntPtr.Zero
        let mutable securityMode = 0UL
        let registeredProcessName = "SomethingCustom"

        let mutable configString = 
            LSA_STRING_IN(
                length = uint16(registeredProcessName.Length), 
                maxLength = uint16(registeredProcessName.Length + 1), 
                buffer = registeredProcessName
            )

        LsaRegisterLogonProcess(&configString, &lsaProcessHandle, &securityMode) |> ignore
        lsaProcessHandle |> LsaProcessHandle


    let private deregisterLsaLogonProcess lsaHandle =
        let mutable (LsaProcessHandle lHandle) = lsaHandle
        LsaDeregisterLogonProcess(lHandle) |> ignore


    let private untrustedLsaConnection () : LsaProcessHandle =
        let mutable lsaHandle = IntPtr.Zero
        LsaConnectUntrusted(&lsaHandle) |> ignore
        lsaHandle |> LsaProcessHandle


    let private closeLsaHandle handle : unit = 
        let mutable (LsaProcessHandle _handle) = handle
        LsaFreeReturnBuffer(&_handle) |> ignore


    let private closeLsaH (ptr) =
        let mutable ptr = ptr
        LsaFreeReturnBuffer(&ptr) |> ignore

    let private enumerateLsaLogonSessions () : (uint64 * LUIDPtr) =
        let mutable countOfLUIDs = 0UL
        let mutable luidPtr = IntPtr.Zero

        LsaEnumerateLogonSessions(&countOfLUIDs, &luidPtr) |> ignore
        (countOfLUIDs, luidPtr |> LUIDPtr)


    let private getLsaSessionData (count, luidPtr) : SECURITY_LOGON_SESSION_DATA list =
        //Returns a filtered list of SECURITY_LOGON_SESSION_DATA structs. 
        //Seatbelt only processed results with a non-null pSID, so that's what
        //we're doing. Will deal with Results/error states later.
        let mutable sessionDataPtr = IntPtr.Zero
        let mutable (LUIDPtr _luidPtr) = luidPtr
        let sessionData = 
            [|1..int(count)|]
            |> Array.map(fun _ -> 
                LsaGetLogonSessionData(_luidPtr, &sessionDataPtr) |> ignore
                let sessionData = Marshal.PtrToStructure<SECURITY_LOGON_SESSION_DATA>(sessionDataPtr)
                _luidPtr <- IntPtr.Add(_luidPtr, Marshal.SizeOf<LUID>())
                closeLsaH sessionDataPtr
                sessionData
                )
             |> Array.filter(fun _s -> not(_s.pSID = IntPtr.Zero)) // We only want results where there is a pSID
             |> Array.toList
        
        closeLsaHandle (_luidPtr |> LsaProcessHandle)
        sessionData
    
    
    let private fetchLsaSessions = enumerateLsaLogonSessions >> getLsaSessionData


    let private lookupLsaAuthenticationPackage lsaHandle lsaKerberosString : LsaAuthPackage = 
        // This call is around to generate authpkgs for the later call to LsaCallAuthenticationPackage
        // which is where the magic happens, I suppose. Leveraging types again to help keep the 
        // handles and pointer types straight.
        let mutable (LsaProcessHandle lsaHandle) = lsaHandle
        let mutable authPkg = 0
                
        LsaLookupAuthenticationPackage(lsaHandle, lsaKerberosString, &authPkg) |> ignore
        authPkg |> LsaAuthPackage

    
    let private getKerberosTicketResponse lsaHandle authPkg kerbReq : (IntPtr * KerberosResponse) option = 
        //Returns a KERB response, depending on the type of KERB request submitted
        let mutable ticketPtr = IntPtr.Zero
        let mutable returnBufferLength = 0
        let mutable protocolStatus = 0
        
        let mutable (LsaProcessHandle _lsaHandle) = lsaHandle
        let mutable (LsaAuthPackage _aPkg) = authPkg
        
        match kerbReq with
        |KERB_QUERY_TKT_CACHE_REQ kReq -> 
            let mutable _kReq = kReq
            LsaCallAuthenticationPackage_CACHE(
                _lsaHandle, 
                _aPkg, 
                _kReq, 
                Marshal.SizeOf(_kReq),
                &ticketPtr,
                &returnBufferLength,
                protocolStatus
                ) |> ignore

            match returnBufferLength with
            |x when x > 0 -> 
                let kR = Marshal.PtrToStructure<KERB_QUERY_TKT_CACHE_RESPONSE>(ticketPtr)
                
                match kR.countOfTickets with
                | x when x > 0 -> Some (ticketPtr, kR |> KERB_QUERY_TKT_CACHE_RESP)
                | _ -> None
            | _ -> None

        |KERB_RETRIEVE_TKT_REQ kReq -> 
            let mutable _kReq = kReq
            LsaCallAuthenticationPackage_RET(
                _lsaHandle, 
                _aPkg, 
                _kReq, 
                Marshal.SizeOf(_kReq),
                &ticketPtr,
                &returnBufferLength,
                protocolStatus
                ) |> ignore
            
            match returnBufferLength with
            | x when x > 0 -> 
                Some (ticketPtr, Marshal.PtrToStructure<KERB_RETRIEVE_TKT_RESPONSE>(ticketPtr) 
                |> KERB_RETRIEVE_TKT_RESP)
            | _ -> None
                                        
    
    let private extractKerberosReponseTickets
        (ticketPtr: IntPtr, kResponse: KerberosResponse)
        : KerberosTicketStruct list =
        //Takes in either type of response struct, and outputs a list we can work with
        match kResponse with
        |KERB_QUERY_TKT_CACHE_RESP ticket -> 
            [0..(ticket.countOfTickets - 1)] 
            |> List.map(fun count -> 
                Marshal.PtrToStructure<KERB_TICKET_CACHE_INFO>(IntPtr.Add(ticketPtr, (8 + (count * 64)))) 
                |> KERB_TKT_CACHE_INFO)
        |KERB_RETRIEVE_TKT_RESP x -> 
            [Marshal.PtrToStructure<KERB_EXTERNAL_TICKET>(ticketPtr) |> KERB_EXTERNAL_TKT] 

    
    let private createKerberosQueryTicket
        (ticket: KERB_TICKET_CACHE_INFO)
        : KerberosQueryTicket =
        {serverName = marshalLSAString ticket.serverName
         realm = marshalLSAString ticket.realmName
         startTime = DateTime.FromFileTime(ticket.startTime)
         endTime = DateTime.FromFileTime(ticket.endTime)
         renewTime = DateTime.FromFileTime(ticket.renewTime)
         encryptionType = KERB_ENCRYPTION_TYPE.GetName(typeof<KERB_ENCRYPTION_TYPE>, ticket.encryptionType)
         ticketFlags = Microsoft.FSharp.Core.LanguagePrimitives.EnumOfValue<uint32, Fetters.DomainTypes.KERB_TICKET_FLAGS>(ticket.ticketFlags)
        }
      
   
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
        
        //Have to create some base64 strings here before packing the record
        let rawSessionKey = Array.create (ticket.SessionKey.length) 0uy
        Marshal.Copy(ticket.SessionKey.value, rawSessionKey, 0, ticket.SessionKey.length)
        let b64SessionKey = Convert.ToBase64String(rawSessionKey)
        let rawEncodedTicket = Array.create (ticket.EncodedTicketSize) 0uy
        Marshal.Copy(ticket.EncodedTicket, rawEncodedTicket, 0, ticket.EncodedTicketSize)
        let b64Ticket = Convert.ToBase64String(rawEncodedTicket)

        {serviceName = serviceName
         target = targetName
         client = clientName
         domain = marshalLSAString ticket.DomainName
         targetDomain = marshalLSAString ticket.TargetDomainName
         altTargetDomain = marshalLSAString ticket.AltTargetDomainName
         sessionKeyType = KERB_ENCRYPTION_TYPE.GetName(typeof<KERB_ENCRYPTION_TYPE>, ticket.SessionKey.keyType)
         base64SessionKey = b64SessionKey
         keyExpiry = DateTime.FromFileTime(ticket.KeyExpirationTime)
         flags = flags
         startTime = DateTime.FromFileTime(ticket.StartTime)
         endTime = DateTime.FromFileTime(ticket.EndTime)
         renewTime = DateTime.FromFileTime(ticket.RenewUntil)
         skewTime = DateTime.FromFileTime(ticket.TimeSkew)
         encodedSize = ticket.EncodedTicketSize
         base64EncodedTicket = b64Ticket
        }
        

    let private createDomainSessionRecord (sess: SECURITY_LOGON_SESSION_DATA, kQRecords, kRRecords) : DomainSession =
        //A bodge to deal with the fact that both high and low priv codepaths  
        //run through this function, and low priv enum can't get session info
        //So a dummy value 'Everyone' SID is placed here.
        let SID = 
             match isHighIntegrity () with
             |true -> SecurityIdentifier(sess.pSID)
             |false -> SecurityIdentifier("S-1-1-0")
                     
        {username = marshalLSAStringS sess.username
         domain = marshalLSAStringS sess.loginDomain
         logonID = sess.loginID.lower
         userSID = SID
         authenticationPkg = marshalLSAStringS sess.authenticationPackage
         logonType = sess.logonType.ToString()
         loginTime = DateTime.FromFileTime(int64(sess.loginTime))
         logonServer = marshalLSAStringS sess.logonServer
         logonServerDnsDomain = marshalLSAStringS sess.dnsDomainName
         userPrincipalName = marshalLSAStringS sess.upn
         kerberosCachedTickets = kQRecords
         kerberosTGTcontents = kRRecords
        }
        

    let private createKerberosRecordList ticketList : KerberosTicket list =
        //Returns a list of Ticket records.
        ticketList 
        |> List.map(fun ticket ->   
            match ticket with
            |KERB_EXTERNAL_TKT tkt -> 
                createKerberosRetrieveTicket tkt |> KerberosRetrieveTicket
            |KERB_TKT_CACHE_INFO tkt -> 
                createKerberosQueryTicket tkt |> KerberosQueryTicket)

    let enumerateDomainSessions () : FettersPInvokeRecord list =
        // Emits a DomainSession for each enumerated session, containing KerberosTickets as well
        // as other metadata.
        let LSAStringQuery = 
            LSA_STRING_IN(
                length = uint16("kerberos".Length), 
                maxLength = uint16("kerberos".Length + 1), 
                buffer = "kerberos")
        
        //Because low priv processes can't enumerate the other sessions on the 
        //system,I have to inject fake values for later processing to work.
        let tTuple = 
            match isHighIntegrity () with
            |true -> getSystem()
                     let lsaHandle = registerLsaLogonProcess ()
                     let lsaAuthPackage = lookupLsaAuthenticationPackage lsaHandle LSAStringQuery
                     let sessionList = fetchLsaSessions ()
                     let luidList = 
                         sessionList
                         |> List.map(fun session -> session.loginID.lower, session.loginID.upper)
                     revertToSelf () |> ignore
                     sessionList, luidList, lsaAuthPackage, lsaHandle
            |false -> let lsaHandle = untrustedLsaConnection ()
                      let lsaAuthPackage = lookupLsaAuthenticationPackage lsaHandle LSAStringQuery
                      let sessionList = [SECURITY_LOGON_SESSION_DATA()]
                      let luidList = [0u,0]
                      sessionList, luidList, lsaAuthPackage, lsaHandle
        //Just tuple things
        let sessionList, luidList, lsaAuthPackage, lsaHandle =
            match tTuple with
            |w, x, y, z -> w, x, y, z
        
        let domainSessionRecord =
            (sessionList, luidList)
            ||>List.map2(fun sess luid -> 
                let luid = LUID(lower= fst luid, upper = snd luid)
                let kQTCR = KERB_QUERY_TKT_CACHE_REQUEST(
                             messageType = KERB_PROTOCOL_MESSAGE_TYPE.KerbQueryTicketCacheMessage, logonID = luid ) |> KERB_QUERY_TKT_CACHE_REQ
                let kRTR = KERB_RETRIEVE_TKT_REQUEST(
                             messageType = KERB_PROTOCOL_MESSAGE_TYPE.KerbRetrieveTicketMessage, logonID = luid) |> KERB_RETRIEVE_TKT_REQ
                (sess, kQTCR, kRTR)) 
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
            |> List.map FettersPInvokeRecord.DomainSession

        //Cleanup and then pass out result
        deregisterLsaLogonProcess lsaHandle
        closeLsaHandle lsaHandle
        domainSessionRecord 

    //////////////////
    //Credential Vault
    //////////////////

    let private enumerateVaults () : (int32 * VaultGuid) =
        let mutable countOfVaults = 0
        let mutable vaultGuid = IntPtr.Zero

        VaultEnumerateVaults(0, &countOfVaults, &vaultGuid) |> ignore
        (countOfVaults, vaultGuid |> VaultGuid)
        

    let private openVault (count, vaultGuid) : VaultHandle list = 
        let  mutable (VaultGuid vaultGuidPtr) = vaultGuid
        let mutable vaultHandle = IntPtr.Zero
        [0..(count - 1)]
        |> List.map(fun x -> 
            let mutable vaultGUID = Marshal.PtrToStructure<Guid>(vaultGuidPtr)
            let mutable vaultHandle = IntPtr.Zero
            VaultOpenVault(vaultGUID, 0u, &vaultHandle) |> ignore
            vaultGuidPtr <- IntPtr.Add(vaultGuidPtr, Marshal.SizeOf<Guid>())
            vaultHandle|> VaultHandle)


    let private enumerateVaultItems vaultHandle : (VaultHandle * VaultItem list) =
        let mutable (VaultHandle vaultHandle) = vaultHandle
        let mutable vaultItemCount = 0
        let mutable vaultItem = IntPtr.Zero

        VaultEnumerateItems(vaultHandle, 512, &vaultItemCount, &vaultItem) |>ignore
        let vaultItems =
            [0..(vaultItemCount - 1)]
            |> List.map(fun _ -> 
                match Environment.OSVersion.Version.Build with
                | x when x > 7601 -> 
                    let vaultStruct = Marshal.PtrToStructure<VAULT_ITEM_WIN8>(vaultItem)
                    vaultItem <- IntPtr.Add(vaultItem, Marshal.SizeOf<VAULT_ITEM_WIN8>())
                    vaultStruct |> WIN8VAULT
                | _ -> 
                    let vaultStruct = Marshal.PtrToStructure<VAULT_ITEM_WIN7>(vaultItem)
                    vaultItem <- IntPtr.Add(vaultItem, Marshal.SizeOf<VAULT_ITEM_WIN7>())
                    vaultStruct |> WIN7VAULT)
        (vaultHandle |> VaultHandle, vaultItems)

    
    let private getVaultElementContent element : string option =
        match element with
        |x when not(x = IntPtr.Zero) ->
            let elementStruct = Marshal.PtrToStructure<VAULT_ITEM_ELEMENT>(element)
            let elementContentPtr = IntPtr.Add(element, 16)

            match elementStruct.Type with
            |VAULT_ELEMENT_TYPE.Boolean -> marshalIndirectString 0 elementContentPtr |> Some
            |VAULT_ELEMENT_TYPE.Guid -> (Marshal.PtrToStructure<Guid>(elementContentPtr)).ToString() |> Some
            |VAULT_ELEMENT_TYPE.String -> marshalVaultString elementContentPtr |> Some
            |VAULT_ELEMENT_TYPE.Sid -> (SecurityIdentifier(elementContentPtr)).ToString() |> Some
            |_ -> None
        | _ -> None


    let private createVaultRecord (vaultHandle, vaultItems) : VaultRecord list = 
        let mutable (VaultHandle vaultHandle) = vaultHandle

        vaultItems
        |> List.map(fun vItem -> 
            match vItem with
            |WIN8VAULT vItem ->
                let mutable passwordPtr = IntPtr.Zero
                VaultGetItem_WIN8(
                    vaultHandle, 
                    vItem.SchemaId, 
                    vItem.pResourceElement,
                    vItem.pIdentityElement,
                    vItem.pPackageSid,
                    IntPtr.Zero,
                    0,
                    &passwordPtr
                ) |> ignore
                (vItem |> WIN8VAULT, passwordPtr)
            |WIN7VAULT vItem -> 
                let mutable passwordPtr = IntPtr.Zero
                VaultGetItem_WIN7(
                    vaultHandle,
                    vItem.SchemaId,
                    vItem.pResourceElement,
                    vItem.pIdentityElement,
                    IntPtr.Zero,
                    0,
                    &passwordPtr
                ) |> ignore
                (vItem |> WIN7VAULT, passwordPtr))
                                    
        |>List.map(fun tuple -> 
            let vItem, passwordPtr = tuple
            match vItem with
            | WIN8VAULT vItem -> 
                let mutable passwordVaultItem = Marshal.PtrToStructure<VAULT_ITEM_WIN8>(passwordPtr)
                {name = Marshal.PtrToStringAuto(vItem.pszCredentialFriendlyName)
                 resource = getVaultElementContent vItem.pResourceElement
                 identity = getVaultElementContent vItem.pIdentityElement
                 packageSid = getVaultElementContent vItem.pPackageSid
                 credential = getVaultElementContent passwordVaultItem.pAuthenticatorElement
                 lastModified = DateTime.FromFileTime(int64(vItem.LastModified))
                 }
            |WIN7VAULT vItem -> 
                let mutable passwordVaultItem = Marshal.PtrToStructure<VAULT_ITEM_WIN7>(passwordPtr)
                {name = Marshal.PtrToStringAuto(vItem.pszCredentialFriendlyName)
                 resource = getVaultElementContent vItem.pResourceElement
                 identity = getVaultElementContent vItem.pIdentityElement
                 packageSid = None
                 credential = getVaultElementContent passwordVaultItem.pAuthenticatorElement
                 lastModified = DateTime.FromFileTime(int64(vItem.LastModified))
                 })


    let enumerateUserVaults () : FettersPInvokeRecord list =
        enumerateVaults ()
        |> openVault 
        |> List.map enumerateVaultItems
        |> List.map createVaultRecord
        |> List.concat
        |> List.map FettersPInvokeRecord.VaultRecord


    ////////////////////////////
    //TCP Connection Enumeration
    ////////////////////////////

    let private getServiceNameInfo pid serviceTag : string option =
        let mutable serviceTagQuery = SC_SERVICE_TAG_QUERY(processId = pid, serviceTag = serviceTag)
        
        let retcode = 
            I_QueryTagInformation(
                IntPtr.Zero, 
                SC_SERVICE_TAG_QUERY_TYPE.ServiceNameFromTagInformation, 
                &serviceTagQuery)
        match retcode with
        | x when x = 0u ->  Marshal.PtrToStringAuto(serviceTagQuery.buffer) |> Some
        | _ -> None


    let private getTcpTable () : IntPtr option = 
        let mutable tableBufferSize = 0u
        let mutable tablePtr = IntPtr.Zero

        GetExtendedTcpTable(
            tablePtr, 
            &tableBufferSize, 
            true, 
            2, 
            TCP_TABLE_CLASS.TCP_TABLE_OWNER_MODULE_ALL, 
            0) |> ignore

        match tableBufferSize with
        |x when x > 0u -> 
            tablePtr <- Marshal.AllocHGlobal(int(tableBufferSize))
            GetExtendedTcpTable(
                tablePtr, 
                &tableBufferSize, 
                true, 
                2, 
                TCP_TABLE_CLASS.TCP_TABLE_OWNER_MODULE_ALL, 
                0) |> ignore
            tablePtr |> Some
        | _ -> Marshal.FreeHGlobal(tablePtr)
               None


    let private getTcpTableRows tablePtr : MIB_TCPROW_OWNER_MODULE list =
        let rowList = 
            match tablePtr with
            |Some tPtr -> 
                let tcpTable = Marshal.PtrToStructure<MIB_TCPTABLE_OWNER_MODULE>(tPtr)
                let mutable rowPtr = IntPtr.Add(tPtr, Marshal.SizeOf<MIB_TCPTABLE_OWNER_MODULE>())
                [0u..(tcpTable.numEntries - 1u)]
                |> List.map(fun _ -> 
                    let rowStruct = Marshal.PtrToStructure<MIB_TCPROW_OWNER_MODULE>(rowPtr)
                    rowPtr <- IntPtr.Add(rowPtr, Marshal.SizeOf<MIB_TCPROW_OWNER_MODULE>())
                    rowStruct)
            |None -> []
        
        match tablePtr with
        | Some x -> Marshal.FreeHGlobal(x)
        | None -> ()
        rowList


    let private createTCPRecord (tcpRow: MIB_TCPROW_OWNER_MODULE) : TCPConnection =
        {localAddress = IPAddress(int64(tcpRow.LocalAddr))
         remoteAddress = IPAddress(int64(tcpRow.RemoteAddr))
         localport = BitConverter.ToUInt16([|tcpRow.LocalPort2;tcpRow.LocalPort1|], 0)
         remoteport = BitConverter.ToUInt16([|tcpRow.RemotePort2;tcpRow.RemotePort1|], 0)
         connectionState = tcpRow.State.ToString()
         pid = tcpRow.OwningPid
         service = getServiceNameInfo tcpRow.OwningPid (uint32(tcpRow.OwningModuleInfo0))
         }
        

    let enumerateTCPConnections () : FettersPInvokeRecord list =
        getTcpTable () 
        |> getTcpTableRows 
        |> List.map createTCPRecord 
        |> List.map FettersPInvokeRecord.TCPConnection

    ///////////////////////////
    //UDP conection enumeration
    ///////////////////////////

    let private getUdpTable () : IntPtr option = 
        let mutable tableBufferSize = 0u
        let mutable tablePtr = IntPtr.Zero

        GetExtendedUdpTable(
            tablePtr, 
            &tableBufferSize, 
            true, 
            2, 
            UDP_TABLE_CLASS.UDP_TABLE_OWNER_MODULE, 
            0) |> ignore

        match tableBufferSize with
        |x when x > 0u -> 
            tablePtr <- Marshal.AllocHGlobal(int(tableBufferSize))
            GetExtendedUdpTable(
                tablePtr, 
                &tableBufferSize, 
                true, 
                2, 
                UDP_TABLE_CLASS.UDP_TABLE_OWNER_MODULE, 
                0) |> ignore
            tablePtr |> Some
        | _ -> Marshal.FreeHGlobal(tablePtr)
               None


    let private getUdpTableRows tablePtr : MIB_UDPROW_OWNER_MODULE list =
        let rowList = 
            match tablePtr with
            |Some tPtr -> 
                let udpTable = Marshal.PtrToStructure<MIB_UDPTABLE_OWNER_MODULE>(tPtr)
                let mutable rowPtr = IntPtr.Add(tPtr, Marshal.SizeOf<MIB_UDPTABLE_OWNER_MODULE>())
                [0u..(udpTable.numEntries - 1u)]
                |> List.map(fun _ -> 
                    let rowStruct = Marshal.PtrToStructure<MIB_UDPROW_OWNER_MODULE>(rowPtr)
                    rowPtr <- IntPtr.Add(rowPtr, Marshal.SizeOf<MIB_UDPROW_OWNER_MODULE>())
                    rowStruct)
            |None -> []
        
        match tablePtr with
        | Some x -> Marshal.FreeHGlobal(x)
        | None -> ()
        rowList


    let private createUdpRecord (udpRow: MIB_UDPROW_OWNER_MODULE) : UDPListener =
        {localAddress = IPAddress(int64(udpRow.LocalAddr))
         localport = BitConverter.ToUInt16([|udpRow.LocalPort2;udpRow.LocalPort1|], 0) 
         pid = udpRow.OwningPid
         service = getServiceNameInfo udpRow.OwningPid (uint32(udpRow.OwningModuleInfo0))
         }
 

    let enumerateUDPConnections () : FettersPInvokeRecord list =
        getUdpTable () 
        |> getUdpTableRows 
        |> List.map createUdpRecord
        |> List.map FettersPInvokeRecord.UDPListener

    ///////////////////////
    //Arp Table Enumeration
    ///////////////////////

    let getLocalArpTables () : FettersPInvokeRecord list =
        let mutable tableSize = 0
        let mutable tablePtr = IntPtr.Zero
        let mutable tRowPtr = IntPtr.Zero
        //Call twice, once for size of tablePtr, second for contents
        GetIpNetTable(tablePtr, &tableSize, false) |> ignore
        tablePtr <- Marshal.AllocHGlobal(tableSize)
        GetIpNetTable(tablePtr, &tableSize, false) |> ignore

        let tcpTable = Marshal.PtrToStructure<MIB_IPNETTABLE>(tablePtr)
        tRowPtr <- IntPtr.Add(tablePtr, 4)
        let arpTableByIndexResult = 
            [0..int(tcpTable.numEntries)- 1]
            |> List.map(fun _ -> 
                let tcpRow = Marshal.PtrToStructure<MIB_IPNETROW>(tRowPtr)
                tRowPtr <- IntPtr.Add(tRowPtr, Marshal.SizeOf<MIB_IPNETROW>())
                tcpRow)
            |> List.filter(fun row -> row.dwType = 3) //My opinionated belief that non-dynamic entries are mostly useless information
            |> List.map(fun row -> 
                let addr = IPAddress(BitConverter.GetBytes(row.dwAddr))
                let hwaddr = BitConverter.ToString([|row.mac0;row.mac1;row.mac2;row.mac3;row.mac4;row.mac5|]) 
                let arpTableByIndex = {indexaddresses = (row.dwIndex,(addr, hwaddr))}
                arpTableByIndex |> FettersPInvokeRecord.ArpTableByInd)

        FreeMibTable(tablePtr) |> ignore
        arpTableByIndexResult

    /////////////////////////////
    //Token Privilege Enumeration
    /////////////////////////////

    let getTokenPrivInformation () : FettersPInvokeRecord =
        let mutable tokenInfoLength = 0
        let mutable tokenInfo = IntPtr.Zero
        let currToken = WindowsIdentity.GetCurrent().Token
        //Have to call twice, once to get the size, again to fetch real value
        GetTokenInformation(
                    currToken, 
                    TOKEN_INFORMATION_CLASS.TokenPrivileges, 
                    tokenInfo, 
                    tokenInfoLength, 
                    &tokenInfoLength
                    ) |> ignore
        tokenInfo <- Marshal.AllocHGlobal(tokenInfoLength)
        GetTokenInformation(
                    currToken, 
                    TOKEN_INFORMATION_CLASS.TokenPrivileges, 
                    tokenInfo, 
                    tokenInfoLength, 
                    &tokenInfoLength
                    ) |> ignore
        
        //Fetch the struct from the tokenInfo Ptr, and then advance it to ready
        //for the rest of the calculation
        let tokenPrivs = Marshal.PtrToStructure<TOKEN_PRIVILEGES>(tokenInfo)
        let mutable privPtr = IntPtr.Add(tokenInfo, 4)
        
        //Setup mutable throw-aways, call twice for size and retrieve, advance
        //ptr and retrieve string. Free the buffer, repeat.
        let privList = 
            [0u..(tokenPrivs.privilegeCount - 1u)]
            |> List.map(fun _ ->  
                let mutable cchName = 0
                let mutable stringPtr = IntPtr.Zero
                LookupPrivilegeName("", privPtr, stringPtr, &cchName) |> ignore
                stringPtr <- Marshal.AllocHGlobal(cchName)
                LookupPrivilegeName("", privPtr, stringPtr, &cchName) |> ignore
                let privString =  Marshal.PtrToStringAnsi(stringPtr)
                privPtr <- IntPtr.Add(privPtr, 12)
                Marshal.FreeHGlobal(stringPtr)
                privString)
        //Pack and ship
        CloseHandle privPtr |> ignore
        CloseHandle tokenInfo |> ignore
        {privileges = privList} |> FettersPInvokeRecord.TokenPrivileges
        
    
    /////////////////////////
    //Token Group Enumeration
    /////////////////////////

    let getTokenGroupSIDs () =
        //I deeply suspect this will not work on 32bit Windows, because the 
        //Marshal insists on calling the SID_AND_ATTRIBUTES struct as 16bytes
        //when it's 12 or 8. Not sure what to do about it. Gives results that
        //don't line up with other telemtry. I'm probably doing something wrong
        let mutable tokenInfoLength = 0
        let mutable tokenInfo = IntPtr.Zero
        let mutable csid = IntPtr.Zero

        GetTokenInformation(
            WindowsIdentity.GetCurrent().Token,
            TOKEN_INFORMATION_CLASS.TokenGroups,
            tokenInfo,
            tokenInfoLength,
            &tokenInfoLength
            ) |> ignore
        tokenInfo <- Marshal.AllocHGlobal(tokenInfoLength)
        GetTokenInformation(
            WindowsIdentity.GetCurrent().Token,
            TOKEN_INFORMATION_CLASS.TokenGroups,
            tokenInfo,
            tokenInfoLength,
            &tokenInfoLength
            ) |> ignore
        
        let tokenGroups = Marshal.PtrToStructure<TOKEN_GROUPS>(tokenInfo)
        let groupCount = tokenGroups.GroupCount
        let mutable sidPtr = tokenGroups.Groups  
        let result = 
            [0u..(groupCount - 1u)]
            |> List.map(fun count -> 
                let sid =
                    match ConvertSidToStringSid(sidPtr, &csid) with
                    |true -> 
                        let sid = Marshal.PtrToStringAuto(csid)
                        sidPtr <- IntPtr.Add(sidPtr, 12)
                        sid
                    |false -> 
                        sidPtr <- IntPtr.Add(sidPtr, 12)
                        ""
                sid )
            |> List.filter (fun f -> not(f = ""))
        Marshal.FreeHGlobal(tokenInfo)
        result