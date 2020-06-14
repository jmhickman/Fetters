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

module Fetters.Lists

    let lsaNames = [|
        "LsaPid"
        "Notification Packages"
        "Authentication Packages"
        "ProductType"
        "LimitBlankPasswordUse"
        "SecureBoot"
        "disabledomaincreds"
        "everyoneincludesanonymous"
        "forceguest"
        "restrictanonymous"
        "restrictanonymoussam"
        "SamConnectedAccountsExist"
        |]

    let puttySessionNames = [|
        "HostName"
        "UserName"
        "PublicKeyFile"
        "PortForwardings"
        "ConnectionSharing"
        |]

    let autorunLocations = [|
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
        "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run"
        "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunService"
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceService"
        "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunService"
        "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnceService"
        |]

    let filterUserFolders = [|
        "C:\\Users\\Default"
        "C:\\Users\\Default User"
        "C:\\Users\\Public"
        "C:\\Users\\All Users"
        |]

    let filteredEventAccounts = [
        "SYSTEM"
        "LOCAL SERVICE"
        "NETWORK SERVICE"
        "UMFD-0"
        "UMFD-1"
        "UMFD-2"
        "UMFD-3"
        "UMFD-4"
        "UMFD-5"
        "UMFD-6"
        "UMFD-7"
        "UMFD-8"
        "UMFD-9"
        "DWM-0"
        "DWM-1"
        "DWM-2"
        "DWM-3"
        "DWM-4"
        "DWM-5"
        "DWM-6"
        "DWM-7"
        "DWM-8"
        "DWM-9"
        "ANONYMOUS LOGON"
        ]

    let firewallPropertyNames = [
        "Name"
        "Description"
        "Protocol"
        "ApplicationName"
        "LocalAddresses"
        "LocalPorts"
        "RemoteAddresses"
        "RemotePorts"
        "Direction"
        "Profiles"
        ]

    let functionNames = [
        "getlocaluserfolders" 
        "getbasicinfo" 
        "islocaladmin" 
        "ishighintegrity" 
        "triagechrome" 
        "triagefirefox" 
        "getfirewallrules-deny"
        "getfirewallrules-allow"
        "geteventlog4624" 
        "geteventlog4648" 
        "getdpapimasterkeys" 
        "getcredfiles" 
        "detectrdcmanfile" 
        "getgooglecloudcreds" 
        "getgooglecloudcredsl" 
        "getgoogleaccesstokens" 
        "getazuretokens" 
        "getazureprofile" 
        "getawscreds" 
        "getlapssettings" 
        "getautologonsettings" 
        "getautorunvalues" 
        "listsysmonconfig" 
        "getrdpsavedconnections" 
        "getrecentcommands" 
        "getuacsystempolicies" 
        "getpshellenv" 
        "getsystemenvvariables" 
        "getuserenvvariables" 
        "getsysteminternetsettings" 
        "getuserinternetsettings" 
        "getlsasettings" 
        "getauditsettings" 
        "getwefsettings" 
        "getputtysessions" 
        "getputtyhostkeys" 
        "getinternetexplorerhistory" 
        "querywmi-av" 
        "querywmi-service" 
        "querywmi-mappeddrive" 
        "querywmi-networkshare" 
        "querywmi-process" 
        "querywmi-disk" 
        "querywmi-group" 
        "querywmi-patches" 
        "querywmi-user" 
        "getprocessinformation"
        "gettokengroupsids" 
        "gettokenprivinformation" 
        "getlocalarptables" 
        "enumerateudpconnections" 
        "enumeratetcpconnections" 
        "enumerateuservaults" 
        "enumeratedomainsessions" 
        "getlocalgroupmembership" 
        "enumeraterdpsessions" 
        ]

    let systemGroup = [
        "listsysmonconfig"
        "getautorunvalues"
        "getautologonsettings"
        "enumeraterdpsessions"
        "getlapssettings"
        "getuserinternetsettings"
        "getsysteminternetsettings"
        "getuserenvvariables"
        "getsystemenvvariables"
        "getlsasettings"
        "getwefsettings"
        "getauditsettings"
        "getpshellenv"
        "getuacsystempolicies"
        "getfirewallrules-deny"
        "enumerateudpconnections"
        "enumeratetcpconnections"
        "enumeratetcpconnections"
        "getlocalarptables"
        "gettokenprivinformation"
        "querywmi-user"
        "querywmi-service"
        "querywmi-process"
        "querywmi-networkshare"
        "querywmi-mappeddrive"
        "querywmi-group"
        "querywmi-disk"
        "querywmi-av"
        "getbasicinfo"
        ]

    let userGroup = [
        "triagefirefox"
        "triagechrome"
        "getdpapimasterkeys"
        "getcredfiles"
        "detectrdcmanfile"
        "getgooglecloudcreds" 
        "getgooglecloudcredsl"
        "getgoogleaccesstokens"
        "getazuretokens"
        "getazureprofile"
        "getawscreds"
        "getrdpsavedconnections"
        "getrecentcommands"
        "getputtysessions"
        "getputtyhostkeys"
        "getinternetexplorerhistory"
        "enumerateuservaults"
        "enumeratedomainsessions"
        ]

    let extraGroup = [
        "geteventlog4624"
        "geteventlog4648"
        "querywmi-patches"
        ]