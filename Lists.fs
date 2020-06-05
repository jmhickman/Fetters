module Fetters.Lists

    open System.Security.AccessControl
    //Opinionated decision to cull UNKNOWN processes from the parent list.
    let InterestingProcesses = 
        [("mcshield.exe","McAfeeAV","AV")
         ("windefend.exe","WindowsDefenderAV","AV")
         ("MSASCui.exe","WindowsDefenderAV","AV")
         ("MSASCuiL.exe","WindowsDefenderAV","AV")
         ("msmpeng.exe","WindowsDefenderAV","AV")
         ("msmpsvc.exe","WindowsDefenderAV","AV")
         ("WRSA.exe","WebRootAV","AV")
         ("savservice.exe","SophosAV","AV")
         ("TMCCSF.exe","TrendMicroAV","AV")
         ("symantecantivirus.exe","SymantecAV","AV")
         ("mbae.exe","MalwareBytesAnti-Exploit","AV")
         ("parity.exe","Bit9applicationwhitelisting","Whitelist")
         ("cb.exe","CarbonBlackbehavioralanalysis","EDR")
         ("bds-vision.exe","BDSVisionbehavioralanalysis","EDR")
         ("Triumfant.exe","Triumfantbehavioralanalysis","EDR")
         ("CSFalcon.exe","CrowdStrikeFalconEDR","EDR")
         ("ossec.exe","OSSECintrusiondetection","EDR")
         ("TmPfw.exe","TrendMicrofirewall","AV")
         ("dgagent.exe","VerdasysDigitalGuardianDLP","DLP")
         ("kvoop.exe","UnknownDLPprocess","DLP")
         ("fcagswd.exe","McAfeeDLPAgent","DLP")
         ("fcags.exe","McAfeeDLPAgent","DLP")
         ("firesvc.exe","McAfeeHostIntrusionPrevention","EDR")
         ("HipMgmt.exe","McAfeeHostIntrusionProtection","EDR")
         ("masvc.exe","McAfeeAgent","AV")
         ("mfeann.exe","McAfeeVirusScanEnterprise","AV")
         ("mfemactl.exe","McAfeeVirusScanEnterprise","AV")
         ("MsSense.exe","MicrosoftDefenderATP","EDR")
         ("shstat.exe","McAfeeVirusScanEnterprise","AV")
         ("splunk.exe","Splunk","Logging")
         ("splunkd.exe","Splunk","Logging")
         ("splunk-admon.exe","Splunk","Logging")
         ("splunk-powershell.exe","Splunk","Logging")
         ("splunk-winevtlog.exe","Splunk","Logging")
         ("sysmon.exe","SysinternalsSysmon","Logging")
         ("TaniumClient.exe","Tanium","EDR")
         ("vstskmgr.exe","McAfeeVirusScanEnterprise","AV")
         ]

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
        "DWM-0"
        "DWM-1"
        "DWM-2"
        "DWM-3"
        "DWM-4"
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