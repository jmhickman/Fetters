module Fetters.Lists

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