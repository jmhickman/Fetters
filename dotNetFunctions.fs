module Fetters.dotNetFunctions
// Common functionality in pure .net code.

    open System
    open System.Security.Principal

    let getCurrentRole (role: WindowsBuiltInRole) = 
    // Ask Windows about the role of the user who owns the Fetters process.
    // This is linked to the privileges on the token, not necessarily the literal groups
    // the user is in. An administrative user will still come back False if their token
    // is not elevated, so be aware of the difference.

        let currentUser = WindowsPrincipal(WindowsIdentity.GetCurrent())
        currentUser.IsInRole(role)

