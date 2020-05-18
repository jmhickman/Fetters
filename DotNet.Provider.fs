module Fetters.DotNet.Provider

    open System
    open Fetters.DomainTypes
    open Fetters.DotNet.Common
    //open Fetters.Registry.Provider
    open Fetters.WMI.Provider


    let extractChromeHistory (path: string) : ChromeHistory =
        let cPath = path + "\\" + "AppData\\Local\\Google\\Chrome\\User Data\\Default\\History"
        match fileExistsAtLocation cPath with
        |true ->
            let rgx = createMatchRegex @"(http|ftp|https|file)://([\w_-]+(?:(?:\.[\w_-]+)+))([\w.,@?^=%&:/~+#-]*[\w@?^=%&/~+#-]\s)?"
            let res = yieldLineSequence cPath  |> Seq.map (matchStringRegex rgx) |> Seq.toList |> List.filter(fun l -> not(l = ""))
            {path = path; url = res}

        |false -> {path = ""; url = []}


    let extractChromeBookmarks (path: string) : ChromeBookmark list =
        let cPath = path + "\\" + "AppData\\Local\\Google\\Chrome\\User Data\\Default\\Bookmarks"
        match fileExistsAtLocation cPath with
        |true -> let bookmarks = ChromeBookmarkJ.Parse(yieldWholeFile cPath)
                 bookmarks.Roots.BookmarkBar.Children 
                 |> Array.map(fun b -> {name = b.Name; url = b.Url})
                 |> Array.toList
        |false -> []


    let triageChrome (path: string) : ChromeInfo =
        let b = extractChromeBookmarks path
        let h = extractChromeHistory path
        {bookmarks = b; history = h}
        
    
    let getFirefoxProfiles (path: string) =
        let cPath = path + "\\" + "AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\"
        match dirExistsAtLocation cPath with
        |true -> let dirs = listChildDirectories cPath
                 dirs 
                 |> Array.map (fun d -> d + "\\places.sqlite")
                 |> Array.filter(fun d -> fileExistsAtLocation d)
        |false -> [||]


    let extractFirefoxHistory (path: string) : FirefoxHistory =
        match fileExistsAtLocation path with //Leaving the check because whatever
        |true ->
            printfn "True path"
            let rgx = createMatchRegex @"(http|ftp|https|file)://([\w_-]+(?:(?:\.[\w_-]+)+))([\w.,@?^=%&:/~+#-]*[\w@?^=%&/~+#-]\s)?"
            let res = yieldLineSequence path  |> Seq.map (matchStringRegex rgx) |> Seq.toList |> List.filter(fun l -> not(l = ""))
            {path = path; url = res}

        |false -> {path = ""; url = []}