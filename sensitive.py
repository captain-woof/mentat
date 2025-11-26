from browser import createBrowser, typeTextHuman
from os import path
from time_custom import sleepRandom
from queue import Queue, Empty as ExceptionQueueEmpty
from threading import Lock
from file_custom import sanitizeFilename
from playwright.sync_api import Download
from concurrent.futures import ThreadPoolExecutor, wait
from ssh import SSHProxyManager
import random

# GLOBAL

## Scanner threads started
isGoogleSearchDone = False

## Google Dorks queue (yet to be used)
googleSearchDorks = Queue()

## Search result URLs queue (URLs yet to be scanned)
searchResultUrlsQueue = Queue()

## Print mutex
lockPrint = Lock()

# Function to generate a list of Google search dorks
def generateGoogleSearchDorks(
        companyNames: list[str],
        companyDomains: list[str],
        skipCompanyDomains: bool,
        skipThirdParty: bool
        ) -> list[str]:
    """
    Generates a large list of highly granular Google dorks for deep OSINT.

    This function adopts a granular strategy, creating many simple dorks instead
    of one complex one. This is more effective as it avoids Google's query
    complexity limits and often uncovers more results. Each dork tests for
    one condition (e.g., one filetype or one keyword) on one target site.

    Args:
        companyNames: A list of company names to search for.
        companyDomains: A list of company domains to target.

    Returns:
        A large list of specific, granular dork strings.
    """
    global googleSearchDorks
    if not companyNames and not companyDomains:
        return []

    # Define the component lists for dork generation
    thirdPartySitesTerms = [
        "site:github.com", "site:gist.github.com", "site:gitlab.com", "inurl:gitlab",
        "site:bitbucket.org", "site:pastebin.com", "site:codepen.io", "site:ideone.com",
        "site:trello.com", "site:*.atlassian.net", "site:*.notion.site", "site:scribd.com",
        "site:docs.google.com", "site:drive.google.com", "site:storage.googleapis.com",
        "site:s3.amazonaws.com", "site:blob.core.windows.net", "site:stackoverflow.com"
    ]

    sensitiveFiletypes = [
        "sql", "env", "log", "bak", "config", "ini", "yml", "yaml", "bkf", "bkp", "csv", "json",
        "xls", "xlsx", "mdb", "db", "txt", "conf", "inf", "rdp", "key", "pem", "crt", "pfx",
        "p12", "cer", "asc", "jks", "kdbx", "sh", "ps1", "ovpn", "ppk", "udl", "zip", "tar.gz"
    ]

    credentialKeywords = [
        "password", "secret", "api_key", "apikey", "access_key", "client_secret",
        "auth_token", "credentials", "DB_PASSWORD", "database_connection", "ftp_password",
        "connectionstring", "bearer token", "jwt", "authkey", "private_token",
        "aws_access_key", "aws_secret_key", "Account SID", "ghp_", "xoxp-"
    ]
    
    privateKeyNames = [
        "id_rsa", "id_dsa", "id_ecdsa", "private.key", "privatekey.pem", "server.key",
        "api.key", "key.pem", "cert.pem", "private_key", "service_account.json",
        "BEGIN RSA PRIVATE KEY", "BEGIN PGP PRIVATE KEY BLOCK", "BEGIN OPENSSH PRIVATE KEY"
    ]
    
    confidentialityMarkers = [
        "internal use only", "confidential", "proprietary", "debug information", "stack trace"
    ]

    # These keywords are for finding open server directories
    directoryListingKeywords = [
        "backup", "dump", "db", "admin", "private", "confidential", "keys", 
        "config", ".git", ".env", ".aws"
    ]
    
    # Generate dorks by iterating through every combination

    ## Dorks for searching in company domains and subdomains
    if not skipCompanyDomains:
        for companyDomain in companyDomains:
            for filetype in sensitiveFiletypes:
                googleSearchDorks.put(f'site:*.{companyDomain} filetype:{filetype}')
                googleSearchDorks.put(f'site:{companyDomain} filetype:{filetype}')
            for keyword in credentialKeywords + privateKeyNames + confidentialityMarkers:
                googleSearchDorks.put(f'site:{companyDomain} intext:"{keyword}"')
                googleSearchDorks.put(f'site:*.{companyDomain} intext:"{keyword}"')
            for keyword in directoryListingKeywords:
                googleSearchDorks.put(f'site:{companyDomain} intitle:"index of" intext:"{keyword}"')
                googleSearchDorks.put(f'site:*.{companyDomain} intitle:"index of" intext:"{keyword}"')

    ## Dorks for searching on 3rd party sites
    if not skipThirdParty:
        targetsTerm = "(" + " OR ".join(f'"{kw}"' for kw in (companyNames + companyDomains + [f"@{domain}" for domain in companyDomains])) + ")"
        for thirdPartySiteTerm in thirdPartySitesTerms:
            for filetype in sensitiveFiletypes:
                googleSearchDorks.put(f'{thirdPartySiteTerm} {targetsTerm} filetype:{filetype}')
            for keyword in credentialKeywords + privateKeyNames + confidentialityMarkers + directoryListingKeywords:
                googleSearchDorks.put(f'{thirdPartySiteTerm} {targetsTerm} intext:"{keyword}"')
            for keyword in credentialKeywords + privateKeyNames + confidentialityMarkers + directoryListingKeywords:
                googleSearchDorks.put(f'{thirdPartySiteTerm} intitle:"index of" {targetsTerm} intext:{keyword}"')
            
def handleScanUrlThread(outputPath: str):
    """
    Function for individual scanner thread
    """
    global searchResultUrlsQueue
    global isGoogleSearchDone
    global lockPrint

    with lockPrint:
        print("[+] Sensitive files: Scanner thread started")

    # Initialise browser
    browser = createBrowser(
        downloadsPath=path.join(outputPath, "downloads"),
        userDataDir=path.join(outputPath, "user_data_dir")
        )
    pageScanner = browser.new_page()

    # Setup download handler
    isDownload = False
    def handleDownload(download: Download):
        nonlocal isDownload
        try:
            downloadPath = path.join(outputPath, "downloads", sanitizeFilename(download.suggested_filename))
            download.save_as(downloadPath)
            isDownload = True
            with lockPrint:
                print(f"{download.url} > {downloadPath}")
        except Exception:
            with lockPrint:
                print(f"{download.url} > FAILED")

    pageScanner.on("download", handleDownload)

    # Keep processing URLs
    while not isGoogleSearchDone:
        try:
            searchResultUrl: str = searchResultUrlsQueue.get(timeout=10.0)
            try:
                pageScanner.goto(searchResultUrl, wait_until="domcontentloaded")
                # Take screenshot
                if not isDownload:
                    screenshotPath = path.join(outputPath, "screenshots", f"{sanitizeFilename(searchResultUrl)}.jpg")
                    pageScanner.screenshot(type="jpeg", quality=70, path=screenshotPath)
                    with lockPrint:
                        print(f"{searchResultUrl} > {screenshotPath}")
                else:
                    isDownload = False # reset download flag
            except Exception:
                with lockPrint:
                    print(f"{searchResultUrl} > FAILED")

        except ExceptionQueueEmpty:
            pass
        except Exception:
            pass

    # Close page
    with lockPrint:
        print("[+] Sensitive files: Scanner thread ended")

def gatherThread(
        downloadsPath: str,
        userDataDir: str,
        companyNames: list[str],
        companyDomains: list[str],
        waitBeforePaginationMin: int,
        waitBeforePaginationMax: int,
        proxy: str = None
        ):
    global isGoogleSearchDone
    global searchResultUrlsQueue
    global googleSearchDorks
    global lockPrint

    browser = createBrowser(
        downloadsPath=downloadsPath,
        userDataDir=userDataDir,
        proxy=proxy
        )
    pageGoogle = browser.new_page()

    pageGoogle.goto("https://google.com", wait_until="domcontentloaded")
    pageGoogle.locator(selector='textarea[title="Search"]').click()
    typeTextHuman(locator=pageGoogle.locator(selector='textarea[title="Search"]'), text=(companyNames + companyDomains)[0])
    pageGoogle.locator(selector='textarea[title="Search"]').press("Enter")
    
    # Captcha alert
    attemptsSinceLastCaptcha = 0
    pageGoogle.wait_for_load_state("domcontentloaded")
    pageGoogle.wait_for_load_state("networkidle")
    if len(pageGoogle.get_by_text(text="Our systems have detected unusual traffic from your computer network").all()) != 0:
        input("[+] Sensitive files: CAPTCHA detected! Solve it and press Enter...")
        pageGoogle.wait_for_load_state("domcontentloaded")
        pageGoogle.wait_for_load_state("networkidle")
    
    # Go through dorks
    while True:
        try:
            googleDork = googleSearchDorks.get(block=True, timeout=10.0)
            with lockPrint:
                print(f">> Using Google dork '{googleDork}'")

            # Enter the dork
            pageGoogle.locator(selector='textarea[aria-label="Search"]').click()
            pageGoogle.locator(selector='textarea[aria-label="Search"]').clear()
            typeTextHuman(locator=pageGoogle.locator(selector='textarea[aria-label="Search"]'), text=googleDork)
            pageGoogle.locator(selector='textarea[aria-label="Search"]').press("Enter")

            # Keep scraping results from each page
            while True:
                try:
                    # Captcha alert
                    pageGoogle.wait_for_load_state("domcontentloaded")
                    pageGoogle.wait_for_load_state("networkidle")
                    if len(pageGoogle.get_by_text(text="Our systems have detected unusual traffic from your computer network").all()) != 0:
                        input("[+] Sensitive files: CAPTCHA detected! Solve it and press Enter...")
                        pageGoogle.wait_for_load_state("domcontentloaded")
                        pageGoogle.wait_for_load_state("networkidle")
                        attemptsSinceLastCaptcha = 0
                    attemptsSinceLastCaptcha += 1
                    # Read all individual results and access them
                    resultsHeadings = pageGoogle.locator("h3").all()
                    for resultHeading in resultsHeadings:
                        searchResultUrl = resultHeading.locator("..").get_attribute("href")
                        resultHeading.scroll_into_view_if_needed()
                        # resultHeading.hover()
                        searchResultUrlsQueue.put(searchResultUrl)
                        with lockPrint:
                            print(f">> FOUND '{searchResultUrl}'")
                    # If it has been long since last Captcha
                    if attemptsSinceLastCaptcha % 7 == 0:
                        # Sleep some
                        print("[..] Sleeping to evade Captcha, be patient...")
                        sleepRandom(max(waitBeforePaginationMin * 3, 90.0), max(waitBeforePaginationMax * 3, 120.0))
                        # Do some junk human search
                        url = pageGoogle.url
                        for junkSearchTerm in random.choices(
                            [
                            "nvidia stock price",
                            "apple stock price",
                            "how to invest in stocks""best laptop deals",
                            "how to make cold brew",
                            "fun facts about space",
                            "why cats purr",
                            "easy dinner ideas",
                            "latest tech news",
                            "how rainbows form",
                            "cheap weekend trips",
                            "python list tutorial",
                            "is coffee good for you",
                            "fast workout routines",
                            "beginner guitar songs",
                            "how to stay focused",
                            "famous historical myths",
                            "what is cloud computing",
                            "how to spot fake reviews",
                            "movie recommendations 2025",
                            "why we procrastinate",
                            "best free learning websites",
                            "how to improve memory"
                            ],
                            k=3
                        ):
                            pageGoogle.locator(selector='textarea[aria-label="Search"]').click()
                            pageGoogle.locator(selector='textarea[aria-label="Search"]').clear()
                            typeTextHuman(locator=pageGoogle.locator(selector='textarea[aria-label="Search"]'), text=junkSearchTerm)
                            pageGoogle.locator(selector='textarea[aria-label="Search"]').press("Enter")
                            pageGoogle.mouse.wheel(delta_y=float(random.randint(50, 200)))
                            sleepRandom(max(waitBeforePaginationMin, 30.0), max(waitBeforePaginationMax, 45.0))
                            if pageGoogle.go_back(timeout=0, wait_until="domcontentloaded") is None:
                                pageGoogle.goto(url=url, timeout=0, wait_until="domcontentloaded")
                    # Click next button
                    nextButton = pageGoogle.locator("a", has_text="Next").all()
                    if len(nextButton) == 0:
                        break
                    else:
                        if waitBeforePaginationMin > 0 or waitBeforePaginationMax > 0:
                            sleepRandom(waitBeforePaginationMin, waitBeforePaginationMax)
                        nextButton = nextButton[0].locator("..")
                        nextButton.hover()
                        nextButton.click()
                except:
                    break
            # Sleep before going to next dork
            if waitBeforePaginationMin > 0 or waitBeforePaginationMax > 0:
                sleepRandom(waitBeforePaginationMin, waitBeforePaginationMax)
        except ExceptionQueueEmpty:
            break

def gather(
        companyNames: list[str],
        companyDomains: list[str],
        outputPath: str,
        waitBeforePaginationMin: float,
        waitBeforePaginationMax: float,
        sshLogins: list[str] = [],
        sshLoginsKey: str = "",
        skipCompanyDomains: bool = False,
        skipThirdParty: bool = False
    ):
    """
    This function does the actual searching and coordinating
    """
    global isGoogleSearchDone
    global searchResultUrlsQueue
    global googleSearchDorks

    try:
        # Setup SSH proxies if needed
        socksProxies = []
        if len(sshLogins) != 0:
            ssh_configs = [
                {
                    "username": sshLogin.split("@")[0],
                    "private_key_path": sshLoginsKey,
                    "ip": sshLogin.split("@")[1]
                } for sshLogin in sshLogins
            ]

            sshProxyManager = SSHProxyManager(ssh_configs=ssh_configs)
            sshProxyManager.start_tunnels()
            sshProxyManager.test_tunnels()

            socksProxies = sshProxyManager.proxies
        
        # Generate Google dorks; special thanks to Google AI studio ;)
        generateGoogleSearchDorks(
            companyNames=companyNames,
            companyDomains=companyDomains,
            skipCompanyDomains=skipCompanyDomains,
            skipThirdParty=skipThirdParty
            )
        print(f"[+] Sensitive files: {googleSearchDorks.unfinished_tasks} Google dorks generated")
        
        # Start Google-handling threads + Scanner thread
        print("[+] Sensitive files: Opening browser(s)...")
        with ThreadPoolExecutor(max_workers=max(1, len(socksProxies)) + 1) as threadPoolExecutor:
            tasks = []

            # Start scanner thread
            print(f"[+] Sensitive files: Starting scanner thread...")
            threadPoolExecutor.submit(
                handleScanUrlThread,
                outputPath
            )

            # Start Google-threads
            print(f"[+] Sensitive files: Starting search on Google...")
            if len(socksProxies) == 0:
                tasks.append(
                    threadPoolExecutor.submit(
                        gatherThread,
                        path.join(outputPath, "downloads"),
                        path.join(outputPath, "user_data_dir"),
                        companyNames,
                        companyDomains,
                        waitBeforePaginationMin,
                        waitBeforePaginationMax
                    )
                )
            else:
                for socksProxy in socksProxies:
                    tasks.append(
                        threadPoolExecutor.submit(
                            gatherThread,
                            path.join(outputPath, "downloads"),
                            path.join(outputPath, "user_data_dir"),
                            companyNames,
                            companyDomains,
                            waitBeforePaginationMin,
                            waitBeforePaginationMax,
                            socksProxy
                        )
                )
                    
            wait(tasks)

            isGoogleSearchDone = True
            print(f"[+] Sensitive files: Waiting for scanner thread to close...")

            if len(socksProxies) != 0:
                sshProxyManager.stop_tunnels()
    except Exception as e:
        print(e)
