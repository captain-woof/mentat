from browser import createBrowser, typeTextHuman
from os import path
from time_custom import sleepRandom
from queue import Queue, Empty as ExceptionQueueEmpty
from threading import Thread, Lock
from file_custom import sanitizeFilename
from playwright.sync_api import Download
import random

# GLOBAL

## Scanner threads started
isGoogleSearchDone = False

## Search result URLs queue (URLs yet to be scanned)
searchResultUrlsQueue = Queue()

## Print mutex
lockPrint = Lock()

# Function to generate a list of Google search dorks
def generateGoogleSearchDorks(companyNames: list[str], companyDomains: list[str]) -> list[str]:
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
    generatedDorks = []    

    ## Dorks for searching in company domains and subdomains
    for companyDomain in companyDomains:
        for filetype in sensitiveFiletypes:
            generatedDorks.append(f'site:*.{companyDomain} filetype:{filetype}')
            generatedDorks.append(f'site:{companyDomain} filetype:{filetype}')
        for keyword in credentialKeywords + privateKeyNames + confidentialityMarkers:
            generatedDorks.append(f'site:{companyDomain} intext:"{keyword}"')
            generatedDorks.append(f'site:*.{companyDomain} intext:"{keyword}"')
        for keyword in directoryListingKeywords:
            generatedDorks.append(f'site:{companyDomain} intitle:"index of" intext:"{keyword}"')
            generatedDorks.append(f'site:*.{companyDomain} intitle:"index of" intext:"{keyword}"')

    ## Dorks for searching on 3rd party sites
    targetsTerm = "(" + " OR ".join(f'"{kw}"' for kw in (companyNames + companyDomains + [f"@{domain}" for domain in companyDomains])) + ")"
    for thirdPartySiteTerm in thirdPartySitesTerms:
        for filetype in sensitiveFiletypes:
            generatedDorks.append(f'{thirdPartySiteTerm} {targetsTerm} filetype:{filetype}')
        for keyword in credentialKeywords + privateKeyNames + confidentialityMarkers + directoryListingKeywords:
            generatedDorks.append(f'{thirdPartySiteTerm} {targetsTerm} intext:"{keyword}"')
        for keyword in credentialKeywords + privateKeyNames + confidentialityMarkers + directoryListingKeywords:
            generatedDorks.append(f'{thirdPartySiteTerm} intitle:"index of" {targetsTerm} intext:{keyword}"')
            
    return generatedDorks

def handleScanUrlThread(outputPath: str):
    """
    Function for individual scanner thread
    """
    global searchResultUrlsQueue
    global isGoogleSearchDone

    with lockPrint:
        print("[+] Sensitive files: Scanner thread started")

    # Initialise browser
    browser = createBrowser(downloadsPath=path.join(outputPath, "downloads"))
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
            searchResultUrl: str = searchResultUrlsQueue.get(timeout=10)
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

def gather(companyNames: list[str], companyDomains: list[str], outputPath: str, waitBeforePaginationMin: float, waitBeforePaginationMax: float):
    """
    This function does the actual searching and coordinating
    """
    global isGoogleSearchDone

    try:
        # Generate Google dorks; special thanks to Google AI studio ;)
        googleSearchDorks = generateGoogleSearchDorks(companyNames=companyNames, companyDomains=companyDomains)
        print(f"[+] Sensitive files: {len(googleSearchDorks)} Google dorks generated")

        # Start browser and Google search page
        print("[+] Sensitive files: Opening google.com in a browser...")
        browser = createBrowser(downloadsPath=path.join(outputPath, "downloads"))
        pageGoogle = browser.new_page()

        # Create scanner threads list
        print(f"[+] Sensitive files: Starting scanner thread...")
        scannerThreads: list[Thread] = []
        for _ in range(0, 1):
            thread = Thread(
                target=handleScanUrlThread,
                kwargs={
                    'outputPath': outputPath,
                    }
                )
            thread.start()
            scannerThreads.append(thread)

        # Search on Google
        with lockPrint:
            print(f"[+] Sensitive files: Starting search on Google...")

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

        for googleDork in googleSearchDorks:
            with lockPrint:
                print(f">> Using Google dork '{googleDork}'")

            # Enter the dork
            pageGoogle.locator(selector='textarea[aria-label="Search"]').click()
            pageGoogle.locator(selector='textarea[aria-label="Search"]').clear()
            typeTextHuman(locator=pageGoogle.locator(selector='textarea[aria-label="Search"]'), text=googleDork)
            pageGoogle.locator(selector='textarea[aria-label="Search"]').press("Enter")

            pageGoogle.go_back(timeout=0, wait_until="domcontentloaded") # TODO: REMOVE

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
                        resultHeading.hover()
                        searchResultUrlsQueue.put(searchResultUrl)
                        with lockPrint:
                            print(f">> FOUND '{searchResultUrl}'")

                    # If it has been long since last Captcha
                    if attemptsSinceLastCaptcha % 7 == 0:
                        # Sleep some
                        sleepRandom(max(waitBeforePaginationMin * 3, 10.0), max(waitBeforePaginationMax * 3, 15.0))

                        # Do some junk human search
                        url = pageGoogle.url
                        pageGoogle.locator(selector='textarea[aria-label="Search"]').click()
                        pageGoogle.locator(selector='textarea[aria-label="Search"]').clear()
                        typeTextHuman(locator=pageGoogle.locator(selector='textarea[aria-label="Search"]'), text=random.choice(companyNames + companyDomains))
                        pageGoogle.locator(selector='textarea[aria-label="Search"]').press("Enter")
                        sleepRandom(max(waitBeforePaginationMin, 6.0), max(waitBeforePaginationMax, 10.0))
                        if pageGoogle.go_back(timeout=0, wait_until="domcontentloaded") is None:
                            pageGoogle.goto(url=url, timeout=0, wait_until="domcontentloaded")

                    # Click next button
                    nextButton = pageGoogle.locator("a", has_text="Next").all()
                    if len(nextButton) == 0:
                        break
                    else:
                        nextButton = nextButton[0].locator("..")
                        nextButton.scroll_into_view_if_needed()
                        nextButton.hover()
                        if waitBeforePaginationMin > 0 or waitBeforePaginationMax > 0:
                            sleepRandom(waitBeforePaginationMin, waitBeforePaginationMax)
                        nextButton.click()
                except:
                    break

            # Sleep before going to next dork
            if waitBeforePaginationMin > 0 or waitBeforePaginationMax > 0:
                sleepRandom(waitBeforePaginationMin, waitBeforePaginationMax)

        isGoogleSearchDone = True
        # Wait for Scanner threads
        with lockPrint:
            print(f"[+] Sensitive files: Waiting for all scanner thread to close...")
        for scannerThread in scannerThreads:
            scannerThread.join()
    except Exception as e:
        print(e)
