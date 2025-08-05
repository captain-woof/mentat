from browser import createBrowser
from playwright.sync_api import Response
from browser import createBrowser
from os import environ, path, mkdir
import time
from time_custom import sleepRandom
from csv_custom import sanitiseForCsv

# Global flags
tooManyReqs = False

# Data to save
csvDataList = [
    "email,username,name,hashed_password,password,ip_address,address,phone,vin,license_plate,company,url,social,cryptocurrency_address,domain,database_name"
]

# Process responses from DeHashed API responses
def processResponse(response: Response):
    global tooManyReqs
    global csvDataList

    # Capture data
    if response.url == "https://web-api.dehashed.com/search":
        try:
            # If "Too many requests"
            if response.status == 429 or response.status_text.lower() == "too many requests" or response.text() == "too many requests":
                tooManyReqs = True
            elif response.status == 200:
                tooManyReqs = False

                keys = csvDataList[0].split(",")
                for entry in (response.json())["results"]:
                    entryCsvList = []
                    for key in keys:
                        value = entry.get(key, "")

                        if type(value) == list: # If value is a list
                            if len(value) == 1: # Store the only present entry
                                entryCsvList.append(sanitiseForCsv(value[0]))
                            else:
                                if key in ["password","hashed_password"]: # Store all entries
                                    entryCsvList.append(sanitiseForCsv("/".join(value)))
                                else: # Store longest entry
                                    individualLengths = []
                                    for v in value:
                                        individualLengths.append(len(v))
                                    for v in value:
                                        if len(v) == max(individualLengths):
                                            entryCsvList.append(sanitiseForCsv(v))
                                            break
                        else: # If value is singular
                            entryCsvList.append(sanitiseForCsv(value))

                    entryCsv = ",".join(entryCsvList)     
                    csvDataList.append(entryCsv)
                    print(entryCsv)

        except:
            pass

# Gather information from DeHashed
def gather(companyNames: list[str], companyDomain: list[str], outputPath: str):
    global tooManyReqs
    global csvDataList

    # Search on DeHashed
    print("[+] DeHashed: Starting browser...")
    (_,_,_,context) = createBrowser(downloadsPath=path.join(outputPath, "downloads"))
    page = context.new_page()
    page.on("response", processResponse) # This will capture all responses
    
    # Login
    print("[+] DeHashed: Logging in...")
    page.goto("https://app.dehashed.com/login")
    
    emailField = page.get_by_placeholder("Email")
    passwordField = page.get_by_placeholder("Password")
    emailField.fill(environ["DEHASHED_EMAIL"])
    passwordField.fill(environ["DEHASHED_PASSWORD"])
    page.get_by_role("button", name="Log In").click()
    
    # Search using company domains
    for domain in companyDomain:
        # Do "Domain" search
        page.get_by_role("button", name="Domain Scan").click()
        searchBar = page.get_by_placeholder("Search")
        searchBar.fill(domain)
        page.get_by_role("button", name="Find").click()
        page.wait_for_selector("button.paginator-button", state="visible")
        isEllipsisPresent = "..." in page.locator("div.paginator").inner_text()
        totalPagesNum = int((page.locator("button.paginator-button").all())[-2 if isEllipsisPresent else -1].inner_text())
        
        # Start reading page-by-page
        for currentPageNum in range(1, totalPagesNum):                
            # Go to next page
            if currentPageNum != totalPagesNum - 1:
                if len(page.locator("button.paginator-button").all()) == 0:
                    break
                if isEllipsisPresent:
                    (page.locator("button.paginator-button").all())[-1].click()
                else:
                    (page.locator("button.paginator-button").all())[currentPageNum].click()
                page.wait_for_event("response") # Response is handled in the 'response' event handler
                sleepRandom(2, 5)
                if tooManyReqs:
                    while tooManyReqs:
                        sleepRandom(10, 15)
                        if isEllipsisPresent:
                            (page.locator("button.paginator-button").all())[-1].click()
                        else:
                            (page.locator("button.paginator-button").all())[currentPageNum].click()
                        page.wait_for_event("response") # Response is handled in the 'response' event handler
    
    # Search using company names
    for name in companyNames:
        pass
    
    # Save all data
    try:
        mkdir(outputPath)
    except FileExistsError:
        pass

    outputFilePath = path.join(outputPath, "data_dehashed.csv")
    with open(outputFilePath, "w") as dehashedFile:
        dehashedFile.write("\n".join(csvDataList))
        print(f"[+] DeHashed: Results stored in '{outputFilePath}'")
    
    # Logout
    print("[+] DeHashed: Logging out")
    page.goto("https://app.dehashed.com/logout")
    page.wait_for_timeout(10000)
    page.close()