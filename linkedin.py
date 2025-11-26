from browser import createBrowser, typeTextHuman
from os import path, mkdir
from time_custom import sleepRandom
from csv_custom import sanitiseForCsv
from ssh import SSHProxyManager
import random

# Globals
tooManyReqs = False

# Data to save
csvDataList = [
    "email,username,name,hashed_password,password,ip_address,address,phone,vin,license_plate,company,url,social,cryptocurrency_address,domain,database_name"
]

# Gather information from LinkedIn
def gather(
        companyNames: list[str],
        companyDomains: list[str],
        outputPath: str,
        waitBeforePaginationMin: float,
        waitBeforePaginationMax: float,
        sshLogins: list[str] = [],
        sshLoginsKey: str = ""
        ):
    global tooManyReqs
    global csvDataList

    attemptsSinceLastCaptcha = 0

    # Setup SSH proxies if needed
    sshProxyManager = None
    if len(sshLogins) != 0:
        sshLoginUsername, sshLoginIp = random.choice(sshLogins).split("@")
        ssh_config = {
                "username": sshLoginUsername,
                "private_key_path": sshLoginsKey,
                "ip": sshLoginIp
            }
        sshProxyManager = SSHProxyManager(ssh_configs=[ssh_config])
        sshProxyManager.start_tunnels()
        sshProxyManager.test_tunnels()

    # Search on LinkedIn
    print("[+] LinkedIn: Starting browser...")
    browser = createBrowser(
        downloadsPath=path.join(outputPath, "downloads"),
        userDataDir=path.join(outputPath, "user_data_dir"),
        proxy=None if sshProxyManager is None else sshProxyManager.proxies[0]
        )
    page = browser.new_page()

    page.goto("https://google.com", wait_until="domcontentloaded")
    page.locator(selector='textarea[title="Search"]').click()
    typeTextHuman(locator=page.locator(selector='textarea[title="Search"]'), text=(random.choice(companyNames + companyDomains)))
    page.locator(selector='textarea[title="Search"]').press("Enter")
    
    page.wait_for_load_state("domcontentloaded")
    page.wait_for_load_state("networkidle")
    if len(page.get_by_text(text="Our systems have detected unusual traffic from your computer network").all()) != 0:
        input("[+] Sensitive files: CAPTCHA detected! Solve it and press Enter...")
        page.wait_for_load_state("domcontentloaded")
        page.wait_for_load_state("networkidle")
        
    # Search on Google
    for companyName in companyNames:
        print(f"[+] LinkedIn: Searching for '{companyName}' employees on Google...")
        googleDork = f"(site:linkedin.com/in OR site:linkedin.com/pub) intitle:\"{companyName}\""
        page.locator(selector='textarea[aria-label="Search"]').click()
        page.locator(selector='textarea[aria-label="Search"]').clear()
        typeTextHuman(locator=page.locator(selector='textarea[aria-label="Search"]'), text=googleDork)
        page.locator(selector='textarea[aria-label="Search"]').press("Enter")
        
        # Keep scraping results
        while True:
            try:
                # Captcha alert
                page.wait_for_load_state("domcontentloaded")
                page.wait_for_load_state("networkidle")
                if len(page.get_by_text(text="Our systems have detected unusual traffic from your computer network").all()) != 0:
                    input("[+] LinkedIn: CAPTCHA detected! Solve it and press Enter...")
                    page.wait_for_load_state("domcontentloaded")
                    page.wait_for_load_state("networkidle")
                    attemptsSinceLastCaptcha = 0
                attemptsSinceLastCaptcha += 1

                # Read all individual results
                resultsHeadings = page.locator("h3").all()
                for resultHeading in resultsHeadings:
                    heading = resultHeading.inner_text()
                    headingHyphenIndex = heading.find("-")

                    resultHeading.hover(force=True)

                    if headingHyphenIndex != -1:
                        fullName = heading[:headingHyphenIndex].strip()
                        url = resultHeading.locator("..").get_attribute("href")
                        address = ""

                        dataDivs = resultHeading.locator("..").locator("..").locator("..").locator("..").locator("..").locator("..").locator("> div").all()
                        if len(dataDivs) >= 2:
                            addressEle = (dataDivs[1].locator("> div").all())[0]
                            if "·" in addressEle.text_content():
                                address = addressEle.text_content().split("·")[0].strip()

                        csvData = f",{url.split("/")[-1]},{sanitiseForCsv(fullName)},,,,{sanitiseForCsv(address)},,,,{sanitiseForCsv(companyName)},{url},{url},,,linkedin-from-google"
                        csvDataList.append(csvData)
                        print(csvData)

                # Sleep if it has been long since last Captcha
                if attemptsSinceLastCaptcha % 7 == 0:
                    sleepRandom(max(waitBeforePaginationMin * 3, 10.0), max(waitBeforePaginationMax * 3, 15.0))

                # Click next button
                nextButton = page.locator("a", has_text="Next").all()
                if len(nextButton) == 0:
                    break
                else:
                    sleepRandom(waitBeforePaginationMin, waitBeforePaginationMax)
                    nextButton = nextButton[0].locator("..")
                    nextButton.hover(force=True)
                    nextButton.click()
            except:
                break
                
    # Save results
    if len(csvDataList) > 1:
        try:
            mkdir(outputPath)
        except FileExistsError:
            pass

        fileSavePath = path.join(outputPath, "data_linkedin.csv")
        with open(fileSavePath, "w") as file:
            file.write("\n".join(csvDataList))
            print(f"[+] LinkedIn: Results for '{companyName}' saved in '{fileSavePath}'")

    # Stop SOCKS proxies
    if len(sshLogins) != 0 and sshProxyManager is not None:
        sshProxyManager.stop_tunnels()
