from browser import createBrowser
from os import path, mkdir
import urllib
from time_custom import sleepRandom
from csv_custom import sanitiseForCsv

# Globals
tooManyReqs = False

# Data to save
csvDataList = [
    "email,username,name,hashed_password,password,ip_address,address,phone,vin,license_plate,company,url,social,cryptocurrency_address,domain,database_name"
]

# Gather information from LinkedIn
def gather(companyNames: list[str], companyDomains: list[str], outputPath: str, waitBeforePaginationMin: float, waitBeforePaginationMax: float):
    global tooManyReqs
    global csvDataList

    attemptsSinceLastCaptcha = 0

    # Search on LinkedIn
    print("[+] LinkedIn: Starting browser...")
    browser = createBrowser(downloadsPath=path.join(outputPath, "downloads"))
    page = browser.new_page()
        
    # Search on Google
    for companyName in companyNames:
        print(f"[+] LinkedIn: Searching for '{companyName}' employees on Google...")
        googleDork = urllib.parse.quote_plus(f"(site:linkedin.com/in OR site:linkedin.com/pub) intitle:\"{companyName}\"")
        page.goto(f"https://www.google.com/search?q={googleDork}")
        
        # Keep scraping results
        while True:
            try:
                # Captcha alert
                page.wait_for_load_state("networkidle")
                if len(page.get_by_text(text="Our systems have detected unusual traffic from your computer network").all()) != 0:
                    input("[+] LinkedIn: CAPTCHA detected! Solve it and press Enter...")
                    page.wait_for_load_state("networkidle")
                    attemptsSinceLastCaptcha = 0
                attemptsSinceLastCaptcha += 1

                # Read all individual results
                resultsHeadings = page.locator("h3").all()
                for resultHeading in resultsHeadings:
                    resultHeading.scroll_into_view_if_needed()
                    resultHeading.hover()

                    heading = resultHeading.inner_text()
                    headingHyphenIndex = heading.find("-")
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
                    nextButton = nextButton[0].locator("..")
                    nextButton.scroll_into_view_if_needed()
                    nextButton.hover()
                    sleepRandom(3.0, 5.0)
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
