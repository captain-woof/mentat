from argparse import ArgumentParser
from os import path, environ
from browser import createBrowser
from playwright.sync_api import sync_playwright
import dotenv

# Load env vars
dotenv.load_dotenv()


if __name__ == "__main__":
    # Parse arguments
    parser = ArgumentParser()

    parser.add_argument("--company-name", action="append", help="Name of the company; can use multiple")
    parser.add_argument("--company-domain", action="append", help="Domain of the company; can use multiple")
    parser.add_argument("--downloads-path", action="store", help="Directory to store download files in; default: ./downloads", default=path.join(path.curdir, "downloads"))

    args = parser.parse_args()
    companyName = args.company_name
    companyDomain = args.company_domain
    downloadsPath = args.downloads_path

    # Search on DeHashed
    with sync_playwright() as p:
        context = createBrowser(p, downloadsPath=downloadsPath)
        page = context.new_page()

        # Login
        page.goto("https://app.dehashed.com/login")
        
        emailField = page.get_by_placeholder("Email")
        passwordField = page.get_by_placeholder("Password")
        emailField.fill(environ["DEHASHED_EMAIL"])
        passwordField.fill(environ["DEHASHED_PASSWORD"])
        page.get_by_role("button", name="Log In").click()
        
        page.wait_for_timeout(10000)
        #page.close()