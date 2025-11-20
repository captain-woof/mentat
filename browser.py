from playwright.sync_api import Browser, Locator
from camoufox.sync_api import Camoufox
from browserforge.fingerprints import Screen
import random
import string
from time_custom import sleepRandom

def createBrowser(downloadsPath: str, proxy: str = None):
    try:
        contextManager = Camoufox(
            config={
                "mediaDevices:enabled": True,
                "pdfViewerEnabled": True
            },
            os=["linux", "windows", "macos"],
            screen=Screen(max_width=800, max_height=600),
            humanize=1.73,
            headless=False,
            locale="en-US",
            downloads_path=downloadsPath,
            proxy={
                'server': proxy,
                #'username': 'username',
                #'password': 'password'
            } if proxy not in [None, [], ""] else None,
            geoip=True,
        )
        browser: Browser = contextManager.start()

        return browser
    except Exception as e:
        print(e)
        return None

def typeTextHuman(locator: Locator, text: str):
    for char in text:
        if random.random() < 0.05:
            numWrongChars = random.randint(1,3)
            wrongStr = "".join([random.choice(string.ascii_lowercase) for _ in range(0, numWrongChars)])
            for wrongChar in wrongStr:
                locator.type(text=wrongChar, delay=(100.0 + (20.0 * random.random())), timeout=0)
            sleepRandom(0.1, 0.5)
            for _ in range(0, numWrongChars):
                locator.press(key="Backspace", timeout=0)
        locator.type(text=char, delay=(100.0 + (20.0 * random.random())), timeout=0)