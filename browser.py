from playwright.sync_api import Playwright, BrowserContext

def createBrowser(p: Playwright, downloadsPath: str):
    browser = p.firefox.launch(
        downloads_path=downloadsPath,
        headless=False
    )
    context: BrowserContext = browser.new_context(
        accept_downloads=True,
        color_scheme="dark",
        geolocation={"latitude": 30.229633483214656, "longitude": -97.74997700334794},
        permissions=["geolocation"],
        has_touch=False,
        is_mobile=False,
        java_script_enabled=True,
        user_agent="",
        screen={
          "width": 1920,
          "height": 1080
        },
        viewport={
          "width": 1280,
          "height": 720
        },
        locale="en-US",
        timezone_id="America/Chicago",
        default_browser_type="firefox",
        device_scale_factor=1.0
    )
    
    return context