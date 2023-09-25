import time
import platform
from webdriver_manager.firefox import GeckoDriverManager
from selenium import webdriver

def test_app_config(link):
    firefox_options = webdriver.FirefoxOptions()
    firefox_options.add_argument("--headless")

    driver = webdriver.Firefox(
        executable_path=GeckoDriverManager().install(),
        options=firefox_options
    )
    driver.get(link)
    time.sleep(2) 

    good = True

    if not "https://login.live.com" in driver.current_url or "<h2>We're unable to complete your request</h2>" in driver.page_source:
        good = False

    driver.quit()
    return good
