import re

def parse_user_agent(user_agent):
    patterns = re.compile(
        r"(?P<os>"
        r"Windows NT 10\.0|Windows NT 6\.3|Windows NT 6\.2|Windows NT 6\.1|"
        r"Windows NT 6\.0|Windows NT 5\.1|Windows NT 5\.0|Mac OS X \d+[._]\d+[._]?\d*|"
        r"iPhone OS \d+[._]\d+|iPad.*OS \d+[._]\d+|Android \d+\.\d+|Linux|CrOS|"
        r"Windows Phone \d+\.\d+|SymbianOS/\d+\.\d+|BlackBerry|BB10|Tizen/\d+\.\d+|KaiOS/\d+\.\d+)"
        r"|(?P<browser>"
        r"MSIE \d+\.\d+|Trident/.*rv:\d+\.\d+|Edge/\d+\.\d+|Edg/\d+\.\d+|Firefox/\d+\.\d+|"
        r"Chrome/\d+\.\d+|OPR/\d+\.\d+|Version/\d+\.\d+ .*Safari/|Opera/\d+\.\d+|CriOS/\d+\.\d+|"
        r"FxiOS/\d+\.\d+|SamsungBrowser/\d+\.\d+|UCBrowser/\d+\.\d+|YaBrowser/\d+\.\d+|"
        r"Vivaldi/\d+\.\d+|Seamonkey/\d+\.\d+|Silk/\d+\.\d+|Puffin/\d+\.\d+|BaiduBrowser/\d+\.\d+|"
        r"QQBrowser/\d+\.\d+|SogouMobileBrowser/\d+\.\d+|MiuiBrowser/\d+\.\d+)"
        r"|(?P<device>"
        r"iPhone|iPad|iPod|Android.*Mobile|Android|Windows Phone|Windows NT|Macintosh|CrOS|Linux|"
        r"Nokia|BlackBerry|BB10|PlayStation \d+|Xbox One|Xbox|Nintendo Switch|Nintendo 3DS|"
        r"Nintendo WiiU|Nintendo Wii|Sony Bravia|SmartTV|Valve Steam|OculusBrowser|"
        r"HTC.*VR|Sony.*VR|Lenovo.*VR)"
    )

    match = patterns.search(user_agent)
    if not match:
        return "Unknown Device, Unknown OS, Unknown Browser"

    os_info = match.group("os") or "Unknown OS"
    browser_info = match.group("browser") or "Unknown Browser"
    device_info = match.group("device") or "Unknown Device"

    os_info = os_info.replace("_", ".")
    return f"{device_info}, {os_info}, {browser_info}"
