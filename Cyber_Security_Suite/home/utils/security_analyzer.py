import requests
from bs4 import BeautifulSoup

def xss_scan(url):
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        scripts = soup.find_all('script')
        inline_js = [script for script in scripts if script.string]
        
        results = {
            "url": url,
            "status": "Completed",
            "potential_xss": len(inline_js) > 0,
            "inline_scripts": len(inline_js)
        }
        
        return results
    except Exception as e:
        return {"error": str(e)}

