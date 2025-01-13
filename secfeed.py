# secfeed by Sharon Brizinov 2023
import random
import logging
import requests
import time
import pickle
import re
import sys
import json
from pprint import pprint
from rocketchat_API.rocketchat import RocketChat


DB_PATH = "secfeed.db"
LIST_PARSED_DATA = []
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36"
HEADERS = {"User-Agent": USER_AGENT}

# Set the webhook URL
webhook_url = "https://your-rocketchat-webhook-url.com"

SEC_FEEDS = {
         # Example:
         # "URL TO QUERY TO GET LINKS" : 
         #    ("BASE ADDRESS",
         #    r"EXTRACT WITH REGEX AND APPEND TO BASE ADDRESS",
         #    ["LIST", "OF", "KEYWORDS", "THAT AT LEAST", ONE", "MUST", "EXISTS", "IN", "URL"]),

        # https://claroty.com/team82/research/
       	"https://claroty.com/team82/research/":
            ("https://claroty.com/team82/research/",
            r"href=\"/team82/research/([^\"]+)\"",
            None),

        # https://www.cisa.gov/news-events/cybersecurity-advisories
        "https://www.cisa.gov/news-events/cybersecurity-advisories" : 
            ("https://www.cisa.gov/",
            r"<a href=\"/(news-events/ics-medical-advisories/icsma-\d+-\d+-\d+)\" target=\"_self\">",
            None),

        # https://www.cisa.gov/news-events/cybersecurity-advisories
        "https://www.cisa.gov/news-events/cybersecurity-advisories/" : 
            ("https://www.cisa.gov/",
            r"<a href=\"/(news-events/ics-advisories/icsa-\d+-\d+-\d+)\" target=\"_self\">",
            None),

        # https://cert.europa.eu/static/SecurityAdvisories/2022/CERT-EU-SA2022-082.pdf
        "https://cert.europa.eu/publications/security-advisories/" :
            ("https://cert.europa.eu/static/SecurityAdvisories/",
            r"(\d+/CERT-EU-SA\d+-\d+\.pdf)", 
            None),

        # https://www.tenable.com/security/research/tra-2020-34
        "https://www.tenable.com/security/research" : 
             ("https://www.tenable.com/security/research/tra-",
             r"/security/research/tra-(\d+\-\d+)",
             None), 

        # https://srcincite.io/blog/
        "https://srcincite.io/blog/":
            ("https://srcincite.io/blog/",
            r"<a class=\"post-link\" href=\"/blog/(\d+/\d+/\d+/[^\"]+)\">",
            None),

        # https://doar-e.github.io/index.html
        "https://doar-e.github.io/index.html":
            ("https://doar-e.github.io/blog/",
            r"\"\./blog/(\d+/\d+/\d+/[^\"]+)\">",
            None),

        # https://www.zerodayinitiative.com/advisories/ZDI-20-683/
        "https://www.zerodayinitiative.com/advisories/published" :
             ("https://www.zerodayinitiative.com/advisories/ZDI-",
             r"ZDI-(\d+\-\d+)",
             None), 

        # https://chemical-facility-security-news.blogspot.com/2020/05/public-ics-disclosures-week-of-5-23-20.html, https://chemical-facility-security-news.blogspot.com/2022/12/review-3-advisories-published-12-8-22.html
        "https://chemical-facility-security-news.blogspot.com/" : 
             ("https://chemical-facility-security-news.blogspot.com/", 
             r"\.blogspot\.com/(\d+/\d+/[\w+\d+\-]+\.html)", 
             ["disclosure", "advisories", "advisory"]), 
         
        "https://talosintelligence.com/vulnerability_reports" : 
            ("https://talosintelligence.com/vulnerability_reports/TALOS-", 
            r"/vulnerability_reports/TALOS-(\d+\-\d+)", 
            None), # https://talosintelligence.com/vulnerability_reports/TALOS-2020-1056
         
        "https://cert.vde.com/en/advisories" : 
            ("https://cert.vde.com/en/advisories/", 
            r"advisories/([vV][dD][eE]\-\d+\-\d+)", 
            None), # https://cert.vde.com/en/advisories/VDE-2021-045/
         
         "https://www.zeroscience.mk/en/vulnerabilities" : 
            ("https://www.zeroscience.mk/en/vulnerabilities/", 
            r"(ZSL-20\d+-\d+.php)", 
            None),
        
        # https://research.nccgroup.com/category/technical-advisory/
        "https://research.nccgroup.com/category/technical-advisory/":
            ("https://research.nccgroup.com/",
            r"\"https://research.nccgroup.com/(\d+/\d+/\d+/[^\"]+)\"",
            None),

        # https://ssd-disclosure.com/apple-safari-javascriptcore-inspector-type-confusion/
        "https://ssd-disclosure.com/advisories/" : 
            ("https://ssd-disclosure.com/", 
            r"<a href=\"https://ssd-disclosure\.com/([^\"]+)\" \>", 
            None), 
         
        "https://awesec.com/advisories.html" : 
            ("https://awesec.com/advisories/", 
            r"advisories\/(AWE-\d+-\d+\.html)\">", 
            None),

        # https://www.nozominetworks.com/blog/technical-analysis-of-the-winbox-payload-in-windigo/
        "https://www.nozominetworks.com/research-reports" : 
            ("https://www.nozominetworks.com/resources/", 
            r"href\=\"/resources/([^\"]+)\"", 
            None), 

        # https://www.armis.com/research/tlstorm/
        "https://www.armis.com/armis-research/" : 
            ("https://www.armis.com/research/", 
            r"armis\.com\/research\/([\w+\d+\-]+\/)\"><", 
            None), 

        # https://research.checkpoint.com/?p=26395
        "https://research.checkpoint.com/feed/" : 
            ("https://research.checkpoint.com/?p=", 
            r"research.checkpoint.com\/\?p=(\d+)<\/guid>", 
            None),

        # https://blog.neodyme.io/posts/secure-randomness-part-2/
        "https://blog.neodyme.io/":
            ("https://blog.neodyme.io",
            r"tr href=\"(/posts/[^\"]+)\" class",
            None),
 
        # https://blog.viettelcybersecurity.com/security-wall-of-s7commplus-3/
        "https://blog.viettelcybersecurity.com":
            ("https://blog.viettelcybersecurity.com",
            r"<a class=\"post-card-image-link\" href=\"([^\"]+)\">",
            None),

        # https://starlabs.sg/blog/2022/12-the-last-breath-of-our-netgear-rax30-bugs-a-tragic-tale-before-pwn2own-toronto-2022/
        "https://starlabs.sg/blog/":
            ("https://starlabs.sg/blog/",
            r"\"https://starlabs.sg/blog/(\d+/[^\"]+)\"",
            None),

        # https://www.seebug.org/vuldb/ssvid-99599
        "https://www.seebug.org/rss/new/":
            ("",
            r"(http://www.seebug.org/vuldb/ssvid-\d+)",
            None),            
         
        # https://www.cobaltstrike.com/blog/revisiting-the-udrl-part-1-simplifying-development/
        "https://www.cobaltstrike.com/blog/":
            ("https://www.cobaltstrike.com/blog/",
            r"href\=\"https://www.cobaltstrike.com/blog/([^\"]+)\">",
            None),

        # https://trustedsec.com/blog/the-triforce-of-initial-access
        "https://trustedsec.com/blog/":
            ("https://trustedsec.com/blog/",
            r"data-href\=\"https://trustedsec.com/blog/([^\"]+)\"",
            None),
			
        # https://www.blackhillsinfosec.com/your-browser-is-not-a-safe-space/
        "https://www.blackhillsinfosec.com/blog/":
            ("https://www.blackhillsinfosec.com/blog/",
            r"<h2 class=\"post-title entry-title\"><a href=\"https://www.blackhillsinfosec.com/([^\"]+)\">",
            None),			
			
        # https://posts.specterops.io/
        "https://posts.specterops.io/":
            ("https://posts.specterops.io/",
            r"value=\"https://posts.specterops.io/([^\"\?]+)\?",
            None),			

        # https://www.mdsec.co.uk/2023/03/exploiting-cve-2023-23397-microsoft-outlook-elevation-of-privilege-vulnerability/
        "https://www.mdsec.co.uk/knowledge-centre/insights/":
            ("https://www.mdsec.co.uk/",
            r"href=\"https://www.mdsec.co.uk/(\d{4}/\d{2}/[^\"]+)\">",
            None),	

        # https://www.mandiant.com/resources/blog/3cx-software-supply-chain-compromise
        "https://www.mandiant.com/resources/blog":
            ("https://www.mandiant.com/resources/blog/",
            r"href=\"https://www.mandiant.com/resources/blog/([^\"]+)\"",
            None),	

        # https://outflank.nl/blog/2023/03/28/attacking-visual-studio-for-initial-access/
        "https://outflank.nl/blog/":
            ("https://outflank.nl/blog/",
            r"href=\"https://outflank.nl/blog/(\d{4}/\d{2}/\d{2}/[^\"]+)\" t",
            None),	


        # https://fortynorthsecurity.com/blog/extending-and-detecting-persistassist-act-ii/
        "https://fortynorthsecurity.com/blog/":
            ("https://fortynorthsecurity.com/blog/",
            r"href=\"/blog/([^\"]+)\" class=\"post-title\"",
            None),	

        # https://googleprojectzero.blogspot.com/2023/03/multiple-internet-to-baseband-remote-rce.html
        "https://googleprojectzero.blogspot.com/":
            ("https://googleprojectzero.blogspot.com/",
            r"<li><a href='https://googleprojectzero.blogspot.com/(\d{4}/\d{2}/[^\"]+)\'>.*</a></li>",
            None),

        # https://medium.com/@mitrecaldera/deconstructing-a-defense-evasion-adversary-with-mitre-caldera-dc8604664aa0
        "https://medium.com/@mitrecaldera/":
            ("https://medium.com/@mitrecaldera/",
            r"href=\"/@mitrecaldera/(?!followers)(?!about)([^\"]+)(?=\?)",
            None),

        # https://whiteknightlabs.com/2023/08/02/flipper-zero-and-433mhz-hacking-part-1/
        "https://whiteknightlabs.com/blog/":
            ("https://whiteknightlabs.com/",
            r"href=\"https://whiteknightlabs.com/(\d{4}/\d{2}/\d{2}/[^\"]+)\"",
            None),

        # https://blog.nviso.eu/2023/11/08/ai-in-cybersecurity-bridging-the-gap-between-imagination-and-reality/
        "https://blog.nviso.eu":
            ("https://blog.nviso.eu/",
            r"href=\"https://blog.nviso.eu/(\d{4}/\d{2}/\d{2}/[^\"]+)\"",
            None),

        # https://shorsec.io/blog/dll-notification-injection/
        "https://shorsec.io/blog/":
            ("https://shorsec.io/blog/",
            r"href=\"https://shorsec.io/blog/(?!tag/)(?!page/)([^\"]+)\"",
            None),

        # https://xl-sec.github.io/AppSecEzine/latest.rss
        "https://xl-sec.github.io/AppSecEzine/latest.rss":
            ("",
            r"<link>(.*)</link>",
            None),

        # https://www.lrqa.com/en/cyber-labs/binary-ninja-plugin/
        "https://www.lrqa.com/en/cyber-labs/":
            ("https://www.lrqa.com/en/cyber-labs/",
            r"href=\"\/en\/cyber-labs\/([^\"]+)\"",
            None),

        # https://www.mdsec.co.uk/2024/12/extracting-account-connectivity-credentials-accs-from-symantec-management-agent-aka-altiris/
        "https://www.mdsec.co.uk/knowledge-centre/insights/":
            ("https://www.mdsec.co.uk/",
            r"href=\"https:\/\/www\.mdsec\.co\.uk\/(\d{4}\/\d{2}\/[^\"]+)",
            None),

        # https://www.elastic.co/security-labs/detonating-beacons-to-illuminate-detection-gaps
        "https://www.elastic.co/security-labs":
            ("https://www.elastic.co/security-labs/",
            r"href=\"\/security-labs\/([^\/\.\"]+)\"",
            None),

        # https://www.attackiq.com/2025/01/09/emulating-ako-ransomware/
        "https://www.attackiq.com/blog/":
            ("https://www.attackiq.com/",
            r"href=\"https:\/\/www\.attackiq\.com\/(\d{4}/\d{2}/\d{2}/[^\"]+)\"",
            None),

        # https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-326a
        "https://www.cisa.gov/news-events/cybersecurity-advisories?f%5B0%5D=advisory_type%3A94":
            ("https://www.cisa.gov/news-events/cybersecurity-advisories/",
            r"href=\"\/news-events\/cybersecurity-advisories\/([^\/\.\"]+)\"",
            None),
        # https://www.cisa.gov/news-events/analysis-reports/ar24-038a
        "https://www.cisa.gov/news-events/cybersecurity-advisories?f%5B0%5D=advisory_type%3A65":
            ("https://www.cisa.gov/news-events/analysis-reports",
            r"href=\"\/news-events\/analysis-reports\/([^\/\.\"]+)\"",
            None),

        # https://cloud.google.com/blog/topics/threat-intelligence/ivanti-connect-secure-vpn-zero-day/
        "https://feeds.feedburner.com/threatintelligence/pvexyqv7v0v":
            ("https://cloud.google.com/blog/topics/threat-intelligence/",
            r"<link>https://cloud.google.com/blog/topics/threat-intelligence/([^\>]+)</link>",
            None),

        # https://news.sophos.com/en-us/2024/12/19/phishing-platform-rockstar-2fa-trips-and-flowerstorm-picks-up-the-pieces/
        "https://news.sophos.com/en-us/category/security-operations/feed/":
            ("https://news.sophos.com/en-us/",
            r"<link>https://news.sophos.com/en-us/([^\>]+)</link>",
            None),

        # https://www.zscaler.com/blogs/security-research/threatlabz-report-threats-delivered-over-encrypted-channels
        "https://www.zscaler.com/blogs?type=security-research":
            ("https://www.zscaler.com/blogs/security-research/",
            r"href=\"/blogs/security-research/([^\/\.\"]+)\"",
            None)
}

SLEEP_TIME = 60 * 60 * 2 # 2 hours -+ 10-5000 seconds
IS_TEST_MODE = False
SHOULD_REPORT = True

def setup_logger():
    logging.basicConfig(filename="secfeed.log", filemode="w", level=logging.DEBUG)
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    root.addHandler(handler)


def notify_rocketchat(url):
    if SHOULD_REPORT:
        payload = {
            "alias": "secfeed",
            "text": url,
        }
        # Send the HTTP POST request to the webhook URL with the message payload in JSON format
        resp = requests.post(webhook_url, data=json.dumps(payload), headers={'Content-Type': 'application/json'})
        logging.debug("rocketchat responded: '{}'".format(resp))
        time.sleep(0.5)

setup_logger()

if not IS_TEST_MODE:
    try:
        # First load from database everything we have
        logging.info("Loading data from: {}".format(DB_PATH))
        with open(DB_PATH, "rb") as f:
            LIST_PARSED_DATA = pickle.load(f)
        logging.info("Loaded {} entries from DB".format(len(LIST_PARSED_DATA)))
    except Exception as e:
        pass

while True:
    previous_full_url = ""
    logging.info("Getting data")

    for sec_feed in SEC_FEEDS:
        if IS_TEST_MODE:
            print("--> {}".format(sec_feed))

        # Prepare
        url_feed = sec_feed
        # one keyword must be present
        base_url, regex_str, keywords = SEC_FEEDS[url_feed]
        # Get data
        try:
            data = requests.get(sec_feed, headers=HEADERS)
        except Exception as e:
            continue
        # Extract
        extracted_datas = re.findall(regex_str, data.text)
        for extracted_data in extracted_datas:
            if not keywords or any([keyword in extracted_data for keyword in keywords]):
                full_url = base_url + extracted_data
                if full_url == previous_full_url:
                    continue
                else:
                    previous_full_url = full_url
                    if IS_TEST_MODE:
                        print("  [-] {}".format(full_url))
                    else:                          
                        if full_url not in LIST_PARSED_DATA:
                            logging.info("Saving new url, and notifying rocketchat: '{}'".format(full_url))
                            LIST_PARSED_DATA.append(full_url)
                            notify_rocketchat(full_url)

    if not IS_TEST_MODE:
        logging.info("Saving everything back to DB: {}".format(DB_PATH))
        with open(DB_PATH, "wb") as f:
            pickle.dump(LIST_PARSED_DATA, f)

        rand_time = random.randint(10, 5000)
        logging.info("Going to sleep {:.2f} hours".format((rand_time+SLEEP_TIME) / 3600.0))
        time.sleep(SLEEP_TIME + rand_time)
    else:
        break
