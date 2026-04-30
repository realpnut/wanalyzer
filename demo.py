import scrapy
from scrapy.crawler import CrawlerProcess
import socket
import requests
import whois
from urllib.parse import urljoin, urlparse


def scan():
    domain = input("Domain: ").strip().replace("www.", "")

    # ---------------- IP LOOKUP ----------------
    try:
        ip = socket.gethostbyname(domain)
        print(f"\n{domain} -> {ip}")

        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = r.json()

        if data.get("status") == "success":
            print("\n--- IP INFO ---")
            print("Country:", data.get("country"))
            print("City:", data.get("city"))
            print("ISP:", data.get("isp"))
            print("ASN:", data.get("as"))

    except Exception as e:
        print("IP error:", e)

    # ---------------- WHOIS ----------------
    try:
        w = whois.whois(domain)

        exp = w.expiration_date
        if isinstance(exp, list):
            exp = exp[0]

        print("\n--- WHOIS ---")
        print("Registrar:", w.registrar)
        print("Creation:", w.creation_date)
        print("Expiration:", exp)
        print("Nameservers:", w.name_servers)

    except Exception as e:
        print("WHOIS error:", e)

    # ---------------- ROBOTS.TXT ----------------
    try:
        r = requests.get(f"https://{domain}/robots.txt", timeout=5)
        if r.status_code == 200:
            print("\n--- ROBOTS.TXT ---")
            print(r.text[:1000])
    except Exception:
        pass

    # ---------------- SCRAPY ----------------
    class LinkSpider(scrapy.Spider):
        name = "links"

        def __init__(self, domain, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.domain = domain

        def start_requests(self):
            yield scrapy.Request(f"https://{self.domain}", callback=self.parse)

        def parse(self, response):
            print(f"\nCRAWLING: {response.url}")

            for href in response.css("a::attr(href)").getall():
                if not href:
                    continue

                if href.startswith(("mailto:", "tel:", "javascript:", "#")):
                    continue

                url = urljoin(response.url, href)

                netloc = urlparse(url).netloc.replace("www.", "")
                if self.domain not in netloc:
                    continue

                print(f"{url}")

                yield {"link": url}

                yield scrapy.Request(url, callback=self.parse)


    process = CrawlerProcess(settings={
        "ROBOTSTXT_OBEY": False,
        "LOG_LEVEL": "ERROR",
        "DEPTH_LIMIT": 2,
        "DOWNLOAD_TIMEOUT": 10,
        "RETRY_ENABLED": False,
        "COOKIES_ENABLED": False,
        "USER_AGENT": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120 Safari/537.36",

        "FEEDS": {
            "links.json": {
                "format": "json",
                "encoding": "utf8",
                "overwrite": True
            },
        },
    })

    process.crawl(LinkSpider, domain=domain)
    process.start()


scan()
