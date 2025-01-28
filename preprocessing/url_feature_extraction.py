import pandas as pd
import re
import ipaddress
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import whois
from datetime import datetime
import dns.resolver
from googlesearch import search
import csv
from sklearn.base import BaseEstimator, TransformerMixin

class FeatureExtractor(BaseEstimator, TransformerMixin):
    def __init__(self):
        pass
    
    def fit(self, X, y=None):
        return self
    
    def transform(self, X):
        if not isinstance(X, list):
            X = [X]


        features_list = [self.process_url(url) for url in X]
        return pd.DataFrame(features_list)
    
    '''1. UsingIP : {-1,1}'''
    def using_ip(self, url):
        try:
            domain = urlparse(url).netloc
            ipaddress.ip_address(domain)
            return -1
        except ValueError:
            return 1

    '''2. LongURL: {-1, 0, 1}'''
    def long_url(self, url):
        url_length = len(url)
        if url_length > 100:
            return -1
        elif url_length >= 50:
            return 0
        else:
            return 1

    '''3. ShortURL: {-1, 1}'''
    def short_url(self, url):
        shortening_domains = [
            'bit.ly', 'goo.gl', 'shorte.st', 'go2l.ink', 'x.co', 'ow.ly', 't.co', 'tinyurl', 'tr.im',
            'is.gd', 'cli.gs', 'yfrog.com', 'migre.me', 'ff.im', 'tiny.cc', 'url4.eu', 'twit.ac',
            'su.pr', 'twurl.nl', 'snipurl.com', 'short.to', 'BudURL.com', 'ping.fm', 'post.ly', 'Just.as',
            'bkite.com', 'snipr.com', 'fic.kr', 'loopt.us', 'doiop.com', 'short.ie', 'kl.am', 'wp.me',
            'rubyurl.com', 'om.ly', 'to.ly', 'bit.do', 't.co', 'lnkd.in', 'db.tt', 'qr.ae', 'adf.ly',
            'goo.gl', 'bitly.com', 'cur.lv', 'tinyurl.com', 'ow.ly', 'bit.ly', 'ity.im', 'q.gs', 'is.gd',
            'po.st', 'bc.vc', 'twitthis.com', 'u.to', 'j.mp', 'buzurl.com', 'cutt.us', 'u.bb', 'yourls.org',
            'x.co', 'prettylinkpro.com', 'scrnch.me', 'filoops.info', 'vzturl.com', 'qr.net', '1url.com',
            'tweez.me', 'v.gd', 'tr.im', 'link.zip.net'
        ]
        return -1 if any(domain in url for domain in shortening_domains) else 1

    '''4. Symbol@: {-1,1}'''
    def symbol_at(self, url):
        parsed_url = urlparse(url)
        return -1 if "@" in parsed_url else 1

    '''5. Redirecting//: {-1, 1}'''
    def double_slash_redirecting(self, url):
        parsed_url = urlparse(url)
        return -1 if "//" in parsed_url else 1

    '''6. PrefixSuffix-: {-1,1}'''
    def prefix_suffix(self, url):
        domain = urlparse(url).netloc.split("/")[0].split('?')[0].split('#')[0]
        return -1 if '-' in domain else 1

    '''7. SubDomains: {-1, 0, 1}'''
    def sub_domains(self, url):
        try:
            parsed_url = urlparse(url)
            netloc_parts = parsed_url.netloc.split('.')

            # Omitting the first "www." part if present
            if netloc_parts[0] == 'www':
                netloc_parts.pop(0)

            # List of known ccTLDs
            cctlds = ['ac', 'ad', 'ae', 'af', 'ag', 'ai', 'al', 'am', 'ao', 'aq', 'ar', 'as', 'at', 'au', 'aw', 'ax', 'az', 'ba', 'bb', 'bd', 'be', 'bf', 'bg', 'bh', 'bi', 'bj', 'bl', 'bm', 'bn', 'bo', 'bq', 'br', 'bs', 'bt', 'bv', 'bw', 'by', 'bz', 'ca', 'cc', 'cd', 'cf', 'cg', 'ch', 'ci', 'ck', 'cl', 'cm', 'cn', 'co', 'cr', 'cu', 'cv', 'cw', 'cx', 'cy', 'cz', 'de', 'dj', 'dk', 'dm', 'do', 'dz', 'ec', 'ee', 'eg', 'eh', 'er', 'es', 'et', 'eu', 'fi', 'fj', 'fk', 'fm', 'fo', 'fr', 'ga', 'gb', 'gd', 'ge', 'gf', 'gg', 'gh', 'gi', 'gl', 'gm', 'gn', 'gp', 'gq', 'gr', 'gs', 'gt', 'gu', 'gw', 'gy', 'hk', 'hm', 'hn', 'hr', 'ht', 'hu', 'id', 'ie', 'il', 'im', 'in', 'io', 'iq', 'ir', 'is', 'it', 'je', 'jm', 'jo', 'jp', 'ke', 'kg', 'kh', 'ki', 'km', 'kn', 'kp', 'kr', 'kw', 'ky', 'kz', 'la', 'lb', 'lc', 'li', 'lk', 'lr', 'ls', 'lt', 'lu', 'lv', 'ly', 'ma', 'mc', 'md', 'me', 'mf', 'mg', 'mh', 'mk', 'ml', 'mm', 'mn', 'mo', 'mp', 'mq', 'mr', 'ms', 'mt', 'mu', 'mv', 'mw', 'mx', 'my', 'mz', 'na', 'nc', 'ne', 'nf', 'ng', 'ni', 'nl', 'no', 'np', 'nr', 'nu', 'nz', 'om', 'pa', 'pe', 'pf', 'pg', 'ph', 'pk', 'pl', 'pm', 'pn', 'pr', 'ps', 'pt', 'pw', 'py', 'qa', 're', 'ro', 'rs', 'ru', 'rw', 'sa', 'sb', 'sc', 'sd', 'se', 'sg', 'sh', 'si', 'sj', 'sk', 'sl', 'sm', 'sn', 'so', 'sr', 'ss', 'st', 'su', 'sv', 'sx', 'sy', 'sz', 'tc', 'td', 'tf', 'tg', 'th', 'tj', 'tk', 'tl', 'tm', 'tn', 'to', 'tp', 'tr', 'tt', 'tv', 'tw', 'tz', 'ua', 'ug', 'uk', 'us', 'uy', 'uz', 'va', 'vc', 've', 'vg', 'vi', 'vn', 'vu', 'wf', 'ws', 'ye', 'yt', 'za', 'zm', 'zw']

            # Removing the last part if it matches any of the known ccTLDs
            if len(netloc_parts) > 1 and netloc_parts[-1] in cctlds:
                netloc_parts.pop(-1)

            num_subdomains = len(netloc_parts)

            return 1 if num_subdomains <= 1 else 1 if num_subdomains == 2 else -1
        except:
            return -1


    '''8.HTTPS: {-1, 0, 1}'''
    def http_s(self, url, timeout=2):
        if url.startswith("https://"):
            return 1
        else:
            try:
                response = requests.head("https://" + url, timeout=timeout)
                return 1 if response.status_code == 200 else -1
            except requests.RequestException:
                return -1

    '''9. DomainRegLen: {-1,1}'''
    def domain_reg_len(self, url):
        try:
            domain = urlparse(url).netloc.split("/")[0]
            domain_info = whois.whois(domain)
            creation_date = min(domain_info.creation_date) if isinstance(domain_info.creation_date, list) else domain_info.creation_date
            registration_length = (datetime.now() - creation_date).days / 30
            return 1 if registration_length > 12 else -1
        except Exception:
            return -1

    '''10.Favicon: {-1, 1}'''
    def favicon(self, url):
        try:
            response = requests.get(url, timeout=2)
            response.raise_for_status()
            soup = BeautifulSoup(response.content, 'html.parser')
            favicon_link = soup.find('link', rel='icon') or soup.find('link', rel='shortcut icon')
            if favicon_link:
                favicon_url = favicon_link.get('href')
                # Check if favicon URL is a relative path
                if not urlparse(favicon_url).netloc:
                    return 1  # Return 1 if favicon URL is a relative path
                else:
                    # Compare favicon domain with page domain
                    favicon_domain = urlparse(favicon_url).netloc
                    page_domain = urlparse(url).netloc
                    if favicon_domain != page_domain:
                        return -1  # Return -1 if favicon domain doesn't match page domain
            return -1  # Return -1 if no favicon found or favicon URL is not a relative path
        except requests.exceptions.RequestException:
            return -1

    '''11.NonStdPort: {-1, 1}'''
    def non_std_port(self, url):
        standard_ports = {80, 443}
        parsed_url = urlparse(url)

        # Check if the URL has a port specified
        if parsed_url.port is not None:
            return 1 if parsed_url.port in standard_ports else -1
        else:
            # If no port is specified, check if the scheme is HTTP or HTTPS
            if parsed_url.scheme == 'https':
                return 1 if 80 in standard_ports else -1
        # elif parsed_url.scheme == 'https':
            #    return 1 if 443 in standard_ports else -1
            else:
                # If the scheme is not HTTP or HTTPS, return -1
                return -1

    '''12.HTTPSDomainURL: {-1,1}'''
    def is_https_in_domain(self, url):
        return -1 if 'https' in urlparse(url).netloc else 1

    '''13.RequestURL: {-1,1}'''
    def request_urls(self, url):
        try:
            response = requests.get(url, timeout=2)
            if response.status_code != 200:
                return -1
            soup = BeautifulSoup(response.content, 'html.parser')
            success, total_resources = 0, 0
            for tag in ['img', 'audio', 'embed', 'iframe']:
                for resource in soup.find_all(tag, src=True):
                    total_resources += 1
                    dots = [x.start(0) for x in re.finditer('\.', resource['src'])]
                    if url in resource['src'] or len(dots) == 1:
                        success += 1
            return -1 if total_resources == 0 else 1 if (success / total_resources) * 100 >= 42.0 else -1
        except Exception:
            return -1

    '''14.AnchorURL: {-1,0,1}'''
    def anchor_urls(self, url):
        try:
            response = requests.get(url, timeout=2)
            soup = BeautifulSoup(response.content, 'html.parser')
            unsafe, i = 0, 0
            for a in soup.find_all('a', href=True):
                if "#" in a['href'] or "javascript" in a['href'].lower() or "mailto" in a['href'].lower() or not (url in a['href'] or url.split('/')[2] in a['href']):
                    unsafe += 1
                i += 1
            percentage = unsafe / float(i) * 100
            return 1 if percentage < 31.0 else 0 if 31.0 <= percentage < 67.0 else -1
        except Exception:
            return -1

    '''15.LinksInScriptTags: {-1, 0, 1}'''
    def links_in_script_tags(self, url):
        try:
            i, success = 0, 0

            # Make an HTTP request to the URL
            response = requests.get(url, timeout=2)
            soup = BeautifulSoup(response.content, 'html.parser')

            for link in soup.find_all('link', href=True):
                dots = [x.start(0) for x in re.finditer('\.', link['href'])]
                if url in link['href'] or self.domain in link['href'] or len(dots) == 1:
                    success += 1
                i += 1

            for script in soup.find_all('script', src=True):
                dots = [x.start(0) for x in re.finditer('\.', script['src'])]
                if url in script['src'] or self.domain in script['src'] or len(dots) == 1:
                    success += 1
                i += 1

            # Calculate the percentage of successful links
            percentage = (success / float(i)) * 100

            # Return -1, 0, or 1 based on the percentage
            if percentage < 17.0:
                return 1
            elif 17.0 <= percentage < 81.0:
                return 0
            else:
                return -1

        except Exception:
            return -1

    '''16.ServerFormHandler: {-1, 0, 1}'''
    def server_form_handler(self, url):
        try:
            response = requests.get(url, timeout=2)
            soup = BeautifulSoup(response.content, 'html.parser')
            forms = soup.find_all('form', action=True)
            if len(forms) == 0:
                return 1
            else:
                for form in forms:
                    action = form['action']
                    if action == "" or action == "about:blank" or (url not in action and urlparse(url).netloc not in action):
                        return 0
                return 1
        except Exception:
            return -1

    '''17.InfoEmail: {-1, 1}'''
    def info_email(self, url):
        try:
            response = requests.get(url, timeout=2)
            soup = BeautifulSoup(response.content, 'html.parser')
            return -1 if re.findall(r"(mail\(\)|mailto:)", str(soup)) else 1
        except Exception:
            return -1

    '''18.AbnormalURL: {-1, 1}'''
    def abnormal_url(self, url):
        try:
            response = requests.get(url, timeout=2)
            response_text = response.text
            domain = urlparse(url).netloc
            whois_response = str(whois.whois(domain))
            return 1 if response_text == whois_response else -1
        except Exception:
            return -1

    '''19.WebsiteForwarding: {0, 1}'''
    def website_forwarding(self, url):
        try:
            max_redirects = 4
            redirects_count = 0
            while True:
                response = requests.head(url, allow_redirects=True, timeout=1)
                if response.status_code in [301, 302]:
                    redirects_count += 1
                    if redirects_count > max_redirects:
                        return -1
                    url = response.headers['Location']
                else:
                    return redirects_count
        except Exception as e:
            print("Error:", e)
            return -1

    '''20.StatusBarCust: {-1, 1}'''
    def status_bar_cust(self, url):
        try:
            response = requests.get(url, timeout=2)
            html_content = response.text
            return 1 if re.findall("<script>.+onmouseover.+</script>", html_content) or re.findall("<style>.+statusbar.+</style>", html_content) or re.findall("<a .+onmouseover.+title=.+>", html_content) or re.findall("addEventListener\('mouseover', .+setStatusBar", html_content) else -1
        except Exception:
            return -1

    '''21.DisableRightClick: {-1, 1}'''
    def disable_right_click(self, url):
        try:
            response = requests.get(url, timeout=2)
            html_content = response.text
            return 1 if re.findall(r"event\.button\s*===\s*2", html_content) else -1
        except Exception:
            return -1

    '''22.UsingPopupWindow: {-1, 1}'''
    def using_popup_window(self, url):
        try:
            response = requests.get(url, timeout=2)
            response.raise_for_status()
            html_content = response.text
            return 1 if re.findall(r"window\.open\(|alert\(", html_content) else -1
        except Exception:
            return -1

    '''23.IframeRedirection: {-1, 1}'''
    def iframe_redirect(self, url):
        try:
            # Send a GET request to the URL and fetch the HTML content
            response = requests.get(url, timeout=2)
            response.raise_for_status()  # Raise an exception for non-200 status codes

            # Extract the HTML content from the response
            html_content = response.text

            # Use regular expressions to search for iframe tags with frameBorder attribute set to 0
            if re.search(r'<iframe\s[^>]*frameborder\s*=\s*["\']?0["\']?[^>]*>', html_content, re.IGNORECASE):
                return 1  # Phishing website detected
            else:
                return 1  # No phishing detected
        except Exception as e:
            print("An error occurred:", e)
            return -1  # Error occurred, unable to determine


    '''24.AgeofDomain: {-1, 1}'''
    def age_of_domain(self, url):
        try:
            domain = urlparse(url).netloc
            domain_info = whois.whois(domain)
            creation_date = min(domain_info.creation_date) if isinstance(domain_info.creation_date, list) else domain_info.creation_date
            age_in_months = (datetime.now().year - creation_date.year) * 12 + (datetime.now().month - creation_date.month)
            return 1 if age_in_months >= 6 else -1
        except Exception:
            return -1

    '''25.DNSRecording: {-1, 1}'''
    def dns_record(self, url):
        try:
            domain = urlparse(url).netloc
            answers = dns.resolver.resolve(domain, 'A')
            return 1 if answers else -1
        except Exception:
            return -1

    '''26.WebsiteTraffic: {-1, 0, 1}'''
    def load_alexa_data(self, file_path):
        try:
            with open(file_path) as f:
                return list(csv.reader(f))
        except FileNotFoundError:
            print(f"Error: File '{file_path}' not found.")
        except Exception as e:
            print(f"Error loading Alexa data: {e}")
        return []  # Return an empty list if there's an error

    def website_traffic(self, url, alexa_data=None):
        if alexa_data is None:
            alexa_data = self.load_alexa_data('datafiles/top-1m.csv')
        try:
            domain = urlparse(url).netloc
            if domain.startswith('www.'):
                domain = domain[4:]
            rank = next((i + 1 for i, v in enumerate(alexa_data) if v[1] == domain), None)
            return 1 if rank is not None and rank < 100000 else 0 if rank is not None else -1
        except Exception:
            return -1

    '''27.PageRank: {-1, 1}'''
    def page_rank(self, url, alexa_data=None):
        if alexa_data is None:
            alexa_data = self.load_alexa_data('datafiles/top-1m.csv')
        try:
            domain = urlparse(url).netloc
            if domain.startswith('www.'):
                domain = domain[4:]
            rank = next((i + 1 for i, v in enumerate(alexa_data) if v[1] == domain), None)
            return 1 if rank is not None and rank < 100000 else 0 if rank is not None else -1
        except Exception:
            return -1


    '''28.GoogleIndex: {-1, 1}'''
    def google_index(self, url):
        try:
            search_results = list(search(url, num=5, stop=5, pause=2))
            return 1 if url in search_results else -1
        except Exception:
            return -1

    '''29.LinksPointingToPage: {-1, 0, 1}'''
    def links_pointing_to_page(self, url):
        try:
            response = requests.get(url, timeout=2)
            if response.status_code == 200:
                number_of_links = len(re.findall(r"<a href=", response.text))
                return -1 if number_of_links == 0 else 1 if number_of_links > 3 else 0
            else:
                return -1
        except Exception:
            return -1

    '''30.StatsReport: {-1,1}'''
    def stats_report(self, url):
        try:
            response = requests.get('https://openphish.com/feed.txt', timeout=2)
            response.raise_for_status()
            for line in response.text.split('\n'):
                line = line.strip()
                if line == url:
                    return -1
            return 1
        except Exception as e:
            print(f"An error occurred: {e}")
            return 1

    def process_url(self, url):
        return {
            "UsingIP": self.using_ip(url),
            "LongURL": self.long_url(url),
            "ShortURL": self.short_url(url),
            "Symbol@": self.symbol_at(url),
            "Redirecting//": self.double_slash_redirecting(url),
            "PrefixSuffix-": self.prefix_suffix(url),
            "SubDomains": self.sub_domains(url),
            "HTTPS": self.http_s(url),
            "DomainRegLen": self.domain_reg_len(url),
            "Favicon": self.favicon(url),
            "NonStdPort": self.non_std_port(url),
            "HTTPSDomainURL": self.is_https_in_domain(url),
            "RequestURL": self.request_urls(url),
            "AnchorURL": self.anchor_urls(url),
            "LinksInScriptTags": self.links_in_script_tags(url),
            "ServerFormHandler": self.server_form_handler(url),
            "InfoEmail": self.info_email(url),
            "AbnormalURL": self.abnormal_url(url),
            "WebsiteForwarding": self.website_forwarding(url),
            "StatusBarCust": self.status_bar_cust(url),
            "DisableRightClick": self.disable_right_click(url),
            "UsingPopupWindow": self.using_popup_window(url),
            "IframeRedirection": self.iframe_redirect(url),
            "AgeofDomain": self.age_of_domain(url),
            "DNSRecording": self.dns_record(url),
            "WebsiteTraffic": self.website_traffic(url),
            "PageRank": self.page_rank(url),
            "GoogleIndex": self.google_index(url),
            "LinksPointingToPage": self.links_pointing_to_page(url),
            "StatsReport": self.stats_report(url)
        }
