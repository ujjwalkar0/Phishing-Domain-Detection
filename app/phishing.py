from tld import get_tld
import pandas as pd
from dns import resolver,reversename
from whois import whois
import ssl
from aslookup import get_as_data
import datetime
from urllib.parse import urlparse
import requests as rq
import dns
import socket
from django.conf import settings
import pickle

# Number of redirects  --> datatype --> number
def get_qty_redirects(url):
    try:
        return len(rq.get(url).history)
    except:
        return -1

# Is URL shortened  --> datatype --> boolean
def is_url_shortened(url):
    try:
        return 1 if rq.get(url).is_redirect else 0
    except:
        return -1

def get_time_response(url):
    try:
        return rq.get(url).elapsed.total_seconds()
    except:
        return -1

def get_ttl(url):
    try:
        return dns.resolver.resolve(url).rrset.ttl
    except:
        return -1


def get_tld_url(url):
    try:
        return len(get_tld(url))
    except:
        return -1


def get_qty_ip_resolved(url):
    try:
        return len(dns.resolver.resolve(url))
    except:
        return -1

def get_qty_nameservers(url):
    try:
        w = whois(url)
        return len(w.name_servers)
    except:
        return -1

def is_tls_ssl_certificate(hostname):
    try:
        context = ssl.create_default_context()
        context.check_hostname = False

        conn = context.wrap_socket(
            socket.socket(socket.AF_INET),
            server_hostname=hostname,
        )

        conn.connect((hostname, 443))
        ssl_info = conn.getpeercert()

        return 1 if len(ssl_info)!=0 else 0
    except:
        return -1

def get_qty_mx_servers(url):
    try:
        return len(resolver.resolve(url, "MX"))
    except:
        return -1


def get_asn_ip(url):
    try:
        ip = dns.resolver.resolve(url, "A")[0].to_text()
        return get_as_data(ip, service="shadowserver").asn
    except:
        return -1

def get_domain_spf(url):
    try:
        r = dns.resolver.Resolver() 
        a = r.resolve(url, 'TXT') 
        for i in a:
            if f"_spf.{url}" in i.to_text():
                return 1
        return 0
    except:
        return -1

def get_time_domain_expiration(url):
    try:
        if type(whois(url).expiration_date)==list:
            return (min(whois(url).expiration_date) - datetime.datetime.now()).days
        else:
            return (whois(url).expiration_date - datetime.datetime.now()).days
    except:
        return -1

def get_time_domain_activation(url):
    try:
        if type(whois(url).expiration_date)==list:
            return (datetime.datetime.now() - min(whois(url).creation_date)).days
        else:
            return (datetime.datetime.now() - whois(url).creation_date).days
    except:
        return -1

def is_phishing(POST):
    df = pd.DataFrame()

    type_ = POST.get("type")
    url = POST.get("website")

    result = dict()
    context = dict()

    print(type_)
    if type_ == 'url':

        result['qty_percent_url'] =  url.count("%")
        result['qty_at_url'] =  url.count("@")
        result['url_shortened'] = is_url_shortened(url)

        result['qty_tld_url'] =  get_tld_url(url)
        result['qty_slash_url'] =  url.count("/")
        result['qty_equal_url'] =  url.count("=")
        result['qty_dot_url'] =  url.count(".")
        result['qty_hyphen_url'] =  url.count("-")
        result['qty_underline_url'] =  url.count("_")

        result['qty_dot_domain'] = urlparse(url).netloc.count(".")
        result['qty_vowels_domain'] = sum([urlparse(url).netloc.count(i) for i in ("a", "e", "i", "o", "u", "A", "E", "I", "O", "U" )])
        result['qty_hyphen_domain'] = urlparse(url).netloc.count("-")

        result['qty_redirects'] = get_qty_redirects(url)
        result['time_response'] = get_time_response(url)
        result['ttl_hostname'] = get_ttl(url)

        result['qty_hyphen_params'] = urlparse(url).params.count("-")
        result['qty_percent_params'] = urlparse(url).params.count("%")
        result['qty_slash_params'] = urlparse(url).params.count("/")

        result['qty_ip_resolved'] = get_qty_ip_resolved(url)
        result['qty_nameservers'] = get_qty_nameservers(url)
        result['tls_ssl_certificate'] = is_tls_ssl_certificate(url)
        result['qty_mx_servers'] = get_qty_mx_servers(url)
        result['asn_ip'] = get_asn_ip(url)
        result['domain_spf'] = get_domain_spf(url)
        result['time_domain_activation'] = get_time_domain_expiration(url)
        result['time_domain_expiration'] = get_time_domain_activation(url)

    elif type_== "features":
        result['qty_percent_url'] = POST.get("qty_percent_url")
        result['qty_at_url'] = POST.get("qty_at_url")
        result['url_shortened'] = POST.get("url_shortened")
        
        result['qty_tld_url'] = POST.get("qty_tld_url")
        result['qty_slash_url'] = POST.get("qty_slash_url")
        result['qty_equal_url'] = POST.get("qty_equal_url")
        result['qty_dot_url'] = POST.get("qty_dot_url")
        result['qty_hyphen_url'] = POST.get("qty_hyphen_url")
        result['qty_underline_url'] = POST.get("qty_underline_url")
        
        result['qty_dot_domain'] = POST.get("qty_dot_domain")
        result['qty_vowels_domain'] = POST.get("qty_vowels_domain")
        result['qty_hyphen_domain'] = POST.get("qty_hyphen_domain")
        
        result['qty_redirects'] = POST.get("qty_redirects")
        result['time_response'] = POST.get("time_response")
        result['ttl_hostname'] = POST.get("ttl_hostname")
        
        result['qty_hyphen_params'] = POST.get("qty_hyphen_params")
        result['qty_percent_params'] = POST.get("qty_percent_params")
        result['qty_slash_params'] = POST.get("qty_slash_params")
        
        result['qty_ip_resolved'] = POST.get("qty_ip_resolved")
        result['qty_nameservers'] = POST.get("qty_nameservers")
        result['tls_ssl_certificate'] = POST.get("tls_ssl_certificate")
        result['qty_mx_servers'] = POST.get("qty_mx_servers")
        result['asn_ip'] = POST.get("asn_ip")
        result['domain_spf'] = POST.get("domain_spf")
        result['time_domain_activation'] = POST.get("time_domain_activation")
        result['time_domain_expiration'] = POST.get("time_domain_expiration")
        
    df = pd.DataFrame({k: [v] for k, v in result.items()})
    print(df)
    df = df[[
        'qty_percent_url', 'qty_at_url', 'url_shortened', 'qty_hyphen_domain',
        'qty_tld_url', 'tls_ssl_certificate', 'domain_spf', 'qty_ip_resolved',
        'qty_redirects', 'qty_slash_params', 'qty_equal_url',
        'qty_underline_url', 'qty_percent_params', 'qty_nameservers',
        'qty_mx_servers', 'qty_vowels_domain', 'qty_dot_url', 'qty_hyphen_url',
        'qty_hyphen_params', 'time_response', 'time_domain_expiration',
        'ttl_hostname', 'asn_ip', 'qty_dot_domain', 'time_domain_activation',
        'qty_slash_url'
    ]]

    with open(settings.MODEL, 'rb') as files:
        rfc = pickle.load(files)

    context["valued_features"] = result

    context['class'] = "Phishing Website" if rfc.predict(df)==1 else "Not a Phishing Website"
    
    return context