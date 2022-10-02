from django.shortcuts import render
from app.phishing import is_phishing

def home(request):
    if request.method == 'GET':
        context = {
            'features': ['qty_percent_url', 'qty_at_url', 'url_shortened', 'qty_hyphen_domain',
                            'qty_tld_url', 'tls_ssl_certificate', 'domain_spf', 'qty_ip_resolved',
                            'qty_redirects', 'qty_slash_params', 'qty_equal_url',
                            'qty_underline_url', 'qty_percent_params', 'qty_nameservers',
                            'qty_mx_servers', 'qty_vowels_domain', 'qty_dot_url', 'qty_hyphen_url',
                            'qty_hyphen_params', 'time_response', 'time_domain_expiration',
                            'ttl_hostname', 'asn_ip', 'qty_dot_domain', 'time_domain_activation',
                            'qty_slash_url'
                        ]
        }
        return render(request, 'index.html', context)
    if request.method == 'POST':
        
        context = is_phishing(request.POST)

        return render(request, 'index.html', context)