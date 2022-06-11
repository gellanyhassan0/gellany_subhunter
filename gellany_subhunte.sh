#!/bin/bash

#https://github.com/gellanyhassan0/gellany_subhunter


#nmap -Pn -p- hackerone.com
#https://github.com/owtf/owtf/blob/7a04f7df44d4719d582708e0c4cfe961be7776e2/owtf/scripts/subdomain_takeover.sh
#https://github.com/haccer/subjack
#https://github.com/imalfuncti0n/forloops-for-bugbounty

#certspotter.com
curl -s -N "https://certspotter.com/api/v1/issuances?domain=$1&expand=dns_names" | jq -r '.[].dns_names[]' 2>/dev/null | grep -o "\w.*$1" | sort -u > subdomain_$1.txt &&
#crt.sh
curl -s -N "https://crt.sh/?q=%25.$1&output=json"| jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g' | sort -u | grep -o "\w.*$1" >> subdomain_$1.txt &&
#hackertarget.com
curl -s -N "https://api.hackertarget.com/hostsearch/?q=$1" | cut -d ',' -f1 | sort -u >> subdomain_$1.txt &&
#alienvault.com
curl -s -N "https://otx.alienvault.com/api/v1/indicators/domain/$1/passive_dns"|jq '.passive_dns[].hostname' 2>/dev/null |grep -o "\w.*$1"|sort -u >> subdomain_$1.txt &&
#riddler.io
curl -s -N "https://riddler.io/search/exportcsv?q=pld:$1"| grep -o "\w.*$1"|awk -F, '{print $6}'|sort -u  >> subdomain_$1.txt &&
#virustotal.com
curl -s -N "https://www.virustotal.com/ui/domains/$1/subdomains?limit=40" | grep '"id":' | cut -d '"' -f4 | sort -u >> subdomain_$1.txt &&
#web.archive.org
curl -s -N "http://web.archive.org/cdx/search/cdx?url=*.$1/*&output=text&fl=original&collapse=urlkey" | sort | sed -e 's_https*://__' -e "s/\/.*//" -e 's/:.*//' -e 's/^www\.//' |sort -u >> subdomain_$1.txt &&
#urlscan.io
curl -s -N "https://urlscan.io/api/v1/search/?q=domain:$1"|jq '.results[].page.domain' 2>/dev/null |grep -o "\w.*$1"|sort -u >> subdomain_$1.txt &&
# threatminer.org
curl -s -N "https://api.threatminer.org/v2/domain.php?q=$1&rt=5" | jq -r '.results[]' 2>/dev/null |grep -o "\w.*$1"|sort -u >> subdomain_$1.txt &&
# threatcrowd.org
curl -s -N "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=$1"|jq -r '.subdomains' 2>/dev/null |grep -o "\w.*$1" |sort -u >> subdomain_$1.txt &&
#bufferover.run Rapid7
curl -s -N "https://dns.bufferover.run/dns?q=.$1" | jq -r .FDNS_A[] 2>/dev/null | cut -d ',' -f2 | grep -o "\w.*$1" | sort -u >> subdomain_$1.txt &&
curl -s -N "https://dns.bufferover.run/dns?q=.$1" | jq -r .RDNS[] 2>/dev/null | cut -d ',' -f2 | grep -o "\w.*$1" | sort -u >> subdomain_$1.txt &&
curl -s -N "https://tls.bufferover.run/dns?q=.$1" | jq -r .Results 2>/dev/null | cut -d ',' -f3 |grep -o "\w.*$1"| sort -u >> subdomain_$1.txt &&
#dnsdumpster
cmdtoken=$(curl -ILs https://dnsdumpster.com | grep csrftoken | cut -d " " -f2 | cut -d "=" -f2 | tr -d ";");curl -s --header "Host:dnsdumpster.com" --referer https://dnsdumpster.com --user-agent "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0" --data "csrfmiddlewaretoken=$cmdtoken&targetip=$1" --cookie "csrftoken=$cmdtoken; _ga=GA1.2.1737013576.1458811829; _gat=1" https://dnsdumpster.com > dnsdumpster.html;cat dnsdumpster.html|grep "https://api.hackertarget.com/httpheaders"|grep -o "\w.*$1"|cut -d "/" -f7|sort -u >> subdomain_$1.txt;rm dnsdumpster.html &&
#rapiddns.io
curl -s "https://rapiddns.io/subdomain/$1?full=1#result" | grep -oaEi "https?://[^\"\\'> ]+" | grep $1 | cut -d "/" -f3 | sort -u >> subdomain_$1.txt &&
# jldc
curl -s -N "https://jldc.me/anubis/subdomains/$1?limit=40" | grep '"id":' | cut -d '"' -f4 | sort -u >> subdomain_$1.txt &&



#subfinder
subfinder -d $1 -v -o subfinder_$1.txt &&
cat subfinder_$1.txt >> subdomain_$1.txt  &&

#assetfinder
assetfinder -subs-only $1 > assetfinder_$1.txt &&
cat assetfinder_$1.txt >> subdomain_$1.txt  &&

#amass
amass enum -d $1 >> subdomain_$1.txt &&

#sublister
sublist3r -d $1 -o sublist3r_$1.txt &&
cat sublist3r_$1.txt >> subdomain_$1.txt &&


#chaos
DOMAIN=$(echo $1|awk -F".com" '{print $1}')

wget https://chaos-data.projectdiscovery.io/${DOMAIN}.zip && unzip -op ${DOMAIN}.zip >> subdomain_$1.txt  &&

#github-subdomains
timeout -v 20 $path ~/go/bin/./github-subdomains -t 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 -d $1 -o github-subdomains_$1.txt 

cat github-subdomains_$1.txt >>subdomain_$1.txt  &&



#dns level 1
python3 /dnscan/./dnscan.py -d $1 -N -r -w /wordlist/subdomains.txt -R 8.8.8.8 -o dnscan_$1.txt &&
cat dnscan_$1.txt | grep -oP '[a-zA-Z0-9]+\.[a-zA-Z0-9]+\.[a-zA-Z0-9]+\.[a-zA-Z0-9]+\.[a-z]+$|[a-zA-Z0-9]+\.[a-zA-Z0-9]+\.[a-zA-Z0-9]+\.[a-z]+$|[a-zA-Z0-9]+\.[a-zA-Z0-9]+\.[a-z]+$|[a-zA-Z0-9]+\.[a-z]+$' >> subdomain_$1.txt &&

#subdomains before final

awk '!a[$0]++' subdomain_$1.txt > subdomains_$1.txt &&

#dnscan level 2 very deep subdomain

python3 /dnscan/./dnscan.py -l subdomains_$1.txt $1 -N -r -w /wordlist/subdomains.txt -R 8.8.8.8 -o dnscans_$1.txt &&
cat dnscans_$1.txt | grep -oP '[a-zA-Z0-9]+\.[a-zA-Z0-9]+\.[a-zA-Z0-9]+\.[a-zA-Z0-9]+\.[a-z]+$|[a-zA-Z0-9]+\.[a-zA-Z0-9]+\.[a-zA-Z0-9]+\.[a-z]+$|[a-zA-Z0-9]+\.[a-zA-Z0-9]+\.[a-z]+$|[a-zA-Z0-9]+\.[a-z]+$' >> subdomainss_$1.txt &&



#subdomainss final
$path ~/go/bin/./naabu -iL /home/geo/subdomainss_$1.txt -verify -o subdomainsss_$1.txt &&

##################################subdomain takeover################################################
cat subdomainsss_$1.txt | xargs -I% sh -c 'dig @8.8.8.8 {} | grep "CNAME"' >> takeover_check_$1.txt &&

subjack -a -v -w subdomainsss_$1.txt -t 20 -timeout 15 -c wordlist/fingerprints.json -o takeover_$1.txt &&
sort -u takeover_$1.txt > takeovers_$1.txt &&

##################################get all urls #####################################################

cat subdomainsss_$1.txt |$path ~/go/bin/./gau -subs > allurl_$1.txt &&
cat subdomainsss_$1.txt |getallurls >> allurl_$1.txt &&

waybackpy --known_urls --subdomain --url $1 --user_agent "my-unique-user-agent" >>  allurl_$1.txt &&
 

cat subdomainsss_$1.txt |$path ~/go/bin/./waybackurls >> allurl_$1.txt &&


cat allurl_$1.txt | ~/go/bin/./hakrawler > allurls_$1.txt

sort -u allurls_$1.txt > allurlss_$1.txt

cat allurlss_$1.txt |$path ~/go/bin/./httpx -filter-string Page not found -ports 53,80,443,2052,2080-2100,8080,8880,8443 > allurlsss_$1.txt  

#final all urls
sort -u allurlsss_$1.txt > allurlssss_$1.txt 
###################################javascipt and json mining#############################################################

cat subdomainssss_$1.txt|~/go/bin/./gau |grep -iE "\.js$|\.json$|\.js[?]|\.json[?]"|sort -u > js_$1.txt
#cat allurlssss_$1.txt |grep -iE "\.js$|\.json$"|sort -u >> js_$1.txt

sort -u js_$1.txt > jss_$1.txt



##################################specific endpoint with regex###########################################################


#echo hackerone.com|~/go/bin/./gau |grep -iE "\.[a-z0-9]+$"|sort -u
#echo hackerone.com|~/go/bin/./gau |grep -iE "\.[a-zA-Z0-9]+$"|sort -u
#curl -d GET https://www.hackerone.com/home |grep -oP "[a-zA-Z0-9]+/[a-zA-Z0-9]+/[a-zA-Z0-9]+/[a-zA-Z0-9]+"

####################################grep patterns + qsreplace#############################################################

cat allurlssss_$1.txt | grep '=' |./qsreplace '"><script>alert(1)</script>' | while read host do ; do curl -s --path-as-is --insecure "$host" | grep -qs "<script>alert(1)</script>" && echo "$host \033[0;31m" Vulnerable;done

#cat allurlssss_$1.txt |./kxss|sed 's/=.*/=/'|sed 's/URL: //'|./dalfox pipe
