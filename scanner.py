from urllib import request, response
import requests
import re
import urllib.parse as urlparse
from bs4 import BeautifulSoup
import html5lib

class Scanner:
    def __init__(self,url,ignore_links):
        self.session= requests.Session()
        self.target_url=url
        self.target_links=[]
        self.links_to_ignore=ignore_links

    def extract_link_form(self, url):
        
        response =self.session.get(url)
        return re.findall('(?:href=")(.*?)"' ,response.content.decode(errors="ignore"))

    def crawl (self,url=None):
        if url==None:
            url=self.target_url
        href_links=self.extract_link_form(url)
        for link in href_links:
            link=urlparse.urljoin(url, link)

            if "#" in link:
                link =link.split("#")[0]

            if self.target_url in link and link not in self.target_links and link not in self.links_to_ignore:
                self.target_links.append(link)
                print(link)
                self.crawl(link)# to recursively call the craw funtion to discover all path and underlying link in a website


    def extract_forms(self,url):
        response=self.session.get(url)
        parsed_html=BeautifulSoup(response.content ,'html5lib')
        return parsed_html.findAll("form")

    def submit_form(self,form,value,url):
        action=form.get("action")
        post_url=urlparse.urljoin(url,action)
        method=form.get("method")

        input_list=form.findAll("input")
        post_data={}
        for input in input_list:
            input_name=input.get("name")
            input_type=input.get("type")
            input_value=input.get("value")
            if input_type=="text":
                input_value=value
            
            post_data[input_name]=input_value
        if method=="post":
            return self.session.post(post_url,data=post_data)
        return self.session.get(post_url,params=post_data)

    def run_scanner(self):
        for link in self.target_links:
            forms=self.extract_forms(link)
            for form in forms:
                print("[+] Testing form in " +link)
                is_vunerable_to_XSS=self.test_xss_in_form(form,link)
                if is_vunerable_to_XSS:
                    print("\n\n[###] XSS discoved in " +link +" in the following form")
                    print(form)
            if "=" in link:
                print("[+] Testing" +link)
                is_vunerable_to_XSS=self.test_xss_in_link(link)
                if is_vunerable_to_XSS:
                    print("[###] XSS discoved in " +link)

    def test_xss_in_link(self,url):
        xss_test_script="<sCript>alert('Test')</scriPt>"
        url=url.replace("=","=" + xss_test_script) # replacing and adding the payload on the URL after equal
        response=self.session.get(url)
        return xss_test_script.encode() in response.content# to check if Script is there in the webpage
           
    def test_xss_in_form(self,form,url):
        xss_test_script= "<sCript>alert('Test')</scriPt>"
        response= self.submit_form(form,xss_test_script,url)
        return xss_test_script.encode() in response.content# to check if Script is there in the webpage
           





        

        