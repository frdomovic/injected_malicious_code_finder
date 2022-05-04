import difflib
from pymongo import MongoClient
from datetime import datetime
from bs4 import BeautifulSoup as bs
from termcolor import colored
from bs4.element import NavigableString


def remove_text(soup):
    contents = []
    for element in soup.contents:
        if not isinstance(element, NavigableString):
            contents.append(remove_text(element))      
    soup.contents = contents
    return soup
def onlyTagsDB(dbpage):
    soup = bs(dbpage, 'lxml')
    for tag in soup.find_all():
        tag.attrs = {} 
    soup = remove_text(soup)
    return soup.prettify()

def getParsedPageDB(dbpage):
    soup = bs(dbpage, 'lxml')
    soup = remove_text(soup)
    return(soup.prettify())
def getParsedPageDBS(dbpage):
    soup = bs(dbpage, 'lxml')
    soup = remove_text(soup)
    return soup

def databaseiterator(iteration_number):
    html_tags_with_urls = ["<a>","<applet>","<api>","<area>","<base>","<blockquote>","<body>","<del>"
                        ,"<form>","<frame>","<head>","<iframe>","<img>","<input>","<ins>","<link>","<object>","<q>"
                        ,"<script>","<source>","<meta>","<audio>","<button>","<command>","<embed>","<input>","<track>",
                        "<video>","<formaction>"]
    bad_css=["z-index","margin","left","right","top","bottom","filter","opacity","height","width","letter-spacing"]
    bad_css_positioning =["margin","left","right","top","bottom","height","width"]
    client = MongoClient('mongodb://@localhost:27017/')
    db = client['websecradar']
    pages_collection = db.crawled_data_pages_v0
    url_collection = db.crawled_data_urls_v0
    firsthash = ""
    secondhash = ""
    index = 1
    pages_tested = 5000
    pages_with_changes = 0
    pages_with_malicious_code = 0

    for url in url_collection.find({}).limit(int(pages_tested)).skip(iteration_number):
            try:    
                arr_len =  len(url['checks'])
                firsthash = url['checks'][arr_len-1]['hash']
                try:
                    
                    secondhash = url['checks'][arr_len-2]['hash']
                    

                    if(firsthash != secondhash):
                        
                        name = (url['url'])
                        date1 = str(datetime.fromtimestamp( url['checks'][arr_len-1]['timestamp'])).split(" ")[0]
                        date2 = str(datetime.fromtimestamp( url['checks'][arr_len-2]['timestamp'])).split(" ")[0]
                        nameref =  date1+url['url']
                        nameref2 = date2+url['url']
                        name = name.replace("https://","")
                        name = name.replace("http://","")
                        if "/" in name:
                            name = name[0:name.index("/")]
                        name = str('./DIFFERENCES/'+str(index)+'_'+name+'.html')
                        
                        firstpage = ""
                        secondpage = ""
                        for obj in pages_collection.find({"hash":str(firsthash)}).limit(1):
                            firstpage = obj['page']

                        for obj in pages_collection.find({"hash":str(secondhash)}).limit(1):
                            secondpage = obj['page']
                        
                        first_parsed_page = onlyTagsDB(firstpage)
                        second_parsed_page = onlyTagsDB(secondpage)
                        
                        if(first_parsed_page != second_parsed_page):
                            
                            difference = "\n".join(difflib.Differ().compare(second_parsed_page.split("\n"),first_parsed_page.split("\n"))).replace(" ","")
                            diffCharArray = difference.split("\n")
                            new_added_tags = []
                            for line in diffCharArray:
                                if(len(line) > 1):
                                    if "+" == line[0]:
                                        new_added_tags.append(line.replace("+",""))
                            
                            continue_search = False
                            for line in new_added_tags:
                                if line.strip() in html_tags_with_urls:
                                    continue_search= True
                                    break
                            if(continue_search):   
                                parsed_page_attrs_new = getParsedPageDB(firstpage)
                                parsed_page_attrs_old = getParsedPageDB(secondpage)         
                                urls_on_page = set({})
                                security_index = 0
                                malicious_code = set()
                                c_sec1 = True
                                c_sec2 = True
                                c_sec3 = True
                                c_sec4 = True
                                c_sec5 = True
                                c_sec6 = True
                                c_sec7 = True
                                parsed = getParsedPageDBS(firstpage)
                                for tag in parsed.findAll({}):
                                    if(len(tag.attrs) > 0 ):
                                        for attribute_name in tag.attrs:
                                            inline_security_index = 0
                                            url_regex_lista = ["www","www.",".com",".org","https://","http://","ftp://","gopher://","file://"]
                                            if any(x in tag.attrs[attribute_name] for x in url_regex_lista):
                                                if(tag.attrs[attribute_name] != "http://www.w3.org/1999/xhtml" and "@" not in tag.attrs[attribute_name]):  
                                                    if(tag.name != "html"):
                                                        urls_on_page.add(tag.attrs[attribute_name])

                                            if(attribute_name == "hidden"):
                                                if(c_sec1):
                                                    security_index +=1
                                                    c_sec1 = False

                                            if(attribute_name == "style"):

                                                if(tag.name == "div" or tag.name == "p" or tag.name=="a"):
                                                    """
                                                        inline css code separated with ";" between attributes and
                                                        ":" between css name and value
                                                    """
                                                    lista_css_atributa = tag.attrs[attribute_name].split(";")

                                                    for css_name_value in lista_css_atributa:
                                                        
                                                        if(css_name_value != "" and ":" in css_name_value):

                                                            a = css_name_value.split(":")
                                                            if a[0].strip() in bad_css:
                                                                if(a[0].strip() == "z-index"):
                                                                    if(int(a[1]) < 10):
                                                                        if(c_sec2):
                                                                            security_index +=1
                                                                            c_sec2 = False
                                                                        inline_security_index +=1

                                                                elif a[0].strip() in bad_css_positioning:

                                                                    val = int(a[1].replace("px","").replace("vh","").replace("vw","").replace("rem","").replace("em","").replace("%","").replace("auto",""))
                                                                    if( val < -500 or val > 2500):
                                                                        if(c_sec3):
                                                                            security_index +=2
                                                                            c_sec3 = False

                                                                        inline_security_index +=2
                                                                    elif (val == 0):
                                                                        if(c_sec4):
                                                                            security_index +=1
                                                                            c_sec4 = False
                                                                        inline_security_index +=1
                                                                elif(a[0].strip() == "filter"):
                                                                    if(a[1] == "alpha(opacity=0)"):
                                                                        if(c_sec5):
                                                                            security_index +=1
                                                                            c_sec5 =False
                                                                        inline_security_index +=1
                                                                elif(a[0].strip() == "opacity"):
                                                                    if(float(a[1]) < 1):
                                                                        if(c_sec6): 
                                                                            security_index +=1
                                                                            c_sec6 =False
                                                                        inline_security_index +=1
                                                                elif(a[0].strip() == "letter-spacing"):
                                                                    if(a[1].strip() == "0px"):
                                                                        if(c_sec7):
                                                                            security_index +=1
                                                                            c_sec7 = False
                                                                        inline_security_index +=1
                                            if(inline_security_index >= 2):
                                                malicious_code.add(tag)
                                
                                if(len(urls_on_page) != 0):
                                        security_index += 2
                                if(security_index >= 4):
                                    
                                    pages_with_malicious_code += 1
                                    pages_with_changes +=1
                                    print(str(index)+"."+colored("[MALICIOUS]","red")+" SECURITY INDEX IS: "+str(security_index)+" || ",url['url'])
                                    difference = difflib.HtmlDiff(wrapcolumn=40).make_file(parsed_page_attrs_old.split("\n"),parsed_page_attrs_new.split("\n"),nameref2,nameref,True)
                                    with open(name,"w") as f:
                                        f.write(difference)
                                    tmp = []
                                    for line in malicious_code:
                                        tmp.append(str(line))
                                    printing_soup = bs("\n".join(tmp),'lxml')
                                    with open('./MALICIOUSCODE/'+str(secondhash)+'.html',"w") as x:
                                        x.write(printing_soup.prettify())
                                        x.write("\n\n\nXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
                                        x.write("\nURLS DETECTED ON PAGE:\n")
                                        for link in urls_on_page:
                                            x.write(str(link)+"\n")
                                else:
                                    print(str(index)+"."+colored("[NO MALICIOUS ELEMENTS]","yellow")+" SECURITY INDEX IS: "+str(security_index)+" || ",url['url'])
                                    pages_with_changes +=1
                            else:
                                print(str(index)+"."+colored("[NO MALICIOUS ELEMENTS]","magenta")+" THERE ARE CHANGES URL: ",url['url'])
                                pages_with_changes +=1
                    else:
                        print(str(index)+"."+colored("[HASH OK]","green")+" PAGES HAVE IDENTICAL HASH")
                    index += 1
                except:
                    try:
                        print(str(index)+"."+colored("[ERROR]","red")+" URL: ",url['url']," DOES NOT HAVE SAVED ANY _PREVIOUS_ VERSIONS")
                        index += 1
                    except:
                        print(colored("[ERROR]","red")+" COULD NOT GET PAGES")
                        index += 1
            except:
                try:
                    print(str(index)+"."+colored("[ERROR]","red")+"URL: ",url['url']," DOES NOT HAVE SAVED ANY VERSIONS")
                    index += 1
                except:
                    print(colored("[ERROR]","red")+" COULD NOT GET PAGES")
                    index += 1
    print(colored("\n\-\-\-\-\-\-\-\-\-\-\-\-\-\ \n","green"))
    print(colored("[DONE]: YES ","yellow"))
    print(colored("[STATISTICS]: ","yellow"))
    print(colored("[TESTED PAGES]: "+colored(str(pages_tested),"green"),"yellow"))
    print(colored("[CHANGED PAGES]: "+colored(str(pages_with_changes),"green"),"yellow"))
    print(colored("[MALICIOUS PAGES]: "+colored(str(pages_with_malicious_code),"green"),"yellow"))
    
    print(colored("[TESTED / CHANGED - RATIO]: "+colored(str(float(pages_with_changes/pages_tested)*100),"red"),"yellow" ))
    print(colored("[TESTED / MALICIOUS - RATIO]: "+colored(str(float(pages_with_malicious_code/pages_tested)*100),"red"),"yellow" ))
    if(pages_with_changes == 0):
        print(colored("[TESTED / CHANGED - RATIO]: "+colored(str(0),"red"),"yellow" ))
    else:  
        print(colored("[MALICIOUS / CHANGED - RATIO]: "+colored(str(float(pages_with_malicious_code/pages_with_changes)*100),"red"),"yellow" ))
    with open("stats.txt","a") as x:
        x.write(str(int(iteration_number/5000))+". ITERATION\n")
        x.write("\n[TESTED PAGES]:"+str(pages_tested))
        x.write("\n[CHANGED PAGES]: "+str(pages_with_changes))
        x.write("\n[MALICIOUS PAGES]: "+str(pages_with_malicious_code))
        x.write("\n[TESTED/MALICIOUS RATIO]: "+str(float(pages_with_malicious_code/pages_tested)*100))
        x.write("\n[TESTED/CHANGED RATIO]: "+str(float(pages_with_changes/pages_tested)*100))
        if(pages_with_changes > 0):
            x.write("\n[MALICIOUS / CHANGED]: "+str(float(pages_with_malicious_code/pages_with_changes)*100))
        x.write("\n_________________________________________________________________________________________________\n")



""""
    Main program -> sending iteration number for testing
"""

for i in range(13,25):
    databaseiterator(i*5000)

