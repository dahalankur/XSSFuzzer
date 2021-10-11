######################################
#           fuzzer.py                #
#      Ankur Dahal (10/01/2021)      #
#  Script to detect reflected XSS    #
#   vulnerabilities on websites      #
######################################
import os
import requests
import argparse
from bs4 import BeautifulSoup

vuln_count = 0
vuln_list = []


"""
extractForms
argument: webpage - the wepbage to be parsed (html)
returns: a bs4 object of html form elements
"""
def extractForms(webpage):
    soup = BeautifulSoup(webpage, "html.parser")
    return soup.find_all("form")


"""
urlToHTML
argument: url - the url of the website
returns: a string containing the html of the website
"""
def urlToHTML(url):
    try:
        page = requests.get(url)
    except:
        print(f"Please check that {url} is a valid URL.")
        exit()
    
    return page.text



"""
parseForms
argument: forms - a bs4 object of html form element
returns: a dictionary containing the parsed form information
"""
def parseForms(forms):
    # result is a list of dictionaries, each of which contains individual form's data
    result = []
    parsed_form_data = {}

    for form in forms:
        try:
            parsed_form_data['action'] = form['action'] if form.has_attr('action') else None
            parsed_form_data['method'] = form['method'] if form.has_attr('method') else None
            parsed_form_data['inputs'] = [inputs for inputs in form.find_all('input')]
            result.append(parsed_form_data)
        except:
            continue
    
    return result



"""
createPayload
argument: input_elem - a bs4 object that contains information about the input element
returns: a dictionary - the payload formed from the information from input_elem
"""
def createPayload(input_elem):
    if input_elem.has_attr('name'):
        payload = {input_elem['name'] : "default"}
    else:
        payload = {"token" : "default"}

    return payload




"""
injectPayload
argument: payload - the payload to be sent to the url
          input_elem - a bs4 object that contains information about the input element
          url - the url of the website to be scanned
          fuzz_list - the list of fuzzing words to be used
          method - the method that the form uses, "post" or "get"
returns: nothing; injects the payload to the url using the scripts given in the 
         fuzz_list and keeps track of any vulnerabilities found
"""
def injectPayload(payload, input_elem, url, fuzz_list, method):
    global vuln_count, vuln_list
    potential_textboxes = ["query", "token", "queries", "name", "field", "login", "id", "password", "identity", \
                            "id", "box", "enter", "status", "detail", "details", "text", "textbox"]
    is_textbox = (input_elem.has_attr('type') and input_elem['type'] == 'text') \
                 or (input_elem.has_attr('name') and input_elem['name'].lower() in potential_textboxes)
    
    # prioritize text boxes to avoid spending time on other elements like radio buttons
    # if not is_textbox: # need to uncomment this if a fuzz_list is small
    #     return
    try:
        with open(fuzz_list, 'r') as f:
            if input_elem.has_attr('name'):
                name = input_elem['name']
            else:
                name = 'token'
            scripts = f.read().split('\n')
            for num, script in enumerate(scripts):
                progress = "{:.3f}".format((num + 1) / len(scripts) * 100)
                print(f"Testing script #{num + 1}. Progress = {progress}% (press \33[34mCTRL+C\033[0m to stop and view summary)")
                payload[name] = script
                
                if method.lower() == "get":
                    response = requests.get(url, payload).text
                else:
                    response = requests.post(url, payload).text
                
                if payload[name] in response:
                    vuln_count += 1
                    vuln_list.append([input_elem, payload[name]])
                    print(f"\033[91mVulnerability found!\033[0m Vulnerability count = {vuln_count}")
            
    except:
        print(f"Cannot read from file {fuzz_list}. Please try again later.")
        exit()



"""
showSummary
argument: none
returns: nothing; prints the summary of the vulnerabilities found
"""
def showSummary():
    global vuln_list, vuln_count
    print("\n\n" + 20 * "=" + "\x1b[6;30;42mSUMMARY\x1b[0m" + 20 * "=" + "\n\n")
    print(f"{vuln_count} VULNERABILITIES FOUND!\n")
    print("Vulnerability summary: The \33[32melements vulnerable\033[0m along with the \33[31minjected script\033[0m are shown below:\n")
    for count, vuln in enumerate(vuln_list):
        print(f"\33[34m\t# {count + 1}:\033[0m\t\33[32m{vuln[0]}\033[0m\t\33[31m{vuln[1]}\033[0m")
    print()



"""
getFuzzLists
argument: seclists_dir - the location of the Seclists repo
returns: the list of fuzzing lists present in the seclists_dir directory
"""
def getFuzzLists(seclists_dir):
    if seclists_dir:
        return [file for file in os.listdir(seclists_dir) if file[-4:] == ".txt"]
    return []




def main():
    url = "http://www.cs.tufts.edu/comp/120/hackme.php" 
    parser = argparse.ArgumentParser(description = "A python script that detects reflected XSS vulnerability in websites")
    parser.add_argument("-u", required = False, dest = "url", help = f"The URL of the website. If no URL is provided, the default URL {url} is used.")
    parser.add_argument("-f", required = False, dest = "fuzz_list", help = "A text file that contains fuzz lists. A default fuzz list will be used if nothing is provided.")
    parser.add_argument("-s", required = False, dest = "seclists_dir", help = "The location of the SecLists repository on this machine.")
    args = parser.parse_args()
    
    url = args.url if args.url else url
    fuzz_list = args.fuzz_list if args.fuzz_list else "default-fuzz"
    seclists_dir = None
    use_seclists = False

    if args.seclists_dir:
        if args.seclists_dir[-1] == "/":
            seclists_dir = args.seclists_dir + "Fuzzing/XSS/"
        else:
            seclists_dir = args.seclists_dir + "/Fuzzing/XSS/"

    # create a file consisting of a single script if no lists provided
    if fuzz_list == "default-fuzz":
        with open("default-fuzz.txt", "w") as f:
            f.write("<script>alert(1)</script>")
        fuzz_list += ".txt"
    
    # if -s flag is provided, check if the directory exists
    if seclists_dir:
        if not os.path.isdir(seclists_dir):
            print(f"Error: Please check that {seclists_dir} is a valid path.")
            exit()
        else:
            use_seclists = True

    webpage = urlToHTML(url)
    forms = extractForms(webpage)
    parsed_forms = parseForms(forms) # list of dicts containing all the form data
    response = ""

    print("\t\t\x1b[6;30;42mStarting vulnerability scan...\x1b[0m")
    
    # for each form, in each textbox, inject the payload and check the response
    for form in parsed_forms:
        try:
            method = form['method'].lower() if form['method'] else None
            inputs = form['inputs']
            for input_elem in inputs:
                payload = createPayload(input_elem)
                if use_seclists:
                    fuzz_list = getFuzzLists(seclists_dir)
                    for f_list in fuzz_list:
                        file_path = f"{seclists_dir}{f_list}"
                        injectPayload(payload, input_elem, url, file_path, method)
                else:
                    injectPayload(payload, input_elem, url, fuzz_list, method)
        except:
            continue

    showSummary()



if __name__ == "__main__":
    main()