import os
from config import (
    suspicious_agents, 
    status_codes,
    http_methods
)

class LogAnalyzer(object):
    """A log analyzing class"""

    def __init__(self, log):
        """pass in a log file path"""
        self.log = log
        self.lines = []

    def load_file(self):
       """reads the log file""" 

       with open(self.log) as file:
        # save lines in lines list

        self.lines = file.readlines()
       return self.lines

    def count_lines(self):
       """
       Returns the total number
       of log entries.
       """
       return len(self.lines)

    def count_errors(self):
       """
       returns the total number of
       ERROR alerts.
       """
       error_count = 0
       for lines in self.lines:
           if "ERROR" in lines:
               error_count += 1
       return error_count

    def count_keyword(self, keyword):
       """
       keyword is a str you input,
       returns the number of logs containing that
       """
       matches = 0
       for lines in self.lines:
            if keyword in lines:
                matches += 1
       return matches

    def find_logs(self, keyword):
       """
       returns a list of logs matching
       input keyword
       """
       match = []
       for line in self.lines:
             match.append(line)
       return match

        # -------------------------
        # IP Analysis
        # -------------------------

    def extract_ips(self):
        """
        returns all IP's as a list
        """
        all_ips = []

        for line in self.lines:
            current_line = line.split()
            if not current_line: # skip empty lines
                continue

            ip = current_line[0]
            parts = ip.split(".")

            valid = len(parts) == 4
            
            if len(parts) == 4:
                valid = True

            for part in parts:
                if not part.isdigit():
                    valid = False
            # remove duplicates
            if ip in all_ips:
                valid = False
            
            if valid:
                all_ips.append(ip)

        return all_ips

    def count_ip(self, ip):
        """
        input: ip, 
        returns the number of requests
        coming from IP
        """
        count_ip = 0

        for line in self.lines:
            if ip in line:
                count_ip += 1
        return count_ip

    def unique_ips(self):
        """returns unique IP's,
        ips that appear ones."""
        unique = []

        for ip in self.extract_ips():
            if self.count_ip(ip) == 1:
                unique.append(ip)

        return unique

    def top_ip(self):
        """
        returns the IP that appears the most
        """
        high_counter = 0 # keep count of the hightest count

        for ip in self.extract_ips():
            count = self.count_ip(ip)

            if count > high_counter:
                high_counter = count

                # save the highest "ip"
                highest = ip
        return highest

    def count_failed(self, ip):
        """
        Returns the total number of failed
        login attempts for the given IP.
        """
        count = 0
        for line in self.lines:
            if ip in line and "FAILED LOGIN" in line:
                count += 1

        return count

    def detect_bruteforce(self):
        """
        Detects and returns IPs
        that are brute-forcing the service
        through failed requests.
        """ 
        brute_ips = []

         # Loop through all extracted IPs
        for ip in self.extract_ips():

            counter = self.count_failed(ip)       

            if counter >= 5 and ip not in brute_ips:
                brute_ips.append(ip)

        return brute_ips

        # -------------------------
        # User-Agent Analysis
        # -------------------------

    def count_user_agent(self, agent):
        """
        input: str,
        Returns the total count of a given 
        User-Agent
        """
        count = 0
        for line in self.lines:
            if agent in line:
                count += 1

        return count

    def find_user_agent(self, agent):
        """
        input: user-agent 'str',
        returns a list of all matching requests
        containing the agent
        """
        agent_match = [line for line in self.lines if agent in line]

        if not agent_match:
            return f"No request containing agent: {agent}"
        
        return agent_match

    def list_suspicious_agents(self):
        """
        Returns a list of all suspicious
        User-Agents in the logs, a message if None.
        """
        suspicious_results = [] # holds the confirmed agents

        for agent in suspicious_agents:
            # agent is curl,sqlmap, burp...
            count = self.count_user_agent(agent)

            if count > 0:
                suspicious_results.append(agent)

        if not suspicious_results:
            return f"YaY! No suspicious request found."

        return suspicious_results

        # -------------------------
        # Status Code Analysis
        # -------------------------

    def count_status(self, status):
        """
        input: str; status code,
        returns total count of responses with
        the exact status code
        """
        return self.count_keyword(status)

    def find_status(self, status):
        """
        input: status code 'str',
        returns a list of all responses
        of that code.
        """
        code_match = [line for line in self.lines if status in line]

        if not code_match:
            return f"No response containing status code: {status}"

        return code_match

    def most_common_status(self):
        """
        Returns the most frequent response
        status code in the logs..
        """
        highest_count = 0
        most_common = None

        for code in status_codes:
            # code is 200, 301...
            count = self.count_status(code)

            # compare to the highest
            if count > highest_count:
                highest_count = count
                most_common = code

        return most_common, highest_count

    # -------------------------
    # HTTP Method Analysis
    # -------------------------

    def count_method(self, method):
        """
        Returns the total count for the given HTTP method.
        """
        assert method in http_methods, "input must be a valid HTTP method."
        return self.count_keyword(method)

    def find_method(self, method):
        """
        input: HTTP method 'str',
        returns a list of all requests
        of that method.
        """
        assert method in http_methods, "input must be a valid HTTP method."
        method_match = [line for line in self.lines if method in line]
        return method_match

    def top_method(self):
        """returns the top request"""
        highest_count = 0
        highest_req = None

        for method in http_methods:
            count = self.count_method(method)

        # compare the higheest req
            if count > highest_count:
                highest_count = count
                highest_req = method

        return highest_req

    #########################
    #########################
    # DETECT DIRECTORY BRUTEFORCE #
    #########################

    def detect_directory_busting(self):
        """
        detect directory bruteforce from suspicious actions.
        """
        DIRECTORY_BUST_THRESHOLD = 15
        suspicious_list = [] 

        ips = self.extract_ips()
 
        for ip in ips:
            urls = []
            # find the URL that belongs to the ip
            # assuming index 2 contains the URL path, 
            # change this if needed.
            for line in self.lines:
                parts = line.split()
                line_ip = parts[0]

                # check if the current ip owns the current line
                if line_ip == ip:
                    url_path = parts[2]

                    # append path to urls list
                    if url_path not in urls:
                        urls.append(url_path)

                # check if it passses the benchmark or 15

            if len(urls) >= DIRECTORY_BUST_THRESHOLD:
                suspicious_list.append(ip)

        return suspicious_list
            

        
        
            
            



        






            







        


               


                


            

    
       
