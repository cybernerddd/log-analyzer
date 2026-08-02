import os

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


            

    
       
