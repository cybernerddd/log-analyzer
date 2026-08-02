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

    
       
