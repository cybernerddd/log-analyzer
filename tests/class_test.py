import sys
import os

# Add the parent directory to Python's search path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Now this import will work perfectly
from analyzer import LogAnalyzer

logs = LogAnalyzer("access.log")
# print(logs.load_file())
# print(logs.count_lines())
# print(logs.count_errors())
# print(logs.count_keyword("FAILED"))
# print(logs.find_logs("FAILED"))


logs2 = LogAnalyzer("login_logs.log")
logs2.load_file()
# print(logs2.count_lines())
# print(logs2.extract_ips())
# print(logs2.count_ip("192.168.1.15"))
# print(logs2.top_ip())
# print(logs2.detect_bruteforce())
# print(logs2.count_user_agent("curl"))

agent_logs = LogAnalyzer("user_agent.logs")
agent_logs.load_file()
# print(agent_logs.count_user_agent("curl"))
# print(agent_logs.find_user_agent("curl"))
print(agent_logs.list_suspicious_agents())