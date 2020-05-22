import argparse
import time
import random
import dns.resolver
import numpy
import pandas as pd

list = []
links = []
prob = []
total = 0
parser = argparse.ArgumentParser(description="DNS Query Engine Parser")
parser.add_argument('--file', metavar='File with Domains and Prob', type=str, nargs='?', default="top500Domains.csv")
parser.add_argument('--time', metavar='Run time for the Engine', type=int, nargs='?', default=1000)
parser.add_argument('--inttime', metavar='Max Time Interval', type=int, nargs='?', default=100)
args = parser.parse_args()
filename = args.file
run_time = args.time
df = pd.read_csv(filename)
df.dropna(how='all')
record_type = ['A']  # , 'AAAA', 'MX', 'NS', 'TXT', 'SOA']

for name in df['Domain']:
    if name != '0':
        list.append(name)
for number in df['Links']:
    number = str(number).replace(',', '')
    if int(number) != 0:
        links.append(number)
        total += int(number)
for link in links:
    prob.append(int(link) / total)
exit_time = time.time() + run_time
while time.time() < exit_time:
    try:
        name = numpy.random.choice(list, replace=True,
                                   p=prob)  # get a DNS name at random but using the probabilities and then use it for the DNS Query
        for qtype in record_type:
            answer = dns.resolver.query(name, qtype, raise_on_no_answer=False)
            if answer.rrset is not None:
                print(answer.rrset)
        r = random.uniform(1, args.inttime)
        print(r)
        time.sleep(r)
    except Exception as e:
        print(e)
    except dns.exception.DNSException as e:
        print("Query Failed!")
print("Shutting Down the DNS Query Engine")
