# -*- coding: utf-8 -*- 
import csv
import re
from collections import defaultdict
import math
import random
import get_clusters
import operator 


systems_popularity = defaultdict(set) #system:<people>
people_network = defaultdict(set) #person:<systems>
system_list = defaultdict(int)
optimal_system_list = defaultdict(int)
email_system = defaultdict(set) #email:<people>
user_systems = list()
leaked_users = defaultdict(set)
leaked_number = set()
system_users = list()
histogram = defaultdict(int)

system_filter = ["collection4g", "collection4eu", "collection4u", "onlinerspambot", "collection1", "exploit"]

media_system_used = 0


def reset():
	global systems_popularity 
	global people_network
	global system_list
	global optimal_system_list 
	global email_system 
	global user_systems 
	global system_users 
	global histogram
	global media_system_used

	systems_popularity = defaultdict(set) #system:<people>
	
	people_network = defaultdict(set) #person:<systems>
	system_list = defaultdict(int)
	optimal_system_list = defaultdict(int)
	email_system = defaultdict(set)
	user_systems = list()
	system_users = list()
	histogram = defaultdict(int)
	media_system_used = 0

def main(filter=False,optimize_systems=False,leaked_people_filter=False):
	
	data_load(filter,leaked_people_filter)
	
	
	### Summary of the analysis
	print("")			
	print("")			
	print(str(len(system_list)) + " unique systems affected.")
	print(str(len(people_network)) + " unique people analyzed.")
	print("")
	
	person_usage_analysis()
	system_popularity_analysis(optimize_systems)
	
	#random_1 = random.choice(list(people_network.keys()))
	#print("\t USER 'cristiante' : " + str(people_network["cristiante"]))
	#print("")
	#analyze_set(["us"])
		
	for person in people_network:
		histogram[len(people_network[person])] =  histogram[len(people_network[person])] +1
	
	print (histogram)
	
	
def analyze_set(systems_to_join = ["linkedin","instagram","hotmail","facebook"]):
	global systems_popularity
	print("\t Users that use: "+ str(systems_to_join))
	res = systems_popularity[systems_to_join[0]]
	for system in systems_to_join[1:]:
		res = res&systems_popularity[system]	
	print(res)
	
def system_popularity_analysis(optimize_systems):
	### Higher and lesser number of systems used by someone.
	global media_system_used
	withmore = 0
	withless = math.inf
	
	for system in systems_popularity:
		if len(systems_popularity[system]) > withmore:
			withmore = len(systems_popularity[system])
		if len(systems_popularity[system]) < withless:
			withless = len(systems_popularity[system])
		if len(systems_popularity[system]) > 100 or not optimize_systems:
			optimal_system_list[system] = systems_popularity[system]
		system_users.append((system,len(systems_popularity[system])))
		
	
	if optimize_systems:
		print("Optimizing and reducing... Using ", len(optimal_system_list), "/" , len(system_users) , " systems. Using systems used more than average are considered.")
	
	print("The system with the most users  has " + str(withmore))
	print("The system with the less users has " + str(withless))
	
	print("")
	system_users.sort(key = operator.itemgetter(1), reverse = True)
	for x,y in system_users[:3]:
		print("\t",x, "used by",y, "users (",round(y*100/len(people_network)),"%).")
	print(system_users[:10])
	print("")
	print("")	

	
def person_usage_analysis():
	### Higher and lesser number of systems used by someone.
	global media_system_used
	global leaked_number	
	withmore = 0
	withless = math.inf
	total_instances = 0
	for persona in people_network:
		if len(people_network[persona]) > withmore:
			withmore = len(people_network[persona])
		if len(people_network[persona]) < withless:
			withless = len(people_network[persona])
		total_instances = total_instances + len(people_network[persona])
		user_systems.append((persona,len(people_network[persona])))
	media_system_used = get_media(total_instances,people_network)
		
	print("There are a total of " + str(total_instances) + " correletions among systems and users.")
	print(str(media_system_used) + " systems per person")
	print("Standard deviation: "+ str(get_standard_deviation(media_system_used,people_network)))
	
	
	print("")	
	print("The person with the most system has " + str(withmore))
	print("The person with the less system has " + str(withless))
	print("")
	user_systems.sort(key = operator.itemgetter(1), reverse = True)
	for x,y in user_systems[:10]:
		print("\t",x, "is using ",y, "systems (",round(y*100/len(user_systems)),"%).")
	print(system_users[:10])
	print("")
	print("")	
	
	print("")
	user_systems.sort(key = operator.itemgetter(1), reverse = False)
	for x,y in user_systems[:10]:
		print("\t",x, "is using ",y, "systems (",round(y*100/len(user_systems)),"%).")
	print(system_users[:10])
	print("")
	print("")	
	user_systems.sort(key = operator.itemgetter(1), reverse = True)
	print("")
	print("Leaked people: " + str(len(leaked_number)))
	#print(leaked_users)
	
def data_load(filter=False,leaked_people_filter=False):
	global system_filter
	global email_system
	global leaked_users
	global leaked_number
	if not filter:
		system_filter = []
	print (leaked_number)	
	with open('total.csv', newline='', encoding="utf8") as csvfile:
		spamreader = csv.reader(csvfile, delimiter=';', quotechar='"')
		data_list = list(spamreader)
		data_list.pop(0)
		person_email = set()

		for row in data_list:
			system = ""
			persona = ""
			
			if "sfp_accounts" in str(row[1]):
				if "Category" in row[3]:
					persona = row[2]
					substring = row[3].split(")")[0]
					system = substring.split(" ")[0]
					#category = substring.split(" ")[2]
					
			if "sfp_haveibeenpwned" in str(row[1]):	
				busqueda = re.compile("""(.*)\s\[(.*)\]""")
				m=re.search(busqueda,str(row[3]))
				persona = row[2]
				system = m.group(2)

			if "sfp_citadel" in str(row[1]):	
				busqueda = re.compile("""(.*)\s\[(.*)\]""")
				m=re.search(busqueda,str(row[3]))
				persona = row[2]
				system = m.group(2)
			sannitized_system = system_stringPreparation(system)		
			sannitized_persona = person_stringPreparation(persona)
			if (leaked_people_filter == False) or (sannitized_persona in leaked_number):
				if sannitized_system != "":
					update_lists(sannitized_persona,sannitized_system)
				
				if "@" in persona:
					person_email.add(persona)
					sannitized_system = get_email_service(persona)
					
					email_system[persona.split("@")[1]].add(sannitized_persona)
					update_lists(sannitized_persona,sannitized_system)
			#print("Email of wanted people: ", person_email)
	
def update_lists(persona,system):
	people_network[persona].add(system)
	if system not in system_filter:
		system_list[system] = system_list[system]+1
		systems_popularity[system].add(persona)
	else:
		leaked_users[system].add(persona)
		leaked_number.add(persona)
	
def person_stringPreparation(person):
	person = person.split("@")[0]
	person = person.lower()
	person = person.replace("é", "e")
	person = person.replace(" ","")
	person = person.replace(".","")
	person = person.replace("_","")
	person = person.replace("-","")
	return person	

def get_email_service(person):
	system = person.split("@")[1]
	system = system.split(".")[0]
	return system
	
def get_standard_deviation(media,people_network):
	sum_of_deviation = 0
	for persona in people_network:
		media_distance = media-len(people_network[persona])
		sum_of_deviation = sum_of_deviation + (media_distance*media_distance)
	return round(math.sqrt(sum_of_deviation/len(people_network.keys())),2)

def get_media(total_instances,people_network):
	media_system_used = round(total_instances/len(people_network),2)
	return media_system_used
	
def system_stringPreparation(system):
	system = system.split(".")[0]
	system = system.lower()
	system = system.replace("é", "e")
	system = system.replace(" ","")
	system = system.replace(".","")
	system = system.replace("_","")
	system = system.replace("-","")
	return system
	


main(filter=True, optimize_systems=False)

for email in email_system:
	print (str(email)+":"+str(len(email_system[email])))
analyze_set(["facebook","instagram","twitter","linkedin"])
