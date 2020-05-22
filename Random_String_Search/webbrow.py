import time
import random
import numpy
from selenium import webdriver

depth = 0
search_string = []
s_nouns = ["A dude", "My mom", "The king", "Some guy", "A cat with rabies", "A sloth", "Your homie",
           "This cool guy my gardener met yesterday", "the Superman", "the Flash", "the Wonder-woman", "the Cat-woman"]
p_nouns = ["These dudes", "Both of my moms", "All the kings of the world", "Some guys", "All of a cattery's cats",
           "The multitude of sloths living under your bed", "Your homies", "Like, these, like, all these people",
           "Supermen", "The Avengers"]
s_verbs = ["eats", "kicks", "gives", "treats", "meets with", "creates", "hacks", "configures", "spies on", "retards",
           "meows on", "flees from", "tries to automate", "explodes"]
p_verbs = ["eat", "kick", "give", "treat", "meet with", "create", "hack", "configure", "spy on", "retard", "meow on",
           "flee from", "try to automate", "explode"]
infinitives = ["to make a pie.", "for no apparent reason.", "because the sky is green.", "for a disease.",
               "to be able to make toast explode.", "to know more about archeology."]


def sing_sen_maker():
    # Makes a random senctence from the different parts of speech. Uses a SINGULAR subject'''
    return str(random.choice(s_nouns) + str(' ') + random.choice(s_verbs) + str(' ') + (
            random.choice(s_nouns).lower() or random.choice(p_nouns).lower()) + str(' ') + str(' ') + random.choice(
        infinitives))


def browse(driver):
    global depth
    if depth < 2:
        elems = driver.find_elements_by_xpath("//a[@href]")
        elements = []
        list = [True, False]
        prob = [0.05, 0.95]
        for elem in elems:
            elements.append(elem.get_attribute("href"))
        number_of_links_to_explore=int(random.uniform(1,10))
        links_to_fetch=[]
        for _ in range(number_of_links_to_explore):
            links_to_fetch.append(int(random.uniform(1,len(elements))))
        for link_num in links_to_fetch:
            driver.get(elements[link_num])
            depth += 1
            browse(driver)



for i in range(100):
    search_string.append(str(sing_sen_maker()).replace(' ', '+'))
list = [True, False]
prob = [0.3, 0.7]
driver = webdriver.Firefox(executable_path="/home/ubu/Desktop/geckodriver", firefox_binary="/usr/bin/firefox")
try:
    for i in range(len(search_string)):
        string123 = "https://www.google.com/search?q=" + search_string[i] + "&start=" + str(i)
        matched_elements = driver.get(string123)
        print(driver.title)
        print(driver.current_url)
        val = numpy.random.choice(list, replace=True, p=prob)
        if val:
            print("Inside the 'if'")
            browse(driver)
        else:
            r = random.uniform(1, 10) or random.uniform(60, 100)
            print(f"Sleep :{r}")
            time.sleep(r)
except Exception as e:
    print(f"Exception:{e}")
driver.close()
