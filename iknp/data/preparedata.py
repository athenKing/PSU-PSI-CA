
import pickle 
import random
import json

total = 80000

scope = 100*total

alice =[]
bob =[]

aliceDict={}
bobDict={}

for i in range(total):
	ele = random.randint(1, 2*total)
	if ele not in aliceDict:
		alice.append( ele )
		aliceDict[ele] = 1

for i in range(7*total):
	ele = random.randint(0, 5*total)
	if ele not in bobDict:
		bob.append( ele )
		bobDict[ele] = 1

fw = open("alice.data",'w')
fw.write(json.dumps(alice))
fw.close()


fw = open("bob.data",'w')
fw.write(json.dumps(bob))
fw.close()


print("Alice len is: ",len(alice))
print("Bob len is: ",len(bob))

def union(list1,list2):
	intersection = 0
	for a in list1:
		if a in list2:
			intersection += 1

	print("Union value is: ",len(list1)+len(list2) - intersection)
	print("Intersection value is: ",intersection)

union(alice,bob)
