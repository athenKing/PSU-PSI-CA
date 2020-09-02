import json

fr = open("alice.data",'r')
alice = json.loads(fr.read())
fr.close()

fr = open("bob.data",'r')
bob = json.loads(fr.read())
fr.close()

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