#!/usr/bin/python

import re
import argparse
import sys
import os
from pwd import getpwnam
URCONFIG = "/etc/secrbac/policies.db/user_roles_map.config"
ROCONFIG = "/etc/secrbac/policies.db/roles_op_map.config"
ROLELIST = "/etc/secrbac/policies.db/roles.txt"
NO_OPS = 6


operations = ['mkdir','rmdir','create','unlink','rename','setattr']
ops = {}
count = 0
for i in operations:
        ops[i] = count
        count = count + 1

#Add roles to roles.txt
def addRoles(role):
        with open(ROLELIST,"a") as f:
                f.write(role.strip()+"\n")
        return

def addUsertoRole(user,role,status):
        with open(URCONFIG,"a") as f:
                f.write(user.strip()+","+role.strip()+","+str(status)+"\n")
        return

#OPERATIONS may be list
def addOptoRole(role,inode,oper):

        with open(ROCONFIG,"a") as f:
                f.write(role.strip()+","+str(inode)+","+oper.strip()+'\n')
        return

def removeRoles(role):
        #Also remove columns effecting in other files
        with open(ROLELIST,"r") as f:
                lines = f.readlines()
        with open(ROLELIST,"w") as f:
                for line in lines:
                        if role not in line:
                                f.write(line.strip()+"\n")
	with open(URCONFIG,"r") as f:
                lines = f.readlines()
        with open(URCONFIG,"w") as f:
                for line in lines:
                        if role not in line:
                                f.write(line.strip()+"\n")
	with open(ROCONFIG,"r") as f:
                lines = f.readlines()
        with open(ROCONFIG,"w") as f:
                for line in lines:
                        if role not in line:
                                f.write(line.strip()+"\n")

        return


#Update role of existing USER
def updateRoles(user,newrole,status):

        with open(URCONFIG,"r") as f:
                lines = f.readlines()
	l = []
	for line in lines:
         	if line.strip().split(',')[0] == user and line.strip().split(',')[2] == '1':
                     	a = line.strip().split(",")
			new = a[0]+","+a[1]+","+"0"
                        #f.write(new.strip())
			if new not in l:
				l.append(new)

                else:
                        #f.write(line.strip() + "\n")
			if line.strip() not in l:
				l.append(line.strip())
		#f.write(str(user)+","+newrole.strip()+","+status+"\n")
	p = str(user)+","+newrole.strip()+","+str(status)
	if p not in l:
		l.append(p.strip())

	with open(URCONFIG,'w') as f:
		for i in l:
			f.write(i+"\n")
		
        return



#def updateUsertoRole():

#newops is single or list?
def updateOptoRole(role,operand,newops):

        with open(ROCONFIG,"r") as f:
                lines = f.readlines()
        with open(ROCONFIG,"w") as f:
                for line in lines:
                        if role in line and str(operand) in line:
                                new = line.replace(line.strip().split(',')[2],newops)
                                f.write(new)
                        else:
                                f.write(line)

def isRoleExists(role):
	with open(ROLELIST,'r') as f:
		for line in f:
			if line.strip() == role:
				return True
	return False

def error(message):
	sys.stderr.write("Error: %s\n"%message)
	sys.exit(1)
	
def userCheck(user):
	
	with open(URCONFIG,"r") as f:
		for line in f:
			if str(user) == line.strip().split(',')[0] and line.strip().split(',')[2] == '1':
				return True
	return False
			

def getuid(user):
	try:
		userid = getpwnam(user).pw_uid
		return userid
	except Exception,e:
		print "User Does not Exist!",e
		sys.exit(1)

def getInodeNo(path):
	try:
		inodeno = os.stat(path).st_ino
		return inodeno
	except Exception,e:
		print "Invalid Operand:\n",e
		sys.exit(1)
			
def isRoleOperandExists(role,operand):

	with open(ROCONFIG,"r") as f:
		for line in f:
			if role == line.strip().split(',')[0] and str(operand) == line.strip().split(',')[1]:
				return True
	return False

def prepareOperations(oper):
	l = []
	count = 0
	while count < NO_OPS:
		l.append('0')
		count = count + 1
	for i in oper:
		l[ops[i]] = '1'

	return ''.join(l)
		
		
	
if __name__ == "__main__":

	parser =  argparse.ArgumentParser(description='Administrative Control over policies')
	parser.add_argument("-a","--addrole",help="Add Role[Usage: myscript -a role]")
	parser.add_argument("-d","--delrole",help="Delete Role[Usage: myscript -d role]")
	parser.add_argument("-u","--update",help="Add/Update User-Role Mapping[Usage: myscript -u user role status]",nargs=3)
	parser.add_argument("-o","--addops",help="Add/Update Operations[Usage: myscript -o role operant ops..]",nargs = '*')

	args = parser.parse_args()
	
	if args.addrole:
		role = args.addrole.strip()
		if isRoleExists(role):
			error("Role Already Exists\n")
		else:
			addRoles(role)
	elif args.delrole:
		role = args.delrole.strip()
		if isRoleExists(role) == False:
			error("Role Does Not Exists\n")
		else:
			removeRoles(role)
	elif args.update:
		user = str(getuid(args.update[0]))
		role = args.update[1]	
		status = args.update[2]
		if status not in ['0','1']:
			error("Invalid status ! status should be 1 for active else 0 for inactive.")
		if isRoleExists(role) == False:
			error("Role Does Not Exists\n")
		if userCheck(str(user)) == True and status == '1':
			decision = raw_input('User already has an active role.Do you want to override the active role for user[Y/N]?')
			if decision == 'Y' or decision == 'y':
				updateRoles(user,role,status)
			elif decision == 'N' or decision == 'n':
				sys.exit(1)
			else:
				error("Invalid Option Specified\n")
		else:
			addUsertoRole(str(user),role,status)
			
			
	elif args.addops:	
		role = args.addops[0].strip()
		if isRoleExists(role) == False:
			error("Role Does Not Exists\n")
		operand = getInodeNo(args.addops[1].strip())
		oper_list = []
		for i,j in enumerate(args.addops):
			if i > 1:
				oper_list.append(j)	
			
		if isRoleOperandExists(role,str(operand)) == True:
			
			op_str = prepareOperations(oper_list)
                        updateOptoRole(role,str(operand),op_str)


		else:
			op_str = prepareOperations(oper_list)
			addOptoRole(role,str(operand),op_str)
			
			
			

		
				
		


