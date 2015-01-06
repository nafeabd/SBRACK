SBRACK - Design and implementation of RBAC model for linux kernel (3.14.17)


1.Introduction:

In an environment capable of having many users and each user having different set of capabilities, 
it is very difficult to impart security within the system. Some of the access controls like MAC 
and DAC may not be the perfect suit for this kind of scenarios. Role-Based Access control (RBAC) 
would the ideal solution to ensure security and to manage different capabilities of users. 
The key idea in RBAC is that access decisions are based on roles that individual users will have. 
Users are mapped to roles and hence roles define the security aspects/constraints to users. 
In practical sense as roles generally don’t tend to change more often whereas changes in the users 
within a organization is more frequent, managing the assignments by ensuring security with help of RBAC is easy.

2.Purpose:

The main purpose of this project is to design and implement RBAC model for Linux kernel. 
This model is implemented as kernel level reference monitor and uses Linux Security Module (LSM) API’s.  

3.Implementation:

Linux Security Modules (LSM) is a framework that allows Linux to support security models. 
Even the official Linux kernel security models like SElinux, AppArmor uses LSM framework. 
Our RBAC security implementation is designed and implemented using LSM framework which provides 
many hooks and provides a way to control access to kernel data structures. 
The main advantage of using LSM is to avoid incomplete mediation and we can concentrate mainly
about implementing security policies and the framework takes care of inserting hooks wherever necessary in kernel code.

The below diagram helps to understand about LSM functionality
	 
Source:   http://blog.ptsecurity.com/2012/09/writing-linux-security-module.html


This project implementation is confined to certain inode access functions of interest. 
The other functions will be bypassed as per existing security policies in the system.

4.Functionalities:

The administrator or the root user can manage the below functionalities in this security model.
4.1) Add Roles
4.2) Delete Roles
4.3) Add Users to Roles
4.4) Add Roles to Operations


  4.1 Add Roles:
      The administrator can add roles to the existing system. Particular checks are employed if 
      same role is added again to the system.

  4.2 Delete Roles:
      This functionality is exact opposite of above-mentioned function, which deletes existing roles from the system.

  4.3 Add Users to Roles:
      This functionality describes about the mapping between users and roles. For a given user 
      admin can specify the appropriate role to map with from the system.

  4.4 Add Roles to Operations:
      This functionality describes about the mappings between roles to respective operand 
      (in general will be either regular files or directories) and the respective operations that are permitted.

5. Permitted Operations

  Most of the inode operations like mkdir, rmdir, rename, delete, set attributes 
  and create are handled and some of the operations which operate on special type of files are 
  ignored and are out of scope of this project implementation.

6. Strategies and Assumptions

There are specific strategies that are employed to this project implementation.
1)	The kernel should be compiled with this module. Cannot be imported as loadable kernel module
  (for security reasons this feature was disabled in Linux kernel)
2)	At any point of time, user can only be active with a single role.

3)	All the RBAC security implementations/policies are confined to specific folder, 
    which would be the folder of our interest for this project and is located in the root directory.

4)	The policies database which specify all the policies are in /etc location and users are given with only read privilege.

5)	Appropriate permissions have to be given on files by default to test RBAC policies. 
    Otherwise DAC taken priority by default. For example to test this project specific access control policies, 
    on particular files of interest write permissions has to be given.
    
6)	If certain operation is performed on a particular file, which is not part of our specific 
    file system of interest, RBAC policies are bypassed and normal existing policies will apply.
    
7)	If specific policy is not mentioned in access control policies for a file of interest, then to 
    determine whether to permit or deny operation, this implementation traverses backwards through the parent
    dentries and checks for access policies of their parents to take necessary action.
    
8)	This implementation allows users to have multiple roles but only one role can be active at any time.

9)	A master script is implemented which is used by the administrator to control and manage access control policies for this implementation.

7.User Script Usage

User Script can be used to provide functionalities to administrator to maintain RBAC system.

To Add Roles:
./master.py –a Rolename

To Delete Role:
./master.py –d Rolename

To Add/Update User-Role mappings:
./master.py –u Username Rolename Status [Note:Status should be 1 for active and 0 for inactive]	

To Add/Update Role-Operation Mappings:
./master.py –o Rolename Operand [list of operations]

Note:List of operations can be mkdir,rmdir,rename,unlink,create and setattr
