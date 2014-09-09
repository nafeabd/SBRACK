/*
*	author :Nafees Ahmed Abdul
*	
*	date   :8th Sep , 2014

*/
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/capability.h>
#include <linux/unistd.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/namei.h>
#include <linux/string.h>
#include <linux/export.h>
#include <linux/shm.h>
#include <linux/init.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/linkage.h>
#include <linux/string.h>
#include <linux/stddef.h>

#define MODULE_NAME "secrbac"
#define URCONFIGFILE "/etc/secrbac/policies.db/user_roles_map.config"
#define ROCONFIGFILE "/etc/secrbac/policies.db/roles_op_map.config"
#define MEM_CHUNK 4096
#define LEN 4096
#define PATH "/testorg"

/* inode security operations */
static int secrbac_auth_check(struct inode *inode , char *operation,struct dentry *dentry)
{
	struct file *filp1 = NULL;
	struct file *filp2 = NULL;
	struct file *fip = NULL;
	long int root_inode;
        int rbytes,wbytes;
        mm_segment_t oldfs;
        void *ker_buf1;
	void *ker_buf2;
        int retval =0;
	int flag = 0;
	char *line = NULL;
	long int userid,file_id ;
	char *role = NULL;
	char *check_role = NULL;
	char *op = NULL;
	char *data = NULL;
	int index = 0;
	int i;
	int flag1 = 1;
	long int status;
	const char  *options[6] = {"mkdir","rmdir","create","unlink","rename","setattr"};
	fip = filp_open(PATH,O_RDONLY, 0);
        if (!fip || IS_ERR(fip)) {
                retval = (int) PTR_ERR(fip);
                printk(KERN_ERR "\nError : Getting Root inode value");
                goto out;
        }

        root_inode = fip->f_dentry->d_inode->i_ino;
  
	for(i = 0; i < sizeof(options) ; ++i)
	{
		if(options[i] == operation)
		{
			index = i;
			break;
		}
		
	}
        ker_buf1 = kmalloc(MEM_CHUNK, GFP_KERNEL);
        if (!ker_buf1) {
                retval = -ENOMEM;
                printk(KERN_ERR "\n Error: problem with memory allocation");
                goto out;
        }
	ker_buf2 = kmalloc(MEM_CHUNK, GFP_KERNEL);
	if (!ker_buf2) {
                retval = -ENOMEM;
                printk(KERN_ERR "\n Error : problem with memory allocation");
                goto out_ker_buf1;
        }
        /*open configuration file*/
        oldfs = get_fs();
        set_fs(KERNEL_DS);
        filp1 = filp_open(URCONFIGFILE,O_RDONLY, 0);

        if (!filp1 || IS_ERR(filp1)) {
                retval = (int) PTR_ERR(filp1);
                printk(KERN_ERR "\nError : Opening output file");
                goto out_ker_buf2;
        }
	

        if (!filp1->f_op->write) {
                retval = (int) PTR_ERR(filp1);
                printk(KERN_ERR "\n Error: File doesn't allow writes");
                goto out_ker_buf2;
        }
	filp1->f_pos = 0;	
	do {
                rbytes = vfs_read(filp1, ker_buf1 ,LEN, &filp1->f_pos);
                if (rbytes < 0) {
                        printk(KERN_ERR "\n Error:reading the URCONFIGFILE");
                        retval = rbytes;
                        goto out_exp;
                }
		data = (char *) ker_buf1;		
		while(1)
		{
			if(data == NULL){
				flag = 0;
				break;
			}
			line = strsep(&data,"\n");
			if(strlen(line) <= 0){
				flag = 0;
				break;
			}
			kstrtol(strsep(&line,","),10,&userid);
			if (userid == get_current_user()->uid.val){
				role = strsep(&line,",");
				kstrtol(strsep(&line,","),10,&status);
				if(status){	
					printk("role :%s\n",role);
					
					flag = 1;
					break;
					break;
				}
			}
			
		
		}
		if(flag == 0){
			/*Role not found*/
			retval = 0;
			goto out_exp;
		}
		
	} while (rbytes >= LEN);

	filp2 = filp_open(ROCONFIGFILE,O_RDONLY,0);

	if (!filp2 || IS_ERR(filp2)) {
                retval = (int) PTR_ERR(filp2);
                printk(KERN_ERR "\nError : Opening output file");
                goto out_exp;
        }


        if (!filp2->f_op->write) {
                retval = (int) PTR_ERR(filp2);
                printk(KERN_ERR "\n Error: File doesn't allow writes");
                goto out_exp;
        }

	filp2->f_pos = 0;
	flag = 0;
	do {
		wbytes = vfs_read(filp2, ker_buf2 ,LEN, &filp2->f_pos);
                if (wbytes < 0) {
                        printk(KERN_ERR "\n Error:reading ROCONFIGFILE file");
                        retval = wbytes;
                        goto out_exp1;
                }
		data = (char *) ker_buf2;
                while(1)
                {
			if(data == NULL)
			{
				flag1 = 0;
				break;
			}
                        line = strsep(&data,"\n");
			if(strlen(line) <= 0)
			{	flag1 = 0;
				break;
			}
                        check_role = strsep(&line,",");
                         if (!strcmp(role,check_role)) {
				kstrtol(strsep(&line,","),10,&file_id);
				if (file_id == inode->i_ino) {
					op = strsep(&line,",");
					if(op[index] == '1'){
						retval = 0;
						printk("Access OK!\n");
						goto out_exp1;
					}
						
					else{
						printk("Access denied Mr User\n");
						retval =  -EACCES;
						goto out_exp1;
					}	
				}
			}

			
                }
		if(flag1 == 0){
			printk("policy not defined\n");
			
			goto out_exp1;
		}

	}while(wbytes >= LEN);

        set_fs(oldfs);
	out_exp1:
                if (filp2 != NULL)
                        filp_close(filp2,NULL);
        out_exp:
                if (filp1 != NULL)
                        filp_close(filp1,NULL);
        out_ker_buf2:
                kfree(ker_buf2);

        out_ker_buf1:
                kfree(ker_buf1);
        out:
		if(flag1 == 0){
			if (dentry->d_inode->i_ino != root_inode){
				retval = secrbac_auth_check(dentry->d_parent->d_inode,operation,dentry->d_parent);
			}
			else{
				retval = -EACCES;
			}

		}
                return retval;

}

static int applyRBAC(struct dentry *dentry)
{
	struct file *fip = NULL;
	long int root_inode;
	int retval = 0;
	fip = filp_open(PATH,O_RDONLY, 0);
	if (!fip || IS_ERR(fip)) {
                retval = (int) PTR_ERR(fip);
                printk(KERN_ERR "\nError : Opening output file");
                goto out;
        }

	root_inode = fip->f_dentry->d_inode->i_ino;
	while(!IS_ROOT(dentry))
	{
		if(dentry->d_inode->i_ino == root_inode) {
			retval = 1;
			break;
		}
		else {
			dentry = dentry->d_parent;
			
	
		}
	}
	
	out:
		if (fip != NULL)
                        filp_close(fip,NULL);
	
	return retval;

		

}

static int secrbac_inode_alloc_security(struct inode *inode)
{
	return 0;
}
static int secrbac_inode_init_security(struct inode *inode, struct inode *dir,
				       const struct qstr *qstr, char **name,
				       void **value, size_t *len)
{
	return 0;
}

static int secrbac_inode_create(struct inode *dir, struct dentry *dentry, int mask)
{
	if(get_current_user()->uid.val !=0 && applyRBAC(dentry->d_parent))
	{

		 return secrbac_auth_check(dir,"create",dentry->d_parent);
	}
	else
	{	
		return 0;
	}
}


static int secrbac_inode_mkdir(struct inode *dir, struct dentry *dentry, int mask)
{
	
	if(get_current_user()->uid.val != 0 && applyRBAC(dentry->d_parent) )
        {

                return secrbac_auth_check(dir,"mkdir",dentry->d_parent);
        }
	else
	{
		return 0;
	}
}

static int secrbac_inode_rmdir(struct inode *dir, struct dentry *dentry)
{
	if(get_current_user()->uid.val != 0 && applyRBAC(dentry))
        {	
                return secrbac_auth_check(dentry->d_inode,"rmdir",dentry);
        }
        else
        {
                return 0;
        }

}

static int secrbac_inode_unlink(struct inode *dir, struct dentry *dentry)
{
	if(get_current_user()->uid.val != 0 && applyRBAC(dentry))
        {

                return secrbac_auth_check(dentry->d_inode,"unlink",dentry);
        }
        else
        {
                return 0;
        }

}

static int secrbac_inode_rename(struct inode *old_inode, struct dentry *old_dentry,
				struct inode *new_inode, struct dentry *new_dentry)
{
	if(get_current_user()->uid.val != 0 && applyRBAC(old_dentry))
        {
                return secrbac_auth_check(old_dentry->d_inode,"rename",old_dentry);
        }
        else
        {
                return 0;
        }

}

static int secrbac_inode_permission(struct inode *inode, int mask, unsigned flags)
{
	return 0;
}

static int secrbac_inode_setattr(struct dentry *dentry , struct iattr *iattr)
{
        if(get_current_user()->uid.val != 0 && applyRBAC(dentry))
        {
                return secrbac_auth_check(dentry->d_inode,"setattr",dentry);
        }
        else
        {
                return 0;
        }

}
/*static int secrbac_inode_getattr(struct vfsmount *mnt , struct dentry *dentry)
{
        if(get_current_user()->uid.val != 0 && applyRBAC(dentry))
        {
                return secrbac_auth_check(dentry->d_inode,"getattr",dentry);
        }
        else
        {
                return 0;
        }

}*/

static struct security_operations secrbac_ops = {
	.name =				"secrbac",


	.inode_alloc_security 		=		secrbac_inode_alloc_security,
	.inode_init_security 		=		secrbac_inode_init_security,
	.inode_create 				=		secrbac_inode_create,
	.inode_mkdir 				=		secrbac_inode_mkdir,
	.inode_rmdir 				=		secrbac_inode_rmdir,
	.inode_rename 				=		secrbac_inode_rename,
	.inode_unlink				=		secrbac_inode_unlink,
	.inode_permission 			=		secrbac_inode_permission,
	.inode_setattr				=		secrbac_inode_setattr,
//	.inode_getattr				=		secrbac_inode_getattr,
};



static __init int secrbac_init(void)
{
	if (register_security(&secrbac_ops)) 
	{
		panic(KERN_INFO "Failed to register secrbac module\n");
	}
    
    printk(KERN_ALERT "SECRBAC started");
	
    return 0;
}



module_init(secrbac_init);

