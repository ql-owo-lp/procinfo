/////////////////////////////////////////////////////////
//
//	ProcInfo kernel module
//
/////////////////////////////////////////////////////////

#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO */
#include <linux/version.h>
#include <linux/syscalls.h>
#include <linux/security.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/rbtree.h>

#define INVALID_OFFSET 0xFFFFFFFF

#define offset_t uint32_t	// define the offset type
#define kernelAddr_t uint32_t	// kernel address offset type

// here we define the length of specific types
// the reason why I am doing it is because the size of variables
// differs in different x86 and x64 system
#define SIZEOF_ULONG sizeof(unsigned long)	// x86-4, x64-8
#define SIZEOF_INT sizeof(int)	// x86-4, for x64 sometimes it can be 8
#define SIZEOF_UINT sizeof(unsigned int)
#define SIZEOF_ULLONG sizeof(unsigned long long)
#define SIZEOF_PTR sizeof(void *)	// x86-4, x64-8

#define SIZEOF_LIST_HEAD SIZEOF_PTR + SIZEOF_PTR 	// list_head, which consists of two pointers
#define SIZEOF_COMM 16

// define some known facts
#define KERNEL_START 0xC0000000

#define MAX_THREAD_INFO_SEARCH_SIZE 20
#define MAX_TASK_STRUCT_SEARCH_SIZE 4000 
#define MAX_MM_STRUCT_SEARCH_SIZE 100

// here we define the information which we are going to
// extract from the memory.
// perfix "ts_" means it comes from "task_struct"
// "ti_" means it comes from "thread_info"
// "mm_" means mm_struct
// "vma_" means "vm_area_struct"
typedef struct ProcInfo {
	offset_t ts_tasks;
	offset_t ts_pid;
	offset_t ts_tgid;
	offset_t ts_group_leader;
	offset_t ts_thread_group;
	offset_t ts_real_parent;
	offset_t ts_mm;
	union {
		// corresponding to "void * stack" in task_struct,
		// which bascially points to thread_info
		offset_t ts_stack;
		offset_t ts_thread_info;
	};
	offset_t ts_real_cred;
	offset_t ts_cred;
	offset_t ts_comm;
	offset_t cred_uid;
	offset_t cred_gid;
	offset_t cred_euid;
	offset_t cred_egid;
	offset_t mm_pgd;
	offset_t mm_arg_start;
	offset_t mm_start_brk;
	offset_t mm_brk;
	offset_t mm_start_stack;
	offset_t vma_vm_start;
	offset_t vma_vm_end;
	offset_t vma_vm_next;
	offset_t vma_vm_file;
	offset_t vma_vm_flags;
	offset_t file_path_dentry;
	offset_t dentry_d_name;
	offset_t dentry_d_iname;
	offset_t dentry_d_parent;
	offset_t ti_task;
} ProcInfo;

typedef uint32_t gva_t;
typedef uint32_t gpa_t;

#define PGD_MASK 0xFFFFF000
#define PGD_TO_CR3(_pgd) (_pgd - KERNEL_START) //this is a guess
// but at any rate, PGD virtual address, which must be converted into 
// a physical address - see load_cr3 function in arch/x86/include/asm/processor.h

#define GET_FIELD(_struct, _fieldOffset) ( *((gva_t*)(_struct + _fieldOffset)) )

//here is a simple function that I wrote for
// use in this kernel module, but you get the idea
// the problem is that not all addresses above
// 0xC0000000 are valid, some are not 
// depending on whether the virtual address range is used
// we can figure this out by searching through the page tables
inline int isKernelAddress(gva_t addr) {
	return ((addr >= KERNEL_START) && (addr < 0xF8000000));
}

inline int isStructKernelAddress(gva_t addr, uint32_t structSize) {
	return (isKernelAddress(addr) && isKernelAddress(addr + structSize));
}

// get the content of ESP register
uint32_t getESP(void) {
	uint32_t t = 0;
	__asm__ ("mov %%esp, %0" : "=r"(t) : : "%eax" );
	return (t);
}

gpa_t getPGD(void) {
	gpa_t t = 0;
	__asm__ ("mov %%cr3, %0" : "=r"(t) : : "%eax" );
	return (t & PGD_MASK);
}

// just find the first field in mm struct, which is mmap
gpa_t findVMAStructFromMMStruct(gva_t mm) {
	uint32_t* tmp_mmap = NULL;
	tmp_mmap = mm;
	return (gpa_t) (*tmp_mmap);
}

gpa_t findPGDFromMMStruct(gva_t mm, uint32_t* pPGDOffset, int bDoubleCheck) {
	uint32_t i = 0;
	gpa_t* temp = NULL;
	gpa_t pgd = getPGD();
	if (!isStructKernelAddress(mm, MAX_MM_STRUCT_SEARCH_SIZE)) {
		return (0);
	}
	for (i = 0; i < MAX_MM_STRUCT_SEARCH_SIZE; i += 4) {
		temp = (gpa_t*) (mm + i);
		if (pgd == PGD_TO_CR3((*temp & PGD_MASK))) {
			if (pPGDOffset != NULL) {
				*pPGDOffset = i;
			}
			return (*temp);
		}
	}

	return (0);
}

gva_t findMMStructFromTaskStruct(gva_t ts, uint32_t* pMMStructOffset,
		uint32_t* pPGDOffset, int bDoubleCheck) {
	uint32_t i = 0;
	gva_t* temp = NULL;
	if (!isStructKernelAddress(ts, MAX_TASK_STRUCT_SEARCH_SIZE)) {
		return (0);
	}

	for (i = 0; i < MAX_TASK_STRUCT_SEARCH_SIZE; i += 4) {
		temp = (gva_t*) (ts + i);
		if (isKernelAddress(*temp)) {
			if (findPGDFromMMStruct(*temp, pPGDOffset, bDoubleCheck) != 0) {
				if (pMMStructOffset != NULL) {
					*pMMStructOffset = i;
				}
				return (*temp);
			}
		}
	}

	return (0);
}

// the characteristic of task struct list is that next is followed by previous
// both of which are pointers
// furthermore, next->previous should be equal to self
// same with previous->next
int isListHead(gva_t lh) {
	gva_t* temp = (gva_t*) lh;	// next pointer
	gva_t* temp2 = (gva_t*) (lh + 4);	// previous pointer

	// check the pointer address and the pointed object's base address
	if (!isKernelAddress((gva_t) temp) || !isKernelAddress((gva_t) (*temp))
			|| !isKernelAddress((gva_t) temp2)
			|| !isKernelAddress((gva_t) (*temp2))) {
		return (0);
	}

	// check previous->next and next->previous
	if ((*((gva_t*) (*temp2)) == (gva_t) temp)
			&& (*((gva_t*) (*temp + 4)) == (gva_t) temp)) {
		return (1);
	}
	return (0);
}

//TODO: DoubleCheck
//In this case, because there are so many different list_head
// definitions, we are going to use the first
// list head when searching backwards from the mm struct
//The signature that we use to find the task struct is the following (checked against
// version 3.9.5 and 2.6.32)
// depending on whether SMP is configured or not (in 3.9.5) we should see the following
// list_head (tasks) //8 bytes
// int PRIO (if SMP in 3.9.5) //4 bytes
// list_head (plist_node->plist_head->list_head in 2.6.32, and if SMP in 3.9.5) // 8 bytes
// list_head (same // 8 bytes
// spinlock* (optional in 2.6.32 if CONFIG_DEBUG_PI_LIST is set)
//So the idea is that we will see if we have a listhead followed by an int followed by 
// 2 list heads followed by mm struct (basically we search backwards from mmstruct
// if this pattern is found, then we should have the task struct offset
gva_t findTaskStructListFromTaskStruct(gva_t ts, uint32_t mmStructOffset,
		uint32_t* pTaskStructListOffset, int bDoubleCheck) {
	uint32_t i = 0;
	gva_t* temp = NULL;

	if (mmStructOffset >= MAX_TASK_STRUCT_SEARCH_SIZE) {
		return (0);
	}

	//must check the whole range (includes overflow)
	if (!isStructKernelAddress(ts, MAX_TASK_STRUCT_SEARCH_SIZE)) {
		return (0);
	}

	//We use the first such doubly linked list that comes before the
	// mm struct pointer, 28 is the size of the template
	// 3 list heads plus an int
	for (i = (SIZEOF_LIST_HEAD * 3 + 4); i < mmStructOffset; i += 4) {
		temp = (gva_t*) (ts + mmStructOffset - i);
		//check to see if temp is a kernel address
		if (isKernelAddress(*temp)) {
			printk(KERN_INFO "[i = %d] %d, %d, %d, --- \n", i, isListHead((gva_t)temp)
					, isListHead((gva_t)temp + SIZEOF_LIST_HEAD + 4)
					, isListHead((gva_t)temp + SIZEOF_LIST_HEAD +SIZEOF_LIST_HEAD + 4)
			);

			if (isListHead((gva_t) temp)
					&& isListHead((gva_t) temp + SIZEOF_LIST_HEAD + 4)
					&& isListHead(
							(gva_t) temp + SIZEOF_LIST_HEAD + SIZEOF_LIST_HEAD
									+ 4)) {
				//printk(KERN_INFO "FOUND task_struct_list offset [%d]\n", (uint32_t)temp - ts);
				if (pTaskStructListOffset != NULL) {
					*pTaskStructListOffset = (gva_t) temp - ts;
				}
				return (*temp);
			}
		}
	}

	//if we are here - then that means we did not find the pattern - which could be because SMP
	// was not configured so we default to using the first list_head
	//TODO: enable and test this part - needs a second level check later just in case
	// this was incorrect
	for (i = 4; i < mmStructOffset; i += 4) {
		temp = (gva_t*) (ts + mmStructOffset - i);
		if (isListHead((gva_t) temp)) {
			if (pTaskStructListOffset != NULL) {
				*pTaskStructListOffset = (gva_t) temp - ts;
			}
			return (*temp);
		}
	}

	return (0);
}

//The idea is to go through the data structures and find an
// item that points back to the threadinfo
//ASSUMES 4 byte aligned
gva_t findTaskStructFromThreadInfo(gva_t threadinfo,
		uint32_t* pTaskStructOffset, uint32_t* pThreadInfoOffset,
		int bDoubleCheck) {
	int bFound = 0;
	uint32_t i = 0;
	uint32_t j = 0;
	gva_t* temp = NULL;
	gva_t* temp2 = NULL;
	gva_t ret = 0;

	//iterate through the thread info structure
	for (i = 0; i < MAX_THREAD_INFO_SEARCH_SIZE; i += 4) {
		temp = (gva_t*) (threadinfo + i);
		//if it looks like a kernel address
		if (isKernelAddress(*temp)) {
			//iterate through the potential task struct 
			for (j = 0; j < MAX_TASK_STRUCT_SEARCH_SIZE; j += 4) {
				temp2 = (gva_t*) (*temp + j);
				//if there is an entry that has the same 
				// value as threadinfo then we are set 
				if (*temp2 == threadinfo) {
					if (bFound) {
						printk(KERN_INFO "in findTaskStructFromThreadInfo: Double Check failed\n");
						return (0);
					}

					if (pTaskStructOffset != NULL) {
						*pTaskStructOffset = i;
					}
					if (pThreadInfoOffset != NULL) {
						*pThreadInfoOffset = j;
					}
					ret = *temp;
					if (!bDoubleCheck) {
						return (ret);
					} else {
						printk(KERN_INFO "TASK STRUCT @ [0x%x] FOUND @ offset %d\n", *temp, j);
						bFound = 1;
					}
				}
			}
		}
	}
	return (ret);
}

//basically uses the threadinfo test to see if the current is a task struct
//We also use the task_list as an additional precaution since
// the offset of the threadinfo (i.e., stack) is 4 and the offset of 
// the task_struct in threadinfo is 0 which just happens to correspond
// to previous and next if this ts was the address of a list_head
// instead
//TODO: Find another invariance instead of the tasks list?
int isTaskStruct(gva_t ts, ProcInfo* pPI) {
	gva_t* temp = NULL;
	gva_t* temp2 = NULL;

	if (pPI == NULL) {
		return (0);
	}

	if (!isStructKernelAddress(ts, MAX_TASK_STRUCT_SEARCH_SIZE)) {
		return (0);
	}

	temp = (gva_t*) (ts + pPI->ts_stack);

	//dereference temp to get to the TI and then add the offset to get back
	// the pointer to the task struct
	temp2 = (gva_t*) (*temp + pPI->ti_task);
	if (!isKernelAddress((uint32_t) temp2)) {
		return (0);
	}

	//now see if the tasks is correct
	if (!isListHead(ts + pPI->ts_tasks)) {
		return (0);
	}

	return (1);
}

//the signature for real_parent is that this is the
// first item where two task_struct pointers are together
// real_parent is the first one (this should most likely
// be the same as parent, although not necessarily true)
//NOTE: We can also use the follow on items which are
// two list_heads for "children" and "sibling" as well 
// as the final one which is a task_struct for "group_leader"
gva_t findRealParentGroupLeaderFromTaskStruct(gva_t ts, ProcInfo* pPI) {
	uint32_t i = 0;

	if (pPI == NULL) {
		return (0);
	}

	for (i = 0; i < MAX_TASK_STRUCT_SEARCH_SIZE; i += 4) {
		if (isTaskStruct(*((gva_t*) (ts + i)), pPI) //real_parent
				&& isTaskStruct(*((gva_t*) (ts + i + 4)), pPI) //parent
				&& isListHead(ts + i + 4 + 4) //children
				&& isListHead(ts + i + 4 + 4 + SIZEOF_LIST_HEAD) //sibling
				&& isTaskStruct(
						*((gva_t*) (ts + i + 4 + 4 + SIZEOF_LIST_HEAD
								+ SIZEOF_LIST_HEAD)), pPI) //group_leader
						) {
			if (pPI->ts_real_parent == INVALID_OFFSET) {
				pPI->ts_real_parent = i;
			}
			if (pPI->ts_group_leader == INVALID_OFFSET) {
				pPI->ts_group_leader = i + 4 + 4 + SIZEOF_LIST_HEAD
						+ SIZEOF_LIST_HEAD;
			}
			return (ts + i);
		}
	}
	return (0);
}

//The characteristics of the init_task that we use are
//The mm struct pointer is NULL - since it shouldn't be scheduled?
//The parent and real_parent is itself
int isInitTask(gva_t ts, ProcInfo* pPI, int bDoubleCheck) {
	int bMMCheck = 0;
	int bRPCheck = 0;

	if ((pPI == NULL)
			|| !isStructKernelAddress(ts, MAX_TASK_STRUCT_SEARCH_SIZE)) {
		return (0);
	}

	if (pPI->ts_mm != INVALID_OFFSET) {
		if (*((gva_t*) (ts + pPI->ts_mm)) == 0) {
			bMMCheck = 1;
		}
	}
	if (pPI->ts_real_parent != INVALID_OFFSET) {
		if (*((gva_t*) (ts + pPI->ts_real_parent)) == ts) {
			bRPCheck = 1;
		}
	}

	if (bDoubleCheck) {
		return (bMMCheck && bRPCheck);
	}

	return (bMMCheck || bRPCheck);
}

//To find the "comm" field, we look for the name of
// init_task which is "swapper" -- we don't check for "swapper/0" or anything else
gva_t findCommFromTaskStruct(gva_t ts, ProcInfo* pPI) {
	uint32_t i = 0;
	//char* temp = NULL; //not used yet, because we are using the int comparison instead
	uint32_t* temp2 = NULL;
	//char* strInit = "swapper";
	uint32_t intSWAP = 0x70617773; //p, a, w, s
	uint32_t intPER = 0x2f726570; ///, r, e, p
	if (pPI == NULL) {
		return (0);
	}

	if (!isInitTask(ts, pPI, 0)) {
		return (0);
	}

	//once again we are assuming that things are aligned
	for (i = 0; i < MAX_TASK_STRUCT_SEARCH_SIZE; i += 4) {
		temp2 = (uint32_t*) (ts + i);
		if (*temp2 == intSWAP) {
			temp2 += 1; //move to the next item
			if (((*temp2) & 0x00FFFFFF) == (intPER & 0x00FFFFFF)) {
				if (pPI->ts_comm == INVALID_OFFSET) {
					pPI->ts_comm = i;
				}
				return (ts + i);
			}
		}
	}

	return (0);
}

//The signature for thread_group is
// that thread_group comes after an array of pid_links
// and PID_links contains an hlist_node (which 2 pointers)
// followed by a pid pointer - this means 3 points
//So we are looking for 3 pointers followed by
// a list_head for the thread group
//Turns out the simple signature above doesn't work
// because there are too many points
// so we will use a signature for the
// hlist instead
//The uniqueness of an hlist (as opposed to the list)
// is that the second parameter is a pointer to a pointer (**prev)
//At the lowest level, this doesn't work either since
// it is hard to distinguish between a pointer to a pointer
// from a pointer - which means a list will look like an hlist
//Sigh - so instead we are going to use the cputime_t
// fields as part of the signature instead - this can be useful
// especially if we do this kind of test early on during
// the boot process
//So the new signature is list_head followed by 3 pointers
// followed by cputimes
//This one didn't work either, so going to just use 
// a signature based on initTask
// which happens to have the whole array of pids
// do not have a hlist, but it does have a pointer
// to the pid (which seems to be the same value)
gva_t findThreadGroupFromTaskStruct(gva_t ts, ProcInfo* pPI) {
	uint32_t i = 0;

	if ((pPI == NULL) || (pPI->ts_group_leader == INVALID_OFFSET)) {
		i = 0;
	} //we can start from the group_leader as a shortcut
	else {
		i = pPI->ts_group_leader;
	}

	if (!isInitTask(ts, pPI, 0)) {
		return (0);
	}

	for (; i < MAX_TASK_STRUCT_SEARCH_SIZE; i += 4) {
		/*
		 if ( isKernelAddress(GET_FIELD(ts, i))
		 && isKernelAddress(GET_FIELD(ts, i+4))
		 && isKernelAddress(GET_FIELD(ts, i+8))
		 && !isKernelAddress(*((int*)GET_FIELD(ts, i+8))) //this should be a PID 
		 && isListHead(ts+i+12)
		 && isKernelAddress(GET_FIELD(ts, i+12+SIZEOF_LIST_HEAD))
		 && isKernelAddress(GET_FIELD(ts, i+12+SIZEOF_LIST_HEAD+4))
		 && isKernelAddress(GET_FIELD(ts, i+12+SIZEOF_LIST_HEAD+8))
		 && !isKernelAddress(GET_FIELD(ts, i+12+SIZEOF_LIST_HEAD+12))
		 && !isKernelAddress(GET_FIELD(ts, i+12+SIZEOF_LIST_HEAD+16))
		 && !isKernelAddress(GET_FIELD(ts, i+12+SIZEOF_LIST_HEAD+20))
		 && !isKernelAddress(GET_FIELD(ts, i+12+SIZEOF_LIST_HEAD+24))
		 && !isKernelAddress(GET_FIELD(ts, i+12+SIZEOF_LIST_HEAD+28))
		 )
		 */
		if ((GET_FIELD(ts, i) == 0) && (GET_FIELD(ts, i+4) == 0)
				&& isKernelAddress(GET_FIELD(ts, i+8))
				&& isListHead(GET_FIELD(ts, i+12)) //is a list head
				&& (GET_FIELD(ts, i+20) == 0) //this is the entry for vfork_done ?
				) {
			if ((pPI != NULL) && (pPI->ts_thread_group == INVALID_OFFSET)) {
				pPI->ts_thread_group = i + 12;
			}
			return (ts + i + 12);
		}
	}
	return (0);
}

/*
 * The key to find the proper uid / gid is about to figure out wether
 * the system is compiled with CONFIG_DEBUG_CREDENTIALS or not.  And the way
 * to check this is about check if there is a put_addr pointer
 */
gva_t findGUIDFromCred(gva_t cred, ProcInfo* pPI) {
	uint32_t offset = SIZEOF_INT;	// var: usage
	uint32_t* _put_addr = NULL;
	if ((pPI == NULL) || !isKernelAddress(cred)) {
		return (0);
	}
	// now test the put_addr
	_put_addr = (uint32_t*) (cred + 8);
	if (isKernelAddress(*_put_addr))
		offset += SIZEOF_INT + SIZEOF_PTR + SIZEOF_ULONG;// var: subscribers + put_addr + magic
	pPI->cred_uid = offset;
	pPI->cred_gid = pPI->cred_uid + SIZEOF_UINT;	// + uid
	pPI->cred_euid = pPI->cred_gid + SIZEOF_UINT + SIZEOF_UINT + SIZEOF_UINT;// + gid + suid + sgid
	pPI->cred_egid = pPI->cred_euid + SIZEOF_UINT;
	return (0);
}

/* 
 * in 2.6.31, the vma_struct starts with a vm_mm, then followed by
 * two unsigned long fields: vm_start and vm_end, then a pointer: vm_next
 * starting 2.6.32, we have one more pointer: vm_prev after vm_next
 * However, in 3.8+, the vma_struct starts with vm_start and vm_end,
 * then two pointers: vm_next and vm_previous
 * @param vma: base address of vm_area_struct
 */

gva_t findVMInfoFromVMA(gva_t vma, gva_t mm, ProcInfo* pPI) {
	uint32_t* _mm = NULL;
	uint32_t* _vm_prev = NULL;
	if ((pPI == NULL) || !isKernelAddress(vma) || !isKernelAddress(mm)) {
		return (0);
	}
	// check whether the first field is vm_mm
	_mm = (uint32_t*) vma;	// get the mm pointer
	// check if the value equals to mm
	if ((*_mm) == mm) {	// we get a vm_mm here
		pPI->vma_vm_start = SIZEOF_PTR;
		pPI->vma_vm_end = pPI->vma_vm_start + SIZEOF_ULONG;
		pPI->vma_vm_next = pPI->vma_vm_end + SIZEOF_ULONG;
		// see if we have vm_prev here
		_vm_prev = (uint32_t*) (vma + pPI->vma_vm_next + SIZEOF_PTR);
		// the size of prprot_t is unsure, by default it is unsigned long
		// however, starting for 2.6.34, in arch/sh/include/asm/page.h, it comes to be unsigned long long
		pPI->vma_vm_flags = pPI->vma_vm_next + SIZEOF_PTR + sizeof(pgprot_t);
		if (isKernelAddress(*_vm_prev)) { // we have a vm_prev here
			// do a double check here, go to this one's previous and then go next, we should return
			if (*((uint32_t*) ((*_vm_prev) + pPI->vma_vm_next)) != vma) {
				printk(KERN_INFO "double check fails when grabbing vm_prev!\n");
				return (0);
			}
			printk(KERN_INFO "vm_prev found!\n");
			pPI->vma_vm_flags += SIZEOF_PTR;
		} else if ((*_vm_prev) == 0) {
			printk(KERN_INFO "vm_prev found! this is an init vm area\n");
			pPI->vma_vm_flags += SIZEOF_PTR;
		} else { 	// debug
		printk(KERN_INFO "vm_prev value: 0x%x!\n", *_vm_prev);
	}
} else {
	// do a double check, by checking 
printk(KERN_INFO "vm_mm double check passed!\n");
//pPI->vma_vm_flags = sizeof(rb_node) + 8 + 4 + sizeof(pgprot_t) + 4;	// vm_rb + rb_subtree_gap + *vm_mm + vm_page_prot
}
 // now search for vm_file, what I am going to do is to find anon_vma_node, which
 // is a list_head, anon_vma, which is a pointer, following is vm_ops, which is also a pointer,
 // which can be used for double check
return (0);
}

//we find cred by searching backwards starting from comm
//The signature is that we have an array of list heads (which is for
// the cpu_timers
// followed by real_cred and cred (both of which are pointers)
// followed by stuff (in 2.6.32) and then comm
gva_t findCredFromTaskStruct(gva_t ts, ProcInfo* pPI) {
uint32_t i = 0;
if ((pPI == NULL) || (pPI->ts_comm == INVALID_OFFSET))
return (0);
if (!isStructKernelAddress(ts, MAX_TASK_STRUCT_SEARCH_SIZE))
return (0);

	//we start at 16 because of the list_head followed by
	// the two pointers
for (i = 16; i < pPI->ts_comm; i += 4) {
if (isListHead(GET_FIELD(ts, pPI->ts_comm - i)) && isKernelAddress(
GET_FIELD(ts, pPI->ts_comm - i + SIZEOF_LIST_HEAD)) && isKernelAddress(
GET_FIELD(ts, pPI->ts_comm - i + SIZEOF_LIST_HEAD + 4))) {
	if (pPI->ts_real_cred == INVALID_OFFSET) {
		pPI->ts_real_cred = pPI->ts_comm - i + SIZEOF_LIST_HEAD;
	}
	if (pPI->ts_cred == INVALID_OFFSET) {
		pPI->ts_cred = pPI->ts_comm - i + SIZEOF_LIST_HEAD + 4;
	}
	return (ts + pPI->ts_comm - i + SIZEOF_LIST_HEAD + 4);
}
}
return (0);
}

// the key is to find the path struct,
// then we can locate path.dentry
gva_t findDentryFromFileStruct() {
	
}

//pid and tgid are pretty much right on top of
// the real_parent, except for the case when a stack
// canary might be around. We will try to see
// if the canary is there - because canaries are supposed
// to be random - which is different from tgid and pid
// both of which are small numbers - so we try it this
// way
gva_t findPIDFromTaskStruct(gva_t ts, ProcInfo* pPI) {
uint32_t offset = 0;
if ((pPI == NULL) || (pPI->ts_real_parent == INVALID_OFFSET)) {
return (0);
}
if (!isStructKernelAddress(ts, MAX_TASK_STRUCT_SEARCH_SIZE)) {
return (0);
}

	//see if the field before real_parent is a canary
	//we do this by seeing if the field anded with 0xFFFF0000
	// has any 1's in it. The idea is that if its a canary - this is
	// very likely to be true
	//Whereas, if it is a tgid, then this is likely to be false - especially
	// if we are doing this check early after the system boots up
if (GET_FIELD(ts, pPI->ts_real_parent - 4) & 0xFFFF0000) {
offset = 4;
}

if (pPI->ts_pid == INVALID_OFFSET) {
pPI->ts_pid = pPI->ts_real_parent - 8 - offset;
}
if (pPI->ts_tgid == INVALID_OFFSET) {
pPI->ts_tgid = pPI->ts_real_parent - 4 - offset;
}
return (ts + pPI->ts_real_parent - 8 - offset);
}


// print the procinfo struct
void print_offset_struct(ProcInfo* pi) {
	char* var_name = "OFFSET_PROFILE";
	printk(KERN_INFO
		"	%s.ts_tasks = 0x%x;\n"
		"	%s.ts_pid = 0x%x;\n"
		"	%s.ts_tgid = 0x%x;\n"
		"	%s.ts_group_leader = 0x%x;\n"
		"	%s.ts_thread_group = 0x%x;\n"
		"	%s.ts_real_parent = 0x%x;\n"
		"	%s.ts_mm = 0x%x;\n"
		"	%s.ts_stack = 0x%x;\n"
		"	%s.ts_thread_info = 0x%x;\n"
		"	%s.ts_real_cred = 0x%x;\n"
		"	%s.ts_cred = 0x%x;\n"
		"	%s.ts_comm = 0x%x;\n"
		"	%s.cred_uid = 0x%x;\n"
		"	%s.cred_gid = 0x%x;\n"
		"	%s.cred_euid = 0x%x;\n"
		"	%s.cred_egid = 0x%x;\n"
		"	%s.mm_pgd = 0x%x;\n"
		"	%s.mm_arg_start = 0x%x;\n"
		"	%s.mm_start_brk = 0x%x;\n"
		"	%s.mm_brk = 0x%x;\n"
		"	%s.mm_start_stack = 0x%x;\n"
		"	%s.vma_vm_start = 0x%x;\n"
		"	%s.vma_vm_end = 0x%x;\n"
		"	%s.vma_vm_next = 0x%x;\n"
		"	%s.vma_vm_file = 0x%x;\n"
		"	%s.vma_vm_flags = 0x%x;\n"
		"	%s.file_path_dentry = 0x%x;\n"
		"	%s.dentry_d_name = 0x%x;\n"
		"	%s.dentry_d_iname = 0x%x;\n"
		"	%s.dentry_d_parent = 0x%x;\n"
		"	%s.ti_task = 0x%x;\n",

		var_name, pi.ts_tasks,
		var_name, pi.ts_pid,
		var_name, pi.ts_tgid,
		var_name, pi.ts_group_leader,
		var_name, pi.ts_thread_group,
		var_name, pi.ts_real_parent,
		var_name, pi.ts_mm,
		var_name, pi.ts_stack,
		var_name, pi.ts_thread_info,
		var_name, pi.ts_real_cred,
		var_name, pi.ts_cred,
		var_name, pi.ts_comm,
		var_name, pi.cred_uid,
		var_name, pi.cred_gid,
		var_name, pi.cred_euid,
		var_name, pi.cred_egid,
		var_name, pi.mm_pgd,
		var_name, pi.mm_arg_start,
		var_name, pi.mm_start_brk,
		var_name, pi.mm_brk,
		var_name, pi.mm_start_stack,
		var_name, pi.vma_vm_start,
		var_name, pi.vma_vm_end,
		var_name, pi.vma_vm_next,
		var_name, pi.vma_vm_file,
		var_name, pi.vma_vm_flags,
		var_name, pi.file_path_dentry,
		var_name, pi.dentry_d_name,
		var_name, pi.dentry_d_iname,
		var_name, pi.dentry_d_parent,
		var_name, pi.ti_task
	);
}

int try_vmi(void) {
	//first we will try to get the threadinfo structure and etc
struct ProcInfo pi;
uint32_t i = 0;

gva_t taskstruct = 0;
gva_t mmstruct = 0;
gva_t vmastruct = 0;
gva_t threadinfo = getESP() & ~8191;

gva_t ret = 0;
gva_t tempTask = 0;

gva_t gl = 0;

memset(&pi, INVALID_OFFSET, sizeof(ProcInfo));

printk(KERN_INFO "ThreadInfo @ [0x%x]\n", threadinfo);
taskstruct = findTaskStructFromThreadInfo(threadinfo, &pi.ti_task, &pi.ts_stack,
	0);
printk(KERN_INFO "task_struct @ [0x%x] TSOFFSET = %d, TIOFFSET = %d\n", taskstruct, pi.ti_task, pi.ts_stack);

mmstruct = findMMStructFromTaskStruct(taskstruct, &pi.ts_mm, &pi.mm_pgd, 0);
printk(KERN_INFO "mm_struct @ [0x%x] mmOFFSET = %d, pgdOFFSET = %d\n", mmstruct, pi.ts_mm, pi.mm_pgd);

vmastruct = findVMAStructFromMMStruct(mmstruct);
printk(KERN_INFO "vm_area_struct @ [0x%x]\n", vmastruct);

findVMInfoFromVMA(vmastruct, mmstruct, &pi);
printk(KERN_INFO "vm_start = %d, vm_end = %d,vm_next = %d, vm_flags = %d\n", pi.vma_vm_start, pi.vma_vm_end, pi.vma_vm_next, pi.vma_vm_flags);

findTaskStructListFromTaskStruct(taskstruct, pi.ts_mm, &pi.ts_tasks, 0);
printk(KERN_INFO "task_struct offset = %d\n", pi.ts_tasks);

findRealParentGroupLeaderFromTaskStruct(taskstruct, &pi);
printk(KERN_INFO "real_parent = %d, group_leader = %d\n", pi.ts_real_parent, pi.ts_group_leader);

	// test
	//printk(KERN_INFO "unsigned long = %d\n", sizeof(void *));

gl = GET_FIELD(taskstruct, pi.ts_group_leader);
ret = findCommFromTaskStruct(gl, &pi);
	//don't forget to to get back to the head of the task struct
	// by subtracting ts_tasks offset
tempTask = GET_FIELD(gl, pi.ts_tasks) - pi.ts_tasks;
while ((ret == 0) && (tempTask != gl) && (isKernelAddress(tempTask))) {
ret = findCommFromTaskStruct(tempTask, &pi);
//move to the next task_struct
tempTask = GET_FIELD(tempTask, pi.ts_tasks) - pi.ts_tasks;
}

if (ret)
printk(KERN_INFO "Comm offset is = %d, %s\n", pi.ts_comm, (char*)(taskstruct + pi.ts_comm));

findCredFromTaskStruct(taskstruct, &pi);
printk(KERN_INFO "real_cred = %d, cred = %d\n", pi.ts_real_cred, pi.ts_cred);

findGUIDFromCred(taskstruct + pi.ts_real_cred, &pi);
printk(KERN_INFO "cred_uid = %d, cred_gid = %d, cred_euid = %d, cred_egid = %d\n", pi.cred_uid, pi.cred_gid, pi.cred_euid, pi.cred_egid);

findPIDFromTaskStruct(taskstruct, &pi);
printk(KERN_INFO "pid = %d, tgid = %d\n", pi.ts_pid, pi.ts_tgid);

//For this next test, I am just going to use the task struct lists
findThreadGroupFromTaskStruct((gva_t) (&init_task), &pi);
printk(KERN_INFO "Thread_group offset is %d\n", pi.ts_thread_group);

for (i = 0; i < 100; i += 4) {
//printk(KERN_INFO "[%d, %x]%x\n", i + pi.ts_group_leader, (gva_t)&init_task + i + pi.ts_group_leader, GET_FIELD((gva_t)&init_task, i + pi.ts_group_leader));
}

return (0);
}

int init_module(void) {
struct vm_area_struct vma;
struct file filestruct;
struct dentry dentrystr;
struct cred credstruct;
struct thread_info ti;

try_vmi();
//printk(KERN_INFO "INIT_TASK_MM = [%p]\n", init_task.mm);
//printk(KERN_INFO "INIT_TASK_MM2 = [%d] ABCD\n", ((int)&(init_task.mm->pgd) - (int)&init_task.mm));
//printk(KERN_INFO "INIT_TASK_MM2 = [%x, %x] ABCD\n", init_task.real_parent, &init_task);
return (-1);

printk(KERN_INFO
	"    {  \"%s\", /* entry name */\n"
	"       0x%08lX, /* task struct root */\n"
	"       %d, /* size of task_struct */\n"
	"       %d, /* offset of task_struct list */\n"
	"       %d, /* offset of pid */\n"
	"       %d, /* offset of tgid */\n"
	"       %d, /* offset of group_leader */\n"
	"       %d, /* offset of thread_group */\n"
	"       %d, /* offset of real_parent */\n"
	"       %d, /* offset of mm */\n"
	"       %d, /* offset of stack */\n"
	"       %d, /* offset of real_cred */\n"
	"       %d, /* offset of cred */\n"
	"       %d, /* offset of uid cred */\n"
	"       %d, /* offset of gid cred */\n"
	"       %d, /* offset of euid cred */\n"
	"       %d, /* offset of egid cred */\n"
	"       %d, /* offset of pgd in mm */\n"
	"       %d, /* offset of arg_start in mm */\n"
	"       %d, /* offset of start_brk in mm */\n"
	"       %d, /* offset of brk in mm */\n"
	"       %d, /* offset of start_stack in mm */\n",

	"Android-x86 Gingerbread",
	(long)&init_task,
	sizeof(init_task),
	(int)&init_task.tasks - (int)&init_task,
	(int)&init_task.pid - (int)&init_task,
	(int)&init_task.tgid - (int)&init_task,
	(int)&init_task.group_leader - (int)&init_task,
	(int)&init_task.thread_group - (int)&init_task,
	(int)&init_task.real_parent - (int)&init_task,
	(int)&init_task.mm - (int)&init_task,
	(int)&init_task.stack - (int)&init_task,
	(int)&init_task.real_cred - (int)&init_task,
	(int)&init_task.cred - (int)&init_task,
	(int)&credstruct.uid - (int)&credstruct,
	(int)&credstruct.gid - (int)&credstruct,
	(int)&credstruct.euid - (int)&credstruct,
	(int)&credstruct.egid - (int)&credstruct,
	(int)&init_task.mm->pgd - (int)init_task.mm,
	(int)&init_task.mm->arg_start - (int)init_task.mm,
	(int)&init_task.mm->start_brk - (int)init_task.mm,
	(int)&init_task.mm->brk - (int)init_task.mm,
	(int)&init_task.mm->start_stack - (int)init_task.mm
);

printk(KERN_INFO
	"       %d, /* offset of comm */\n"
	"       %d, /* size of comm */\n"
	"       %d, /* offset of vm_start in vma */\n"
	"       %d, /* offset of vm_end in vma */\n"
	"       %d, /* offset of vm_next in vma */\n"
	"       %d, /* offset of vm_file in vma */\n"
	"       %d, /* offset of vm_flags in vma */\n"
	"       %d, /* offset of dentry in file */\n"
	"       %d, /* offset of d_name in dentry */\n"
	"       %d, /* offset of d_iname in dentry */\n"
	"       %d, /* offset of d_parent in dentry */\n"
	"       %d, /* offset of task in thread_info */\n"
	"    },\n",

	(int)&init_task.comm - (int)&init_task,
	sizeof(init_task.comm),
	(int)&vma.vm_start - (int)&vma,
	(int)&vma.vm_end - (int)&vma,
	(int)&vma.vm_next - (int)&vma,
	(int)&vma.vm_file - (int)&vma,
	(int)&vma.vm_flags - (int)&vma,
	(int)&filestruct.f_dentry - (int)&filestruct,
	(int)&dentrystr.d_name - (int)&dentrystr,
	(int)&dentrystr.d_iname - (int)&dentrystr,
	(int)&dentrystr.d_parent - (int)&dentrystr,
	(int)&ti.task - (int)&ti
);

printk(KERN_INFO "Information module registered.\n");
return -1;
}

void cleanup_module(void) {
printk(KERN_INFO "Information module removed.\n");
}

MODULE_LICENSE("GPL");
