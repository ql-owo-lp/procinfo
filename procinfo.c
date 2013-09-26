#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO */
#include <linux/version.h>
#include <linux/syscalls.h>
#include <linux/security.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/dcache.h>


//here is a simple definition for us to reuse the same code for a kernel module
#ifdef __i386__
  #define __target_i386__
#endif

#ifdef __target_i386__
  typedef uint32_t target_ulong;
  typedef int32_t target_long;
  typedef uint32_t target_uint;
  typedef int32_t target_int;
  #define T_FMT ""
  #define PI_R_EAX "eax"
  #define PI_R_ESP "esp"
#else
  typedef uint64_t target_ulong;
  typedef int64_t target_long;
  typedef uint32_t target_uint;
  typedef int32_t target_int;
  #define T_FMT "ll"
  #define PI_R_EAX "rax"
  #define PI_R_ESP "rsp"
#endif

#define INV_ADDR ((target_ulong)-1)
#define INV_OFFSET ((target_ulong)-1)
typedef target_ulong target_ptr;
typedef int32_t target_pid_t;

/** Data structure that helps keep things organized. **/
typedef struct _ProcInfo
{
  char strName[32];
  target_ulong init_task_addr;
  target_ulong init_task_size;

  target_ulong ts_tasks;
  target_ulong ts_pid;
  target_ulong ts_tgid;
  target_ulong ts_group_leader;
  target_ulong ts_thread_group;
  target_ulong ts_real_parent;
  target_ulong ts_mm;
  union
  {
    target_ulong ts_stack;
    target_ulong ts_thread_info;
  };
  target_ulong ts_real_cred;
  target_ulong ts_cred;
  target_ulong ts_comm;
  target_ulong cred_uid;
  target_ulong cred_gid;
  target_ulong cred_euid;
  target_ulong cred_egid;
  target_ulong mm_mmap;
  target_ulong mm_pgd;
  target_ulong mm_arg_start;
  target_ulong mm_start_brk;
  target_ulong mm_brk;
  target_ulong mm_start_stack;
  target_ulong vma_vm_start;
  target_ulong vma_vm_end;
  target_ulong vma_vm_next;
  target_ulong vma_vm_file;
  target_ulong vma_vm_flags;
  target_ulong file_dentry;
  target_ulong dentry_d_name;
  target_ulong dentry_d_iname;
  target_ulong dentry_d_parent;
  target_ulong ti_task;  
} ProcInfo;


typedef target_ptr gva_t;
typedef target_ulong gpa_t;

//Here are some definitions straight from page_types.h

//this is common to all linux kernels - 4k pages
#define TARGET_PAGE_SHIFT 12
//I just use 1 here instead of 1UL or even the macro for _AC
// which is used in the kernel code
#define TARGET_PAGE_SIZE (1 << TARGET_PAGE_SHIFT)
#define TARGET_PAGE_MASK (~(TARGET_PAGE_SIZE - 1))

#ifdef __target_i386__
  //this is the default value - but keep in mind that a custom built
  // kernel can change this
  #define TARGET_PAGE_OFFSET 0xC0000000

  //defined this extra constant here so that the code
  // for isKernelAddress can be standardized
  #define TARGET_KERNEL_IMAGE_START TARGET_PAGE_OFFSET
  #define TARGET_MIN_STACK_START 0xA0000000 //trial and error?
#else
  //See: http://lxr.linux.no/#linux+v3.11/Documentation/x86/x86_64/mm.txt
  // for the memory regions
  //these definitions are in page_64_types.h
  #define TARGET_PAGE_OFFSET  0xFFFF880000000000
  #define TARGET_KERNEL_IMAGE_START 0xFFFFFFFF80000000
  #define TARGET_MIN_STACK_START 0x0000000100000000 //trial and error?
#endif //target_i386

#define TARGET_KERNEL_IMAGE_SIZE (512 * 1024 * 1024)

//straight from the kernel in processor.h
#define TARGET_TASK_SIZE TARGET_PAGE_OFFSET
#define TARGET_KERNEL_START TARGET_TASK_SIZE

#ifdef __target_i386__
  //got this value from testing - not necessarily true though
  //might be some devices mapped into physical memory
  // that will screw things up a bit
  #define TARGET_KERNEL_END 0xF8000000
#else
  //same here - in fact the global stuff (from the kernel image) are defined in higher addresses
  #define TARGET_KERNEL_END 0xFFFFC80000000000
#endif //target_i386

//some definitions to help limit how much to search
// these will likely have to be adjusted for 64 bit, 20, 4k and 100 works for 32
#define MAX_THREAD_INFO_SEARCH_SIZE 20
#define MAX_TASK_STRUCT_SEARCH_SIZE 4000 
#define MAX_MM_STRUCT_SEARCH_SIZE 500
#define MAX_VM_AREA_STRUCT_SEARCH_SIZE 500
#define MAX_CRED_STRUCT_SEARCH_SIZE 200
#define MAX_DENTRY_STRUCT_SEARCH_SIZE 200

//the list head contains two pointers thus
#define SIZEOF_LIST_HEAD (sizeof(target_ptr) + sizeof(target_ptr))
#define SIZEOF_COMM ((target_ulong)16)

#define TARGET_PGD_MASK TARGET_PAGE_MASK
#define TARGET_PGD_TO_CR3(_pgd) (_pgd - TARGET_KERNEL_START) //this is a guess
// but at any rate, PGD virtual address, which must be converted into 
// a physical address - see load_cr3 function in arch/x86/include/asm/processor.h

//here is a simple function that I wrote for
// use in this kernel module, but you get the idea
// the problem is that not all addresses above
// 0xC0000000 are valid, some are not 
// depending on whether the virtual address range is used
// we can figure this out by searching through the page tables
inline int isKernelAddress(gva_t addr)
{
  return ( 
    //the normal kernel memory area
    ( (addr >= TARGET_KERNEL_START) && (addr < TARGET_KERNEL_END) )
    //OR the kernel image area - in case the kernel image was mapped to some
    // other virtual address region - as from x86_64
    || ( (addr >= TARGET_KERNEL_IMAGE_START) && (addr < (TARGET_KERNEL_IMAGE_START + TARGET_KERNEL_IMAGE_SIZE)) )
  );
}

inline int isStructKernelAddress(gva_t addr, target_ulong structSize)
{
  return ( isKernelAddress(addr) && isKernelAddress(addr + structSize) );
}

target_ulong getESP(void)
{
  target_ulong t = 0;
  __asm__ ("mov %%"PI_R_ESP", %0" : "=r"(t) : : "%"PI_R_EAX"" );
  return (t);
}

gpa_t getPGD(void)
{
  gpa_t t = 0;
  __asm__ ("mov %%cr3, %0" : "=r"(t) : : "%"PI_R_EAX"" );
  return (t & TARGET_PGD_MASK);
}



#if 0 


#endif

//We will have to replace this function with another one - such as
// read_mem in DECAF
static inline target_ulong get_target_ulong_at(gva_t addr)
{
  return (*((target_ulong*)(addr)));
}

static inline uint32_t get_uint32_at(gva_t addr)
{
  return (*((uint32_t*)(addr)));
}

//Dangerous memcpy
static inline int get_mem_at(gva_t addr, void* buf, size_t count)
{
  memcpy(buf, (void*) addr, count);
  return (count);
}

//The idea is to go through the data structures and find an
// item that points back to the threadinfo
//ASSUMES PTR byte aligned
gva_t findTaskStructFromThreadInfo(gva_t threadinfo, ProcInfo* pPI, int bDoubleCheck)
{
  int bFound = 0;
  target_ulong i = 0;
  target_ulong j = 0;
  gva_t temp = 0;
  gva_t temp2 = 0;
  gva_t candidate = 0;
  gva_t ret = 0;
 
  if (pPI == NULL)
  {
    return (INV_ADDR);
  }
 
  //iterate through the thread info structure
  for (i = 0; i < MAX_THREAD_INFO_SEARCH_SIZE; i+= sizeof(target_ptr))
  {
    temp = (threadinfo + i);
    candidate = (get_target_ulong_at(temp));
    //if it looks like a kernel address
    if (isKernelAddress(candidate))
    {
      //iterate through the potential task struct 
      for (j = 0; j < MAX_TASK_STRUCT_SEARCH_SIZE; j+= sizeof(target_ptr))
      {
        temp2 = (candidate + j);
        //if there is an entry that has the same 
        // value as threadinfo then we are set 
        if (get_target_ulong_at(temp2) == threadinfo)
        {
          if (bFound)
          {
            printk(KERN_INFO "in findTaskStructFromThreadInfo: Double Check failed\n");
            return (0);
          }

          pPI->ti_task = i;
          pPI->ts_stack = j;
          ret = candidate;

          if (!bDoubleCheck)
          {
            return (ret);
          }
          else
          {
            printk(KERN_INFO "TASK STRUCT @ [0x%"T_FMT"x] FOUND @ offset %"T_FMT"d\n", candidate, j);
            bFound = 1;
          }
        }
      }
    }
  }
  return (ret);
}


gpa_t findPGDFromMMStruct(gva_t mm, ProcInfo* pPI, int bDoubleCheck)
{
  target_ulong i = 0;
  gpa_t temp = 0;
  gpa_t pgd = getPGD();

  if (pPI == NULL)
  {
    return (INV_ADDR);
  }

  if ( !isStructKernelAddress(mm, MAX_MM_STRUCT_SEARCH_SIZE) )
  {
    return (INV_ADDR);
  } 

  for (i = 0; i < MAX_MM_STRUCT_SEARCH_SIZE; i += sizeof(target_ulong))
  {
    temp = get_target_ulong_at(mm + i);
    if (pgd == TARGET_PGD_TO_CR3((temp & TARGET_PGD_MASK))) 
    {
      pPI->mm_pgd = i;
      return (temp);
    }
  }
 
  return (INV_ADDR);
}

gva_t findMMStructFromTaskStruct(gva_t ts, ProcInfo* pPI, int bDoubleCheck)
{
  target_ulong i = 0;
  gva_t temp = 0;
  
  if (pPI == NULL)
  {
    return (INV_ADDR);
  }
  if ( !isStructKernelAddress(ts, MAX_TASK_STRUCT_SEARCH_SIZE) )
  {
    return (INV_ADDR);
  }
  
  for (i = 0; i < MAX_TASK_STRUCT_SEARCH_SIZE; i += sizeof(target_ulong))
  {
    temp = get_target_ulong_at(ts + i);
    if (isKernelAddress(temp))
    {
      if (findPGDFromMMStruct(temp, pPI, bDoubleCheck) != INV_ADDR)
      {
        pPI->ts_mm = i;
        return (temp);
      }  
    } 
  }

  return (INV_ADDR);
}

//the characteristic of task struct list is that next is followed by previous
//both of which are pointers
// furthermore, next->previous should be equal to self
// same with previous->next
//lh is the list_head (or supposedly list head)
int isListHead(gva_t lh)
{
  gva_t pPrev = lh + sizeof(target_ulong);
  gva_t next = 0;
  gva_t prev = 0;

  if ( !isKernelAddress(lh) || !isKernelAddress(pPrev) )
  {
    return (0);
  }

  //if both lh and lh+target_ulong (previous pointer) are pointers
  // then we can dereference them
  next = get_target_ulong_at(lh);
  prev = get_target_ulong_at(pPrev);

  if ( !isKernelAddress(next) || !isKernelAddress(prev) )
  {
    return (0);
  }
 
  // if the actual dereferences are also pointers (because they should be)
  // then we can check if the next pointer's previous pointer are the same 
  if ( (get_target_ulong_at(prev) == lh)
       && (get_target_ulong_at(next + sizeof(target_ulong)) == lh)
     )
  {
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
gva_t findTaskStructListFromTaskStruct(gva_t ts, ProcInfo* pPI, int bDoubleCheck)
{
  target_ulong i = 0;
  gva_t temp = 0;

  if (pPI == NULL)
  {
    return (INV_ADDR);
  }

  //this works for -1 as well (the default value) since we are using target_ulong
  if (pPI->ts_mm >= MAX_TASK_STRUCT_SEARCH_SIZE)
  {
    return (INV_ADDR);
  }
 
  //must check the whole range (includes overflow)
  if ( !isStructKernelAddress(ts, MAX_TASK_STRUCT_SEARCH_SIZE) )
  {
    return (INV_ADDR);
  }

  //We use the first such doubly linked list that comes before the
  // mmstruct pointer, 28 is the size of the template
  // 3 list heads plus an int
  //The reason for this type of search is because in 2.6 we have
  // list_head tasks, followed by plist_head (which is an int followed
  // by two list heads - might even have an additional pointer even - TODO - handle that case
  //in kernel version 3, the plist_node is wrapped by a CONFIG_SMP #def
  //TODO: Double check that target_ulong is the right way to go
  // the idea is that plist_node actually uses an int - however in 64 bit
  // systems, the fact that list_head defines a pointer - it would imply that
  // the int prio should take up 8 bytes anyways (so that things are aligned properly)
  for (i = (SIZEOF_LIST_HEAD * 3 + sizeof(target_ulong)); i < pPI->ts_mm; i+=sizeof(target_ulong))
  {
    temp = ts + pPI->ts_mm - i;
    //if its a list head - then we can be sure that this should work
    if (isListHead(temp))
    {
      printk(KERN_INFO "[i = %"T_FMT"d] %d, %d, %d, --- \n", i, isListHead(temp)
         , isListHead(temp + SIZEOF_LIST_HEAD + sizeof(target_ulong))
         , isListHead(temp + SIZEOF_LIST_HEAD + SIZEOF_LIST_HEAD + sizeof(target_ulong))
         );
      
      if ( isListHead(temp + SIZEOF_LIST_HEAD + sizeof(target_ulong))
         && isListHead(temp + SIZEOF_LIST_HEAD +SIZEOF_LIST_HEAD + sizeof(target_ulong))
         )
      {
        //printk(KERN_INFO "FOUND task_struct_list offset [%d]\n", (uint32_t)temp - ts);
        pPI->ts_tasks = temp - ts;
        return (get_target_ulong_at(temp)); 
      }
    }
  }

  //if we are here - then that means we did not find the pattern - which could be because
  // we don't have smp configured on a 3 kernel
  //TODO: enable and test this part - needs a second level check later just in case
  // this was incorrect
  for (i = sizeof(target_ulong); i < pPI->ts_mm; i += sizeof(target_ulong))
  {
    temp = ts + pPI->ts_mm - i;
    if (isListHead(temp))
    {
      pPI->ts_tasks = temp - ts;
      return (get_target_ulong_at(temp));
    }
  }

  return (0);
}

//basically uses the threadinfo test to see if the current is a task struct
//We also use the task_list as an additional precaution since
// the offset of the threadinfo (i.e., stack) is 4 and the offset of 
// the task_struct in threadinfo is 0 which just happens to correspond
// to previous and next if this ts was the address of a list_head
// instead
//TODO: Find another invariance instead of the tasks list?
int isTaskStruct(gva_t ts, ProcInfo* pPI)
{
  gva_t temp = 0;
  gva_t temp2 = 0;

  if (pPI == NULL)
  {
    return (0);
  }

  if (!isStructKernelAddress(ts, MAX_TASK_STRUCT_SEARCH_SIZE))
  {
    return (0);
  }

  if ( (pPI->ts_stack == INV_OFFSET) || (pPI->ti_task) )
  {
    return (0);
  }

  temp = ts + pPI->ts_stack;

  //dereference temp to get to the TI and then add the offset to get back
  // the pointer to the task struct
  temp2 = get_target_ulong_at(temp) + pPI->ti_task;
  if ( !isKernelAddress(temp2) )
  {
    return (0);
  }
 
  //now see if the tasks is correct
  if ( !isListHead(ts + pPI->ts_tasks) )
  {
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
gva_t findRealParentGroupLeaderFromTaskStruct(gva_t ts, ProcInfo* pPI)
{
  target_ulong i = 0;
  
  if (pPI == NULL)
  {
    return (INV_ADDR);
  }

  for (i = 0; i < MAX_TASK_STRUCT_SEARCH_SIZE; i += sizeof(target_ulong))
  {
    if ( isTaskStruct(get_target_ulong_at(ts+i), pPI) //real_parent
       && isTaskStruct(get_target_ulong_at(ts+i+sizeof(target_ulong)), pPI) //parent
       && isListHead(ts+i+sizeof(target_ulong)+sizeof(target_ulong)) //children
       && isListHead(ts+i+sizeof(target_ulong)+sizeof(target_ulong)+SIZEOF_LIST_HEAD) //sibling
       && isTaskStruct(get_target_ulong_at(ts+i+sizeof(target_ulong)+sizeof(target_ulong)+SIZEOF_LIST_HEAD+SIZEOF_LIST_HEAD), pPI) //group_leader
       )
    {
      if (pPI->ts_real_parent == INV_OFFSET)
      {
        pPI->ts_real_parent = i;
      }
      if (pPI->ts_group_leader == INV_OFFSET)
      {
        pPI->ts_group_leader = i+sizeof(target_ulong)+sizeof(target_ulong)+SIZEOF_LIST_HEAD+SIZEOF_LIST_HEAD;
      }
      return (ts+i);
    }
  }
  return (INV_ADDR);
}

//The characteristics of the init_task that we use are
//The mm struct pointer is NULL - since it shouldn't be scheduled?
//The parent and real_parent is itself
int isInitTask(gva_t ts, ProcInfo* pPI, int bDoubleCheck)
{
  int bMMCheck = 0;
  int bRPCheck = 0;

  if ( (pPI == NULL) || !isStructKernelAddress(ts, MAX_TASK_STRUCT_SEARCH_SIZE) )
  {
    return (0);
  }

  //if we have the mm offset already then just check it
  if (pPI->ts_mm != INV_OFFSET)
  {
    if ( get_target_ulong_at(ts + pPI->ts_mm) == 0)
    {
      bMMCheck = 1;
    }
  }
  if (pPI->ts_real_parent != INV_OFFSET)
  {
    if (get_target_ulong_at(ts + pPI->ts_real_parent) == ts)
    {
      bRPCheck = 1;
    }
  }
  if ( (bDoubleCheck && bMMCheck && bRPCheck)
     || (!bDoubleCheck && (bMMCheck || bRPCheck))
     )
  {
    if (pPI->init_task_addr == INV_OFFSET)
    {
      pPI->init_task_addr = ts;  
    }
    return (1);
  }

  return (0); 
}

//To find the "comm" field, we look for the name of
// init_task which is "swapper" -- we don't check for "swapper/0" or anything else
gva_t findCommFromTaskStruct(gva_t ts, ProcInfo* pPI)
{
  target_ulong i = 0;
  //char* temp = NULL; //not used yet, because we are using the int comparison instead
  target_ulong temp2 = 0;
  //char* strInit = "swapper";
  uint32_t intSWAP = 0x70617773; //p, a, w, s
  uint32_t intPER = 0x2f726570; ///, r, e, p
  if (pPI == NULL)
  {
    return (INV_ADDR);
  }

  if (!isInitTask(ts, pPI, 0))
  {
    return (INV_ADDR);
  }

  //once again we are assuming that things are aligned
  for (i = 0; i < MAX_TASK_STRUCT_SEARCH_SIZE; i+=sizeof(target_ulong)) 
  {
    temp2 = ts + i;
    if (get_uint32_at(temp2) == intSWAP)
    {
      temp2 += 4; //move to the next item
      if ((get_uint32_at(temp2) & 0x00FFFFFF) == (intPER & 0x00FFFFFF))
      {
        if (pPI->ts_comm == INV_OFFSET)
        {
          pPI->ts_comm = i;
        }
        return (ts+i);
      }
    }
  }

  return (INV_ADDR);
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
// which happens to have the whole array of pid_link
// pid_link consists of hlist, a basically another couple of pointers
// and a pointer to a pid (which seems to be the same value)
gva_t findThreadGroupFromTaskStruct(gva_t ts, ProcInfo* pPI)
{
  target_ulong i = 0;

  if ( (pPI == NULL) )
  {
    return (INV_ADDR);
  }

  if (pPI->ts_group_leader == INV_OFFSET) 
  {
    i = 0;
  } //we can start from the group_leader as a shortcut
  else 
  {
    i = pPI->ts_group_leader;
  }

  if (!isInitTask(ts, pPI, 0))
  {
    return (INV_ADDR);
  }

  for ( ; i < MAX_TASK_STRUCT_SEARCH_SIZE; i+=sizeof(target_ulong))
  {
    /*
    printk(KERN_INFO "%d === %"T_FMT"x, %"T_FMT"x, %"T_FMT"x, %"T_FMT"x, %"T_FMT"x, %d,%d,%d,%d,%d\n", i, get_target_ulong_at(ts + i),
       get_target_ulong_at(ts + i + sizeof(target_ulong)),
       get_target_ulong_at(ts+i+sizeof(target_ulong)+sizeof(target_ulong)),
       get_target_ulong_at(ts+i+(sizeof(target_ulong)*3)),
       get_target_ulong_at(ts+i+(sizeof(target_ulong)*4)),
    (get_target_ulong_at(ts + i) == 0),
       (get_target_ulong_at(ts + i + sizeof(target_ulong)) == 0),
       isKernelAddress(get_target_ulong_at(ts+i+sizeof(target_ulong)+sizeof(target_ulong))),
       isListHead(get_target_ulong_at(ts+i+(sizeof(target_ulong)*3))), //is a list head
       (get_target_ulong_at(ts+i+(sizeof(target_ulong)*4)) == 0) //this is the entry for vfork_done ?
    );
    */
    //for init task the pid_link list should be all NULLS
    if ( (get_target_ulong_at(ts + i) == 0)
       && (get_target_ulong_at(ts + i + sizeof(target_ulong)) == 0)
       && isKernelAddress(get_target_ulong_at(ts+i+sizeof(target_ulong)+sizeof(target_ulong)))
       && isListHead(get_target_ulong_at(ts+i+(sizeof(target_ulong)*3))) //is a list head
       && (get_target_ulong_at(ts+i+(sizeof(target_ulong)*3)+SIZEOF_LIST_HEAD) == 0) //this is the entry for vfork_done ?
       )
    {
      if ( pPI->ts_thread_group == INV_OFFSET )
      {
        pPI->ts_thread_group = i + (sizeof(target_ulong)*3);
      }
      return (ts + i + (sizeof(target_ulong)*3));
    }
  }
  return (INV_ADDR);
}

//we find cred by searching backwards starting from comm
//The signature is that we have an array of list heads (which is for
// the cpu_timers
// followed by real_cred and cred (both of which are pointers)
// followed by stuff (in 2.6.32) and then comm
gva_t findCredFromTaskStruct(gva_t ts, ProcInfo* pPI)
{
  target_ulong i = 0;
  if ((pPI == NULL) || (pPI->ts_comm == INV_OFFSET) )
  {
    return (INV_ADDR);
  }
  if (!isStructKernelAddress(ts, MAX_TASK_STRUCT_SEARCH_SIZE))
  {
    return (INV_ADDR);
  }

  //we start at 16 because of the list_head followed by
  // the two pointers
  for (i = (sizeof(target_ulong)*4); i < pPI->ts_comm; i+=sizeof(target_ulong))
  {
    if ( isListHead(get_target_ulong_at(ts + pPI->ts_comm - i))
        && isKernelAddress(get_target_ulong_at(ts + pPI->ts_comm - i + SIZEOF_LIST_HEAD))
        && isKernelAddress(get_target_ulong_at(ts + pPI->ts_comm - i + SIZEOF_LIST_HEAD + sizeof(target_ulong)))
       )
    {
      if (pPI->ts_real_cred == INV_OFFSET)
      {
        pPI->ts_real_cred = pPI->ts_comm - i + SIZEOF_LIST_HEAD;
      }
      if (pPI->ts_cred == INV_OFFSET)
      {
        pPI->ts_cred = pPI->ts_comm - i + SIZEOF_LIST_HEAD + sizeof(target_ulong);
      }
      return (ts + pPI->ts_comm - i + SIZEOF_LIST_HEAD + sizeof(target_ulong));
    }
  }
  return (INV_ADDR);
}

#ifdef __target_i386__
  #define STACK_CANARY_MASK 0xFFFF0000
#else
  #define STACK_CANARY_MASK 0xFFFF0000FFFF0000 
#endif
//pid and tgid are pretty much right on top of
// the real_parent, except for the case when a stack
// canary might be around. We will try to see
// if the canary is there - because canaries are supposed
// to be random - which is different from tgid and pid
// both of which are small numbers - so we try it this
// way
gva_t findPIDFromTaskStruct(gva_t ts, ProcInfo* pPI)
{
  target_ulong offset = 0;
  target_ulong temp = 0;
  if ( (pPI == NULL) || (pPI->ts_real_parent == INV_OFFSET) )
  {
    return (INV_ADDR);
  }
  if (!isStructKernelAddress(ts, MAX_TASK_STRUCT_SEARCH_SIZE))
  {
    return (INV_ADDR);
  }

  if ( pPI->ts_group_leader == INV_ADDR )
  {
    return (INV_ADDR);
  }

  ts = get_target_ulong_at(ts + pPI->ts_group_leader);

  //the signature is fairly simple - both pid and tgid are going to be the same
  // as long as the task in question is a group_leader 
  //Now there is a potential for 
  // the stack canary to interfere - in which case we will
  // check for the existence of the stack canary by looking at the values
  //Since the canary is supposed to be random it should not be like pids
  // which are expected to be low values
  //Also notice that since pid_t is defined as 
  // an int - it should be 4 bytes. Thus, either the previous eight bytes
  // look like a canary or not - see the masks that mask out the low bits
  temp = get_target_ulong_at(ts+pPI->ts_real_parent-sizeof(target_ulong));
  if (temp & STACK_CANARY_MASK)
  {
    offset = sizeof(target_ulong);
  }

  if (pPI->ts_pid == INV_OFFSET)
  {
    pPI->ts_pid = pPI->ts_real_parent - sizeof(target_pid_t)*2 - offset;
  }
  if (pPI->ts_tgid == INV_OFFSET)
  {
    pPI->ts_tgid = pPI->ts_real_parent - sizeof(target_pid_t) - offset;
  }

  //as it turns out there is also a potential alignment problem on 64 bit
  // x86 - since the pointer for real_parent should be 8 bytes aligned
  // and so should the stack_canary! 
  //To see if there is a problem - we check to see if the "expected"
  // pid and tgid's match
  if (get_uint32_at(ts + pPI->ts_pid) != get_uint32_at(ts + pPI->ts_tgid))
  {
    pPI->ts_pid -= 4;
    pPI->ts_tgid -= 4;  
  }

  if (get_uint32_at(ts + pPI->ts_pid) != get_uint32_at(ts + pPI->ts_tgid))
  {
    printk(KERN_INFO "UH OH THEY ARE NOT THE SAME [%d], [%d]\n", get_uint32_at(pPI->ts_pid), get_uint32_at(pPI->ts_tgid));
  }
  return (ts + pPI->ts_pid);
}

//we should be able to populate all of the mm struct field at once
// since we are mostly interested in the vma, and the start stack, brk and etc
// areas
//So basically what we are going to rely on is the fact that
// we have 11 unsigned longs:
// startcode, endcode, startdata, enddata (4)
// startbrk, brk, startstack (3)
// argstart, argend, envstart, envend (4)
//Meaning we have a lot of fields with relative 
// addresses in the same order as defined - except for brk
int isStartCodeInMM(target_ulong* temp, target_ulong expectedStackStart)
{
  if (temp == NULL)
  {
    return (0);
  }

  if ( 
       (temp[0] > temp[1]) //startcode > endcode
       || (temp[1] > temp[2]) //endcode > startdata
       || (temp[2] > temp[3]) //startdata > enddata
       || (temp[3] > temp[4]) //enddata > startbrk 
       || (temp[4] > temp[6]) //startbrk > startstack
       || (temp[6] > temp[7]) //startstack > argstart
       || (temp[7] > temp[8]) //argstart > argend
       || (temp[8] > temp[9]) //argend > envstart
       || (temp[9] > temp[10]) //envstart > envend
       || (temp[8] != temp[9]) //argend != envstart (the same?)
       || (temp[6] < expectedStackStart) 
     )
  {
    return (0);
  }
/*
  for (i = 0; i < 11; i++)
  {
    printk(KERN_INFO "CUR [%d] %16"T_FMT"x\n", i, ((target_ulong*)(&current->mm->start_code))[i]);
  }
  for (i = 0; i < 11; i++)
  {
    printk(KERN_INFO "[%d] %16"T_FMT"x\n", i, temp[i]);
  }
*/
  return (1);
}

#define MM_TEMP_BUF_SIZE 100
int populate_mm_struct_offsets(gva_t mm, ProcInfo* pPI)
{
  target_ulong temp[MM_TEMP_BUF_SIZE + 11];
  target_ulong* pTemp = temp;
  target_ulong count = 0;
  target_ulong numRead = 0;

  if (pPI == NULL)
  {
    return (-1);
  }

  if (!isStructKernelAddress(mm, MAX_MM_STRUCT_SEARCH_SIZE))
  {
    return (-1); 
  }

  //mmap always comes first it looks like
  if (pPI->mm_mmap == INV_OFFSET)
  {
    pPI->mm_mmap = 0;
  }

  memset(temp, 0, sizeof(temp));
  //grab a 11 ulong block

  for (count = 0; count < (MAX_MM_STRUCT_SEARCH_SIZE / sizeof(target_ulong)); count++)
  {
    if ( (count % MM_TEMP_BUF_SIZE) == 0)
    {
      //if at the end of the buffer reset the pTemp pointer
      // to the beginning
      pTemp = temp;
      //if we are at the beginning then grab 11 ulongs at a time
      if (get_mem_at(mm+(sizeof(target_ulong)*count), pTemp, 11*sizeof(target_ulong)) != (11*sizeof(target_ulong)))
      {
        return (-1);
      }
      numRead += 11;
    }
    else //if not then just read the next value
    {
      //increment pTemp
      pTemp++;
      //10 is the 11th element
      pTemp[10] = get_target_ulong_at(mm+(sizeof(target_ulong) * (numRead)));
      numRead++;
    }
    
    if (isStartCodeInMM(pTemp, TARGET_MIN_STACK_START))
    {
      break;
    }
  }

  if (count >= (MAX_MM_STRUCT_SEARCH_SIZE / sizeof(target_ulong)))
  {
    return (-1);
  }

  //if we are here that means we found it
  if (pPI->mm_start_brk == INV_OFFSET)
  {
    pPI->mm_start_brk = sizeof(target_ulong)*(count+4);
  }
  if (pPI->mm_brk == INV_OFFSET)
  {
    pPI->mm_brk = sizeof(target_ulong)*(count+5);
  }
  if (pPI->mm_start_stack == INV_OFFSET)
  {
    pPI->mm_start_stack = sizeof(target_ulong)*(count+6);
  }
  if (pPI->mm_arg_start == INV_OFFSET)
  {
    pPI->mm_arg_start = sizeof(target_ulong)*(count+7);
  }
  return (0);
}

//determines whether the address belongs to an RB Node
// RB as in Red Black Tree - it should work for any tree really
// maybe?
int isRBNode(gva_t vma)
{
  target_ulong parent = 0;
  target_ulong left = 0;
  target_ulong right = 0;
  target_ulong parent_mask = ~0x3;

  if (!isKernelAddress(vma))
  {
    return (0);
  }

  parent = get_target_ulong_at(vma);
  right = get_target_ulong_at(vma+ sizeof(target_ulong));
  left = get_target_ulong_at(vma+ (sizeof(target_ulong)*2));
  
  if (!isKernelAddress(parent))
  {
    return (0);
  }

  //see if either left or right is NULL and if not NULL
  // then see if they point back to parent
  if (left != 0) 
  {
    if ( !isKernelAddress(left) )
    {
      return (0);
    }
    //now check to see if right and left point back to parent
    // here we are going to simply ignore the least significant 2 bits
    // While it is not perfect (rb_node is long aligned) it should be good enough
    //the minimum size of rb_node is 12 bytes anwways.
    if ( (get_target_ulong_at(left) & (parent_mask)) != (parent & (parent_mask)) )
    {
      return (0);
    }
  }

  if (right != 0) 
  {
    if ( !isKernelAddress(right) )
    {
      return (0);
    }
    if ( (get_target_ulong_at(right) & (parent_mask)) != (parent & (parent_mask)) )
    {
      return (0);
    }
  }

  return (1);
  //finally we can check to see if the current node is one of the paren'ts left
  //TODO:
}

//This signature is different for 2.6 and for 3 
// The basic idea is that in 2.6 we have the mm_struct* vm_mm first
// followed by vm_start and vm_end (both ulongs)
// In 3 we have vm_start and vm_end first and vm_mm will come much later
//Now since vm_start is supposed to be the starting address of 
// the vm area - it must be a userspace virtual address. This is a perfect
// test to see which version of the kernel we are dealing with since
// the mm_struct* would be a kernel address
int populate_vm_area_struct_offsets(gva_t vma, ProcInfo* pPI)
{
  int is26 = 0;
  target_ulong i = 0;

  if (pPI == NULL)
  {
    return (-1);
  }

  if (!isStructKernelAddress(vma, MAX_VM_AREA_STRUCT_SEARCH_SIZE))
  {
    return (-1);
  }

  if (isKernelAddress(get_target_ulong_at(vma)))
  {
    //if its a kernel pointer then we are dealing with 2.6
    is26 = 1;
    if (pPI->vma_vm_start == INV_OFFSET)
    {
      pPI->vma_vm_start = sizeof(target_ulong);
    }
    if (pPI->vma_vm_end == INV_OFFSET)
    {
      pPI->vma_vm_end = sizeof(target_ulong)*2;
    }
    if (pPI->vma_vm_next == INV_OFFSET)
    {
      pPI->vma_vm_next = sizeof(target_ulong)*3;
    } 
  }
  else
  {
    if (pPI->vma_vm_start == INV_OFFSET)
    {
      pPI->vma_vm_start = 0;
    }
    if (pPI->vma_vm_end == INV_OFFSET)
    {
      pPI->vma_vm_end = sizeof(target_ulong);
    }
    if (pPI->vma_vm_next == INV_OFFSET)
    {
      pPI->vma_vm_next = sizeof(target_ulong)*2;
    } 
  }

  //now that we have populated vm_start, vm_end and vm_next, we need to find the rest
  //to find vm_flags - we use two different signatures
  // in 2.6 it is right before the first rb_node
  for (i = 0; i < MAX_VM_AREA_STRUCT_SEARCH_SIZE; i+=sizeof(target_ulong))
  {
    if (isRBNode(vma + i))
    {
      if (pPI->vma_vm_flags == INV_OFFSET)
      {
        if (is26)
        {
          pPI->vma_vm_flags = i - sizeof(target_ulong); //- sizeof(vm_flags)
        }
        else
        {
          //for version 3 we look for the rb_node and add 3 target_ulongs
          // 1 first the rb_subtree_gap, 1 for vm_mm pointer and one for vm_page_prot
          //we also have to add in the size of the rb_node which is another 3 target_ulongs
          pPI->vma_vm_flags = i + (sizeof(target_ulong)*6);
        }
      }
      break;
    }
  }
  
  //to get the vm_file we look for list_head (anon_vma_chain)
  // followed by the anon_vma* followed by the vm_operations_struct pointer
  // followed by a non-poiner since its a page offset (which should be 
  // usespace address -- this is the important one
  // followed by a pointer the vmfile (and another pointer) 
  //we just continue from where we left off before in the search since
  // file comes after flags
  for ( ; i < MAX_VM_AREA_STRUCT_SEARCH_SIZE; i += sizeof(target_ulong))
  {
    if (isListHead(vma+i))
    {
      //first we see if the short circuiting works - if it does then we are set
      if (!isKernelAddress(get_target_ulong_at(vma + i + SIZEOF_LIST_HEAD + sizeof(target_ulong) + sizeof(target_ulong))))
      {
        if (pPI->vma_vm_file == INV_OFFSET)
        {
          pPI->vma_vm_file = i + SIZEOF_LIST_HEAD + (sizeof(target_ulong) * 3);
        }
        break;
      }
    }
  } 

  return (0);
}

//dentry is simple enough its just a pointer away
// first is the union of list_head and rcu_head
// list head is 2 pointers and rcu_head is 2 pointers
// one for rcu_head and another for the function pointer
//then struct path is itself two pointers thus
// its a constant - 3 pointers away
int getDentryFromFile(gva_t file, ProcInfo* pPI)
{
  if (pPI == NULL)
  {
    return (-1);
  }
  if (pPI->file_dentry == INV_OFFSET)
  {
    pPI->file_dentry = sizeof(target_ulong) * 3;
  }
  return (0);
}


//the cred struct hasn't changed from 2.6 so its the same
// the struct is also quite simple in that there is an atomic_t (its an int) in front
// followed by the possibility of a bunch of other declarations including a pointer
// and a magic number
// This is all followed by the entries of interest to us
// thus they either start at an offset 4 (for the atomic_t) or something else
//What we do here is going to just keep searching until we see a bunch of values
// that look like uids. The only problem is that uids can possibly be 16 bits
// in length instead of 32 bits in length. So that can be a little bit tricky.
//We can actually tell the difference by seeing if the higher bits are zero
// in most cases we will see that the uid is going to be low numbers
//Furthermore, we can also look for cred in a known to be root process
// such as init.
#define IS_UID(_x) (_x < 0x0000FFFF)
int populate_cred_struct_offsets(gva_t cred, ProcInfo* pPI)
{
  target_ulong i = sizeof(target_int);

  if (pPI == NULL)
  {
    return (-1);
  }

  if (!isStructKernelAddress(cred, MAX_CRED_STRUCT_SEARCH_SIZE))
  {
    return (-1);
  }

  for (i = sizeof(target_int); i < MAX_CRED_STRUCT_SEARCH_SIZE; i += sizeof(target_int))
  {
    if (
         IS_UID(get_uint32_at(cred + i)) //uid
         && IS_UID(get_uint32_at(cred + i + sizeof(target_int))) //gid
         && IS_UID(get_uint32_at(cred + i + (sizeof(target_int) * 2))) //suid
         && IS_UID(get_uint32_at(cred + i + (sizeof(target_int) * 3))) //sgid
         && IS_UID(get_uint32_at(cred + i + (sizeof(target_int) * 4))) //euid
         && IS_UID(get_uint32_at(cred + i + (sizeof(target_int) * 5))) //egid
       )
    {
      if (pPI->cred_uid == INV_OFFSET)
      {
        pPI->cred_uid = i;
      }
      if (pPI->cred_gid == INV_OFFSET)
      {
        pPI->cred_gid = i + sizeof(target_int);
      }
      if (pPI->cred_euid == INV_OFFSET)
      {
        pPI->cred_euid = i + (sizeof(target_int) * 4);
      }
      if (pPI->cred_egid == INV_OFFSET)
      {
        pPI->cred_egid = i + (sizeof(target_int) * 5);
      }
      break;
    }
  }

  return (0);
}

//d_parent is the third pointer - since it is after hlist_bl_node -
// which contains two pointers
//Then d_name is right after d_parent
// finally d_iname is after d_name and another pointer which is d_inode
// d_iname is a qstr which is a data structure with a HASH plus a 
// pointer to the name
// basically we can use a bunch of pointers to help find the offsets
// of interest
//The only problem is that the pointers can be NULL - 
// so the question is how to handle these situations?
//For now I am just going to use some hardcoded offsets
// since the only unknown in this the seqcount - which is an unsigned
// so basically it is 4 bytes
//TODO: Try to figure this out - the only problem
// is that not all vmarea structs have files and dentry objects
// which means to do this properly - we will likely need to
// search for the first executable page (where the binary is loaded)
// and then look at the name for that dentry - that way
// we can be sure that at least d_iname is defined - and can look
// for the cstring there.
int populate_dentry_struct_offsets(gva_t dentry, ProcInfo* pPI)
{
  target_ulong i = 0;

  if (pPI == NULL)
  {
    return (-1);
  }

  i = sizeof(unsigned int) + sizeof(unsigned); 
  i += sizeof(target_ulong) + sizeof(target_ulong); //hlist_bl_node is two pointers

  
  if (pPI->dentry_d_parent == INV_OFFSET)
  {
    pPI->dentry_d_parent = i;
  }
  if (pPI->dentry_d_name == INV_OFFSET)
  {
    pPI->dentry_d_name = i + sizeof(target_ulong);
  }

  i += sizeof(target_ulong); //push out d_name

  //now we add in the qstr
  i += sizeof(uint64_t) + sizeof(target_ulong); // u32 (for hash) and u32 for len plus the pointer
  //now add in the d_inode pointer
  i += sizeof(target_ulong);


  if (pPI->dentry_d_iname == INV_OFFSET)
  {
    pPI->dentry_d_iname = i;
  }

  return (0);
  
  /** Not used yet **
  if (!isStructKernelAddress(dentry, MAX_DENTRY_STRUCT_SEARCH_SIZE))
  {
    return (-1);
  }

  for (i = 0; i < MAX_DENTRY_STRUCT_SEARCH_SIZE; i += sizeof(target_ulong))
  {
     t1 = get_target_ulong_at(dentry+i);
     t2 = get_target_ulong_at(dentry+i+sizeof(target_ulong));
     t3 = get_target_ulong_at(dentry+i+(sizeof(target_ulong)*3));
printk("%d [%"T_FMT"x, %"T_FMT"x, %"T_FMT"x\n", i, t1, t2, t3);
    if (
         isKernelAddress(get_target_ulong_at(dentry+i))
         && isKernelAddress(get_target_ulong_at(dentry+i+sizeof(target_ulong)))
         && isKernelAddress(get_target_ulong_at(dentry+i+(sizeof(target_ulong)*2)))
       )
    {
      if (pPI->dentry_d_parent == INV_OFFSET)
      {
        pPI->dentry_d_parent = i + (sizeof(target_ulong)*2);
      }
      if (pPI->dentry_d_name == INV_OFFSET)
      {
        pPI->dentry_d_name = i + (sizeof(target_ulong)*3);
      }
      break;
    }
  }

  //now we continue searching (thus not initializing i again
  // until we fine two consecutive pointers
  // after which is d_iname 
  //TODO: there is a chance that the HASH will turn up as a 
  // kernel pointer - so we should just check that d_iname is
  // a character string
  for (; i < MAX_DENTRY_STRUCT_SEARCH_SIZE; i += sizeof(target_ulong))
  {
    if (
         isKernelAddress(get_target_ulong_at(dentry+i))
         && isKernelAddress(get_target_ulong_at(dentry+i+sizeof(target_ulong)))
       )
    {
      if (pPI->dentry_d_iname == INV_OFFSET)
      {
        pPI->dentry_d_iname = i + sizeof(target_ulong);
      }
      break;
    } 
  }
  return (0);
  /** END **/
}

//runs through the guest's memory and populates the offsets within the
// ProcInfo data structure. Returns the number of elements/offsets found
// or -1 if error
int populate_kernel_offsets(ProcInfo* pPI)
{
  //first we will try to get the threadinfo structure and etc
  gva_t taskstruct = 0;
  gva_t mmstruct = 0;
  gva_t vmastruct = 0;
  gva_t vmfile = 0;
  gva_t dentrystruct = 0;
  gva_t realcred = 0;
  gva_t threadinfo = getESP() & ~8191;
 
  gva_t ret = 0;
  gva_t tempTask = 0;

  gva_t gl = 0;

  if (pPI == NULL)
  {
    return (-1);
  }

  printk(KERN_INFO "ThreadInfo @ [0x%"T_FMT"x]\n", threadinfo);
  taskstruct = findTaskStructFromThreadInfo(threadinfo, pPI, 0); 
  printk(KERN_INFO "task_struct @ [0x%"T_FMT"x] TSOFFSET = %"T_FMT"d, TIOFFSET = %"T_FMT"d\n", taskstruct, pPI->ti_task, pPI->ts_stack);

  mmstruct = findMMStructFromTaskStruct(taskstruct, pPI, 0);
  printk(KERN_INFO "mm_struct @ [0x%"T_FMT"x] mmOFFSET = %"T_FMT"d, pgdOFFSET = %"T_FMT"d\n", mmstruct, pPI->ts_mm, pPI->mm_pgd);

  findTaskStructListFromTaskStruct(taskstruct, pPI, 0);
  printk(KERN_INFO "task_struct offset = %"T_FMT"d\n", pPI->ts_tasks);

  findRealParentGroupLeaderFromTaskStruct(taskstruct, pPI);
  printk(KERN_INFO "real_parent = %"T_FMT"d, group_leader = %"T_FMT"d\n", pPI->ts_real_parent, pPI->ts_group_leader);

  //we need the group leader - since current might just be a thread - we need a real task
  gl = get_target_ulong_at(taskstruct + pPI->ts_group_leader); 
  ret = findCommFromTaskStruct(gl, pPI);
  //don't forget to to get back to the head of the task struct
  // by subtracting ts_tasks offset
  tempTask = get_target_ulong_at(gl + pPI->ts_tasks) - pPI->ts_tasks;
  while ((ret == INV_ADDR) && (tempTask != gl) && (isKernelAddress(tempTask)))
  {
    ret = findCommFromTaskStruct(tempTask, pPI);
    //move to the next task_struct
    tempTask = get_target_ulong_at(gl + pPI->ts_tasks) - pPI->ts_tasks;
  }

  if (ret != INV_ADDR)
  {
    printk(KERN_INFO "Comm offset is = %"T_FMT"d, %s \n", pPI->ts_comm, (char*)(taskstruct + pPI->ts_comm));
  }

  findCredFromTaskStruct(taskstruct, pPI);
  printk(KERN_INFO "real_cred = %"T_FMT"d, cred = %"T_FMT"d \n", pPI->ts_real_cred, pPI->ts_cred);

  findPIDFromTaskStruct(taskstruct, pPI);
  printk(KERN_INFO "pid = %"T_FMT"d, tgid = %"T_FMT"d \n", pPI->ts_pid, pPI->ts_tgid);

  //For this next test, I am just going to use the task struct lists
  findThreadGroupFromTaskStruct(pPI->init_task_addr, pPI);
  printk(KERN_INFO "Thread_group offset is %"T_FMT"d\n", pPI->ts_thread_group);

  realcred = get_target_ulong_at(taskstruct + pPI->ts_real_cred);
  populate_cred_struct_offsets(realcred, pPI);

  mmstruct = get_target_ulong_at(taskstruct + pPI->ts_mm);

  populate_mm_struct_offsets(get_target_ulong_at(taskstruct + pPI->ts_mm), pPI);

  vmastruct = get_target_ulong_at(mmstruct + pPI->mm_mmap);

  populate_vm_area_struct_offsets(vmastruct, pPI);

  vmfile = get_target_ulong_at(vmastruct + pPI->vma_vm_file);

  getDentryFromFile(vmfile, pPI);//we don't use the file data structure yet

  dentrystruct = get_target_ulong_at(vmfile + pPI->file_dentry);

  populate_dentry_struct_offsets(dentrystruct, pPI);
  return (0);
}


int printProcInfo(ProcInfo* pPI)
{
  if (pPI == NULL)
  {
    return (-1);
  }

  printk(KERN_INFO
      "    {  \"%s\", /* entry name */\n"
      "       0x%08"T_FMT"X, /* init_task address */\n"
      "       %"T_FMT"d, /* size of task_struct */\n"
      "       %"T_FMT"d, /* offset of task_struct list */\n"
      "       %"T_FMT"d, /* offset of pid */\n"
      "       %"T_FMT"d, /* offset of tgid */\n"
      "       %"T_FMT"d, /* offset of group_leader */\n"
      "       %"T_FMT"d, /* offset of thread_group */\n"
      "       %"T_FMT"d, /* offset of real_parent */\n"
      "       %"T_FMT"d, /* offset of mm */\n"
      "       %"T_FMT"d, /* offset of stack */\n"
      "       %"T_FMT"d, /* offset of real_cred */\n"
      "       %"T_FMT"d, /* offset of cred */\n"
      "       %"T_FMT"d, /* offset of comm */\n"
      "       %"T_FMT"d, /* size of comm */\n",

      pPI->strName,
      pPI->init_task_addr,
      pPI->init_task_size,
      pPI->ts_tasks,
      pPI->ts_pid,
      pPI->ts_tgid,
      pPI->ts_group_leader,
      pPI->ts_thread_group,
      pPI->ts_real_parent,
      pPI->ts_mm,
      pPI->ts_stack,
      pPI->ts_real_cred,
      pPI->ts_cred,
      pPI->ts_comm,
      SIZEOF_COMM
  );
  
  printk(KERN_INFO
      "       %"T_FMT"d, /* offset of uid cred */\n"
      "       %"T_FMT"d, /* offset of gid cred */\n"
      "       %"T_FMT"d, /* offset of euid cred */\n"
      "       %"T_FMT"d, /* offset of egid cred */\n",
      pPI->cred_uid,
      pPI->cred_gid,
      pPI->cred_euid,
      pPI->cred_egid
  );

  printk(KERN_INFO
      "       %"T_FMT"d, /* offset of mmap in mm */\n"
      "       %"T_FMT"d, /* offset of pgd in mm */\n"
      "       %"T_FMT"d, /* offset of arg_start in mm */\n"
      "       %"T_FMT"d, /* offset of start_brk in mm */\n"
      "       %"T_FMT"d, /* offset of brk in mm */\n"
      "       %"T_FMT"d, /* offset of start_stack in mm */\n",
      pPI->mm_mmap,
      pPI->mm_pgd,
      pPI->mm_arg_start,
      pPI->mm_start_brk,
      pPI->mm_brk,
      pPI->mm_start_stack
  );

  printk(KERN_INFO
      "       %"T_FMT"d, /* offset of vm_start in vma */\n"
      "       %"T_FMT"d, /* offset of vm_end in vma */\n"
      "       %"T_FMT"d, /* offset of vm_next in vma */\n"
      "       %"T_FMT"d, /* offset of vm_file in vma */\n"
      "       %"T_FMT"d, /* offset of vm_flags in vma */\n",
      pPI->vma_vm_start,
      pPI->vma_vm_end,
      pPI->vma_vm_next,
      pPI->vma_vm_file,
      pPI->vma_vm_flags
  );

  printk(KERN_INFO
      "       %"T_FMT"d, /* offset of dentry in file */\n"
      "       %"T_FMT"d, /* offset of d_name in dentry */\n"
      "       %"T_FMT"d, /* offset of d_iname in dentry */\n"
      "       %"T_FMT"d, /* offset of d_parent in dentry */\n",
      pPI->file_dentry,
      pPI->dentry_d_name,
      pPI->dentry_d_iname,
      pPI->dentry_d_parent
  );
  
  printk(KERN_INFO
      "       %"T_FMT"d, /* offset of task in thread info */\n",
      pPI->ti_task
  );

  return (0);
}

int init_module(void)
{
  struct vm_area_struct vma;
  struct file filestruct;
  struct dentry dentrystr;
  struct cred credstruct;
  struct thread_info ti;

  ProcInfo hostPI = {
      "Host",
      (target_ulong)&init_task,
      sizeof(init_task), 
      (long)&init_task.tasks - (long)&init_task,
      (long)&init_task.pid - (long)&init_task,
      (long)&init_task.tgid - (long)&init_task,
      (long)&init_task.group_leader - (long)&init_task,
      (long)&init_task.thread_group - (long)&init_task,
      (long)&init_task.real_parent - (long)&init_task,
      (long)&init_task.mm - (long)&init_task,
      { (long)&init_task.stack - (long)&init_task },
      (long)&init_task.real_cred - (long)&init_task,
      (long)&init_task.cred - (long)&init_task,
      (long)&init_task.comm - (long)&init_task,
      (long)&credstruct.uid - (long)&credstruct,
      (long)&credstruct.gid - (long)&credstruct,
      (long)&credstruct.euid - (long)&credstruct,
      (long)&credstruct.egid - (long)&credstruct,
/** Be very careful here since init_task.mm is actually NULL 
    The only reason why this works is because the compiler is
    smart enough to figure this one out. We can always use current
    I guess
**/
      (long)&init_task.mm->mmap - (long)init_task.mm,
      (long)&init_task.mm->pgd - (long)init_task.mm,
      (long)&init_task.mm->arg_start - (long)init_task.mm,
      (long)&init_task.mm->start_brk - (long)init_task.mm,
      (long)&init_task.mm->brk - (long)init_task.mm,
      (long)&init_task.mm->start_stack - (long)init_task.mm,
      (long)&vma.vm_start - (long)&vma,
      (long)&vma.vm_end - (long)&vma,
      (long)&vma.vm_next - (long)&vma,
      (long)&vma.vm_file - (long)&vma,
      (long)&vma.vm_flags - (long)&vma,
      (long)&filestruct.f_dentry - (long)&filestruct,
      (long)&dentrystr.d_name - (long)&dentrystr,
      (long)&dentrystr.d_iname - (long)&dentrystr,
      (long)&dentrystr.d_parent - (long)&dentrystr,
      (long)&ti.task - (long)&ti
    };
  ProcInfo vmi = {"VMI"};

  memset(&vmi.init_task_addr, -1, sizeof(ProcInfo) - sizeof(vmi.strName));

  populate_kernel_offsets(&vmi); 

  printProcInfo(&vmi);

  printProcInfo(&hostPI);
  printk(KERN_INFO "Information module registered.\n");
  return -1;
}

void cleanup_module(void)
{

    printk(KERN_INFO "Information module removed.\n");
}

MODULE_LICENSE("GPL");
