
// is this a hlist_node / hlist_bl_node ?
int isHListNode(CPUState * env, gva_t addr) {
  if ( !isKernelAddress(addr) || !isKernelAddress(addr + sizeof(target_ulong)) )
    return 0;
  target_ulong next = get_target_ulong_at(env, addr);
  target_ulong pprev = get_target_ulong_at(env, addr + sizeof(target_ulong));
  if ( !isKernelAddressOrNULL(next) || !isKernelAddressOrNULL(pprev) )
    return 0;
  if ( !pprev && !next )
    monitor_printf( default_mon, "a solo hlist node? \n" );

  target_ulong tmp = 0;
  if ( pprev ) {
    tmp = get_target_ulong_at(env, pprev);	// read previous node's next
    if ( addr != get_target_ulong_at(env, tmp) )
      return 0;
  }
  // how about a double-check?
  if ( next ) {
    tmp = get_target_ulong_at(env, next);	// check next node's pprev
    if ( addr != get_target_ulong_at(env, tmp + sizeof(target_ulong)) )
      return 0;
  }
  return 1;
}

int populate_dentry_struct_offsets(CPUState *env, gva_t dentry, ProcInfo* pPI)
{
  static bool isOffsetPopulated = false;
  if (isOffsetPopulated)
    return (0);

  target_ulong i = 0;
  target_ulong parent = 0;
  target_ulong chr = 0;

  if (pPI == NULL)
  {
    return (-1);
  }

  if (!isStructKernelAddress(dentry, MAX_DENTRY_STRUCT_SEARCH_SIZE))
  {
    return (-1);
  }

  // find the first hlist_node in the dentry struct
  for (i = 0; i < MAX_DENTRY_STRUCT_SEARCH_SIZE; i+=sizeof(target_ulong))
  {
    //if (DECAF_read_mem(env, dentry+i, sizeof(target_ulong), &chr) < 0)
    //  return (-1); // once the memory read fails, we won't want to populate offsets any more

    if ( isHListNode( env, dentry+i ) ) {
      pPI->dentry_d_parent = i + 2 * sizeof(target_ulong);
      break;
    }
  }

  if ( pPI->dentry_d_parent == INV_OFFSET )
  {
    return (-1);
  }


  isOffsetPopulated = true;
  return (0);
  
}
