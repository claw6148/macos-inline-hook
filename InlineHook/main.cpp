//
//  main.cpp
//  InlineHook
//
//  Created by ChileungL on 2017/12/19.
//  Copyright © 2017年 ChileungL. All rights reserved.
//

#include <iostream>
#include <libkern/OSAtomic.h>
#include <mach/mach.h>
#include <mach-o/loader.h>
#include <unistd.h>
#include <dlfcn.h>
#include "../udis86/udis86.h"

#define HI32(a) ((uint32_t)((uint64_t)(a) >> 32))
#define LO32(a) ((uint32_t)((uint64_t)(a)))


/**********
 
 == Execution flowchart ==
 (CALL) -> TargetFunc
 (CALL) -> Trampoline
 (JMP)  -> Selector
 (JMP)  -> Shadow Selector (opt)
 (JMP)  -> MyFunc
 (CALL)  -> StubFunc
 (JMP)  -> TargetFunc + N
 
 == ASM ==
 TargetFunc:
 JMP <Trampoline>
 
 Trampoline:
 MOV RAX, <Selector>
 JMP RAX
 
 Selector:
 (Head)
 JMP 0x0C   //0x00 for jumping to shadow selector
 JMP <Shadow Selector>
 POP RAX    //get callee's return address
 PUSH RBX   //save the volatile register
 (Body-1)
 MOV RBX, <RetAddr-1>
 CMP RAX, RBX
 JNE 0x0E   //jump to next body
 POP RBX    //restore the volatile register
 MOV RAX, <MyFunc-1>
 JMP RAX
 ...
 (Body-N)
 MOV RBX, <RetAddr-N>
 CMP RAX, RBX
 JNE 0x0E   //jump to next body
 POP RBX    //restore the volatile register
 MOV RAX, <MyFunc-N>
 JMP RAX
 (Dummy Body) //matched nothing
 int 3
 
 StubFunc
 (OrigInst)
 PUSH <TargetFunc + X Lo32>
 MOV [RSP+4], <TargetFunc + X Hi32>
 RET
 
 **********/

typedef struct __attribute__((packed)) {
    const u_char op_push_imm[1]={0x68};
    uint32_t addr_lo;
    const u_char op_mov_rsp_4[4]={0xc7,0x44,0x24,0x04};
    uint32_t addr_hi;
    const u_char op_ret[1]={0xC3};
}PUSH_RET;

typedef struct __attribute__((packed)) {
    const u_char op_mov_rax[2]={0x48,0xb8};
    uint64_t addr;
    const u_char op_jmp_rax[2]={0xff,0xe0};
}JMP_RAX;

typedef struct __attribute__((packed)) {
    const u_char op_call[1]={0xE8};
    uint32_t addr;
}CALL_ADDR;

typedef struct __attribute__((packed)){
    const u_char op_jmp[1]={0xE9};
    uint32_t flag=0x0c;
    JMP_RAX shadow_selector;
    const u_char op_pop_rax[1]={0x58};
    const u_char op_push_rbx[1]={0x53};
}SELECTOR_HEAD;

typedef struct __attribute__((packed)){
    const u_char op_mov_rbx[2]={0x48,0xbb};
    uint64_t src_addr;
    const u_char op_cmp_rax_rbx[3]={0x48,0x39,0xc3};
    const u_char op_jne_0x10[6]={0x0f,0x85,0x0e,0x00,0x00,0x00};
    const u_char op_pop_rbx[1]={0x5b};
    JMP_RAX dst;
}SELECTOR_BODY;

#define MAX_SEL_ITEMS 16

int set_rwe(void* addr,int size){
    int ret;
    task_t task;
    if((ret=task_for_pid(mach_task_self(), getpid(), &task))==KERN_SUCCESS) {
        ret=vm_protect(task,(vm_address_t)addr, size, 0, VM_PROT_READ|VM_PROT_WRITE|VM_PROT_EXECUTE);
    }
    return ret;
}

void selector_add_item(SELECTOR_HEAD* selector,uint64_t ret_addr,uint64_t new_func){
    SELECTOR_BODY* body=(SELECTOR_BODY*)((uint64_t)selector+sizeof(SELECTOR_HEAD));
    memcpy((void*)selector->shadow_selector.addr, selector, sizeof(SELECTOR_HEAD)+sizeof(SELECTOR_BODY)*MAX_SEL_ITEMS);
    selector->flag=0x00;
    while(body->op_mov_rbx[0]==0x48) {
        if(body->src_addr==0) break;
        body=(SELECTOR_BODY*)((uint64_t)body+sizeof(SELECTOR_BODY));
    }
    SELECTOR_BODY new_body;
    new_body.src_addr=ret_addr;
    new_body.dst.addr=new_func;
    memcpy(body, &new_body, sizeof(SELECTOR_BODY));
    body=(SELECTOR_BODY*)((uint64_t)body+sizeof(SELECTOR_BODY));
    memset(body,0xCC,sizeof(SELECTOR_BODY));
    selector->flag=0x0c;
}

void selector_del_item(SELECTOR_HEAD* selector,uint64_t ret_addr){
    SELECTOR_BODY* body=(SELECTOR_BODY*)((uint64_t)selector+sizeof(SELECTOR_HEAD));
    while(body->op_mov_rbx[0]==0x48) {
        if(body->src_addr==ret_addr) {
            memcpy((void*)selector->shadow_selector.addr, selector, sizeof(SELECTOR_HEAD)+sizeof(SELECTOR_BODY)*MAX_SEL_ITEMS);
            selector->flag=0x00;
            body->src_addr=0;
            selector->flag=0x0c;
            return;
        }
        body=(SELECTOR_BODY*)((uint64_t)body+sizeof(SELECTOR_BODY));
    }
}

SELECTOR_HEAD* selector_alloc(SELECTOR_HEAD* shadow_selector){
    int buf_size=sizeof(SELECTOR_HEAD)+sizeof(SELECTOR_BODY)*MAX_SEL_ITEMS;
    SELECTOR_HEAD* selector=(SELECTOR_HEAD*)malloc(buf_size);
    if(!selector) return selector;
    set_rwe(selector,buf_size);
    SELECTOR_HEAD head;
    head.shadow_selector.addr=(uint64_t)shadow_selector;
    memcpy(selector, &head, sizeof(SELECTOR_HEAD));
    return selector;
}

void *get_gap_by_func(void *addr) {
    Dl_info di;
    if(!dladdr(addr,&di)) return NULL;
    struct mach_header_64* hdr=(struct mach_header_64*)di.dli_fbase;
    return (void*)((pointer_t)di.dli_fbase+sizeof(struct mach_header_64)+hdr->sizeofcmds);
}

int get_min_inst_len(void *func,int min_len){
    ud_t ud_obj;
    ud_init(&ud_obj);
    ud_set_input_buffer(&ud_obj,(const uint8_t*)func,(size_t)min_len+64);
    ud_set_mode(&ud_obj, 64);
    ud_set_syntax(&ud_obj, UD_SYN_INTEL);
    int req_len=0;
    while (ud_disassemble(&ud_obj)&&req_len<min_len) {
        req_len+=ud_insn_len(&ud_obj);
    }
    return req_len;
}


bool atomic_memcpy_8bytes(void *dst, void *src, int len) {
    if(len>8) return false;
    uint64_t buf;
    memcpy(&buf,dst,8);
    memcpy(&buf,src,len);
    return OSAtomicCompareAndSwap64(*((uint64_t*)dst), buf, (volatile OSAtomic_int64_aligned64_t *)dst);
}

bool hook64(void* func,void* new_func,void **stub_func,SELECTOR_HEAD* selector) {
    JMP_RAX asm_tmpl={.addr=(uint64_t)selector};
    void* tmpl=get_gap_by_func(func);
    if(memcmp(tmpl,&asm_tmpl,sizeof(JMP_RAX))) {
        if(set_rwe(tmpl,sizeof(JMP_RAX))!=KERN_SUCCESS) return false;
        memcpy(tmpl,&asm_tmpl,sizeof(JMP_RAX));
    }
    int inst_len=get_min_inst_len(func,5);
    *stub_func=malloc(inst_len+sizeof(PUSH_RET));
    if(!*stub_func) {
        return false;
    }
    if(set_rwe(*stub_func,inst_len+sizeof(PUSH_RET))!=KERN_SUCCESS) {
        free(*stub_func);
        return false;
    }
    memcpy(*stub_func,func,inst_len);
    uint64_t ret_addr=(uint64_t)func+inst_len;
    PUSH_RET asm_stub={.addr_lo=LO32(ret_addr),.addr_hi=HI32(ret_addr)};
    memcpy((void*)((uint64_t)*stub_func+inst_len),&asm_stub,sizeof(PUSH_RET));
    CALL_ADDR asm_call={.addr=(uint32_t)((uint64_t)tmpl-(uint64_t)func-sizeof(CALL_ADDR))};
    if(set_rwe(func,sizeof(CALL_ADDR))!=KERN_SUCCESS) {
        free(*stub_func);
        return false;
    }
    selector_add_item(selector,(uint64_t)func+sizeof(CALL_ADDR),(uint64_t)new_func);
    return atomic_memcpy_8bytes(func,&asm_call,sizeof(CALL_ADDR));
}

bool unhook64(void* func,void **stub_func,SELECTOR_HEAD* selector) {
    selector_del_item(selector, (uint64_t)func+sizeof(CALL_ADDR));
    bool ret=atomic_memcpy_8bytes(func,*stub_func,sizeof(CALL_ADDR));
    free(*stub_func);
    return ret;
}

typedef uint(*t_sleep)(uint a);
t_sleep real_sleep;
uint my_sleep(uint a){
    printf("my_sleep: +%ds\n",a);
    return real_sleep(a);
}

int main(int argc, const char*  argv[]) {
    SELECTOR_HEAD* shadow_selector=selector_alloc(0);
    printf("shadow_selector=%p\n",shadow_selector);
    if(!shadow_selector) return -1;
    SELECTOR_HEAD* selector=selector_alloc(shadow_selector);
    if(!selector) return -1;
    printf("selector=%p\n",selector);
    printf("sleep=%p\n",sleep);
    printf("my_sleep=%p\n",my_sleep);
    printf("hook: %s\n",hook64((void*)sleep,
                             (void*)my_sleep,
                             (void**)&real_sleep,
                             selector)?"succ":"fail");
    printf("real_sleep=%p\n",real_sleep);
    for(int i=1;i<=3;++i) {
        printf("(%d/3) call sleep(1)...\n",i);
        sleep(1);
    }
    printf("unhook...\n");
    unhook64((void*)sleep, (void**)&real_sleep, selector);
    for(int i=1;i<=3;++i) {
        printf("(%d/3) call sleep(1)...\n",i);
        sleep(1);
    }
    printf("all done!\n");
    return 0;
}
