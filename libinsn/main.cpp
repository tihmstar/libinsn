//
//  main.cpp
//  libinsn
//
//  Created by tihmstar on 17.03.20.
//  Copyright © 2020 tihmstar. All rights reserved.
//

#include <iostream>
#include "insn.hpp"
#include "vmem.hpp"

using namespace tihmstar::libinsn;

int main(int argc, const char * argv[]) {    
    uint64_t opcode = 0x9BAB2933;
    arm64::insn test(opcode,0xfffffff0084aa6dc);
    
//    arm32::arm test(0xE92D40F0,0x803b65c0);
//    arm32::thumb test(0xE598,0xc044ecde);

//
    auto otest = arm32::thumb::new_T2_immediate_b(0x220002aa, 0x22000110);
    printf("0x%08x\n",otest.opcode());

    auto a = test.type();
    auto s = test.subtype();
//    auto i = test.imm();
    auto rn = test.rn();
    auto rt = test.rd();
//    auto rd = test.condition();
//    auto rm = test.rm();
//    auto rt = test.rt();
//    auto t = test.supertype();
//    auto c = test.classtype();
//    auto regs = test.reglist();
//    auto special = test.special();
//
    
//    auto list = test.reglist();
    
    auto t2 = arm64::insn::new_register_msr(0, 0, tihmstar::libinsn::arm64::insn::tpidr_el1, true);
    uint32_t opcode2 = t2.opcode();
    
    printf("");
    return 0;
}
