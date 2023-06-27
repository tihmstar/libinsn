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
//    uint64_t opcode = 0xD65F0FFF;
//    arm64::insn test(opcode,0xfffffff0084aa6dc);
    
    arm32::thumb test(0x9407,0x5ff13eae);
    
//
//    auto otest = arm64::insn::new_immediate_b(0xfffffff00828d01c, 0xfffffff00828d010);
//    printf("0x%08x\n",otest.opcode());

    auto a = test.type();
    auto s = test.subtype();
//    auto rn = test.rn();
//    auto rd = test.condition();
//    auto rm = test.rm();
    auto rt = test.rt();
//    auto t = test.supertype();
//    auto c = test.classtype();
    auto i = test.imm();
//    auto regs = test.reglist();
//
    
//    auto list = test.reglist();
    
    auto t2 = arm64::insn::new_register_msr(0, 0, tihmstar::libinsn::arm64::insn::tpidr_el1, true);
    uint32_t opcode2 = t2.opcode();
    
    printf("");
    return 0;
}
