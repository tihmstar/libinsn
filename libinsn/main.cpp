//
//  main.cpp
//  libinsn
//
//  Created by tihmstar on 17.03.20.
//  Copyright © 2020 tihmstar. All rights reserved.
//

#include <iostream>
#include "insn.hpp"

using namespace tihmstar::libinsn;

int main(int argc, const char * argv[]) {

    uint64_t opcode = 0x58000101; //ldr        x1, =...
    
    insn test(opcode,0);
    
    
    auto a = test.type();
    auto s =test.subtype();
    auto i = test.imm();
    
    insn ts = insn::new_literal_ldr(0, 4*8, 1);
    uint32_t opcode2 = ts.opcode();

    
    printf("");
    return 0;
}
