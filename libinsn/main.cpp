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

    uint64_t opcode = 3532016201; //ldr
    
    insn test(opcode,0x4000);
    
    
    auto a = test.type();
    auto s =test.subtype();

    auto i = test.imm();
    
    printf("");
    return 0;
}
