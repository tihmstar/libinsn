//
//  insn_encode.cpp
//  libinsn
//
//  Created by tihmstar on 04.04.20.
//  Copyright © 2020 tihmstar. All rights reserved.
//

#include <libgeneral/macros.h>

#include "insn.hpp"
#include "INSNexception.hpp"

#ifdef DEBUG
#   include <stdint.h>
static constexpr uint64_t BIT_RANGE(uint64_t v, int begin, int end) { return ((v)>>(begin)) % (1UL << ((end)-(begin)+1)); }
static constexpr uint64_t BIT_AT(uint64_t v, int pos){ return (v >> pos) & 1; }
static constexpr uint64_t SET_BITS(uint64_t v, int begin) { return (((uint64_t)v)<<(begin));}
#else
#   define BIT_RANGE(v,begin,end) ( ((v)>>(begin)) % (1UL << ((end)-(begin)+1)) )
#   define BIT_AT(v,pos) ( (v >> pos) & 1 )
#   define SET_BITS(v, begin) ((((uint64_t)v)<<(begin)))
#endif

using namespace tihmstar::libinsn;

#pragma mark general


insn insn::new_general_adr(loc_t pc, uint64_t imm, uint8_t rd){
    insn ret(0,pc);
    
    ret._opcode |= SET_BITS(0b10000, 24);
    ret._opcode |= SET_BITS(rd & 0b11111, 0);
    
    if (imm > pc) {
        retassure(imm-pc < (1UL<<20), "immediate difference needs to be smaller than (1<<20)");
    }else{
        retassure(pc-imm < (1UL<<20), "immediate difference needs to be smaller than (1<<20)");
    }
    imm -= pc;
    
    ret._opcode |= SET_BITS(BIT_RANGE(imm,0,1), 29);
    ret._opcode |= SET_BITS(BIT_RANGE(imm,2,20), 5);
    
    return ret;
}

insn insn::new_general_adrp(loc_t pc, uint64_t imm, uint8_t rd){
    insn ret(0,pc);
    
    retassure((imm & 0xfff) == 0, "immediate needs to be 0xfff byte aligned!");
    
    ret._opcode |= SET_BITS(0b10010000, 24);
    ret._opcode |= SET_BITS(rd & 0b11111, 0);

    if (imm > pc) {
        retassure(imm-pc < (1UL<<32), "immediate difference needs to be smaller than (1<<32)");
    }else{
        retassure(pc-imm < (1UL<<32), "immediate difference needs to be smaller than (1<<32)");
    }
    
    imm -=pc;
    
    ret._opcode |= SET_BITS(BIT_RANGE(imm,0,1), 29);
    ret._opcode |= SET_BITS(BIT_RANGE(imm,2,19), 5);
    
    return ret;
}

insn insn::new_general_br(loc_t pc, uint8_t rn, uint8_t rm, enum pactype pac){
    insn ret(0,pc);
    uint8_t Z = 0;
    uint8_t A = 0;
    uint8_t M = 0;

    ret._opcode |= SET_BITS(0b1101011, 25);
    ret._opcode |= SET_BITS(0b111110000, 12);
    ret._opcode |= SET_BITS(rn & 0b11111, 5);

    if (pac == pac_none) {
        Z = 0;
        A = 0;
        M = 0;
        rm = 0;
    }else{
        A = 1;
        switch (pac) {
            case pac_AA:
                Z = 1;
                M = 0;
                break;
            case pac_AAZ:
                Z = 0;
                M = 0;
                rm = 0b11111;
                break;
            case pac_AB:
                Z = 1;
                M = 1;
                break;
            case pac_ABZ:
                Z = 0;
                M = 1;
                rm = 0b11111;
                break;

            case pac_none: //not reached!
            default:
                reterror("unexpecetd pac type!");
                break;
        }
    }
    
    ret._opcode |= SET_BITS(Z, 24);
    ret._opcode |= SET_BITS(A, 11);
    ret._opcode |= SET_BITS(M, 10);
    ret._opcode |= SET_BITS(rm & 0b11111, 5);

    return ret;
}

insn insn::new_general_ldp_index(loc_t pc, int8_t imm, uint8_t rt, uint8_t rt2, uint8_t rn, bool isPreindex){
    insn ret(0,pc);
    ret._opcode |= SET_BITS(0b1010100011, 22);

    ret._opcode |= SET_BITS(isPreindex & 1, 24);

    retassure(imm < 64 || imm <= -64, "immediate needs to be 7 bit signed int");

    ret._opcode |= SET_BITS(rt2 & 0b11111, 10);
    ret._opcode |= SET_BITS(rn & 0b11111, 5);
    ret._opcode |= SET_BITS(rt & 0b11111, 0);
    
    return ret;
}

insn insn::new_general_ldp_offset(loc_t pc, int8_t imm, uint8_t rt, uint8_t rt2, uint8_t rn){
    insn ret(0,pc);
    ret._opcode |= SET_BITS(0b1010100101, 22);

    retassure(imm < 64 || imm <= -64, "immediate needs to be 7 bit signed int");

    ret._opcode |= SET_BITS(rt2 & 0b11111, 10);
    ret._opcode |= SET_BITS(rn & 0b11111, 5);
    ret._opcode |= SET_BITS(rt & 0b11111, 0);
    
    return ret;
}

insn insn::new_general_stp_index(loc_t pc, int8_t imm, uint8_t rt, uint8_t rt2, uint8_t rn, bool isPreindex){
    insn ret(0,pc);
    ret._opcode |= SET_BITS(0b1010100010, 22);

    ret._opcode |= SET_BITS(isPreindex & 1, 24);

    retassure(imm < 64 || imm <= -64, "immediate needs to be 7 bit signed int");

    ret._opcode |= SET_BITS(rt2 & 0b11111, 10);
    ret._opcode |= SET_BITS(rn & 0b11111, 5);
    ret._opcode |= SET_BITS(rt & 0b11111, 0);
    
    return ret;
}

insn insn::new_general_stp_offset(loc_t pc, int8_t imm, uint8_t rt, uint8_t rt2, uint8_t rn){
    insn ret(0,pc);
    ret._opcode |= SET_BITS(0b1010100100, 22);

    retassure(imm < 64 || imm <= -64, "immediate needs to be 7 bit signed int");

    ret._opcode |= SET_BITS(rt2 & 0b11111, 10);
    ret._opcode |= SET_BITS(rn & 0b11111, 5);
    ret._opcode |= SET_BITS(rt & 0b11111, 0);
    
    return ret;
}

insn insn::new_general_nop(loc_t pc){
    insn ret(0,pc);
    ret._opcode = 0b11010101000000110010000000011111;
    return ret;
}

insn insn::new_general_ret(loc_t pc){
    insn ret(0,pc);
    ret._opcode = 0b11010110010111110000001111000000;
    return ret;
}


#pragma mark register

insn insn::new_register_mov(loc_t pc, int64_t imm, uint8_t rd, uint8_t rn, uint8_t rm){
    insn ret(0,pc);
    
    ret._opcode |= SET_BITS(0b0101010, 24) | SET_BITS(1, 31);
    ret._opcode |= (rd % (1<<5));
    ret._opcode |= SET_BITS(rm & 0b11111, 16) ;
    ret._opcode |= SET_BITS(rn & 0b11111, 5) ;
    ret._opcode |= SET_BITS(imm & 0b111111, 10) ;
    
    return ret;
}

insn insn::new_register_ccmp(loc_t pc, cond condition, uint8_t flags, uint8_t rn, uint8_t rm){
    insn ret(0,pc);

    ret._opcode |= SET_BITS(0b1111010010, 21) | SET_BITS(1, 31);//64bit val (x regs, not w regs)

    ret._opcode |= SET_BITS(rm % (1<<5), 16);
    ret._opcode |= SET_BITS((uint8_t)condition % (1<<4), 12);
    ret._opcode |= SET_BITS(rn % (1<<5), 5);
    ret._opcode |= SET_BITS(flags % (1<<5), 0);

    return ret;
}


#pragma mark literal immediate

insn insn::new_immediate_add(loc_t pc, uint64_t imm, uint8_t rn, uint8_t rd){
    insn ret(0,pc);
    uint8_t shift = 0b00;
    
    if ((imm & ((1UL << 12)-1)) == 0) {
        //DO LSL 12
        shift = 0b01;
        imm >>= 12;
    }
    retassure(imm < (1UL<<12), "immediate difference needs to be smaller than (1<<12)");
    
    ret._opcode |= SET_BITS(0b0010001, 24);
    ret._opcode |= SET_BITS(shift, 22);
    ret._opcode |= SET_BITS(imm & ((1UL<<12)-1), 10);
    ret._opcode |= SET_BITS(rn & 0b11111, 5);
    ret._opcode |= SET_BITS(rd & 0b11111, 0);

    return ret;
}

insn insn::new_immediate_bl(loc_t pc, int64_t imm){
    insn ret(0,pc);
    
    ret._opcode |= SET_BITS(0b100101, 26);
    imm -= (uint64_t)pc;
    imm >>=2;
    ret._opcode |= imm & ((1<<26)-1);
    
    return ret;
}

insn insn::new_immediate_b(loc_t pc, uint64_t imm){
    insn ret(0,pc);
    retassure((imm & 0b11) == 0, "immediate needs to be 4 byte aligned!");

    ret._opcode |= SET_BITS(0b000101, 26);
    if (imm > pc) {
        retassure(imm-pc < (1UL<<25), "immediate difference needs to be smaller than (1<<25)");
    }else{
        retassure(pc-imm < (1UL<<25), "immediate difference needs to be smaller than (1<<25)");
    }
    imm -= pc;
    imm >>=2;
    ret._opcode |= imm & ((1UL<<26)-1);
    
    return ret;
}

insn insn::new_immediate_bcond(loc_t pc, uint64_t imm, enum cond condition){
    insn ret(0,pc);
    retassure((imm & 0b11) == 0, "immediate needs to be 4 byte aligned!");

    ret._opcode |= SET_BITS(0b01010100, 24);
    
    if (imm > pc) {
        retassure(imm-pc < (1UL<<19), "immediate difference needs to be smaller than (1<<19)");
    }else{
        retassure(pc-imm < (1UL<<19), "immediate difference needs to be smaller than (1<<19)");
    }
    imm -= pc;
    imm >>=2;
    ret._opcode |= SET_BITS(imm,5);
    ret._opcode |= SET_BITS(condition & 0b1111, 0);
    
    return ret;
}

insn insn::new_immediate_cbz(loc_t pc, int32_t imm, int8_t rt, bool isCBNZ){
    insn ret(0,pc);
    ret._opcode |= SET_BITS(0b1011010, 25);

    ret._opcode |= SET_BITS(isCBNZ & 1, 24);

    retassure(imm < 0x80000 || imm <= -0x80000, "imm nees to be signed 19 bit");
    
    ret._opcode |= SET_BITS(imm & 0x7ffff, 5);
    ret._opcode |= SET_BITS(rt & 0b11111, 0);
    
    return ret;
}

insn insn::new_immediate_movz(loc_t pc, int64_t imm, uint8_t rd, uint8_t rm){
    insn ret(0,pc);

    ret._opcode |= SET_BITS(0b10100101, 23) | SET_BITS(1, 31);//64bit val (x regs, not w regs)
    ret._opcode |= (rd % (1<<5));
    ret._opcode |= SET_BITS(imm & ((1<<16)-1), 5);
    ret._opcode |= SET_BITS(rm & 0b11, 21); //set shift here
    
    return ret;
}

insn insn::new_immediate_movk(loc_t pc, int64_t imm, uint8_t rd, uint8_t rm){
    insn ret(0,pc);

    ret._opcode |= SET_BITS(0b11100101, 23) | SET_BITS(1, 31);//64bit val (x regs, not w regs)
    ret._opcode |= (rd % (1<<5));
    ret._opcode |= SET_BITS(imm & ((1UL<<16)-1), 5);
    ret._opcode |= SET_BITS(rm & 0b11, 21); //set shift here
    
    return ret;
}

insn insn::new_immediate_ldr(loc_t pc, int64_t imm, uint8_t rn, uint8_t rt){
    insn ret(0,pc);
    
    ret._opcode |= SET_BITS(0b1111100101, 22);
    imm >>= (ret._opcode >> 30);
    imm %= (1 << 11);
    imm <<= 10;
    ret._opcode |= imm;
    
    ret._opcode |= SET_BITS(rn & 0b11111, 5);
    ret._opcode |= SET_BITS(rt & 0b11111, 0);

    return ret;
}

insn insn::new_immediate_tbz(loc_t pc, int16_t imm, uint8_t b5, uint8_t b40, uint8_t rt, bool isTBNZ){
    insn ret(0,pc);
    ret._opcode |= SET_BITS(0b011011, 25);
    ret._opcode |= SET_BITS(b5 & 1, 31);
    ret._opcode |= SET_BITS(b40 & 0b11111, 19);

    ret._opcode |= SET_BITS(isTBNZ & 1, 24);

    retassure(imm < 0x4000 || imm <= -0x4000, "imm nees to be signed 14 bit");
    
    ret._opcode |= SET_BITS(imm & 0x3fff, 5);
    ret._opcode |= SET_BITS(rt & 0b11111, 0);
    
    return ret;
}



#pragma mark literal

insn insn::new_literal_ldr(loc_t pc, uint64_t imm, uint8_t rt){
    insn ret(0,pc);
    
    if (imm > pc) {
        retassure(imm-pc < (1UL<<18), "immediate difference needs to be smaller than (1<<18)");
    }else{
        retassure(pc-imm < (1UL<<18), "immediate difference needs to be smaller than (1<<18)");
    }

    imm -= pc;

    retassure((imm & 0b11) == 0, "immediate needs to be 4 byte aligned");

    imm >>=2;
        
    ret._opcode |= SET_BITS(0b01011000, 24);
    ret._opcode |= SET_BITS(imm & ((1UL<<19)-1), 5);
    ret._opcode |= SET_BITS(rt & 0b11111, 0);
    
    return ret;
}
