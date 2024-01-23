//
//  arm32_thumb_encode.cpp
//  libinsn
//
//  Created by tihmstar on 07.07.21.
//  Copyright © 2021 tihmstar. All rights reserved.
//

#include <libgeneral/macros.h>
#include "../include/libinsn/INSNexception.hpp"
#include "../include/libinsn/arm32/arm32_thumb.hpp"

#ifdef DEBUG
#   include <stdint.h>
__attribute__((unused)) static constexpr uint32_t BIT_RANGE(uint32_t v, int begin, int end) { return ((v)>>(begin)) % (1UL << ((end)-(begin)+1)); }
__attribute__((unused)) static constexpr uint32_t BIT_AT(uint32_t v, int pos){ return (v >> pos) & 1; }
__attribute__((unused)) static constexpr uint32_t SET_BITS(uint32_t v, int begin) { return (((uint32_t)v)<<(begin));}
#else
#   define BIT_RANGE(v,begin,end) ( ((v)>>(begin)) % (1UL << ((end)-(begin)+1)) )
#   define BIT_AT(v,pos) ( (v >> pos) & 1 )
#   define SET_BITS(v, begin) ((((uint32_t)v)<<(begin)))
#endif

using namespace tihmstar::libinsn::arm32;

extern std::pair<int32_t, bool> ThumbExpandImm_C(int16_t imm12, bool carry_in);

int16_t ThumbShrinkImm_C(int32_t imm32) {
    uint8_t p0 = (imm32 >>  0) & 0xff;
    uint8_t p1 = (imm32 >>  8) & 0xff;
    uint8_t p2 = (imm32 >> 16) & 0xff;
    uint8_t p3 = (imm32 >> 24) & 0xff;

    if (imm32 < 0x100) {
        return (int16_t)imm32;
    }
    
    if (p0 == p1 && p0 == p2 && p0 == p3) {
        return p0 | SET_BITS(0b11, 8);
    }else if (p0 && p0 == p2) {
        return p0 | SET_BITS(0b01, 8);
    } else if (p1 && p1 == p3) {
        return p1 | SET_BITS(0b10, 8);
    }else{
        reterror("either unimplemented, or impossible value");
    }
}

#pragma mark general

thumb thumb::new_T1_general_nop(loc_t pc){
    return {
        static_cast<uint32_t>(0xbf00)
        ,pc
    };
}

thumb thumb::new_T1_general_bx(loc_t pc, uint8_t rm){
    return {
        static_cast<uint32_t>(SET_BITS(0b010001110, 7) |
                              SET_BITS(rm & 0b1111, 3) |
                              SET_BITS(0b000, 0))
        ,pc
    };
}

#pragma mark register
thumb thumb::new_T2_register_mov(loc_t pc, uint8_t rd, uint8_t rm){
    return {
        static_cast<uint32_t>(SET_BITS(0b0000000000, 6) |
                              SET_BITS(rm & 0b111, 3) |
                              SET_BITS(rd & 0b111, 0))
        ,pc
    };
}

thumb thumb::new_T3_register_mov(loc_t pc, uint8_t rd, uint8_t rm){
    return {
        /*I1*/static_cast<uint32_t>(SET_BITS(0b1110101001001111, 0))
        | (
        /*I2*/static_cast<uint32_t>(SET_BITS(0b0000, 12) |
                                    SET_BITS(rd & 0b1111, 8) |
                                    SET_BITS(0b0000, 4) |
                                    SET_BITS(rm & 0b1111, 0))
        << 16)
        ,pc
    };
}

#pragma mark immediate

thumb thumb::new_T1_immediate_bcond(loc_t pc, loc_t dst, enum cond condition){
    int16_t imm = (dst-pc-4) >> 1;
    retassure(imm >= -128 & imm <= 127, "imm out of range");
    return {
        static_cast<uint32_t>(SET_BITS(0b1101, 12) |
                              SET_BITS(condition & 0b1111, 8) |
                              SET_BITS(imm & 0xff, 0))
        ,pc
    };
}

thumb thumb::new_T1_immediate_bl(loc_t pc, loc_t dst){
    int32_t imm = (dst - pc - 4) >> 1;
    uint32_t i_S = BIT_AT(imm, 24);
    uint32_t i_J1 = BIT_AT(imm, 23) ^ 1 ^ i_S;
    uint32_t i_J2 = BIT_AT(imm, 22) ^ 1 ^ i_S;
    uint16_t imm10 = BIT_RANGE(imm, 11, 21);
    uint16_t imm11 = BIT_RANGE(imm, 0, 11);

    return {
        /*I1*/static_cast<uint32_t>(SET_BITS(0b11110, 11) |
                                    SET_BITS(i_S & 1, 10) |
                                    SET_BITS(imm10, 0))
        | (
        /*I2*/static_cast<uint32_t>(SET_BITS(0b1101, 12) |
                                    SET_BITS(i_J1, 13)   |
                                    SET_BITS(i_J2, 11)   |
                                    SET_BITS(imm11, 0))
        << 16)
        ,pc
    };
}

thumb thumb::new_T1_immediate_ldr(loc_t pc, uint8_t imm, uint8_t rn, uint8_t rt){
    retassure((imm & 0b11) == 0, "imm needs to be 4 byte aliged!");
    imm >>=2;
    return {
        static_cast<uint32_t>(SET_BITS(0b01101, 11) |
                              SET_BITS(imm & 0b11111, 6) |
                              SET_BITS(rn & 0b111, 3)    |
                              SET_BITS(rt & 0b111, 0))
        ,pc
    };
}

thumb thumb::new_T1_immediate_cmp(loc_t pc, uint8_t imm, uint8_t rn){
    return {
        static_cast<uint32_t>(SET_BITS(0b00101, 11) |
                              SET_BITS(rn & 0b111, 8)    |
                              SET_BITS(imm & 0xff, 0))
        ,pc
    };
}

thumb thumb::new_T1_immediate_movs(loc_t pc, int8_t imm, uint8_t rd){
    return {
        static_cast<uint32_t>(SET_BITS(0b00100, 11) |
                              SET_BITS(rd & 0b111, 8) |
                              SET_BITS(imm, 0))
        ,pc
    };
}

thumb thumb::new_T1_immediate_str(loc_t pc, int8_t imm, uint8_t rn, uint8_t rt){
    return {
        static_cast<uint32_t>(SET_BITS(0b01100, 11) |
                              SET_BITS(imm & 0b11111, 6) |
                              SET_BITS(rn & 0b111, 3) |
                              SET_BITS(rt & 0b111, 0))
        ,pc
    };
}

thumb thumb::new_T2_immediate_b(loc_t pc, loc_t dst){
    int16_t imm = (dst - pc - 4) >> 1;
    return {
        static_cast<uint32_t>(SET_BITS(0b11100, 11) |
                              SET_BITS(imm & 0x7ff, 0))
        ,pc
    };
}

thumb thumb::new_T2_immediate_cmp(loc_t pc, int32_t imm, uint8_t rn){
    uint16_t putimm = ThumbShrinkImm_C(imm);
    return {
        /*I1*/static_cast<uint32_t>(SET_BITS(0b11110, 11) |
                                    SET_BITS((putimm >> 11) & 1, 10) |
                                    SET_BITS(0b011011, 4) |
                                    SET_BITS(rn & 0b1111, 0))
        | (
        /*I2*/static_cast<uint32_t>(SET_BITS((putimm >> 8) & 0b111, 12) |
                                    SET_BITS(0b1111, 8) |
                                    SET_BITS(putimm & 0b11111111, 0))
        << 16)
        ,pc
    };
}

thumb thumb::new_T2_immediate_ldr(loc_t pc, int16_t imm, uint8_t rt){
    retassure((imm & 0b11) == 0, "imm needs to be 4 byte aliged!");
    imm >>=2;
    return {
        static_cast<uint32_t>(SET_BITS(0b10011, 11) |
                              SET_BITS(rt & 0b111, 8) |
                              SET_BITS(imm & 0xff, 0))
        ,pc
    };
}

thumb thumb::new_T2_immediate_str(loc_t pc, int16_t imm, uint8_t rt){
    retassure((imm & 0b11) == 0, "imm needs to be 4 byte aliged!");
    imm >>=2;
    return {
        static_cast<uint32_t>(SET_BITS(0b10010, 11) |
                              SET_BITS(rt & 0b111, 8) |
                              SET_BITS(imm & 0xff, 0))
        ,pc
    };
}

#pragma mark literal

thumb thumb::new_T1_literal_ldr(loc_t pc, loc_t src, uint8_t rt){
    uint16_t imm = (src-pc-4);
    retassure((imm & 0b11) == 0, "imm needs to be 4 byte aliged!");
    imm >>=2;
    
    return {
        static_cast<uint32_t>(SET_BITS(0b01001, 11) |
                              SET_BITS(rt & 0b111, 8) |
                              SET_BITS(imm & 0xff, 0))
        ,pc
    };
}
