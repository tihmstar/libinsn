//
//  insn.cpp
//  liboffsetfinder64
//
//  Created by tihmstar on 09.03.18.
//  Copyright © 2018 tihmstar. All rights reserved.
//

#include <libgeneral/macros.h>

#include "../include/libinsn/arm64.hpp"
#include "../include/libinsn/INSNexception.hpp"

#ifdef DEBUG
#   include <stdint.h>
static constexpr uint64_t BIT_RANGE(uint64_t v, int begin, int end) { return ((v)>>(begin)) % (1 << ((end)-(begin)+1)); }
static constexpr uint64_t BIT_AT(uint64_t v, int pos){ return (v >> pos) % 2; }
static constexpr uint64_t SET_BITS(uint64_t v, int begin) { return ((v)<<(begin));}
#else
#   define BIT_RANGE(v,begin,end) ( ((v)>>(begin)) % (1 << ((end)-(begin)+1)) )
#   define BIT_AT(v,pos) ( (v >> pos) % 2 )
#   define SET_BITS(v, begin) (((v)<<(begin)))
#endif

using namespace tihmstar::libinsn::arm64;


insn::insn(uint32_t opcode, uint64_t pc)
: _opcode(opcode), _pc(pc), _type(unknown)
{
    //
}

#pragma mark reference manual helpers
__attribute__((always_inline)) static uint64_t signExtend64(uint64_t v, int vSize){
    uint64_t e = (v & 1 << (vSize-1))>>(vSize-1);
    for (int i=vSize; i<64; i++)
        v |= e << i;
    return v;
}

__attribute__((always_inline)) static int highestSetBit(uint64_t x){
    for (int i=63; i>=0; i--) {
        if (x & ((uint64_t)1<<i))
            return i;
    }
    return -1;
}

__attribute__((always_inline)) static int lowestSetBit(uint64_t x){
    for (int i=0; i<=63; i++) {
        if (x & (1<<i))
            return i;
    }
    return 64;
}

__attribute__((always_inline)) static uint64_t replicate(uint64_t val, int bits){
    uint64_t ret = val;
    unsigned shift;
    for (shift = bits; shift < 64; shift += bits) {    // XXX actually, it is either 32 or 64
        ret |= (val << shift);
    }
    return ret;
}

__attribute__((always_inline)) static uint64_t ones(uint64_t n){
    uint64_t ret = 0;
    while (n--) {
        ret <<=1;
        ret |= 1;
    }
    return ret;
}

__attribute__((always_inline)) static uint64_t ROR(uint64_t x, int shift, int len){
    return ((x >> shift) | (x << (len - shift))) & ones(len);
}

static inline uint64_t ror(uint64_t elt, unsigned size)
{
    return ((elt & 1) << (size-1)) | (elt >> 1);
}

static inline uint64_t AArch64_AM_decodeLogicalImmediate(uint64_t val, unsigned regSize){
    // Extract the N, imms, and immr fields.
    unsigned N = (val >> 12) & 1;
    unsigned immr = (val >> 6) & 0x3f;
    unsigned imms = val & 0x3f;
    unsigned i;
    
    // assert((regSize == 64 || N == 0) && "undefined logical immediate encoding");
//    int len = 31 - countLeadingZeros((N << 6) | (~imms & 0x3f));
    int len = highestSetBit( (uint64_t)((N<<6) | ((~imms) & 0b111111)) );

    // assert(len >= 0 && "undefined logical immediate encoding");
    unsigned size = (1 << len);
    unsigned R = immr & (size - 1);
    unsigned S = imms & (size - 1);
    // assert(S != size - 1 && "undefined logical immediate encoding");
    uint64_t pattern = (1ULL << (S + 1)) - 1;
    for (i = 0; i < R; ++i)
        pattern = ror(pattern, size);
    
    // Replicate the pattern to fill the regSize.
    while (size != regSize) {
        pattern |= (pattern << size);
        size *= 2;
    }
    
    return pattern;
}

__attribute__((always_inline)) static std::pair<int64_t, int64_t> DecodeBitMasks(uint64_t immN, uint8_t imms, uint8_t immr, bool immediate){
    uint64_t tmask = 0, wmask = 0;
    int8_t levels = 0; //6bit

    int len = highestSetBit( (uint64_t)((immN<<6) | ((~imms) & 0b111111)) );
    assure(len != -1); //reserved value
    levels = ones(len);

    assure(!(immediate && (imms & levels) == levels)); //reserved value

    uint8_t esize = 1 << len;
    uint8_t S = imms & levels;
    uint8_t R = immr & levels;


    uint8_t diff = S - R; // 6-bit subtract with borrow
    
    uint8_t d = (diff & ((1<<len)-1)) << 1;
    
    uint64_t welem = ones(S + 1);
    uint64_t telem = ones(d + 1);
        
    wmask = replicate(ROR(welem, R, esize),esize);
    tmask = replicate(telem,esize);
#warning TODO incomplete function implementation!
    return {wmask,tmask};
}


#pragma mark static type determinition

constexpr enum insn::type is_ret(uint32_t i){
    return ((0b111111111111 | i) == 0b11010110010111110000111111111111) ? insn::ret : insn::unknown;
}

constexpr enum insn::type is_br_blr(uint32_t i){
    if (BIT_RANGE(i, 25, 31) == 0b1101011 && BIT_RANGE(i, 11, 23) == 0b0011111100001) {
        if (BIT_AT(i, 24) == 1) return BIT_AT(i, 10) == 0 ? insn::blraa : insn::blrab;
        else if (BIT_RANGE(i, 0, 4) == 0b11111) return BIT_AT(i, 10) == 0 ? insn::blraaz : insn::blrabz;
    }
    i = (BIT_RANGE(i | SET_BITS(1, 24), 12, 31));
    return (i == 0b11010111000111110000) ? insn::br //check for BR
        :  (i == 0b11010111001111110000) ? insn::blr : insn::unknown; //check for BLR
}

constexpr enum insn::type is_ldrh(uint32_t i){
    return (((BIT_RANGE(i, 21, 31) == 0b01000011) && (BIT_RANGE(i, 10, 11) == 0b10)) /* register*/
        || ((BIT_RANGE(i, 21, 31) == 0b01111000010)
            && ((BIT_RANGE(i, 10, 11) == 0b01) /* imm post-index*/ || (BIT_RANGE(i, 10, 11) == 0b11) /* imm pre-index*/ ))
        || (BIT_RANGE(i, 22, 31) == 0b0111100101) /*unsigned offset */) ? insn::ldrh : insn::unknown;
}

constexpr enum insn::type is_movk(uint32_t i){
    return (BIT_RANGE(i, 23, 30) == 0b11100101) ? insn::movk : insn::unknown;
}

constexpr enum insn::type is_orr(uint32_t i){
    return (BIT_RANGE(i, 23, 30) == 0b01100100) ? insn::orr : insn::unknown;
}

constexpr enum insn::type is_ldxr(uint32_t i){
    return ((BIT_RANGE(i, 24, 29) == 0b001000) && (i >> 31) && BIT_AT(i, 22)) ? insn::ldxr : insn::unknown;
}

constexpr enum insn::type is_ldrb(uint32_t i){
    return (BIT_RANGE(i, 21, 31) == 0b00111000010 || //Immediate post/pre -indexed
           BIT_RANGE(i, 22, 31) == 0b0011100101  || //Immediate unsigned offset
           (BIT_RANGE(i, 21, 31) == 0b00111000011 && BIT_RANGE(i, 10, 11) == 0b10)/*Register*/) ? insn::ldrb : insn::unknown;
}

constexpr enum insn::type is_strb(uint32_t i){
    return (BIT_RANGE(i, 21, 31) == 0b00111000000 || //Immediate post/pre -indexed
           BIT_RANGE(i, 22, 31) == 0b0011100100  || //Immediate unsigned offset
           (BIT_RANGE(i, 21, 31) == 0b00111000001 && BIT_RANGE(i, 10, 11) == 0b10)/*Register*/) ? insn::strb : insn::unknown;
}

constexpr enum insn::type is_str(uint32_t i){
    if ((BIT_RANGE(i, 22, 29) == 0b11100100) && (i >> 31)) return insn::str; //immediate
    if (BIT_RANGE(i | SET_BITS(1, 30), 21, 31) == 0b11111000001 && BIT_RANGE(i, 10, 11) == 0b10) return insn::str; //register
    return insn::unknown;
}

constexpr enum insn::type is_stp(uint32_t i){
    return (BIT_RANGE(i, 25, 30) == 0b10100 && BIT_RANGE(i, 23, 24) != 0b00 && BIT_AT(i, 22) == 0) ? insn::stp : insn::unknown;
}

constexpr enum insn::type is_ldp(uint32_t i){
    return (BIT_RANGE(i, 25, 30) == 0b10100 && BIT_RANGE(i, 23, 24) != 0b00 && BIT_AT(i, 22) == 1) ? insn::ldp : insn::unknown;
}

constexpr enum insn::type is_movz(uint32_t i){
    return (BIT_RANGE(i, 23, 30) == 0b10100101) ? insn::movz : insn::unknown;
}

constexpr enum insn::type is_bcond(uint32_t i){
    return ((BIT_RANGE(i, 24, 31) == 0b01010100) && !BIT_AT(i, 4)) ? insn::bcond : insn::unknown;
}

constexpr enum insn::type is_nop(uint32_t i){
    return (i == 0b11010101000000110010000000011111) ? insn::nop : insn::unknown;
}

constexpr enum insn::type is_and(uint32_t i){
    return (BIT_RANGE(i, 23, 30) == 0b00100100 /*immediate*/) ? insn::and_ : insn::unknown;
}

constexpr enum insn::type is_csel(uint32_t i){
    return ((BIT_RANGE(i, 21, 30) == 0b0011010100) && (BIT_RANGE(i, 10, 11) == 0b00)) ? insn::csel : insn::unknown;
}

constexpr enum insn::type is_mrs(uint32_t i){
    return (BIT_RANGE(i, 20, 31) == 0b110101010011) ? insn::mrs : insn::unknown;
}

constexpr enum insn::type is_msr(uint32_t i){
    return (BIT_RANGE(i, 20, 31) == 0b110101010001) ? insn::msr : insn::unknown;
}

constexpr enum insn::type is_ccmp(uint32_t i){
    return (BIT_RANGE(i, 21, 30) == 0b1111010010/* register */) ? insn::ccmp : insn::unknown;
}

constexpr enum insn::type is_madd(uint32_t i){
    return ((BIT_RANGE(i, 21, 30) == 0b0011011000) && (BIT_AT(i, 15) == 0)) ? insn::madd : insn::unknown;
}

constexpr enum insn::type is_smaddl(uint32_t i){
    return ((BIT_RANGE(i, 21, 30) == 0b0011011001) && (BIT_AT(i, 15) == 0)) ? insn::smaddl : insn::unknown;
}

constexpr enum insn::type is_umaddl(uint32_t i){
    return ((BIT_RANGE(i, 21, 30) == 0b0011011101) && (BIT_AT(i, 15) == 0)) ? insn::umaddl : insn::unknown;
}

constexpr enum insn::type is_autda(uint32_t i){
    return (BIT_RANGE(i, 10, 31) == 0b1101101011000001000110 /*autda*/) ? insn::autda : insn::unknown;
}

constexpr enum insn::type is_autdza(uint32_t i){
    return (BIT_RANGE(i, 5, 31) == 0b110110101100000100111011111 /*autdza*/) ? insn::autdza : insn::unknown;
}

constexpr enum insn::type is_pacib_int(uint32_t i){
    return (BIT_RANGE(i, 10, 31) == 0b1101101011000001000001 /*pacib*/) ? insn::pacib : insn::unknown;
}

constexpr enum insn::type is_pacizb_int(uint32_t i){
    return (BIT_RANGE(i, 10, 31) == 0b1101101011000001000001 /*pacizb*/) ? insn::pacizb : insn::unknown;
}

constexpr enum insn::type is_pacda(uint32_t i){
    return (BIT_RANGE(i | SET_BITS(1, 13), 10, 31) == 0b1101101011000001001010 /*pacda*/) ? insn::pacda : insn::unknown;
}

constexpr enum insn::type is_pacdza(uint32_t i){
    return (BIT_RANGE(i, 5, 31) == 0b110110101100000100111011111 /*pacda*/) ? insn::pacdza : insn::unknown;
}

constexpr enum insn::type is_xpacd(uint32_t i){
    return (BIT_RANGE(i, 5, 31) == 0b110110101100000101000111111 /*xpacd*/) ? insn::xpacd : insn::unknown;
}

constexpr enum insn::type is_xpaci(uint32_t i){
    return (BIT_RANGE(i, 5, 31) == 0b110110101100000101000011111 /*xpaci*/) ? insn::xpaci : insn::unknown;
}

constexpr enum insn::type is_pacibsp(uint32_t i){
    return (i == 0b11010101000000110010001101111111) ? insn::pacibsp : insn::unknown;
}

constexpr enum insn::type is_ldr(uint32_t i){
    if (((BIT_RANGE(i, 22, 29) == 0b11100001) && BIT_AT(i, 10) && BIT_AT(i, 31))
        || (BIT_RANGE(i, 22, 29) == 0b11100101 && BIT_AT(i, 31))) return insn::ldr; //immediate

    if (BIT_RANGE(i | SET_BITS(1, 30), 21, 31) == 0b11111000011 && BIT_RANGE(i, 10, 11) == 0b10) return insn::ldr; //register

    return (
            (BIT_RANGE(i | SET_BITS(1, 23), 22, 29) == 0b11110111)/*SIMD LDR*/
            || (BIT_RANGE(i | SET_BITS(1, 30), 22, 31) == 0b1111100101)
            ) ? insn::ldr : insn::unknown;
}

constexpr enum insn::type is_lsl(uint32_t i){
    return (BIT_RANGE(i, 23, 30) == 0b10100110) ? insn::lsl : insn::unknown;
}


#pragma mark decoding unit (special decoders)

typedef enum insn::type (*insn_type_test_func)(uint32_t);

constexpr const insn_type_test_func special_decoders_stp_ldp[] = {
    is_stp,
    is_ldp,
    NULL
};


constexpr const insn_type_test_func special_decoders_0b11010110[] = {
    is_ret,
    is_br_blr,
    NULL
};

constexpr const insn_type_test_func special_decoders_0b11010111[] = {
    is_br_blr,
    NULL
};


constexpr const insn_type_test_func special_decoders_0b01111000[] = {
    is_ldrh,
    NULL
};

constexpr const insn_type_test_func special_decoders_0b01111001[] = {
    is_ldrh,
    NULL
};

constexpr const insn_type_test_func special_decoders_0b00111001[] = {
    is_ldrb,
    is_strb,
    NULL
};

constexpr const insn_type_test_func special_decoders_0b01110010[] = {
    is_movk,
    NULL
};

constexpr const insn_type_test_func special_decoders_0b11110010[] = {
    is_movk,
    NULL
};

constexpr const insn_type_test_func special_decoders_0b00110010[] = {
    is_orr,
    NULL
};

constexpr const insn_type_test_func special_decoders_0b10110010[] = {
    is_orr,
    NULL
};

constexpr const insn_type_test_func special_decoders_0b10001000[] = {
    is_ldxr,
    NULL
};

constexpr const insn_type_test_func special_decoders_0b11001000[] = {
    is_ldxr,
    NULL
};

constexpr const insn_type_test_func special_decoders_0b00111000[] = {
    is_ldrb,
    is_strb,
    NULL
};

constexpr const insn_type_test_func special_decoders_0b10111000[] = {
    is_str,
    is_ldr,
    NULL
};

constexpr const insn_type_test_func special_decoders_0b11111000[] = {
    is_str,
    is_ldr,
    NULL
};

constexpr const insn_type_test_func special_decoders_0b01010010[] = {
    is_movz,
    NULL
};

constexpr const insn_type_test_func special_decoders_0b11010010[] = {
    is_movz,
    NULL
};

constexpr const insn_type_test_func special_decoders_0b01010100[] = {
    is_bcond,
    NULL
};

constexpr const insn_type_test_func special_decoders_0b11010101[] = {
    is_nop,
    is_pacibsp,
    is_mrs,
    is_msr,
    NULL
};

constexpr const insn_type_test_func special_decoders_0b00010010[] = {
    is_and,
    NULL
};

constexpr const insn_type_test_func special_decoders_0b10010010[] = {
    is_and,
    NULL
};

constexpr const insn_type_test_func special_decoders_0b00011010[] = {
    is_csel,
    NULL
};

constexpr const insn_type_test_func special_decoders_0b10011010[] = {
    is_csel,
    NULL
};

constexpr const insn_type_test_func special_decoders_0b01111010[] = {
    is_ccmp,
    NULL
};

constexpr const insn_type_test_func special_decoders_0b11111010[] = {
    is_ccmp,
    NULL
};

constexpr const insn_type_test_func special_decoders_0b00011011[] = {
    is_madd,
    is_smaddl,
    is_umaddl,
    NULL
};

constexpr const insn_type_test_func special_decoders_0b10011011[] = {
    is_madd,
    is_smaddl,
    is_umaddl,
    NULL
};

constexpr const insn_type_test_func special_decoders_0b11011010[] = {
    is_autda,
    is_autdza,
    is_pacib_int,
    is_pacizb_int,
    is_pacda,
    is_pacdza,
    is_xpacd,
    is_xpaci,
    NULL
};

constexpr const insn_type_test_func special_decoders_0b11111001[] = {
    is_ldr,
    is_str,
    NULL
};

constexpr const insn_type_test_func special_decoders_0b10111001[] = {
    is_ldr,
    is_str,
    NULL
};

constexpr const insn_type_test_func special_decoders_0b01010011[] = {
    is_lsl,
    NULL
};

constexpr const insn_type_test_func special_decoders_0b11010011[] = {
    is_lsl,
    NULL
};


#pragma mark decoding unit

struct decoder_val{
    bool isInsn;
    union {
        enum insn::type type;
        const insn_type_test_func *next_stage_decoder;
    };
};

struct decoder_stage1{
    decoder_val _stage1_insn[0x100];
    constexpr decoder_stage1() : _stage1_insn{}
    {
        for (int i=0; i<4; i++) _stage1_insn[0b10010000 | SET_BITS(i,5)] = {true, insn::adrp};
        for (int i=0; i<4; i++) _stage1_insn[0b00010000 | SET_BITS(i,5)] = {true, insn::adr};
        for (int i=0; i<4; i++) _stage1_insn[0b10010100 | SET_BITS(i,0)] = {true, insn::bl};
        for (int i=0; i<2; i++) _stage1_insn[0b00110100 | SET_BITS(i,7)] = {true, insn::cbz};
        for (int i=0; i<2; i++) _stage1_insn[0b00110111 | SET_BITS(i,7)] = {true, insn::tbnz};
        for (int i=0; i<2; i++) _stage1_insn[0b10111000 | SET_BITS(i,6)] = {true, insn::ldr};
        for (int i=0; i<2; i++) _stage1_insn[0b00110101 | SET_BITS(i,7)] = {true, insn::cbnz};
        for (int i=0; i<2; i++) _stage1_insn[0b00110110 | SET_BITS(i,7)] = {true, insn::tbz};
        for (int i=0; i<4; i++) _stage1_insn[0b00010100 | SET_BITS(i,0)] = {true, insn::b};
        for (int i=0; i<2; i++) _stage1_insn[0b00101010 | SET_BITS(i,7)] = {true, insn::mov};
        for (int i=0; i<2; i++) _stage1_insn[0b01110001 | SET_BITS(i,7)] = {true, insn::subs}; //immediate
        for (int i=0; i<2; i++) _stage1_insn[0b01101011 | SET_BITS(i,7)] = {true, insn::subs}; //shifted register

        for (int i=0; i<2; i++) _stage1_insn[0b00010001 | SET_BITS(i,7)] = {true, insn::add}; //imediate
        for (int i=0; i<2; i++) _stage1_insn[0b00001011 | SET_BITS(i,7)] = {true, insn::add}; //register
        for (int i=0; i<2; i++) _stage1_insn[0b01010001 | SET_BITS(i,7)] = {true, insn::sub}; //imediate
        for (int i=0; i<2; i++) _stage1_insn[0b01001011 | SET_BITS(i,7)] = {true, insn::sub}; //register

        for (int i=0; i<2; i++) _stage1_insn[0b00011000 | SET_BITS(i,6)] = {true, insn::ldr}; //literal

        for (int i=0; i<2; i++) _stage1_insn[0b00001010 | SET_BITS(i,7)] = {true, insn::and_}; //shifted register

        for (int i=0; i<4; i++) _stage1_insn[0b00101000 | SET_BITS(i & 1,7) | SET_BITS(i >> 1,0)] = {.isInsn = false, .next_stage_decoder = special_decoders_stp_ldp};


#define defineDecoder(binaryByte) _stage1_insn[binaryByte] = {.isInsn = false, .next_stage_decoder = special_decoders_##binaryByte};
        
        defineDecoder(0b01111001);//unchecked
        defineDecoder(0b00111001);//unchecked
        
        defineDecoder(0b11010110);
        defineDecoder(0b11010111);
        defineDecoder(0b01111000);
        defineDecoder(0b01110010);
        defineDecoder(0b11110010);
        defineDecoder(0b00110010);
        defineDecoder(0b10110010);
        defineDecoder(0b10001000);
        defineDecoder(0b11001000);
        defineDecoder(0b00111000);
        defineDecoder(0b10111000);
        defineDecoder(0b11111000);
        defineDecoder(0b01010010);
        defineDecoder(0b11010010);
        defineDecoder(0b01010100);
        defineDecoder(0b11010101);
        defineDecoder(0b00010010);
        defineDecoder(0b10010010);
        defineDecoder(0b00011010);
        defineDecoder(0b10011010);
        defineDecoder(0b01111010);
        defineDecoder(0b11111010);
        defineDecoder(0b00011011);
        defineDecoder(0b10011011);
        defineDecoder(0b11011010);
        defineDecoder(0b11111001);
        defineDecoder(0b10111001);

        defineDecoder(0b01010011);
        defineDecoder(0b11010011);

#undef defineDecoder
    };
    constexpr decoder_val operator[](uint32_t i) const{
        uint8_t l1val = static_cast<uint8_t>(i >> 24);
        decoder_val dec = _stage1_insn[l1val];
        if (dec.isInsn) {
            switch (dec.type) {
                case insn::subs:
                    //subs and cmp is the same thing, but mnemonic cmp is prefered when rd=0b11111
                    if (BIT_RANGE(i, 0, 4) == 0b11111){
                        return {true, insn::cmp};
                    }
                    break;
                    
                default:
                    break;
            }
        }
        return dec;
    }
};

constexpr const decoder_stage1 decode_table_stage1;


#pragma mark insn type accessors

uint32_t insn::opcode(){
    return _opcode;
}

uint64_t insn::pc(){
    return _pc;
}

enum insn::type insn::type(){
    if (_type != unknown) {
        return _type;
    }
    
    decoder_val lookup = {};
    
    lookup = decode_table_stage1[_opcode];
    if (lookup.isInsn) {
        _type = lookup.type;
    }else if (lookup.next_stage_decoder){
        for (int i=0; lookup.next_stage_decoder[i]; i++) {
            if ((_type = lookup.next_stage_decoder[i](_opcode)) != insn::unknown) {
                break;
            }
        }
    }
    
    return _type;
}

enum insn::subtype insn::subtype(){
    switch (type()) {
        case add:
            if (BIT_RANGE(_opcode, 24, 28) == 0b10001) {
                return st_immediate;
            }else{
                return st_register;
            }
        case ldrh:
            if (((BIT_RANGE(_opcode, 21, 31) == 0b01000011) && (BIT_RANGE(_opcode, 10, 11) == 0b10))) {
                return st_register;
            }else{
                return st_immediate;
            }
        case ldr:
            if ((((_opcode>>22) | (1 << 8)) == 0b1111100001) && BIT_RANGE(_opcode, 10, 11) == 0b10)
                return st_register;
            else if (_opcode>>31)
                return st_immediate;
            else if ((BIT_RANGE(_opcode | SET_BITS(1, 30), 22, 31) == 0b1111100101))
                return st_immediate;
            else
                return st_literal;
            break;
        case ldrb:
            if (BIT_RANGE(_opcode, 21, 31) == 0b00111000011 && BIT_RANGE(_opcode, 10, 11) == 0b10)
                return st_register;
            else
                return st_immediate;
            break;
        case strb:
        case str:
            if ((BIT_RANGE(_opcode, 21, 29) == 0b111000001) && (BIT_RANGE(_opcode, 10, 11) == 0b10) /* register*/) {
                return st_register;
            }else{
                return st_immediate;
            }
        case subs:
            if (BIT_RANGE(_opcode, 21, 30) == 0b1101011001 /* register_extended */) {
                return st_register_extended;
            }else if (BIT_RANGE(_opcode, 24, 30) == 0b1101011/* register */) {
                return st_register;
            }else if (BIT_RANGE(_opcode, 24, 30) == 0b1110001 /* immediate */){
                return st_immediate;
            }else{
                reterror("unexpected subtype");
            }
        case ccmp:
            if (BIT_RANGE(_opcode, 21, 30) == 0b1111010010/* register */){
                return st_register;
            }else{
                reterror("unexpected subtype");
            }
        case movz:
        case movk:
            return st_immediate;
        case mov:
            return st_register;
        default:
            return st_general;
    }
}

enum insn::supertype insn::supertype(){
    switch (type()) {
        case bl:
        case cbz:
        case cbnz:
        case tbnz:
        case tbz:
        case bcond:
        case b:
            return sut_branch_imm;

        case ldr:
        case ldrh:
        case ldrb:
        case ldxr:
        case str:
        case strb:
        case stp:
            return sut_memory;
        default:
            return sut_general;
    }
}

enum insn::classtype insn::classtype(){
    switch (type()) {
        case stp:
        case ldp:
            if (BIT_RANGE(_opcode, 23, 30) == 0b01010001)
                return cl_postindex;
            else if (BIT_RANGE(_opcode, 23, 30) == 0b01010011)
                return cl_preindex;
            else if (BIT_RANGE(_opcode, 23, 30) == 0b01010010)
                return cl_offset;
            else
                reterror("unexpected classtype for insn");
        default:
            return cl_general;
    }
}

enum insn::pactype insn::pactype(){
    switch (type()) {
        case br:
            if (BIT_AT(_opcode, 11) == 1) {//is authenticated
                if (BIT_AT(_opcode, 10) == 0) {
                    //is A
                    return (BIT_AT(_opcode, 24) == 1) ? pac_AAZ : pac_AA;
                }else{
                    //is B
                    return (BIT_AT(_opcode, 24) == 1) ? pac_ABZ : pac_AB;
                }
            }
        default:
            return pac_none;
    }
}

#pragma mark register

int64_t insn::imm(){
    switch (type()) {
        case unknown:
            reterror("can't get imm value of unknown instruction");
            break;
        case adrp:
            return ((_pc>>12)<<12) + signExtend64(((((_opcode % (1<<24))>>5)<<2) | BIT_RANGE(_opcode, 29, 30))<<12,32);
        case adr:
            return _pc + signExtend64((BIT_RANGE(_opcode, 5, 23)<<2) | (BIT_RANGE(_opcode, 29, 30)), 21);
        case add:
        case sub:
        case subs:
            return BIT_RANGE(_opcode, 10, 21) << (((_opcode>>22)&1) * 12);
        case bl:
            return _pc + (signExtend64(_opcode % (1<<26), 25) << 2); //untested
        case cbz:
        case cbnz:
        case bcond:
            return _pc + (signExtend64(BIT_RANGE(_opcode, 5, 23), 19)<<2); //untested
        case tbnz:
        case tbz:
            return _pc + (signExtend64(BIT_RANGE(_opcode, 5, 18), 13)<<2);
        case movk:
        case movz:
            return ((uint64_t)BIT_RANGE(_opcode, 5, 20)) << (BIT_RANGE(_opcode, 21, 22) * 16);
        case ldr:
        case str:
        case ldrh:
        case strh:
        case strb:
        case ldrb:
            if (st_immediate) {
                if (BIT_RANGE(_opcode | SET_BITS(1, 22), 22, 29) == 0b11100101) { //unsigned
                    return BIT_RANGE(_opcode, 10, 21) << BIT_RANGE(_opcode, 30, 31);
                }else{  //pre/post indexed
                    return BIT_RANGE(_opcode, 12, 20);
                }
            }else{
                reterror("needs st_immediate for imm to be defined!");
            }
        case orr:
        case and_:
        {
            auto bm = DecodeBitMasks(BIT_AT(_opcode, 22),BIT_RANGE(_opcode, 10, 15),BIT_RANGE(_opcode, 16,21), true);
            int64_t val = bm.first;
            if (!BIT_AT(_opcode, 31))
                val = val & 0xffffffff;
            return val;
        }
        case stp:
        case ldp:
            return signExtend64(BIT_RANGE(_opcode, 15, 21),7) << (2+(_opcode>>31));
        case b:
            return _pc + signExtend64(((_opcode % (1<< 26))<<2),26);
        case lsl:
            retassure(BIT_AT(_opcode, 31) == BIT_AT(_opcode, 22), "unexpected encoding!");

        {
            int16_t immr = BIT_RANGE(_opcode, 16, 21);
            if (BIT_AT(_opcode, 31)) {
                return 64-immr;
            }else{
                return 32-immr;
            }
        }
        default:
            reterror("failed to get imm value");
            break;
    }
    return 0;
}

uint8_t insn::ra(){
    switch (type()) {
        case unknown:
            reterror("can't get ra of unknown instruction");
            break;
        case madd:
        case smaddl:
        case umaddl:
            return BIT_RANGE(_opcode, 10, 14);

        default:
            reterror("failed to get rd");
            break;
    }
}

uint8_t insn::rd(){
    switch (type()) {
        case unknown:
            reterror("can't get rd of unknown instruction");
            break;
        case subs:
        case adrp:
        case adr:
        case add:
        case sub:
        case movk:
        case orr:
        case and_:
        case movz:
        case mov:
        case csel:
        case pacib:
        case pacizb:
        case lsl:
        case pacda:
        case pacdza:
        case xpacd:
        case xpaci:
        case autda:
        case autdza:
        case madd:
        case smaddl:
        case umaddl:
            return (_opcode % (1<<5));

        default:
            reterror("failed to get rd");
            break;
    }
}

uint8_t insn::rn(){
    switch (type()) {
        case unknown:
            reterror("can't get rn of unknown instruction");
            break;
        case subs:
        case add:
        case sub:
        case ret:
        case br:
        case orr:
        case and_:
        case ldxr:
        case ldrb:
        case str:
        case strb:
        case ldr:
        case ldrh:
        case stp:
        case ldp:
        case csel:
        case mov:
        case ccmp:
        case pacib:
        case pacizb:
        case pacda:
        case autda:
        case lsl:
        case blraa:
        case blrab:
        case blraaz:
        case blrabz:
        case madd:
        case smaddl:
        case umaddl:
            return BIT_RANGE(_opcode, 5, 9);

        default:
            reterror("failed to get rn");
            break;
    }
}

uint8_t insn::rt(){
    switch (type()) {
        case unknown:
            reterror("can't get rt of unknown instruction");
            break;
        case cbz:
        case cbnz:
        case tbnz:
        case tbz:
        case ldxr:
        case ldrb:
        case str:
        case strb:
        case ldr:
        case ldrh:
        case stp:
        case ldp:
        case mrs:
        case msr:
            return (_opcode % (1<<5));

        default:
            reterror("failed to get rt");
            break;
    }
}

uint8_t insn::rt2(){
    switch (type()) {
        case stp:
        case ldp:
            return BIT_RANGE(_opcode, 10, 14);

        default:
            reterror("failed to get rt2");
            break;
    }
}

uint8_t insn::rm(){
    switch (type()) {
        case ccmp:
            retassure(subtype() == st_register, "wrong subtype");
        case csel:
        case mov:
        case subs:
        case madd:
        case smaddl:
        case umaddl:
            return BIT_RANGE(_opcode, 16, 20);
            
        case br:
        case blr:
        case blraa:
        case blrab:
        case blraaz:
        case blrabz:
            retassure(pactype() != pac_none, "wrong pactype");
            return BIT_RANGE(_opcode, 0, 4);
            
        default:
            reterror("failed to get rm");
            break;
    }
}

insn::cond insn::condition(){
    uint8_t ret = 0;
    switch (type()) {
        case ccmp:
            ret = BIT_RANGE(_opcode, 12, 15);
            break;
        case bcond:
            ret = BIT_RANGE(_opcode, 0, 3);
            break;
        default:
            reterror("failed to get condition");
            break;
    }
    return (insn::cond)ret;
}

uint64_t insn::special(){
    switch (type()) {
        case tbz:
        case tbnz:
            return BIT_RANGE(_opcode, 19, 23);
        case mrs:
        case msr:
            return BIT_RANGE(_opcode, 5, 19);
        case ccmp:
            return BIT_RANGE(_opcode, 0, 3);
        default:
            reterror("failed to get special");
            break;
    }
}


#pragma mark cast operators
insn::operator enum type(){
    return type();
}

insn::operator loc_t(){
    return (loc_t)_pc;
}

