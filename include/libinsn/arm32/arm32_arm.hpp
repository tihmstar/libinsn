//
//  insn_arm32.hpp
//  libinsn
//
//  Created by tihmstar on 30.06.21.
//  Copyright © 2021 tihmstar. All rights reserved.
//

#ifndef arm32_arm_hpp
#define arm32_arm_hpp

#include <libinsn/arm32/arm32_insn.hpp>

namespace tihmstar{
    namespace libinsn{
        namespace arm32{
            class arm {
            public:
                typedef uint32_t loc_t;
                typedef uint32_t offset_t;
            private:
                uint32_t _opcode;
                uint32_t _pc;
                enum arm32::type _type;
                enum subtype _subtype;
                enum supertype _supertype;

            public:
                arm(uint32_t opcode, uint32_t pc);
                ~arm();

            public:
                uint32_t opcode();
                uint32_t pc();
                
                enum cputype cputype();
                constexpr uint8_t insnsize() const {return 4;};

                enum type type();
                enum subtype subtype();
                enum supertype supertype();
        //            enum classtype classtype();
                int32_t imm();
                uint8_t rd();
                uint8_t rn();
                uint8_t rt();
        //            uint8_t rt2();
                uint8_t rm();
        //            enum cond condition();
        //            uint32_t special();
                register_list reglist();

                public: //cast operators
                    operator enum type();
                    operator loc_t();

                static constexpr uint8_t size() {return 4;};
                
#pragma mark constructor functions
            public: //constructor functions
#pragma mark general
                static arm new_A1_general_bx(loc_t pc, uint8_t rm);

#pragma mark register
#pragma mark immediate
                static arm new_A1_immediate_mov(loc_t pc, int16_t imm, uint8_t rd);

#pragma mark literal
            };
        };
    };
};
#endif /* arm32_arm_hpp */
