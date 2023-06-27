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
        //            virtual int32_t imm() override;
        //            virtual uint8_t rd() override;
        //            uint8_t rn();
        //            uint8_t rt();
        //            uint8_t rt2();
        //            virtual uint8_t rm() override;
        //            enum cond condition();
        //            uint32_t special();
        //
                public: //cast operators
                    operator enum type();
                    operator loc_t();

                static constexpr uint8_t size() {return 4;};
            };
        };
    };
};
#endif /* arm32_arm_hpp */
