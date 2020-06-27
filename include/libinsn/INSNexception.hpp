//
//  INSNexception.h
//  libinsn
//
//  Created by tihmstar on 17.03.20.
//  Copyright © 2020 tihmstar. All rights reserved.
//

#ifndef INSNexception_h
#define INSNexception_h

#include <libgeneral/macros.h>
#include <libgeneral/exception.hpp>


namespace tihmstar {
    class INSNexception : public tihmstar::exception{
    public:
        INSNexception(int code, const char *filename, const char *err ...) : tihmstar::exception(code,filename,err){}
        
        std::string build_commit_count() const override {
            return VERSION_COMMIT_COUNT;
        };
        
        std::string build_commit_sha() const override{
            return VERSION_COMMIT_SHA;
        };
    };
    //custom exceptions for makeing it easy to catch

    class out_of_range : public INSNexception{
    public:
        out_of_range(int code, const char * filename, const char *err...)
            : INSNexception(code, filename, err){};
    };


};

#endif /* INSNexception_h */
