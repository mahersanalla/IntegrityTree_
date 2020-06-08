//
// Created by root on 6/6/20.
//

#ifndef INTEGRITYTREE_M_STDIO_H
#define INTEGRITYTREE_M_STDIO_H

#include <stdio.h>
#include <iostream>

void m_stdout(unsigned char* to_print,size_t num){
    for(int i=0;i<num;i++){
        std::cout<<to_print[i];
    }
    std::cout << "\n";
}
unsigned char* m_strncpy(unsigned char* dest,unsigned char* src,size_t num){
    if(!dest || !src){
        return NULL;
    }
    for(int i=0;i<num;i++){
        dest[i]=src[i];
    }
    return dest;
}

unsigned char* m_strncat(unsigned char* dest,size_t index,unsigned char* src,size_t num){
    if(!dest || !src){
        return NULL;
    }
    int i = index;
    for(int j=0;j<num;j++){
        dest[i]=src[j];
        i++;
    }
    return dest;
}
int m_strncmp(unsigned char* str1,unsigned char* str2,size_t num){
    if(!str1 || !str2){
        return 5;
    }
    for(int i=0;i<num;i++){
        if(str1[i] != str2[i]){
            return str1[i]-str2[i];
        }
    }
    return 0;
}

void generate_random(unsigned char *s,int len) {
    static const char alphanum[] =
            "0123456789"
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                    "abcdefghijklmnopqrstuvwxyz";

    for (int i = 0; i < len; ++i) {
        s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
    }

    //s[len] = 0;
}


#endif //INTEGRITYTREE_M_STDIO_H
