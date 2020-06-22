//
// Created by root on 6/6/20.
//

#ifndef INTEGRITYTREE_TRUSTEDAREA_H
#define INTEGRITYTREE_TRUSTEDAREA_H

#include "m_stdio.h"
#include <vector>
#include <list>


#define SHA_LENGTH_BYTES 256 //probably 256 as sha256 says..
#define KEY_SIZE 32

class TrustedArea{
    std::vector<unsigned char*> trusted_memory;
    std::list<unsigned char*> tags_list; //FIFO (QUEUE)
    // TODO: LOG
    int index; //what's this for?
    int tag_counter;
public:
    TrustedArea():index(0), tag_counter(0){}
    ~TrustedArea(){
        if(index>0){
            for(int i=0;i<trusted_memory.size();i++){
                delete[] trusted_memory[i];
            }
        }
        if(tag_counter){
            auto it=tags_list.begin();
            for(int i=0;i<trusted_memory.size();i++){
                delete[] *it;
                it=tags_list.begin();
            }
            //FIXME: DELETE EVERY MEMBER OF LIST MANUALLY
            tags_list.clear();
            tag_counter = 0;
        }

    }
    unsigned char* allocate_in_trusted_memory(unsigned char* data,unsigned int len,bool isTag){
        unsigned char* mem_data=new unsigned char[len];
        m_strncpy(mem_data,data,len);
        if(!isTag) {
            trusted_memory.push_back((mem_data));
            ++index;
        }else{
            tags_list.push_back((mem_data));
            ++tag_counter;
        }
        return mem_data;
    }
    void deallocate_from_trusted_area(){
        delete[] (trusted_memory[index]);//to be checked..
        trusted_memory.pop_back();
        index--;
        return;
    }
    void delete_tag(){
        delete[] (tags_list.front());
        tags_list.pop_front();
        --tag_counter;
    }
    void update_root(unsigned char* new_root){
        delete[] (trusted_memory[0]);
        unsigned char* mem_root=new unsigned char[SHA_LENGTH_BYTES];
        m_strncpy(mem_root,new_root,SHA_LENGTH_BYTES);
        trusted_memory[0]=mem_root;
    }
    void update_key(int index_number,unsigned char* m_key){
        if(!index_number){
            return;
        }
        memset(trusted_memory[index_number],0,KEY_SIZE);
        m_strncpy(trusted_memory[index_number],m_key,KEY_SIZE);
    }
    unsigned char* get_key(int index_number){
        if(!index_number){
            return NULL;
        }
        //m_strncpy(buf,trusted_memory[index_number],KEY_SIZE);
        return trusted_memory[index_number];
    }
    unsigned char* get_tag(){
        return tags_list.front();
    }
    unsigned char* get_root(){
        return trusted_memory[0];
    }
    void print(){
        std::cout<<"TRUSTED MEMORY V20.4 \n\n\n\n";
        for(int i=0;i<trusted_memory.size();i++){
            std::cout<<"\n"<<trusted_memory[i]<<" \n ";
        }
        std::cout << "Tags\n\n";
        for(auto it = tags_list.begin(); it != tags_list.end(); ++it){
            std::cout << *it << std::endl;
        }
    }
    int get_number_of_tags(){
        return tags_list.size();
    }


};

#endif //INTEGRITYTREE_TRUSTEDAREA_H
