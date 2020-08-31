//
// Created by root on 6/6/20.
//
#ifndef INTEGRITYTREE_TRUSTEDAREA_H
#define INTEGRITYTREE_TRUSTEDAREA_H
#include "m_stdio.h"
#include <cstring>
#include <vector>
#include <list>
#define SHA_LENGTH_BYTES 256 //probably 256 as sha256 says..
#define KEY_SIZE 32
#define CACHE_SIZE 4

class LRUCache {
    //MainMemory* mainMemory;
    unsigned char *memory;
    // store keys of cache
    list<unsigned char *> dq;
    // store references of key in cache
    std::unordered_map<int, typename list<unsigned char *>::iterator> ma;
    int pointers[15];
    int csize; // maximum capacity of cache

public:
    // Declare the size
    LRUCache(int n, unsigned char *mainMemory1) {
        csize = n;
        memory = mainMemory1;
        //mainMemory=mainMemory1;
    }

    // Refers key x with in the LRU cache
    void refer(int x){
        // not present in cache
        if (ma.find(x) == ma.end()) {
            unsigned char *buf = new unsigned char[HMAC_SIZE];
            memset(buf, 0, HMAC_SIZE);
            //        mainMemory->memread(x,buf,HMAC_SIZE);
            //FIXME
            int i, j = 0;
            for (i = x; i < x + HMAC_SIZE; i++) {
                buf[j++] = memory[i];
            }
            //FIXME

            // cache is full
            if (dq.size() == csize) {
                // delete least recently used element
                unsigned char *last = dq.back();
                // Pops the last element
                dq.pop_back();
                // Erase the last
                //            ma.end().operator*();
                auto prev = ma.end();
                auto curr = ma.begin();
                for (auto it = ma.begin(); curr != ma.end();) {
                    prev = it;
                    curr = ++it;
                }
                ma.erase(prev);
                //            ma.erase(prev(ma.end()));
                //            delete[] last;
                dq.push_front(buf);
                ma[x] = dq.begin();
                return;
            }
            // Cache is not full, but there is a MISS
            dq.push_front(buf);
            ma[x] = dq.begin();
            return;
        }

            // present in cache
        else {
            unsigned char *buf = new unsigned char[HMAC_SIZE];
            memset(buf, 0, HMAC_SIZE);
            m_strncpy(buf, *ma[x], HMAC_SIZE);
            //FIXME: Deleting current node from memory
            unsigned char *curr = *ma[x];
            dq.erase(ma[x]);
            //        delete[] curr;
            //////////////////////////////////////////
            dq.push_front(buf);
            ma[x] = dq.begin();
        }

    }
    unsigned char* is_in_cache(int x) {
        if (ma.find(x) == ma.end()) {
            return NULL;
        }
        return ma[x].operator*();
    }
    unsigned char* read_from_cache(int x) {
        refer(x);
        return ma[x].operator*();
    }

    void write_to_cache(int x, unsigned char *value) {
        refer(x);
        unsigned char *pointer = ma[x].operator*();
        memset(pointer, 0, HMAC_SIZE);
        m_strncpy(pointer, value, HMAC_SIZE);
    }

    // Function to display contents of cache
    void display() {

        // Iterate in the deque and print
        // all the elements in it
        for (auto it = dq.begin(); it != dq.end();
             it++)
            cout << (*it) << " ";

        cout << endl;
    }

    //INPUT: index of node in tree
    //OUTPUT: index of right son index in tree
    int getRightSon(int i) {
        return 2 * i + 2;
    }

    int getLeftSon(int i) {
        return 2 * i + 1;
    }

    int getParentIndex(int i) {
        if (i % 2 == 0) {
            return (i / 2 - 1);
        } else {
            return (i - 1) / 2;
        }
    }

    uint64_t getMapping(int node_index) {
        return (uint64_t)((pointers) + node_index * sizeof(int));
    }

    //INPUT: address of certain node in tree
    //OUTPUT: index of that node. (Node 0, Node 1/Node 5 ....)
    int reverseMapping(int *node_address) {
        return ( node_address - pointers) / sizeof(int);
    }
};



class TrustedArea{
    std::vector<unsigned char*> trusted_memory;
    std::list<unsigned char*> tags_list; //FIFO (QUEUE)
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
