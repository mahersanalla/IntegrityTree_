//
// Created by root on 8/22/20.
// We can use stl container list as a double
// ended queue to store the cache keys, with
// the descending time of reference from front
// to back and a set container to check presence
// of a key. But to fetch the address of the key
// in the list using find(), it takes O(N) time.
// This can be optimized by storing a reference
// (iterator) to each key in a hash map.
#ifndef INTEGRITYTREE_LRU_CACHE_H
#define INTEGRITYTREE_LRU_CACHE_H
#include <bits/stdc++.h>
#include "MainMemory.h"
using namespace std;
class LRUCache {
    MainMemory* mainMemory;
    // store keys of cache
    list<unsigned char*> dq;
    // store references of key in cache
    unordered_map<int,typename list<unsigned char*>::iterator> ma;
    int csize; // maximum capacity of cache

public:
    LRUCache(int,MainMemory*);
    unsigned char* read_from_cache(int);
    void refer(int);
    void write_to_cache(int, unsigned char*);
    void display();
};

// Declare the size
LRUCache::LRUCache(int n,MainMemory* mainMemory1)
{
    csize = n;
    mainMemory=mainMemory1;
}

// Refers key x with in the LRU cache
void LRUCache::refer(int x)
{
    // not present in cache
    if (ma.find(x) == ma.end()) {
        unsigned char* buf=new unsigned char[HMAC_SIZE];
        memset(buf,0,HMAC_SIZE);
        mainMemory->memread(x,buf,HMAC_SIZE);
        // cache is full
        if (dq.size() == csize) {
            // delete least recently used element
            unsigned char* last = dq.back();
            // Pops the last element
            dq.pop_back();
            // Erase the last
//            ma.end().operator*();
            auto prev=ma.end();
            auto curr=ma.begin();
            for (auto it = ma.begin(); curr != ma.end();){
                prev=it;
                curr=++it;
            }
            ma.erase(prev);
//            ma.erase(prev(ma.end()));
//            delete[] last;
            dq.push_front(buf);
            ma[x]=dq.begin();
            return;
        }
        // Cache is not full, but there is a MISS
        dq.push_front(buf);
        ma[x]=dq.begin();
        return;
    }

        // present in cache
    else {
        unsigned char* buf=new unsigned char[HMAC_SIZE];
        memset(buf,0,HMAC_SIZE);
        m_strncpy(buf,*ma[x],HMAC_SIZE);
        //FIXME: Deleting current node from memory
        unsigned char* curr = *ma[x];
        dq.erase(ma[x]);
//        delete[] curr;
        //////////////////////////////////////////
        dq.push_front(buf);
        ma[x] = dq.begin();
    }

}
unsigned char* LRUCache::read_from_cache(int x){
    refer(x);
    return ma[x].operator*();
}
void LRUCache::write_to_cache(int x,unsigned char* value){
    refer(x);
    unsigned char* pointer=ma[x].operator*();
    memset(pointer,0,HMAC_SIZE);
    m_strncpy(pointer,value,HMAC_SIZE);
}

// Function to display contents of cache
void LRUCache::display() {

    // Iterate in the deque and print
    // all the elements in it
    for (auto it = dq.begin(); it != dq.end();
         it++)
        cout << (*it) << " ";

    cout << endl;
}

#endif //INTEGRITYTREE_LRU_CACHE_H
